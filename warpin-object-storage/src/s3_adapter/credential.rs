use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    path::{Component, Path},
};

use object_store::{
    aws::{AmazonS3ConfigKey, AmazonS3ConfigKey::*},
    client::HttpRequest,
};
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

use crate::ObjectStorageError;

use super::aws_dns_suffix;

const ECS_CREDENTIAL_AUTHORITY: &str = "169.254.170.2";
const IMDS_AUTHORITY: &str = "169.254.169.254";
const MAX_CREDENTIAL_TOKEN_BYTES: u64 = 16 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct TrustedCredentialHttpsOrigin {
    origin: Url,
}

impl TrustedCredentialHttpsOrigin {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ObjectStorageError> {
        let value = value.as_ref();
        let origin = Url::parse(value).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none_or(str::is_empty)
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || origin.as_str() != value
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        Ok(Self { origin })
    }

    fn matches(&self, target: &Url) -> bool {
        self.origin.scheme() == target.scheme()
            && self.origin.host_str() == target.host_str()
            && self.origin.port_or_known_default() == target.port_or_known_default()
    }
}

impl fmt::Debug for TrustedCredentialHttpsOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedCredentialHttpsOrigin")
            .field("identity", &digest_bytes(self.origin.as_str().as_bytes()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum CredentialMode {
    Static,
    ImdsV2,
    EcsRelative {
        target: Url,
    },
    EksFullUri {
        target: Url,
        token_digest: Sha256Digest,
    },
    WebIdentity {
        target: Url,
        token_digest: Sha256Digest,
        role_arn_digest: Sha256Digest,
        session_name_digest: Sha256Digest,
    },
}

impl CredentialMode {
    pub(super) fn from_options(
        options: &BTreeMap<String, String>,
        region: &str,
        trusted_https_origins: &[TrustedCredentialHttpsOrigin],
    ) -> Result<Self, ObjectStorageError> {
        let mut access_key = None;
        let mut secret_key = None;
        let mut session_token = None;
        let mut imdsv1_fallback = None;
        let mut metadata_endpoint = None;
        let mut ecs_relative_uri = None;
        let mut container_full_uri = None;
        let mut container_token_file = None;
        let mut web_identity_token_file = None;
        let mut role_arn = None;
        let mut role_session_name = None;
        let mut sts_endpoint = None;

        for (key, value) in options {
            match key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?
            {
                AccessKeyId => access_key = Some(value.as_str()),
                SecretAccessKey => secret_key = Some(value.as_str()),
                Token => session_token = Some(value.as_str()),
                ImdsV1Fallback => imdsv1_fallback = Some(value.as_str()),
                MetadataEndpoint => metadata_endpoint = Some(value.as_str()),
                ContainerCredentialsRelativeUri => ecs_relative_uri = Some(value.as_str()),
                ContainerCredentialsFullUri => container_full_uri = Some(value.as_str()),
                ContainerAuthorizationTokenFile => container_token_file = Some(value.as_str()),
                WebIdentityTokenFile => web_identity_token_file = Some(value.as_str()),
                RoleArn => role_arn = Some(value.as_str()),
                RoleSessionName => role_session_name = Some(value.as_str()),
                StsEndpoint => sts_endpoint = Some(value.as_str()),
                _ => {}
            }
        }

        let groups = [
            access_key.is_some() || secret_key.is_some() || session_token.is_some(),
            imdsv1_fallback.is_some() || metadata_endpoint.is_some(),
            ecs_relative_uri.is_some(),
            container_full_uri.is_some() || container_token_file.is_some(),
            web_identity_token_file.is_some()
                || role_arn.is_some()
                || role_session_name.is_some()
                || sts_endpoint.is_some(),
        ];
        if groups.into_iter().filter(|present| *present).count() > 1 {
            return Err(ObjectStorageError::InvalidConfiguration);
        }

        if access_key.is_some() || secret_key.is_some() || session_token.is_some() {
            if access_key.is_none() || secret_key.is_none() {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            return Ok(Self::Static);
        }
        if imdsv1_fallback.is_some() || metadata_endpoint.is_some() {
            if imdsv1_fallback.is_some_and(|value| value != "false")
                || metadata_endpoint.is_some_and(|value| value != "http://169.254.169.254")
            {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            return Ok(Self::ImdsV2);
        }
        if let Some(relative_uri) = ecs_relative_uri {
            validate_credential_path(relative_uri)?;
            let target = Url::parse(&format!("http://{ECS_CREDENTIAL_AUTHORITY}{relative_uri}"))
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            return Ok(Self::EcsRelative { target });
        }
        if container_full_uri.is_some() || container_token_file.is_some() {
            let target = validate_eks_target(
                container_full_uri.ok_or(ObjectStorageError::InvalidConfiguration)?,
                trusted_https_origins,
            )?;
            let token_digest = bounded_token_digest(
                container_token_file.ok_or(ObjectStorageError::InvalidConfiguration)?,
            )?;
            return Ok(Self::EksFullUri {
                target,
                token_digest,
            });
        }
        if web_identity_token_file.is_some()
            || role_arn.is_some()
            || role_session_name.is_some()
            || sts_endpoint.is_some()
        {
            let role_arn = role_arn.ok_or(ObjectStorageError::InvalidConfiguration)?;
            validate_role_arn(role_arn, region)?;
            if role_session_name.is_some_and(|value| {
                value.is_empty()
                    || value.len() > 64
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'=' | b',' | b'.' | b'@' | b'-' | b'_')
                    })
            }) {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            let target = official_sts_target(region)?;
            if sts_endpoint.is_some_and(|value| value != target.as_str().trim_end_matches('/')) {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            let token_digest = bounded_token_digest(
                web_identity_token_file.ok_or(ObjectStorageError::InvalidConfiguration)?,
            )?;
            let session_name = role_session_name.unwrap_or("WebIdentitySession");
            return Ok(Self::WebIdentity {
                target,
                token_digest,
                role_arn_digest: digest_bytes(role_arn.as_bytes()),
                session_name_digest: digest_bytes(session_name.as_bytes()),
            });
        }

        if trusted_https_origins.is_empty() {
            Ok(Self::ImdsV2)
        } else {
            // A trusted credential origin has meaning only for an explicitly
            // selected EKS full-URI provider.
            Err(ObjectStorageError::InvalidConfiguration)
        }
    }

    pub(super) fn verify_request(&self, request: &HttpRequest) -> Result<(), ObjectStorageError> {
        match self {
            Self::Static => Err(ObjectStorageError::InvalidConfiguration),
            Self::ImdsV2 => verify_imdsv2_request(request),
            Self::EcsRelative { target } => {
                verify_exact_request_target(request, "GET", target)?;
                require_header_absent(request, "authorization")
            }
            Self::EksFullUri {
                target,
                token_digest,
            } => {
                verify_exact_request_target(request, "GET", target)?;
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| {
                        !value.is_empty() && value.len() <= MAX_CREDENTIAL_TOKEN_BYTES as usize
                    })
                    .ok_or(ObjectStorageError::InvalidConfiguration)?;
                if &digest_bytes(authorization.as_bytes()) != token_digest {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                Ok(())
            }
            Self::WebIdentity {
                target,
                token_digest,
                role_arn_digest,
                session_name_digest,
            } => verify_web_identity_request(
                request,
                target,
                token_digest,
                role_arn_digest,
                session_name_digest,
            ),
        }
    }

    pub(super) fn official_sts_endpoint(&self) -> Option<&str> {
        match self {
            Self::WebIdentity { target, .. } => Some(target.as_str().trim_end_matches('/')),
            _ => None,
        }
    }
}

impl fmt::Debug for CredentialMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self {
            Self::Static => "static",
            Self::ImdsV2 => "imds_v2",
            Self::EcsRelative { .. } => "ecs_relative",
            Self::EksFullUri { .. } => "eks_full_uri",
            Self::WebIdentity { .. } => "web_identity",
        };
        formatter
            .debug_struct("CredentialMode")
            .field("mode", &mode)
            .finish()
    }
}

fn validate_credential_path(value: &str) -> Result<(), ObjectStorageError> {
    if value.len() > 2_048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.ends_with('/')
        || value.contains("//")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || value
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn verify_imdsv2_request(request: &HttpRequest) -> Result<(), ObjectStorageError> {
    let uri = request.uri().to_string();
    let token_target = format!("http://{IMDS_AUTHORITY}/latest/api/token");
    let role_target = format!("http://{IMDS_AUTHORITY}/latest/meta-data/iam/security-credentials/");
    match request.method().as_str() {
        "PUT" if uri == token_target => {
            require_header_exact(request, "x-aws-ec2-metadata-token-ttl-seconds", "600")?;
            require_header_absent(request, "x-aws-ec2-metadata-token")?;
            require_header_absent(request, "authorization")
        }
        "GET" if uri == role_target => {
            require_imdsv2_token(request)?;
            require_header_absent(request, "x-aws-ec2-metadata-token-ttl-seconds")?;
            require_header_absent(request, "authorization")
        }
        "GET" if uri.starts_with(&role_target) => {
            let role = uri
                .strip_prefix(&role_target)
                .ok_or(ObjectStorageError::InvalidConfiguration)?;
            validate_credential_path(&format!("/{role}"))?;
            require_imdsv2_token(request)?;
            require_header_absent(request, "x-aws-ec2-metadata-token-ttl-seconds")?;
            require_header_absent(request, "authorization")
        }
        _ => Err(ObjectStorageError::InvalidConfiguration),
    }
}

fn verify_exact_request_target(
    request: &HttpRequest,
    method: &str,
    target: &Url,
) -> Result<(), ObjectStorageError> {
    if request.method().as_str() != method || request.uri() != target.as_str() {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn verify_web_identity_request(
    request: &HttpRequest,
    target: &Url,
    token_digest: &Sha256Digest,
    role_arn_digest: &Sha256Digest,
    session_name_digest: &Sha256Digest,
) -> Result<(), ObjectStorageError> {
    if request.method().as_str() != "POST" {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    require_header_absent(request, "authorization")?;
    let actual = Url::parse(&request.uri().to_string())
        .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
    if actual.scheme() != target.scheme()
        || actual.host_str() != target.host_str()
        || actual.port_or_known_default() != target.port_or_known_default()
        || actual.path() != target.path()
        || !actual.username().is_empty()
        || actual.password().is_some()
        || actual.fragment().is_some()
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    let mut fields = BTreeMap::new();
    for (name, value) in actual.query_pairs() {
        if fields
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
    }
    if fields.len() != 6
        || fields.get("Action").map(String::as_str) != Some("AssumeRoleWithWebIdentity")
        || fields.get("DurationSeconds").map(String::as_str) != Some("3600")
        || fields.get("Version").map(String::as_str) != Some("2011-06-15")
        || fields
            .get("WebIdentityToken")
            .map(|value| digest_bytes(value.as_bytes()))
            .as_ref()
            != Some(token_digest)
        || fields
            .get("RoleArn")
            .map(|value| digest_bytes(value.as_bytes()))
            .as_ref()
            != Some(role_arn_digest)
        || fields
            .get("RoleSessionName")
            .map(|value| digest_bytes(value.as_bytes()))
            .as_ref()
            != Some(session_name_digest)
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn require_imdsv2_token(request: &HttpRequest) -> Result<(), ObjectStorageError> {
    request
        .headers()
        .get("x-aws-ec2-metadata-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= MAX_CREDENTIAL_TOKEN_BYTES as usize)
        .map(|_| ())
        .ok_or(ObjectStorageError::InvalidConfiguration)
}

fn require_header_exact(
    request: &HttpRequest,
    name: &str,
    expected: &str,
) -> Result<(), ObjectStorageError> {
    if request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        != Some(expected)
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn require_header_absent(request: &HttpRequest, name: &str) -> Result<(), ObjectStorageError> {
    if request.headers().contains_key(name) {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_eks_target(
    value: &str,
    trusted_https_origins: &[TrustedCredentialHttpsOrigin],
) -> Result<Url, ObjectStorageError> {
    let target = Url::parse(value).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
    validate_credential_path(target.path())?;
    if !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
        || target.as_str() != value
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    let standard_http_target = target.scheme() == "http"
        && target
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| {
                address.is_loopback()
                    || (target.port().is_none()
                        && (matches!(address, IpAddr::V4(value) if value.octets() == [169, 254, 170, 2] || value.octets() == [169, 254, 170, 23])
                            || matches!(address, IpAddr::V6(value) if value.octets() == [0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x23])))
            });
    let trusted_https_target = target.scheme() == "https"
        && trusted_https_origins
            .iter()
            .any(|origin| origin.matches(&target));
    if !standard_http_target && !trusted_https_target {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(target)
}

fn official_sts_target(region: &str) -> Result<Url, ObjectStorageError> {
    let suffix = aws_dns_suffix(region).ok_or(ObjectStorageError::InvalidConfiguration)?;
    Url::parse(&format!("https://sts.{region}.{suffix}"))
        .map_err(|_| ObjectStorageError::InvalidConfiguration)
}

fn validate_role_arn(value: &str, region: &str) -> Result<(), ObjectStorageError> {
    let expected_partition = if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else {
        "aws"
    };
    let mut parts = value.splitn(6, ':');
    let valid = parts.next() == Some("arn")
        && parts.next() == Some(expected_partition)
        && parts.next() == Some("iam")
        && parts.next() == Some("")
        && parts.next().is_some_and(|account| {
            account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit())
        })
        && parts.next().is_some_and(|resource| {
            resource.starts_with("role/")
                && resource.len() > "role/".len()
                && resource.len() <= 1_024
                && !resource.ends_with('/')
                && !resource.contains("//")
                && resource.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'/' | b'+' | b'=' | b',' | b'.' | b'@' | b'-' | b'_')
                })
        });
    if !valid {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
}

fn bounded_token_digest(value: &str) -> Result<Sha256Digest, ObjectStorageError> {
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_TOKEN_BYTES
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    let token = std::fs::read(path).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
    if u64::try_from(token.len()).ok() != Some(metadata.len())
        || !token.iter().all(|byte| matches!(byte, 0x21..=0x7e))
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(digest_bytes(&token))
}
