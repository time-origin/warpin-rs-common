use std::{collections::BTreeMap, fmt};

use object_store::{
    aws::{AmazonS3ConfigKey, AmazonS3ConfigKey::*},
    client::HttpRequest,
};
use url::Url;

use crate::ObjectStorageError;

const ECS_CREDENTIAL_AUTHORITY: &str = "169.254.170.2";
const IMDS_AUTHORITY: &str = "169.254.169.254";
const MAX_CREDENTIAL_TARGET_BYTES: usize = 2_048;
const MAX_CREDENTIAL_TOKEN_BYTES: usize = 16 * 1024;
const MAX_IAM_ROLE_NAME_BYTES: usize = 64;

/// Credential acquisition modes supported by the 0.2.0 managed-S3 contract.
///
/// Full-URI container credentials, authorization-token files, web identity,
/// role assumption, and custom STS endpoints are rejected during preflight.
#[derive(Clone, Eq, PartialEq)]
pub(super) enum CredentialMode {
    Static,
    ImdsV2,
    EcsRelative { target: Url },
}

impl CredentialMode {
    pub(super) fn from_options(
        options: &BTreeMap<String, String>,
    ) -> Result<Self, ObjectStorageError> {
        let mut access_key = None;
        let mut secret_key = None;
        let mut session_token = None;
        let mut imdsv1_fallback = None;
        let mut metadata_endpoint = None;
        let mut ecs_relative_uri = None;

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
                ContainerCredentialsFullUri
                | ContainerAuthorizationTokenFile
                | WebIdentityTokenFile
                | RoleArn
                | RoleSessionName
                | StsEndpoint => return Err(ObjectStorageError::InvalidConfiguration),
                _ => {}
            }
        }

        let groups = [
            access_key.is_some() || secret_key.is_some() || session_token.is_some(),
            imdsv1_fallback.is_some() || metadata_endpoint.is_some(),
            ecs_relative_uri.is_some(),
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
            let target = ecs_relative_target(relative_uri)?;
            return Ok(Self::EcsRelative { target });
        }

        Ok(Self::ImdsV2)
    }

    pub(super) fn verify_request(&self, request: &HttpRequest) -> Result<(), ObjectStorageError> {
        match self {
            Self::Static => Err(ObjectStorageError::InvalidConfiguration),
            Self::ImdsV2 => verify_imdsv2_request(request),
            Self::EcsRelative { target } => {
                verify_exact_request_target(request, "GET", target)?;
                require_header_absent(request, "authorization")
            }
        }
    }
}

impl fmt::Debug for CredentialMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self {
            Self::Static => "static",
            Self::ImdsV2 => "imds_v2",
            Self::EcsRelative { .. } => "ecs_relative",
        };
        formatter
            .debug_struct("CredentialMode")
            .field("mode", &mode)
            .finish()
    }
}

fn ecs_relative_target(value: &str) -> Result<Url, ObjectStorageError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_TARGET_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('#')
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    let path = value.split_once('?').map_or(value, |(path, _)| path);
    validate_absolute_credential_path(path)?;

    let exact = format!("http://{ECS_CREDENTIAL_AUTHORITY}{value}");
    let target = Url::parse(&exact).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
    if target.scheme() != "http"
        || target.host_str() != Some(ECS_CREDENTIAL_AUTHORITY)
        || target.port().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
        || target.as_str() != exact
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(target)
}

fn validate_absolute_credential_path(value: &str) -> Result<(), ObjectStorageError> {
    if value.is_empty()
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
            let role_name = uri
                .strip_prefix(&role_target)
                .ok_or(ObjectStorageError::InvalidConfiguration)?;
            validate_iam_role_name(role_name)?;
            require_imdsv2_token(request)?;
            require_header_absent(request, "x-aws-ec2-metadata-token-ttl-seconds")?;
            require_header_absent(request, "authorization")
        }
        _ => Err(ObjectStorageError::InvalidConfiguration),
    }
}

fn validate_iam_role_name(value: &str) -> Result<(), ObjectStorageError> {
    if value.is_empty()
        || value.len() > MAX_IAM_ROLE_NAME_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b'-')
        })
    {
        return Err(ObjectStorageError::InvalidConfiguration);
    }
    Ok(())
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

fn require_imdsv2_token(request: &HttpRequest) -> Result<(), ObjectStorageError> {
    request
        .headers()
        .get("x-aws-ec2-metadata-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= MAX_CREDENTIAL_TOKEN_BYTES)
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
