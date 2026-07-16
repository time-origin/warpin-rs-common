use std::fmt;

#[cfg(feature = "aws")]
use std::collections::{BTreeMap, HashSet};

#[cfg(feature = "aws")]
use async_trait::async_trait;
#[cfg(any(feature = "aws", test))]
use object_store::path::Path;
#[cfg(feature = "aws")]
use object_store::{
    ObjectStore,
    aws::{AmazonS3Builder, AmazonS3ConfigKey, AwsAuthorizer, AwsCredentialProvider},
    client::{
        ClientConfigKey, HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest,
        HttpRequestBody, HttpResponse, HttpService,
    },
};
#[cfg(feature = "aws")]
use reqwest::{redirect::Policy as RedirectPolicy, tls::Certificate};
#[cfg(feature = "aws")]
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

#[cfg(feature = "aws")]
mod credential;
#[cfg(feature = "aws")]
use credential::CredentialMode;

use super::{
    EncryptionPolicyError, ManagedEncryptionProfileId, ObservedOperation, ObserverRequestBinding,
    WriteBinding,
};
#[cfg(feature = "aws")]
use super::{ObjectStorageError, ObjectStoreSettings, map_backend_configuration_error};

pub(crate) const S3_BUCKET_KEY_ENABLED_HEADER: &str =
    "x-amz-server-side-encryption-bucket-key-enabled";
const S3_SSE_HEADER: &str = "x-amz-server-side-encryption";
const S3_KMS_KEY_ID_HEADER: &str = "x-amz-server-side-encryption-aws-kms-key-id";
const S3_VERSION_HEADER: &str = "x-amz-version-id";
#[cfg(feature = "aws")]
const AWS_CONTENT_SHA256_HEADER: &str = "x-amz-content-sha256";
#[cfg(feature = "aws")]
const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const S3_SSE_KMS_VALUE: &str = "aws:kms";
const AWS_S3_OBJECT_CONTEXT_PROFILE_DOMAIN: &[u8] =
    b"warpin:managed-encryption-profile:aws-s3-object-arn-sse-kms:v1";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const MINIO_KES_OBJECT_CONTEXT_PROFILE_DOMAIN: &[u8] =
    b"warpin:managed-encryption-profile:minio-kes-bucket-object-sse-kms:v1";
const MAX_OBSERVED_KEY_ID_BYTES: usize = 2_048;

/// Selects the reviewed MinIO/KES managed-encryption profile for a custom S3
/// endpoint without exposing provider algorithm strings or requiring callers to
/// reproduce the opaque profile digest.
///
/// This selects a reviewed adapter contract; it does not identify or attest an
/// arbitrary endpoint as MinIO/KES. The deployment must pass the live MinIO/KES
/// compatibility gate before this profile is enabled. The gate must confirm
/// SSE-KMS response identity and that the selected server version preserves
/// MinIO's documented bucket-and-object KEK derivation guarantee.
#[cfg(feature = "aws")]
pub fn with_minio_kes_object_context_profile(settings: ObjectStoreSettings) -> ObjectStoreSettings {
    with_object_context_profile(settings, minio_kes_object_context_profile_id())
}

/// Selects the reviewed native AWS S3 object-ARN encryption-context profile.
///
/// The adapter explicitly disables S3 Bucket Keys on signed writes so AWS KMS
/// uses the object ARN, rather than only the bucket ARN, as its default
/// encryption context.
#[cfg(feature = "aws")]
pub fn with_aws_s3_object_context_profile(settings: ObjectStoreSettings) -> ObjectStoreSettings {
    with_object_context_profile(settings, aws_s3_object_context_profile_id())
}

#[cfg(feature = "aws")]
fn with_object_context_profile(
    settings: ObjectStoreSettings,
    profile_id: ManagedEncryptionProfileId,
) -> ObjectStoreSettings {
    settings
        .with_managed_encryption_profile_id(profile_id)
        .with_option("aws_server_side_encryption", S3_SSE_KMS_VALUE)
        .with_option("aws_sse_bucket_key_enabled", "false")
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedManagedAlgorithm {
    Missing,
    SseKms,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedBucketKeyState {
    Missing,
    Disabled,
    Enabled,
    Invalid,
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectContextGuarantee {
    AwsObjectArn,
    MinioKesBucketAndObject,
}

#[cfg(feature = "aws")]
#[derive(Clone, Eq, PartialEq)]
struct ExpectedRequestTarget {
    base_url: Url,
    sigv4_region: String,
    signed_sse_shape: ExpectedSignedSseShape,
}

#[cfg(feature = "aws")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedSignedSseShape {
    algorithm: ObservedManagedAlgorithm,
    bucket_key_state: ObservedBucketKeyState,
    key_identity_fingerprint: Option<Sha256Digest>,
}

#[cfg(feature = "aws")]
impl ExpectedRequestTarget {
    fn from_configuration(
        storage_url: &Url,
        bucket: &str,
        region: &str,
        custom_endpoint: Option<&str>,
        virtual_hosted: bool,
        guarantee: ObjectContextGuarantee,
        signed_sse_shape: ExpectedSignedSseShape,
    ) -> Result<Self, ObjectStorageError> {
        let mut base_url = match guarantee {
            ObjectContextGuarantee::AwsObjectArn => {
                if custom_endpoint.is_some() {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                let dns_suffix =
                    aws_dns_suffix(region).ok_or(ObjectStorageError::InvalidConfiguration)?;
                let value = if virtual_hosted {
                    format!("https://{bucket}.s3.{region}.{dns_suffix}")
                } else {
                    format!("https://s3.{region}.{dns_suffix}")
                };
                Url::parse(&value).map_err(|_| ObjectStorageError::InvalidConfiguration)?
            }
            ObjectContextGuarantee::MinioKesBucketAndObject => {
                if virtual_hosted {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                let endpoint = custom_endpoint.ok_or(ObjectStorageError::InvalidConfiguration)?;
                let parsed =
                    Url::parse(endpoint).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none_or(str::is_empty)
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                parsed
            }
        };
        if !matches!(storage_url.scheme(), "s3" | "s3a") || storage_url.host_str() != Some(bucket) {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        {
            let mut segments = base_url
                .path_segments_mut()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            segments.pop_if_empty();
            if !virtual_hosted {
                segments.push(bucket);
            }
        }
        Ok(Self {
            base_url,
            sigv4_region: region.to_owned(),
            signed_sse_shape,
        })
    }

    fn verify(
        &self,
        request: &ObserverRequestBinding,
        method: &str,
        request_uri: &str,
    ) -> Result<Sha256Digest, ObjectStorageError> {
        if !request.operation.matches_method(method) {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let expected = self.request_url(request)?;
        let actual =
            Url::parse(request_uri).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        if actual.scheme() != "https"
            || actual.username() != ""
            || actual.password().is_some()
            || actual.fragment().is_some()
            || actual.as_str() != expected.as_str()
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        Ok(digest_bytes(actual.as_str().as_bytes()))
    }

    fn request_url(&self, request: &ObserverRequestBinding) -> Result<Url, ObjectStorageError> {
        // `object_store` signs S3 paths with AWS's RFC 3986 encoding rules.
        // WHATWG URL path-segment encoding is intentionally different (for
        // example, it leaves `=` unescaped), so using `Url::path_segments_mut`
        // here would construct a target that cannot equal the signed request.
        // Build the canonical path once from raw `Path` parts instead. Exact
        // URI comparison below deliberately rejects decoded or differently
        // percent-encoded aliases.
        let mut expected_uri = self.base_url.as_str().trim_end_matches('/').to_owned();
        for part in request.expected_location.parts() {
            expected_uri.push('/');
            expected_uri.push_str(&encode_sigv4_path_segment(part.as_ref()));
        }
        let mut expected =
            Url::parse(&expected_uri).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        match request.operation {
            ObservedOperation::Put => {
                if request.expected_version.is_some() {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
            }
            ObservedOperation::Readback | ObservedOperation::Delete => {
                if let Some(version) = request.expected_version.as_deref() {
                    expected.query_pairs_mut().append_pair("versionId", version);
                }
            }
        }
        Ok(expected)
    }

    fn verify_sigv4(
        &self,
        request: &ObserverRequestBinding,
        method: &str,
        request_uri: &str,
        headers: &object_store::HeaderMap,
    ) -> Result<(), ObjectStorageError> {
        if !request.operation.matches_method(method) {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let actual =
            Url::parse(request_uri).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        let authority = &actual[url::Position::BeforeHost..url::Position::AfterPort];
        if authority.is_empty() || single_header_value(headers, "host") != Some(authority) {
            return Err(ObjectStorageError::InvalidConfiguration);
        }

        let authorization = single_header_value(headers, "authorization")
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let fields = authorization
            .strip_prefix("AWS4-HMAC-SHA256 ")
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let mut credential = None;
        let mut signed_headers = None;
        let mut signature = None;
        for field in fields.split(", ") {
            let (name, value) = field
                .split_once('=')
                .ok_or(ObjectStorageError::InvalidConfiguration)?;
            if value.is_empty() {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            match name {
                "Credential" if credential.replace(value).is_none() => {}
                "SignedHeaders" if signed_headers.replace(value).is_none() => {}
                "Signature" if signature.replace(value).is_none() => {}
                _ => return Err(ObjectStorageError::InvalidConfiguration),
            }
        }
        let credential = credential.ok_or(ObjectStorageError::InvalidConfiguration)?;
        let signed_headers = signed_headers.ok_or(ObjectStorageError::InvalidConfiguration)?;
        let signature = signature.ok_or(ObjectStorageError::InvalidConfiguration)?;
        let scope = credential.split('/').collect::<Vec<_>>();
        if scope.len() != 5
            || scope[0].is_empty()
            || scope[1].len() != 8
            || !scope[1].bytes().all(|byte| byte.is_ascii_digit())
            || scope[2] != self.sigv4_region
            || scope[3] != "s3"
            || scope[4] != "aws4_request"
            || signature.len() != 64
            || !signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let request_date = single_header_value(headers, "x-amz-date")
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        if request_date.len() != 16
            || !request_date.ends_with('Z')
            || request_date.as_bytes().get(8) != Some(&b'T')
            || &request_date[..8] != scope[1]
            || !request_date[..8].bytes().all(|byte| byte.is_ascii_digit())
            || !request_date[9..15]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let names = signed_headers.split(';').collect::<Vec<_>>();
        if names.is_empty()
            || names.iter().any(|name| {
                name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || names.windows(2).any(|pair| pair[0] >= pair[1])
            || !names.contains(&"host")
            || !names.contains(&AWS_CONTENT_SHA256_HEADER)
            || !names.contains(&"x-amz-date")
            || names
                .iter()
                .any(|name| single_header_value(headers, name).is_none())
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let content_sha = single_header_value(headers, AWS_CONTENT_SHA256_HEADER)
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let expected_content_sha = match request.operation {
            ObservedOperation::Put => request
                .binding
                .as_ref()
                .and_then(|binding| binding.content_digest().as_str().strip_prefix("sha256:"))
                .ok_or(ObjectStorageError::InvalidConfiguration)?,
            ObservedOperation::Readback | ObservedOperation::Delete => EMPTY_SHA256_HEX,
        };
        if content_sha != expected_content_sha {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        if request.operation == ObservedOperation::Put {
            if self.signed_sse_shape.algorithm != ObservedManagedAlgorithm::SseKms
                || single_header_value(headers, S3_SSE_HEADER) != Some(S3_SSE_KMS_VALUE)
                || !names.contains(&S3_SSE_HEADER)
                || self.signed_sse_shape.bucket_key_state != ObservedBucketKeyState::Disabled
                || single_header_value(headers, S3_BUCKET_KEY_ENABLED_HEADER) != Some("false")
                || !names.contains(&S3_BUCKET_KEY_ENABLED_HEADER)
            {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            if let Some(expected) = self.signed_sse_shape.key_identity_fingerprint.as_ref() {
                let actual = single_header_value(headers, S3_KMS_KEY_ID_HEADER)
                    .filter(|value| !value.is_empty() && value.len() <= MAX_OBSERVED_KEY_ID_BYTES)
                    .map(|value| digest_bytes(value.as_bytes()))
                    .ok_or(ObjectStorageError::InvalidConfiguration)?;
                if &actual != expected || !names.contains(&S3_KMS_KEY_ID_HEADER) {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
            } else if headers.contains_key(S3_KMS_KEY_ID_HEADER)
                || names.contains(&S3_KMS_KEY_ID_HEADER)
            {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

/// Encodes one raw S3 object-key path segment for a SigV4 canonical URI.
///
/// AWS S3 preserves only RFC 3986 unreserved bytes and path separators. The
/// caller adds separators between encoded segments, which prevents embedded
/// data from being mistaken for path structure and avoids double-encoding a
/// previously assembled URL.
#[cfg(feature = "aws")]
fn encode_sigv4_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(feature = "aws")]
impl fmt::Debug for ExpectedRequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpectedRequestTarget")
            .field("identity", &digest_bytes(self.base_url.as_str().as_bytes()))
            .finish()
    }
}

#[cfg(feature = "aws")]
fn aws_dns_suffix(region: &str) -> Option<&'static str> {
    let valid = !region.is_empty()
        && region.len() <= 64
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid
        || region.starts_with("us-iso-")
        || region.starts_with("us-isob-")
        || region.starts_with("us-isof-")
        || region.starts_with("eu-isoe-")
    {
        return None;
    }
    if region.starts_with("cn-") {
        return Some("amazonaws.com.cn");
    }
    [
        "af-", "ap-", "ca-", "eu-", "il-", "me-", "mx-", "sa-", "us-",
    ]
    .iter()
    .any(|prefix| region.starts_with(prefix))
    .then_some("amazonaws.com")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfiguredS3Encryption {
    pub(crate) profile_id: ManagedEncryptionProfileId,
    object_context_guarantee: ObjectContextGuarantee,
    pub(crate) algorithm: ObservedManagedAlgorithm,
    pub(crate) bucket_key_state: ObservedBucketKeyState,
    pub(crate) expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    #[cfg(feature = "aws")]
    expected_request_target: ExpectedRequestTarget,
    #[cfg(feature = "aws")]
    credential_mode: CredentialMode,
}

#[cfg(feature = "aws")]
impl ConfiguredS3Encryption {
    pub(crate) fn from_options(
        storage_url: &Url,
        options: &BTreeMap<String, String>,
        selected_profile_id: Option<ManagedEncryptionProfileId>,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Result<Self, ObjectStorageError> {
        let mut algorithm = None;
        let mut expected_request_key_identity_fingerprint = None;
        let mut bucket_key_state = ObservedBucketKeyState::Missing;
        let mut bucket_key_configured = false;
        let mut endpoint = None;
        let mut s3_endpoint = None;
        let mut region = None;
        let mut default_region = None;
        let mut virtual_hosted = false;
        let mut normalized_keys = HashSet::new();
        let mut endpoint_key_seen = false;
        let mut region_key_seen = false;
        for (key, value) in options {
            let parsed = key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            if !normalized_keys.insert(parsed) {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            match parsed {
                AmazonS3ConfigKey::Endpoint => {
                    if endpoint_key_seen {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                    endpoint_key_seen = true;
                    endpoint = Some(value.as_str());
                }
                AmazonS3ConfigKey::S3Endpoint => {
                    if endpoint_key_seen {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                    endpoint_key_seen = true;
                    s3_endpoint = Some(value.as_str());
                }
                AmazonS3ConfigKey::Region => {
                    if region_key_seen {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                    region_key_seen = true;
                    region = Some(value.as_str());
                }
                AmazonS3ConfigKey::DefaultRegion => {
                    if region_key_seen {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                    region_key_seen = true;
                    default_region = Some(value.as_str());
                }
                AmazonS3ConfigKey::VirtualHostedStyleRequest => {
                    virtual_hosted = parse_strict_bool(value)?;
                }
                AmazonS3ConfigKey::Bucket => {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                AmazonS3ConfigKey::SkipSignature => {
                    if parse_strict_bool(value)? {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                }
                AmazonS3ConfigKey::Client(
                    ClientConfigKey::AllowHttp
                    | ClientConfigKey::AllowInvalidCertificates
                    | ClientConfigKey::NoSystemCertificates,
                ) => {
                    if parse_strict_bool(value)? {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                }
                AmazonS3ConfigKey::Client(ClientConfigKey::RandomizeAddresses) => {
                    if parse_strict_bool(value)? {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                }
                AmazonS3ConfigKey::Encryption(_) => match parsed.as_ref() {
                    "aws_server_side_encryption" => {
                        if algorithm.is_some() {
                            return Err(ObjectStorageError::InvalidConfiguration);
                        }
                        algorithm = Some(if value == S3_SSE_KMS_VALUE {
                            ObservedManagedAlgorithm::SseKms
                        } else {
                            ObservedManagedAlgorithm::Other
                        });
                    }
                    "aws_sse_kms_key_id" => {
                        if expected_request_key_identity_fingerprint.is_some()
                            || value.is_empty()
                            || value.len() > MAX_OBSERVED_KEY_ID_BYTES
                        {
                            return Err(ObjectStorageError::InvalidConfiguration);
                        }
                        expected_request_key_identity_fingerprint =
                            Some(digest_bytes(value.as_bytes()));
                    }
                    "aws_sse_bucket_key_enabled" => {
                        if bucket_key_configured {
                            return Err(ObjectStorageError::InvalidConfiguration);
                        }
                        bucket_key_configured = true;
                        bucket_key_state = match value.as_str() {
                            "false" => ObservedBucketKeyState::Disabled,
                            "true" => ObservedBucketKeyState::Enabled,
                            _ => ObservedBucketKeyState::Invalid,
                        };
                    }
                    // Customer-provided keys and any future encryption option
                    // are outside the reviewed managed SSE-KMS contract.
                    _ => return Err(ObjectStorageError::InvalidConfiguration),
                },
                AmazonS3ConfigKey::AccessKeyId
                | AmazonS3ConfigKey::SecretAccessKey
                | AmazonS3ConfigKey::Token
                | AmazonS3ConfigKey::ImdsV1Fallback
                | AmazonS3ConfigKey::MetadataEndpoint
                | AmazonS3ConfigKey::ContainerCredentialsRelativeUri
                | AmazonS3ConfigKey::Client(ClientConfigKey::ConnectTimeout)
                | AmazonS3ConfigKey::Client(ClientConfigKey::DefaultContentType)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http1Only)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http2Only)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http2KeepAliveInterval)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http2KeepAliveTimeout)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http2KeepAliveWhileIdle)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Http2MaxFrameSize)
                | AmazonS3ConfigKey::Client(ClientConfigKey::PoolIdleTimeout)
                | AmazonS3ConfigKey::Client(ClientConfigKey::PoolMaxIdlePerHost)
                | AmazonS3ConfigKey::Client(ClientConfigKey::ReadTimeout)
                | AmazonS3ConfigKey::Client(ClientConfigKey::Timeout)
                | AmazonS3ConfigKey::Client(ClientConfigKey::UserAgent) => {}
                // Proxy/custom trust configuration is deliberately unavailable
                // until the managed transport can bind and attest its trust
                // policy. Silently dropping or partially applying it is unsafe.
                AmazonS3ConfigKey::Client(
                    ClientConfigKey::ProxyUrl
                    | ClientConfigKey::ProxyCaCertificate
                    | ClientConfigKey::ProxyExcludes,
                )
                | AmazonS3ConfigKey::UnsignedPayload
                | AmazonS3ConfigKey::Checksum
                | AmazonS3ConfigKey::CopyIfNotExists
                | AmazonS3ConfigKey::ConditionalPut
                | AmazonS3ConfigKey::DisableTagging
                | AmazonS3ConfigKey::DisableBulkDelete
                | AmazonS3ConfigKey::S3Express
                | AmazonS3ConfigKey::RequestPayer => {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                // These credential surfaces are deliberately absent from the
                // 0.2.0 contract. Reject every canonical or legacy spelling
                // after normalization, before builder construction or I/O.
                AmazonS3ConfigKey::ContainerCredentialsFullUri
                | AmazonS3ConfigKey::ContainerAuthorizationTokenFile
                | AmazonS3ConfigKey::WebIdentityTokenFile
                | AmazonS3ConfigKey::RoleArn
                | AmazonS3ConfigKey::RoleSessionName
                | AmazonS3ConfigKey::StsEndpoint => {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
                // Both outer and nested keys are non-exhaustive. A dependency
                // upgrade must be reviewed before a new option reaches a
                // managed request path.
                _ => {
                    return Err(ObjectStorageError::InvalidConfiguration);
                }
            }
        }
        let custom_endpoint = s3_endpoint.or(endpoint);
        let has_custom_endpoint = custom_endpoint.is_some();
        let region = region
            .or(default_region)
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let bucket = storage_url
            .host_str()
            .filter(|bucket| !bucket.is_empty())
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let aws_profile_id = aws_s3_object_context_profile_id();
        let minio_profile_id = minio_kes_object_context_profile_id();
        let (profile_id, object_context_guarantee) =
            match (has_custom_endpoint, selected_profile_id) {
                (false, None) => (aws_profile_id, ObjectContextGuarantee::AwsObjectArn),
                (false, Some(profile_id)) if profile_id == aws_profile_id => {
                    (profile_id, ObjectContextGuarantee::AwsObjectArn)
                }
                (true, Some(profile_id)) if profile_id == minio_profile_id => {
                    (profile_id, ObjectContextGuarantee::MinioKesBucketAndObject)
                }
                _ => return Err(ObjectStorageError::InvalidConfiguration),
            };
        let expected_request_target = ExpectedRequestTarget::from_configuration(
            storage_url,
            bucket,
            region,
            custom_endpoint,
            virtual_hosted,
            object_context_guarantee,
            ExpectedSignedSseShape {
                algorithm: algorithm.unwrap_or(ObservedManagedAlgorithm::Missing),
                bucket_key_state,
                key_identity_fingerprint: expected_request_key_identity_fingerprint,
            },
        )?;
        let credential_mode = CredentialMode::from_options(options)?;
        Ok(Self {
            profile_id,
            object_context_guarantee,
            algorithm: algorithm.unwrap_or(ObservedManagedAlgorithm::Missing),
            bucket_key_state,
            expected_observed_key_identity_fingerprint,
            expected_request_target,
            credential_mode,
        })
    }

    pub(crate) fn build_store(
        url: &Url,
        options: BTreeMap<String, String>,
        selected_profile_id: Option<ManagedEncryptionProfileId>,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
        trusted_root_certificate_pems: Vec<Vec<u8>>,
    ) -> Result<(Box<dyn ObjectStore>, Path, Self, S3VerifiedDeleteAdapter), ObjectStorageError>
    {
        let configured = Self::from_options(
            url,
            &options,
            selected_profile_id,
            expected_observed_key_identity_fingerprint,
        )?;
        let client_options = managed_client_options(&options)?;
        let delete_connector = S3EncryptionObserverConnector::new(
            configured.expected_request_target.clone(),
            configured.credential_mode.clone(),
            &trusted_root_certificate_pems,
        )?;
        let delete_client = delete_connector
            .connect(&client_options)
            .map_err(map_backend_configuration_error)?;
        let mut builder = AmazonS3Builder::new()
            .with_url(url.as_str())
            .with_config(
                AmazonS3ConfigKey::Client(ClientConfigKey::RandomizeAddresses),
                "false",
            )
            .with_http_connector(S3EncryptionObserverConnector::new(
                configured.expected_request_target.clone(),
                configured.credential_mode.clone(),
                &trusted_root_certificate_pems,
            )?);
        for (key, value) in options {
            let key = key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            builder = builder.with_config(key, value);
        }
        let store = builder.build().map_err(map_backend_configuration_error)?;
        let delete_adapter = S3VerifiedDeleteAdapter {
            credentials: store.credentials().clone(),
            client: delete_client,
            expected_request_target: configured.expected_request_target.clone(),
            sigv4_region: configured.expected_request_target.sigv4_region.clone(),
        };
        let prefix = Path::from_url_path(url.path())
            .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        Ok((Box::new(store), prefix, configured, delete_adapter))
    }
}

#[cfg(feature = "aws")]
fn managed_client_options(
    options: &BTreeMap<String, String>,
) -> Result<object_store::ClientOptions, ObjectStorageError> {
    let mut client_options = object_store::ClientOptions::new()
        .with_config(ClientConfigKey::RandomizeAddresses, "false");
    for (key, value) in options {
        if let AmazonS3ConfigKey::Client(key) = key
            .parse::<AmazonS3ConfigKey>()
            .map_err(|_| ObjectStorageError::InvalidConfiguration)?
        {
            client_options = client_options.with_config(key, value);
        }
    }
    Ok(client_options)
}

#[cfg(feature = "aws")]
#[derive(Clone)]
pub(crate) struct S3VerifiedDeleteAdapter {
    credentials: AwsCredentialProvider,
    client: HttpClient,
    expected_request_target: ExpectedRequestTarget,
    sigv4_region: String,
}

#[cfg(feature = "aws")]
impl fmt::Debug for S3VerifiedDeleteAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3VerifiedDeleteAdapter")
            .field("target", &"[BOUND]")
            .field("credentials", &"[CONFIGURED]")
            .finish()
    }
}

#[cfg(feature = "aws")]
impl S3VerifiedDeleteAdapter {
    pub(crate) async fn delete_exact(
        &self,
        location: Path,
        expected_version: Option<String>,
    ) -> Result<(), ObjectStorageError> {
        let binding = ObserverRequestBinding::delete(location, expected_version.clone());
        let url = self.expected_request_target.request_url(&binding)?;
        let mut request = HttpRequest::new(HttpRequestBody::empty());
        *request.method_mut() = "DELETE"
            .parse()
            .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        *request.uri_mut() = url
            .as_str()
            .parse()
            .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        request.extensions_mut().insert(binding);
        let credentials = self
            .credentials
            .get_credential()
            .await
            .map_err(|_| ObjectStorageError::Backend)?;
        AwsAuthorizer::new(&credentials, "s3", &self.sigv4_region)
            .try_authorize(&mut request, None)
            .map_err(|_| ObjectStorageError::RequestSignatureInvalid)?;
        let response = self.client.execute(request).await.map_err(|error| {
            map_managed_request_error(&error).unwrap_or(ObjectStorageError::Backend)
        })?;
        match response.status().as_u16() {
            200 | 204 => {
                if let Some(expected_version) = expected_version.as_deref()
                    && single_header_value(response.headers(), S3_VERSION_HEADER)
                        != Some(expected_version)
                {
                    return Err(ObjectStorageError::VersionMismatch);
                }
                Ok(())
            }
            404 => Err(ObjectStorageError::NotFound),
            _ => Err(ObjectStorageError::Backend),
        }
    }
}

#[cfg(feature = "aws")]
fn parse_strict_bool(value: &str) -> Result<bool, ObjectStorageError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ObjectStorageError::InvalidConfiguration),
    }
}

impl ConfiguredS3Encryption {
    #[cfg(all(feature = "aws", test))]
    pub(crate) fn verify_request_target(
        &self,
        request: &ObserverRequestBinding,
        method: &str,
        request_uri: &str,
    ) -> Result<Sha256Digest, ObjectStorageError> {
        self.expected_request_target
            .verify(request, method, request_uri)
    }

    #[cfg(all(test, feature = "aws"))]
    pub(crate) fn observer_service(&self, inner: HttpClient) -> S3EncryptionObserverService {
        S3EncryptionObserverService {
            inner,
            expected_request_target: self.expected_request_target.clone(),
            credential_mode: self.credential_mode.clone(),
        }
    }

    #[cfg(all(test, feature = "aws"))]
    pub(crate) fn delete_adapter(
        &self,
        credentials: AwsCredentialProvider,
        inner: HttpClient,
    ) -> S3VerifiedDeleteAdapter {
        S3VerifiedDeleteAdapter {
            credentials,
            client: HttpClient::new(S3EncryptionObserverService {
                inner,
                expected_request_target: self.expected_request_target.clone(),
                credential_mode: self.credential_mode.clone(),
            }),
            expected_request_target: self.expected_request_target.clone(),
            sigv4_region: self.expected_request_target.sigv4_region.clone(),
        }
    }

    pub(crate) fn verify_observed(
        &self,
        evidence: &ObservedEncryptionEvidence,
    ) -> Result<(), EncryptionPolicyError> {
        match (self.algorithm, evidence.algorithm) {
            (ObservedManagedAlgorithm::SseKms, ObservedManagedAlgorithm::SseKms) => {}
            (_, ObservedManagedAlgorithm::Missing) => {
                return Err(EncryptionPolicyError::ManagedEncryptionRequired);
            }
            _ => return Err(EncryptionPolicyError::AlgorithmMismatch),
        }
        // A missing final-response header is accepted only in combination with
        // the signed per-write `bucket-key=false` configuration checked before
        // I/O and the selected reviewed provider guarantee. Absence by itself is
        // never treated as proof.
        let object_context_bound = match self.object_context_guarantee {
            ObjectContextGuarantee::AwsObjectArn
            | ObjectContextGuarantee::MinioKesBucketAndObject => matches!(
                evidence.bucket_key_state,
                ObservedBucketKeyState::Missing | ObservedBucketKeyState::Disabled
            ),
        };
        if !object_context_bound {
            return Err(EncryptionPolicyError::ObjectContextBindingRequired);
        }
        if self.expected_observed_key_identity_fingerprint.is_some()
            && self.expected_observed_key_identity_fingerprint.as_ref()
                != evidence.key_identity_fingerprint.as_ref()
        {
            return Err(EncryptionPolicyError::KeyIdentityMismatch);
        }
        Ok(())
    }
}

#[cfg_attr(not(any(feature = "aws", test)), allow(dead_code))]
pub(crate) fn aws_s3_object_context_profile_id() -> ManagedEncryptionProfileId {
    ManagedEncryptionProfileId::from_digest(digest_bytes(AWS_S3_OBJECT_CONTEXT_PROFILE_DOMAIN))
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
pub(crate) fn minio_kes_object_context_profile_id() -> ManagedEncryptionProfileId {
    ManagedEncryptionProfileId::from_digest(digest_bytes(MINIO_KES_OBJECT_CONTEXT_PROFILE_DOMAIN))
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ObservedEncryptionEvidence {
    pub(crate) binding: WriteBinding,
    pub(crate) operation: ObservedOperation,
    pub(crate) request_path_fingerprint: Sha256Digest,
    pub(crate) response_e_tag: Option<String>,
    pub(crate) response_version: Option<String>,
    pub(crate) algorithm: ObservedManagedAlgorithm,
    pub(crate) bucket_key_state: ObservedBucketKeyState,
    pub(crate) key_identity_fingerprint: Option<Sha256Digest>,
}

impl fmt::Debug for ObservedEncryptionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedEncryptionEvidence")
            .field("binding", &self.binding)
            .field("operation", &self.operation)
            .field("request_path", &"[FINGERPRINTED]")
            .field("response_identity", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[cfg(test)]
pub(crate) fn observed_s3_response(
    request: &ObserverRequestBinding,
    method: &str,
    request_path: &str,
    headers: &object_store::HeaderMap,
) -> Option<ObservedEncryptionEvidence> {
    if !actual_path_matches_expected(request_path, &request.expected_location) {
        return None;
    }
    observed_s3_response_for_verified_target(
        request,
        method,
        digest_bytes(request_path.as_bytes()),
        headers,
    )
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
fn observed_s3_response_for_verified_target(
    request: &ObserverRequestBinding,
    method: &str,
    request_target_fingerprint: Sha256Digest,
    headers: &object_store::HeaderMap,
) -> Option<ObservedEncryptionEvidence> {
    if !request.operation.matches_method(method) {
        return None;
    }
    let algorithm = match header_value(headers, S3_SSE_HEADER) {
        None => ObservedManagedAlgorithm::Missing,
        Some(S3_SSE_KMS_VALUE) => ObservedManagedAlgorithm::SseKms,
        Some(_) => ObservedManagedAlgorithm::Other,
    };
    let key_identity_fingerprint = header_value(headers, S3_KMS_KEY_ID_HEADER)
        .filter(|value| !value.is_empty() && value.len() <= MAX_OBSERVED_KEY_ID_BYTES)
        .map(|value| digest_bytes(value.as_bytes()));
    Some(ObservedEncryptionEvidence {
        binding: request.binding.clone()?,
        operation: request.operation,
        request_path_fingerprint: request_target_fingerprint,
        response_e_tag: header_value(headers, "etag").map(str::to_owned),
        response_version: header_value(headers, S3_VERSION_HEADER).map(str::to_owned),
        algorithm,
        bucket_key_state: observed_bucket_key_state(headers),
        key_identity_fingerprint,
    })
}

#[cfg(test)]
pub(crate) fn actual_path_matches_expected(request_path: &str, expected_location: &Path) -> bool {
    let Ok(actual) = Path::from_url_path(request_path) else {
        return false;
    };
    let actual_parts = actual
        .parts()
        .map(|part| part.as_ref().to_owned())
        .collect::<Vec<_>>();
    let expected_parts = expected_location
        .parts()
        .map(|part| part.as_ref().to_owned())
        .collect::<Vec<_>>();
    actual_parts == expected_parts
}

pub(crate) fn observed_bucket_key_state(
    headers: &object_store::HeaderMap,
) -> ObservedBucketKeyState {
    match header_value(headers, S3_BUCKET_KEY_ENABLED_HEADER) {
        None => ObservedBucketKeyState::Missing,
        Some("false") => ObservedBucketKeyState::Disabled,
        Some("true") => ObservedBucketKeyState::Enabled,
        Some(_) => ObservedBucketKeyState::Invalid,
    }
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
fn header_value<'a>(headers: &'a object_store::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

#[cfg(feature = "aws")]
fn single_header_value<'a>(headers: &'a object_store::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

#[cfg(feature = "aws")]
#[derive(Default)]
pub(crate) struct NoRedirectReqwestConnector {
    trusted_root_certificates: Vec<Certificate>,
}

#[cfg(feature = "aws")]
impl NoRedirectReqwestConnector {
    fn from_trusted_root_certificate_pems(pems: &[Vec<u8>]) -> Result<Self, ObjectStorageError> {
        let trusted_root_certificates = pems
            .iter()
            .map(|pem| {
                Certificate::from_pem(pem).map_err(|_| ObjectStorageError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trusted_root_certificates,
        })
    }
}

#[cfg(feature = "aws")]
impl fmt::Debug for NoRedirectReqwestConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoRedirectReqwestConnector")
            .field(
                "trusted_root_certificate_count",
                &self.trusted_root_certificates.len(),
            )
            .finish()
    }
}

#[cfg(feature = "aws")]
impl HttpConnector for NoRedirectReqwestConnector {
    fn connect(&self, options: &object_store::ClientOptions) -> object_store::Result<HttpClient> {
        let client = no_redirect_reqwest_client(options, &self.trusted_root_certificates)?;
        Ok(HttpClient::new(client))
    }
}

#[cfg(feature = "aws")]
fn no_redirect_reqwest_client(
    options: &object_store::ClientOptions,
    trusted_root_certificates: &[Certificate],
) -> object_store::Result<reqwest::Client> {
    let allow_http = client_bool(options, ClientConfigKey::AllowHttp)?;
    if client_bool(options, ClientConfigKey::AllowInvalidCertificates)?
        || client_bool(options, ClientConfigKey::NoSystemCertificates)?
        || client_bool(options, ClientConfigKey::RandomizeAddresses)?
    {
        return Err(managed_connector_error(
            "unsupported client security option",
        ));
    }

    let mut builder = reqwest::ClientBuilder::new()
        .redirect(RedirectPolicy::none())
        // Do not inherit HTTP(S)_PROXY from the process. Managed artifact
        // traffic has no reviewed proxy trust contract, and explicit proxy
        // options are rejected during configuration validation.
        .no_proxy()
        .https_only(!allow_http)
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();

    builder = builder.tls_certs_merge(trusted_root_certificates.iter().cloned());

    if let Some(headers) = options.get_default_headers() {
        builder = builder.default_headers(headers.clone());
    }

    if let Some(user_agent) = options.get_config_value(&ClientConfigKey::UserAgent) {
        builder = builder.user_agent(user_agent);
    } else {
        builder = builder.user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ));
    }

    if let Some(value) = client_duration(options, ClientConfigKey::Timeout)? {
        builder = builder.timeout(value);
    }
    if let Some(value) = client_duration(options, ClientConfigKey::ConnectTimeout)? {
        builder = builder.connect_timeout(value);
    }
    if let Some(value) = client_duration(options, ClientConfigKey::ReadTimeout)? {
        builder = builder.read_timeout(value);
    }
    if let Some(value) = client_duration(options, ClientConfigKey::PoolIdleTimeout)? {
        builder = builder.pool_idle_timeout(value);
    }
    if let Some(value) = options.get_config_value(&ClientConfigKey::PoolMaxIdlePerHost) {
        builder = builder.pool_max_idle_per_host(
            value
                .parse()
                .map_err(|_| managed_connector_error("invalid pool configuration"))?,
        );
    }
    if let Some(value) = client_duration(options, ClientConfigKey::Http2KeepAliveInterval)? {
        builder = builder.http2_keep_alive_interval(value);
    }
    if let Some(value) = client_duration(options, ClientConfigKey::Http2KeepAliveTimeout)? {
        builder = builder.http2_keep_alive_timeout(value);
    }
    builder = builder.http2_keep_alive_while_idle(client_bool(
        options,
        ClientConfigKey::Http2KeepAliveWhileIdle,
    )?);
    if let Some(value) = options.get_config_value(&ClientConfigKey::Http2MaxFrameSize) {
        builder = builder.http2_max_frame_size(Some(
            value
                .parse()
                .map_err(|_| managed_connector_error("invalid HTTP/2 frame configuration"))?,
        ));
    }
    let http1_only = client_bool(options, ClientConfigKey::Http1Only)?;
    let http2_only = client_bool(options, ClientConfigKey::Http2Only)?;
    if http1_only && http2_only {
        return Err(managed_connector_error(
            "conflicting HTTP protocol configuration",
        ));
    }
    if http1_only {
        builder = builder.http1_only();
    }
    if http2_only {
        builder = builder.http2_prior_knowledge();
    }

    builder
        .build()
        .map_err(|_| managed_connector_error("managed HTTP client construction failed"))
}

#[cfg(feature = "aws")]
fn client_bool(
    options: &object_store::ClientOptions,
    key: ClientConfigKey,
) -> object_store::Result<bool> {
    options
        .get_config_value(&key)
        .ok_or_else(|| managed_connector_error("required client option missing"))?
        .parse()
        .map_err(|_| managed_connector_error("invalid boolean client option"))
}

#[cfg(feature = "aws")]
fn client_duration(
    options: &object_store::ClientOptions,
    key: ClientConfigKey,
) -> object_store::Result<Option<std::time::Duration>> {
    options
        .get_config_value(&key)
        .map(|value| {
            humantime::parse_duration(&value)
                .map_err(|_| managed_connector_error("invalid duration client option"))
        })
        .transpose()
}

#[cfg(feature = "aws")]
fn managed_connector_error(message: &'static str) -> object_store::Error {
    object_store::Error::Generic {
        store: "warpin managed S3 transport",
        source: Box::new(std::io::Error::other(message)),
    }
}

#[cfg(feature = "aws")]
#[derive(Debug)]
struct S3EncryptionObserverConnector {
    inner: NoRedirectReqwestConnector,
    expected_request_target: ExpectedRequestTarget,
    credential_mode: CredentialMode,
}

#[cfg(feature = "aws")]
impl S3EncryptionObserverConnector {
    fn new(
        expected_request_target: ExpectedRequestTarget,
        credential_mode: CredentialMode,
        trusted_root_certificate_pems: &[Vec<u8>],
    ) -> Result<Self, ObjectStorageError> {
        Ok(Self {
            inner: NoRedirectReqwestConnector::from_trusted_root_certificate_pems(
                trusted_root_certificate_pems,
            )?,
            expected_request_target,
            credential_mode,
        })
    }
}

#[cfg(feature = "aws")]
impl HttpConnector for S3EncryptionObserverConnector {
    fn connect(&self, options: &object_store::ClientOptions) -> object_store::Result<HttpClient> {
        let client = self.inner.connect(options)?;
        Ok(HttpClient::new(S3EncryptionObserverService {
            inner: client,
            expected_request_target: self.expected_request_target.clone(),
            credential_mode: self.credential_mode.clone(),
        }))
    }
}

#[cfg(feature = "aws")]
#[derive(Debug)]
pub(crate) struct S3EncryptionObserverService {
    pub(crate) inner: HttpClient,
    expected_request_target: ExpectedRequestTarget,
    credential_mode: CredentialMode,
}

#[cfg(feature = "aws")]
#[async_trait]
impl HttpService for S3EncryptionObserverService {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let binding = request
            .extensions()
            .get::<ObserverRequestBinding>()
            .cloned();
        let method = request.method().as_str().to_owned();
        let request_target_fingerprint = if let Some(binding) = binding.as_ref() {
            let fingerprint = self
                .expected_request_target
                .verify(binding, &method, &request.uri().to_string())
                .map_err(|_| {
                    managed_artifact_request_error(ManagedArtifactRequestRejection::Target)
                })?;
            self.expected_request_target
                .verify_sigv4(
                    binding,
                    &method,
                    &request.uri().to_string(),
                    request.headers(),
                )
                .map_err(|_| {
                    managed_artifact_request_error(ManagedArtifactRequestRejection::Signature)
                })?;
            Some(fingerprint)
        } else {
            self.credential_mode.verify_request(&request).map_err(|_| {
                managed_artifact_request_error(ManagedArtifactRequestRejection::Credential)
            })?;
            None
        };
        let mut response = self.inner.execute(request).await?;
        if response.status().as_u16() == 200
            && let Some(binding) = binding
            && let Some(request_target_fingerprint) = request_target_fingerprint
            && let Some(evidence) = observed_s3_response_for_verified_target(
                &binding,
                &method,
                request_target_fingerprint,
                response.headers(),
            )
        {
            response.extensions_mut().insert(evidence);
        }
        Ok(response)
    }
}

#[cfg(feature = "aws")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedArtifactRequestRejection {
    Target,
    Signature,
    Credential,
}

#[cfg(feature = "aws")]
#[derive(Debug)]
struct ManagedArtifactRequestError {
    rejection: ManagedArtifactRequestRejection,
}

#[cfg(feature = "aws")]
impl fmt::Display for ManagedArtifactRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.rejection {
            ManagedArtifactRequestRejection::Target => "managed_request_target_mismatch",
            ManagedArtifactRequestRejection::Signature => "managed_request_signature_invalid",
            ManagedArtifactRequestRejection::Credential => "managed_credential_request_invalid",
        };
        formatter.write_str(code)
    }
}

#[cfg(feature = "aws")]
impl std::error::Error for ManagedArtifactRequestError {}

#[cfg(feature = "aws")]
fn managed_artifact_request_error(rejection: ManagedArtifactRequestRejection) -> HttpError {
    HttpError::new(
        HttpErrorKind::Unknown,
        ManagedArtifactRequestError { rejection },
    )
}

#[cfg(feature = "aws")]
pub(crate) fn map_managed_request_error(
    error: &(dyn std::error::Error + 'static),
) -> Option<ObjectStorageError> {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<ManagedArtifactRequestError>() {
            return Some(match error.rejection {
                ManagedArtifactRequestRejection::Target => {
                    ObjectStorageError::RequestTargetMismatch
                }
                ManagedArtifactRequestRejection::Signature => {
                    ObjectStorageError::RequestSignatureInvalid
                }
                ManagedArtifactRequestRejection::Credential => {
                    ObjectStorageError::RequestTargetMismatch
                }
            });
        }
        current = source.source();
    }
    None
}
