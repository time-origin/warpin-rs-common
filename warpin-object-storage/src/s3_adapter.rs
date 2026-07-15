use std::fmt;

#[cfg(feature = "aws")]
use std::collections::BTreeMap;

#[cfg(feature = "aws")]
use async_trait::async_trait;
use object_store::path::Path;
#[cfg(feature = "aws")]
use object_store::{
    ObjectStore,
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    client::{
        HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpService,
        ReqwestConnector,
    },
};
#[cfg(feature = "aws")]
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfiguredS3Encryption {
    pub(crate) profile_id: ManagedEncryptionProfileId,
    object_context_guarantee: ObjectContextGuarantee,
    pub(crate) algorithm: ObservedManagedAlgorithm,
    pub(crate) bucket_key_state: ObservedBucketKeyState,
    pub(crate) expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
}

#[cfg(feature = "aws")]
impl ConfiguredS3Encryption {
    pub(crate) fn from_options(
        options: &BTreeMap<String, String>,
        selected_profile_id: Option<ManagedEncryptionProfileId>,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Result<Self, ObjectStorageError> {
        let mut algorithm = None;
        let mut key_identity_configured = false;
        let mut bucket_key_state = ObservedBucketKeyState::Missing;
        let mut bucket_key_configured = false;
        let mut has_custom_endpoint = false;
        for (key, value) in options {
            let parsed = key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            if matches!(
                parsed,
                AmazonS3ConfigKey::Endpoint | AmazonS3ConfigKey::S3Endpoint
            ) {
                has_custom_endpoint = true;
            }
            match parsed.as_ref() {
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
                    if key_identity_configured
                        || value.is_empty()
                        || value.len() > MAX_OBSERVED_KEY_ID_BYTES
                    {
                        return Err(ObjectStorageError::InvalidConfiguration);
                    }
                    key_identity_configured = true;
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
                _ => {}
            }
        }
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
        Ok(Self {
            profile_id,
            object_context_guarantee,
            algorithm: algorithm.unwrap_or(ObservedManagedAlgorithm::Missing),
            bucket_key_state,
            expected_observed_key_identity_fingerprint,
        })
    }

    pub(crate) fn build_store(
        url: &Url,
        options: BTreeMap<String, String>,
        selected_profile_id: Option<ManagedEncryptionProfileId>,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Result<(Box<dyn ObjectStore>, Path, Self), ObjectStorageError> {
        let configured = Self::from_options(
            &options,
            selected_profile_id,
            expected_observed_key_identity_fingerprint,
        )?;
        let mut builder = AmazonS3Builder::new()
            .with_url(url.as_str())
            .with_http_connector(S3EncryptionObserverConnector::default());
        for (key, value) in options {
            let key = key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
            builder = builder.with_config(key, value);
        }
        let store = builder.build().map_err(map_backend_configuration_error)?;
        let prefix = Path::from_url_path(url.path())
            .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        Ok((Box::new(store), prefix, configured))
    }
}

impl ConfiguredS3Encryption {
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

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
pub(crate) fn observed_s3_response(
    request: &ObserverRequestBinding,
    method: &str,
    request_path: &str,
    headers: &object_store::HeaderMap,
) -> Option<ObservedEncryptionEvidence> {
    if !actual_path_matches_expected(request_path, &request.expected_location) {
        return None;
    }
    observed_s3_response_for_verified_path(request, method, headers)
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
fn observed_s3_response_for_verified_path(
    request: &ObserverRequestBinding,
    method: &str,
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
        binding: request.binding.clone(),
        operation: request.operation,
        request_path_fingerprint: digest_bytes(request.expected_location.as_ref().as_bytes()),
        response_e_tag: header_value(headers, "etag").map(str::to_owned),
        response_version: header_value(headers, S3_VERSION_HEADER).map(str::to_owned),
        algorithm,
        bucket_key_state: observed_bucket_key_state(headers),
        key_identity_fingerprint,
    })
}

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
        || (actual_parts.len() == expected_parts.len() + 1
            && actual_parts.ends_with(&expected_parts))
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
#[derive(Debug, Default)]
struct S3EncryptionObserverConnector {
    inner: ReqwestConnector,
}

#[cfg(feature = "aws")]
impl HttpConnector for S3EncryptionObserverConnector {
    fn connect(&self, options: &object_store::ClientOptions) -> object_store::Result<HttpClient> {
        let client = self.inner.connect(options)?;
        Ok(HttpClient::new(S3EncryptionObserverService {
            inner: client,
        }))
    }
}

#[cfg(feature = "aws")]
#[derive(Debug)]
pub(crate) struct S3EncryptionObserverService {
    pub(crate) inner: HttpClient,
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
        let request_path = request.uri().path().to_owned();
        let mut response = self.inner.execute(request).await?;
        if response.status().is_success()
            && let Some(binding) = binding
            && let Some(evidence) =
                observed_s3_response(&binding, &method, &request_path, response.headers())
        {
            response.extensions_mut().insert(evidence);
        }
        Ok(response)
    }
}
