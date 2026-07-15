use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(feature = "aws")]
use async_trait::async_trait;
use bytes::Bytes;
use object_store::{
    Attribute, AttributeValue, Attributes, Extensions, GetOptions, ObjectStore, PutMode,
    PutOptions, path::Path,
};
#[cfg(feature = "aws")]
use object_store::{
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    client::{
        HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpService,
        ReqwestConnector,
    },
};
use thiserror::Error;
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

const DIGEST_METADATA_KEY: &str = "warpin-sha256";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 1_024;
const MAX_URL_BYTES: usize = 2_048;
const MAX_OPTION_KEY_BYTES: usize = 128;
const MAX_OPTION_VALUE_BYTES: usize = 4_096;
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const S3_SSE_HEADER: &str = "x-amz-server-side-encryption";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const S3_KMS_KEY_ID_HEADER: &str = "x-amz-server-side-encryption-aws-kms-key-id";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const S3_VERSION_HEADER: &str = "x-amz-version-id";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const S3_SSE_KMS_VALUE: &str = "aws:kms";
#[cfg_attr(not(any(feature = "aws", test)), allow(dead_code))]
const S3_MANAGED_PROFILE_DOMAIN: &[u8] =
    b"warpin:managed-encryption-profile:s3-compatible-sse-kms:v1";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const MAX_OBSERVED_KEY_ID_BYTES: usize = 2_048;
static NEXT_WRITE_BINDING: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct ObjectStoreSettings {
    pub url: String,
    pub options: BTreeMap<String, String>,
    pub max_object_bytes: u64,
    expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
}

impl ObjectStoreSettings {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            options: BTreeMap::new(),
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            expected_observed_key_identity_fingerprint: None,
        }
    }

    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    pub fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }

    /// Configures the canonical key identity that managed response evidence must
    /// report. This digest is deliberately independent of any provider request
    /// locator supplied through backend options.
    pub fn with_expected_observed_key_identity_fingerprint(
        mut self,
        fingerprint: Sha256Digest,
    ) -> Self {
        self.expected_observed_key_identity_fingerprint = Some(fingerprint);
        self
    }

    fn validate(&self) -> Result<Url, ObjectStorageError> {
        if self.url.is_empty() || self.url.len() > MAX_URL_BYTES || self.max_object_bytes == 0 {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let url = Url::parse(&self.url).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        if !matches!(url.scheme(), "memory" | "file" | "s3" | "s3a") {
            return Err(ObjectStorageError::UnsupportedBackend);
        }
        match url.scheme() {
            "memory" | "file"
                if url.host_str().is_some()
                    || !self.options.is_empty()
                    || self.expected_observed_key_identity_fingerprint.is_some() =>
            {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            "s3" | "s3a" if url.host_str().is_none_or(str::is_empty) => {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
            _ => {}
        }
        if self.options.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > MAX_OPTION_KEY_BYTES
                || value.is_empty()
                || value.len() > MAX_OPTION_VALUE_BYTES
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
                || !value.is_ascii()
                || value.chars().any(char::is_control)
        }) {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        if matches!(url.scheme(), "s3" | "s3a") {
            #[cfg(not(feature = "aws"))]
            return Err(ObjectStorageError::UnsupportedBackend);
            #[cfg(feature = "aws")]
            if self
                .options
                .keys()
                .any(|key| key.parse::<object_store::aws::AmazonS3ConfigKey>().is_err())
            {
                return Err(ObjectStorageError::InvalidConfiguration);
            }
        }
        Ok(url)
    }
}

impl fmt::Debug for ObjectStoreSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreSettings")
            .field("backend", &"[CONFIGURED]")
            .field("option_count", &self.options.len())
            .field(
                "expected_observed_key_identity",
                &self.expected_observed_key_identity_fingerprint.is_some(),
            )
            .field("max_object_bytes", &self.max_object_bytes)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, ObjectStorageError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_KEY_BYTES
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'=' | b'@')
            })
            || value
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(ObjectStorageError::InvalidKey);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct ImmutableObjectWrite {
    pub key: ObjectKey,
    pub content: Bytes,
    pub expected_digest: Sha256Digest,
    pub content_type: String,
}

impl fmt::Debug for ImmutableObjectWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableObjectWrite")
            .field("key", &self.key)
            .field("content_len", &self.content.len())
            .field("expected_digest", &self.expected_digest)
            .field("content_type", &self.content_type)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectWriteReceipt {
    pub key: ObjectKey,
    pub size_bytes: u64,
    pub digest: Sha256Digest,
    pub e_tag: Option<String>,
    pub version: Option<String>,
    pub idempotent_replay: bool,
}

#[derive(Clone, Eq, PartialEq)]
enum EncryptionRequirementKind {
    Managed {
        profile_id: ManagedEncryptionProfileId,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    },
    DevelopmentOrTestPlaintext,
}

/// Opaque, credential-safe identity of a managed encryption adapter profile.
///
/// The digest names a reviewed adapter capability; it does not contain a raw
/// provider name, algorithm string, key locator, or credential.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManagedEncryptionProfileId(Sha256Digest);

impl ManagedEncryptionProfileId {
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn as_digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Read-only typed projection used by provider adapters to translate a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionRequirementView<'a> {
    Managed {
        profile_id: &'a ManagedEncryptionProfileId,
        expected_observed_key_identity_fingerprint: Option<&'a Sha256Digest>,
    },
    DevelopmentOrTestPlaintext,
}

/// Describes the minimum encryption evidence required for an artifact write.
///
/// Provider-specific request options remain the responsibility of storage adapters.
/// The development/test variant must never be selected implicitly by a backend.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptionRequirement {
    kind: EncryptionRequirementKind,
}

impl EncryptionRequirement {
    /// Requires the named reviewed managed-encryption profile and, optionally,
    /// a canonical key identity observed in the provider response.
    pub fn managed(
        profile_id: ManagedEncryptionProfileId,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Self {
        Self {
            kind: EncryptionRequirementKind::Managed {
                profile_id,
                expected_observed_key_identity_fingerprint,
            },
        }
    }

    /// Explicitly permits plaintext only for a development or test deployment.
    pub const fn development_or_test_plaintext() -> Self {
        Self {
            kind: EncryptionRequirementKind::DevelopmentOrTestPlaintext,
        }
    }

    pub const fn is_managed(&self) -> bool {
        matches!(self.kind, EncryptionRequirementKind::Managed { .. })
    }

    pub const fn view(&self) -> EncryptionRequirementView<'_> {
        match &self.kind {
            EncryptionRequirementKind::Managed {
                profile_id,
                expected_observed_key_identity_fingerprint,
            } => EncryptionRequirementView::Managed {
                profile_id,
                expected_observed_key_identity_fingerprint:
                    expected_observed_key_identity_fingerprint.as_ref(),
            },
            EncryptionRequirementKind::DevelopmentOrTestPlaintext => {
                EncryptionRequirementView::DevelopmentOrTestPlaintext
            }
        }
    }
}

impl fmt::Debug for EncryptionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionRequirement")
            .field("mode", &encryption_mode_name(self.is_managed()))
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for EncryptionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(encryption_mode_name(self.is_managed()))
    }
}

/// Provider-neutral policy used to verify observed encryption evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactEncryptionPolicy {
    requirement: EncryptionRequirement,
}

impl ArtifactEncryptionPolicy {
    pub const fn new(requirement: EncryptionRequirement) -> Self {
        Self { requirement }
    }

    pub const fn requirement(&self) -> &EncryptionRequirement {
        &self.requirement
    }

    fn verify_s3_configuration(
        &self,
        configured: &ConfiguredS3Encryption,
    ) -> Result<(), EncryptionPolicyError> {
        let EncryptionRequirementKind::Managed {
            profile_id,
            expected_observed_key_identity_fingerprint,
        } = &self.requirement.kind
        else {
            return Err(EncryptionPolicyError::PolicyBackendMismatch);
        };
        if profile_id != &configured.profile_id {
            return Err(EncryptionPolicyError::PolicyBackendMismatch);
        }
        match configured.algorithm {
            ObservedManagedAlgorithm::Missing => {
                return Err(EncryptionPolicyError::ManagedEncryptionRequired);
            }
            ObservedManagedAlgorithm::Other => {
                return Err(EncryptionPolicyError::AlgorithmMismatch);
            }
            ObservedManagedAlgorithm::SseKms => {}
        }
        if configured
            .expected_observed_key_identity_fingerprint
            .as_ref()
            != expected_observed_key_identity_fingerprint.as_ref()
        {
            return Err(EncryptionPolicyError::KeyIdentityMismatch);
        }
        Ok(())
    }

    fn verify_managed_evidence(
        &self,
        receipt: &ObjectWriteReceipt,
        binding: &WriteBinding,
        evidence: &ObservedEncryptionEvidence,
    ) -> Result<EncryptionAttestation, EncryptionPolicyError> {
        let EncryptionRequirementKind::Managed {
            profile_id,
            expected_observed_key_identity_fingerprint,
        } = &self.requirement.kind
        else {
            return Err(EncryptionPolicyError::PolicyBackendMismatch);
        };
        if !binding.matches_receipt(receipt)
            || evidence.binding != *binding
            || evidence.operation != ObservedOperation::Readback
            || evidence.response_e_tag.as_ref() != receipt.e_tag.as_ref()
            || evidence.response_version.as_ref() != receipt.version.as_ref()
            || receipt.e_tag.is_none()
        {
            return Err(EncryptionPolicyError::EvidenceBindingMismatch);
        }
        match evidence.algorithm {
            ObservedManagedAlgorithm::Missing => {
                return Err(EncryptionPolicyError::ManagedEncryptionRequired);
            }
            ObservedManagedAlgorithm::Other => {
                return Err(EncryptionPolicyError::AlgorithmMismatch);
            }
            ObservedManagedAlgorithm::SseKms => {}
        }
        if expected_observed_key_identity_fingerprint.is_some()
            && evidence.key_identity_fingerprint.as_ref()
                != expected_observed_key_identity_fingerprint.as_ref()
        {
            return Err(EncryptionPolicyError::KeyIdentityMismatch);
        }
        Ok(EncryptionAttestation::managed_from_observer(
            profile_id.clone(),
            binding,
            receipt,
            evidence,
        ))
    }
}

impl fmt::Debug for ArtifactEncryptionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactEncryptionPolicy")
            .field("requirement", &self.requirement)
            .finish()
    }
}

impl fmt::Display for ArtifactEncryptionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "artifact encryption policy: {}",
            self.requirement
        )
    }
}

#[derive(Eq, PartialEq)]
enum EncryptionAttestationKind {
    Managed {
        profile_id: ManagedEncryptionProfileId,
        observed_key_identity_fingerprint: Option<Sha256Digest>,
    },
    DevelopmentOrTestPlaintext,
}

/// Read-only typed projection of sanitized observed encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionAttestationView<'a> {
    Managed {
        profile_id: &'a ManagedEncryptionProfileId,
        observed_key_identity_fingerprint: Option<&'a Sha256Digest>,
    },
    DevelopmentOrTestPlaintext,
}

/// Sanitized evidence describing encryption observed by a storage adapter.
///
/// The type intentionally cannot contain provider response bodies or raw key
/// locators, and its formatting implementations never expose identity values.
/// Managed evidence is created only by [`VerifiedObjectStorage`] after a real
/// observed storage response and cannot be constructed or cloned downstream:
///
/// ```compile_fail
/// use warpin_object_storage::EncryptionAttestation;
///
/// let _ = EncryptionAttestation::managed("s3", "kms", None).unwrap();
/// ```
///
/// ```compile_fail
/// use warpin_object_storage::EncryptionRequirement;
///
/// let _ = EncryptionRequirement::managed(
///     "credential-token-shaped-provider",
///     "https://provider.example/algorithm",
///     None,
/// );
/// ```
///
/// ```compile_fail
/// use warpin_object_storage::EncryptionAttestation;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<EncryptionAttestation>();
/// ```
///
/// Provider-specific algorithm and backend identifiers are deliberately not
/// exported by the provider-neutral contract:
///
/// ```compile_fail
/// use warpin_object_storage::{EncryptionProvider, ManagedEncryptionAlgorithm};
///
/// let _ = EncryptionProvider::S3Compatible;
/// let _ = ManagedEncryptionAlgorithm::SseKms;
/// ```
///
/// ```compile_fail
/// use warpin_object_storage::EncryptionRequirement;
///
/// let _ = EncryptionRequirement::s3_compatible_sse_kms(None);
/// ```
#[derive(Eq, PartialEq)]
pub struct EncryptionAttestation {
    kind: EncryptionAttestationKind,
    receipt_binding: Sha256Digest,
}

impl EncryptionAttestation {
    fn managed_from_observer(
        profile_id: ManagedEncryptionProfileId,
        binding: &WriteBinding,
        receipt: &ObjectWriteReceipt,
        evidence: &ObservedEncryptionEvidence,
    ) -> Self {
        Self {
            kind: EncryptionAttestationKind::Managed {
                profile_id,
                observed_key_identity_fingerprint: evidence.key_identity_fingerprint.clone(),
            },
            receipt_binding: binding.receipt_binding(receipt, &evidence.request_path_fingerprint),
        }
    }

    fn development_or_test_plaintext(binding: &WriteBinding, receipt: &ObjectWriteReceipt) -> Self {
        Self {
            kind: EncryptionAttestationKind::DevelopmentOrTestPlaintext,
            receipt_binding: binding.receipt_binding(receipt, &digest_bytes(b"local-backend")),
        }
    }

    pub const fn view(&self) -> EncryptionAttestationView<'_> {
        match &self.kind {
            EncryptionAttestationKind::Managed {
                profile_id,
                observed_key_identity_fingerprint,
            } => EncryptionAttestationView::Managed {
                profile_id,
                observed_key_identity_fingerprint: observed_key_identity_fingerprint.as_ref(),
            },
            EncryptionAttestationKind::DevelopmentOrTestPlaintext => {
                EncryptionAttestationView::DevelopmentOrTestPlaintext
            }
        }
    }

    pub const fn is_managed(&self) -> bool {
        matches!(self.kind, EncryptionAttestationKind::Managed { .. })
    }

    /// Returns a non-secret digest binding this attestation to the observed
    /// request path and immutable write receipt.
    pub const fn receipt_binding_fingerprint(&self) -> &Sha256Digest {
        &self.receipt_binding
    }
}

impl fmt::Debug for EncryptionAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionAttestation")
            .field("mode", &encryption_mode_name(self.is_managed()))
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for EncryptionAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(encryption_mode_name(self.is_managed()))
    }
}

/// A write receipt paired with encryption evidence accepted by an
/// [`ArtifactEncryptionPolicy`].
#[derive(Eq, PartialEq)]
pub struct EncryptionVerifiedObjectWriteReceipt {
    receipt: ObjectWriteReceipt,
    attestation: EncryptionAttestation,
}

impl EncryptionVerifiedObjectWriteReceipt {
    pub const fn receipt(&self) -> &ObjectWriteReceipt {
        &self.receipt
    }

    pub const fn attestation(&self) -> &EncryptionAttestation {
        &self.attestation
    }
}

impl fmt::Debug for EncryptionVerifiedObjectWriteReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionVerifiedObjectWriteReceipt")
            .field("object", &"[VERIFIED]")
            .field("size_bytes", &self.receipt.size_bytes)
            .field("digest", &self.receipt.digest)
            .field("idempotent_replay", &self.receipt.idempotent_replay)
            .field("attestation", &self.attestation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EncryptionPolicyError {
    #[error("managed encryption is required")]
    ManagedEncryptionRequired,
    #[error("observed encryption algorithm does not satisfy policy")]
    AlgorithmMismatch,
    #[error("observed encryption key identity does not satisfy policy")]
    KeyIdentityMismatch,
    #[error("observed encryption evidence is not bound to this write receipt")]
    EvidenceBindingMismatch,
    #[error("encryption policy is not valid for this storage backend")]
    PolicyBackendMismatch,
}

fn encryption_mode_name(managed: bool) -> &'static str {
    if managed {
        "managed"
    } else {
        "development-or-test-plaintext"
    }
}

#[derive(Clone, Eq, PartialEq)]
struct WriteBinding {
    nonce: u64,
    key: ObjectKey,
    size_bytes: u64,
    digest: Sha256Digest,
}

impl WriteBinding {
    fn for_write(key: &ObjectKey, size_bytes: u64, digest: &Sha256Digest) -> Self {
        Self {
            nonce: NEXT_WRITE_BINDING.fetch_add(1, Ordering::Relaxed),
            key: key.clone(),
            size_bytes,
            digest: digest.clone(),
        }
    }

    #[cfg(test)]
    fn new(receipt: &ObjectWriteReceipt) -> Self {
        Self::for_write(&receipt.key, receipt.size_bytes, &receipt.digest)
    }

    fn matches_receipt(&self, receipt: &ObjectWriteReceipt) -> bool {
        self.key == receipt.key
            && self.size_bytes == receipt.size_bytes
            && self.digest == receipt.digest
    }

    fn receipt_binding(
        &self,
        receipt: &ObjectWriteReceipt,
        request_path_fingerprint: &Sha256Digest,
    ) -> Sha256Digest {
        let value = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.nonce,
            self.key.as_str(),
            self.size_bytes,
            self.digest,
            receipt.e_tag.as_deref().unwrap_or_default(),
            receipt.version.as_deref().unwrap_or_default(),
            request_path_fingerprint,
        );
        digest_bytes(value.as_bytes())
    }
}

impl fmt::Debug for WriteBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteBinding")
            .field("object", &"[BOUND]")
            .field("size_bytes", &self.size_bytes)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedOperation {
    Put,
    Readback,
}

impl ObservedOperation {
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    fn matches_method(self, method: &str) -> bool {
        matches!((self, method), (Self::Put, "PUT") | (Self::Readback, "GET"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObserverRequestBinding {
    binding: WriteBinding,
    operation: ObservedOperation,
}

impl ObserverRequestBinding {
    fn put(binding: WriteBinding) -> Self {
        Self {
            binding,
            operation: ObservedOperation::Put,
        }
    }

    fn readback(binding: WriteBinding) -> Self {
        Self {
            binding,
            operation: ObservedOperation::Readback,
        }
    }
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedManagedAlgorithm {
    Missing,
    SseKms,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfiguredS3Encryption {
    profile_id: ManagedEncryptionProfileId,
    algorithm: ObservedManagedAlgorithm,
    expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
}

#[cfg(feature = "aws")]
impl ConfiguredS3Encryption {
    fn from_options(
        options: &BTreeMap<String, String>,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Result<Self, ObjectStorageError> {
        let mut algorithm = None;
        let mut key_identity_configured = false;
        for (key, value) in options {
            let parsed = key
                .parse::<AmazonS3ConfigKey>()
                .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
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
                _ => {}
            }
        }
        Ok(Self {
            profile_id: s3_managed_profile_id(),
            algorithm: algorithm.unwrap_or(ObservedManagedAlgorithm::Missing),
            expected_observed_key_identity_fingerprint,
        })
    }
}

impl ConfiguredS3Encryption {
    fn verify_observed(
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
fn s3_managed_profile_id() -> ManagedEncryptionProfileId {
    ManagedEncryptionProfileId::from_digest(digest_bytes(S3_MANAGED_PROFILE_DOMAIN))
}

#[derive(Clone, Eq, PartialEq)]
struct ObservedEncryptionEvidence {
    binding: WriteBinding,
    operation: ObservedOperation,
    request_path_fingerprint: Sha256Digest,
    response_e_tag: Option<String>,
    response_version: Option<String>,
    algorithm: ObservedManagedAlgorithm,
    key_identity_fingerprint: Option<Sha256Digest>,
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
fn observed_s3_response(
    request: &ObserverRequestBinding,
    method: &str,
    request_path: &str,
    headers: &object_store::HeaderMap,
) -> Option<ObservedEncryptionEvidence> {
    if request_path.is_empty() {
        return None;
    }
    observed_s3_response_with_path_fingerprint(
        request,
        method,
        digest_bytes(request_path.as_bytes()),
        headers,
    )
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
fn observed_s3_response_with_path_fingerprint(
    request: &ObserverRequestBinding,
    method: &str,
    request_path_fingerprint: Sha256Digest,
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
        request_path_fingerprint,
        response_e_tag: header_value(headers, "etag").map(str::to_owned),
        response_version: header_value(headers, S3_VERSION_HEADER).map(str::to_owned),
        algorithm,
        key_identity_fingerprint,
    })
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
struct S3EncryptionObserverService {
    inner: HttpClient,
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
        let path_fingerprint = (!request.uri().path().is_empty())
            .then(|| digest_bytes(request.uri().path().as_bytes()));
        let mut response = self.inner.execute(request).await?;
        if response.status().is_success()
            && let Some(binding) = binding
            && let Some(path_fingerprint) = path_fingerprint
            && let Some(evidence) = observed_s3_response_with_path_fingerprint(
                &binding,
                &method,
                path_fingerprint,
                response.headers(),
            )
        {
            response.extensions_mut().insert(evidence);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedObject {
    pub key: ObjectKey,
    pub content: Bytes,
    pub digest: Sha256Digest,
    pub content_type: Option<String>,
    pub e_tag: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ObjectStorageError {
    #[error("object storage configuration is invalid")]
    InvalidConfiguration,
    #[error("object storage backend is unsupported by this build")]
    UnsupportedBackend,
    #[error("object key is invalid")]
    InvalidKey,
    #[error("object metadata is invalid")]
    InvalidMetadata,
    #[error("object exceeds the configured size limit")]
    SizeLimitExceeded,
    #[error("object content does not match the expected digest")]
    DigestMismatch,
    #[error("object version does not match the requested immutable version")]
    VersionMismatch,
    #[error("immutable object identity conflicts with existing content")]
    ImmutableConflict,
    #[error("object was not found")]
    NotFound,
    #[error("object storage backend operation failed")]
    Backend,
    #[error(transparent)]
    EncryptionPolicy(#[from] EncryptionPolicyError),
}

#[cfg_attr(not(feature = "aws"), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum BackendSecurityMode {
    DevelopmentOrTestPlaintext,
    S3Observed { configured: ConfiguredS3Encryption },
}

#[derive(Clone)]
pub struct VerifiedObjectStorage {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
    max_object_bytes: u64,
    supports_attributes: bool,
    backend_security: BackendSecurityMode,
}

impl fmt::Debug for VerifiedObjectStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedObjectStorage")
            .field("backend", &"[CONFIGURED]")
            .field("prefix", &self.prefix.as_ref())
            .field("max_object_bytes", &self.max_object_bytes)
            .finish()
    }
}

impl VerifiedObjectStorage {
    pub fn from_settings(settings: ObjectStoreSettings) -> Result<Self, ObjectStorageError> {
        let url = settings.validate()?;
        #[cfg(feature = "aws")]
        let expected_observed_key_identity_fingerprint =
            settings.expected_observed_key_identity_fingerprint.clone();
        let (store, prefix, supports_attributes, backend_security): (
            Box<dyn ObjectStore>,
            Path,
            bool,
            BackendSecurityMode,
        ) = match url.scheme() {
            "file" => {
                #[cfg(not(feature = "fs"))]
                return Err(ObjectStorageError::UnsupportedBackend);
                #[cfg(feature = "fs")]
                {
                    let filesystem_path = url
                        .to_file_path()
                        .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
                    let store =
                        object_store::local::LocalFileSystem::new_with_prefix(filesystem_path)
                            .map_err(map_backend_configuration_error)?
                            .with_fsync(true);
                    (
                        Box::new(store),
                        Path::ROOT,
                        false,
                        BackendSecurityMode::DevelopmentOrTestPlaintext,
                    )
                }
            }
            "memory" => {
                let (store, prefix) = object_store::parse_url_opts(&url, settings.options)
                    .map_err(map_backend_configuration_error)?;
                (
                    store,
                    prefix,
                    true,
                    BackendSecurityMode::DevelopmentOrTestPlaintext,
                )
            }
            "s3" | "s3a" => {
                #[cfg(not(feature = "aws"))]
                return Err(ObjectStorageError::UnsupportedBackend);
                #[cfg(feature = "aws")]
                {
                    let configured = ConfiguredS3Encryption::from_options(
                        &settings.options,
                        expected_observed_key_identity_fingerprint,
                    )?;
                    let mut builder = AmazonS3Builder::new()
                        .with_url(url.as_str())
                        .with_http_connector(S3EncryptionObserverConnector::default());
                    for (key, value) in settings.options {
                        let key = key
                            .parse::<AmazonS3ConfigKey>()
                            .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
                        builder = builder.with_config(key, value);
                    }
                    let store = builder.build().map_err(map_backend_configuration_error)?;
                    let prefix = Path::from_url_path(url.path())
                        .map_err(|_| ObjectStorageError::InvalidConfiguration)?;
                    (
                        Box::new(store),
                        prefix,
                        true,
                        BackendSecurityMode::S3Observed { configured },
                    )
                }
            }
            _ => return Err(ObjectStorageError::UnsupportedBackend),
        };
        Ok(Self {
            store: Arc::from(store),
            prefix,
            max_object_bytes: settings.max_object_bytes,
            supports_attributes,
            backend_security,
        })
    }

    /// Returns the opaque managed-encryption profile implemented by this
    /// storage adapter, if the backend is managed. Provider and algorithm names
    /// intentionally remain private to the adapter.
    pub const fn managed_encryption_profile_id(&self) -> Option<&ManagedEncryptionProfileId> {
        match &self.backend_security {
            BackendSecurityMode::DevelopmentOrTestPlaintext => None,
            BackendSecurityMode::S3Observed { configured } => Some(&configured.profile_id),
        }
    }

    /// Performs an immutable write and returns a policy-verified opaque receipt.
    ///
    /// Managed evidence is derived only from the final GET response observed by
    /// this crate's connector and is bound to the object, write nonce, digest,
    /// size, ETag, and version. A versioned first write pins that GET to the exact
    /// version returned by PUT. This trust boundary proves traversal through the
    /// installed observer; it does not defend against a process-internal attacker
    /// replacing the entire configured HTTP transport.
    ///
    /// On an unversioned managed store, immutability additionally depends on
    /// `PutMode::Create` plus bucket/IAM policy prohibiting overwrite, delete, and
    /// delete-then-recreate for artifact keys.
    pub async fn put_immutable(
        &self,
        write: ImmutableObjectWrite,
        policy: &ArtifactEncryptionPolicy,
    ) -> Result<EncryptionVerifiedObjectWriteReceipt, ObjectStorageError> {
        match (&self.backend_security, policy.requirement().view()) {
            (
                BackendSecurityMode::DevelopmentOrTestPlaintext,
                EncryptionRequirementView::DevelopmentOrTestPlaintext,
            )
            | (BackendSecurityMode::S3Observed { .. }, EncryptionRequirementView::Managed { .. }) =>
                {}
            (
                BackendSecurityMode::DevelopmentOrTestPlaintext,
                EncryptionRequirementView::Managed { .. },
            ) => {
                return Err(EncryptionPolicyError::ManagedEncryptionRequired.into());
            }
            (
                BackendSecurityMode::S3Observed { .. },
                EncryptionRequirementView::DevelopmentOrTestPlaintext,
            ) => return Err(EncryptionPolicyError::PolicyBackendMismatch.into()),
        }
        if let BackendSecurityMode::S3Observed { configured } = &self.backend_security {
            policy.verify_s3_configuration(configured)?;
        }

        validate_content_type(&write.content_type)?;
        let size_bytes = u64::try_from(write.content.len())
            .map_err(|_| ObjectStorageError::SizeLimitExceeded)?;
        validate_write(&write, size_bytes, self.max_object_bytes)?;
        let binding = WriteBinding::for_write(&write.key, size_bytes, &write.expected_digest);
        let outcome = self.put_immutable_internal(write, binding.clone()).await?;
        let attestation = match &self.backend_security {
            BackendSecurityMode::DevelopmentOrTestPlaintext => {
                EncryptionAttestation::development_or_test_plaintext(&binding, &outcome.receipt)
            }
            BackendSecurityMode::S3Observed { configured } => {
                let evidence = outcome
                    .evidence
                    .as_ref()
                    .ok_or(EncryptionPolicyError::EvidenceBindingMismatch)?;
                configured.verify_observed(evidence)?;
                policy.verify_managed_evidence(&outcome.receipt, &binding, evidence)?
            }
        };
        Ok(EncryptionVerifiedObjectWriteReceipt {
            receipt: outcome.receipt,
            attestation,
        })
    }

    async fn put_immutable_internal(
        &self,
        write: ImmutableObjectWrite,
        binding: WriteBinding,
    ) -> Result<ImmutableWriteOutcome, ObjectStorageError> {
        validate_content_type(&write.content_type)?;
        let size_bytes = u64::try_from(write.content.len())
            .map_err(|_| ObjectStorageError::SizeLimitExceeded)?;
        validate_write(&write, size_bytes, self.max_object_bytes)?;
        let location = self.location(&write.key)?;
        let attributes = if self.supports_attributes {
            let mut attributes = Attributes::new();
            attributes.insert(
                Attribute::ContentType,
                AttributeValue::from(write.content_type.clone()),
            );
            attributes.insert(
                Attribute::Metadata(DIGEST_METADATA_KEY.into()),
                AttributeValue::from(write.expected_digest.to_string()),
            );
            attributes
        } else {
            Attributes::new()
        };
        let mut extensions = Extensions::new();
        extensions.insert(ObserverRequestBinding::put(binding.clone()));
        let put_result = self
            .store
            .put_opts(
                &location,
                write.content.clone().into(),
                PutOptions {
                    mode: PutMode::Create,
                    attributes,
                    extensions,
                    ..PutOptions::default()
                },
            )
            .await;
        let (put_e_tag, put_version, idempotent_replay) = match put_result {
            Ok(result) => (result.e_tag, result.version, false),
            Err(object_store::Error::AlreadyExists { .. }) => (None, None, true),
            Err(_) => return Err(ObjectStorageError::Backend),
        };
        let readback = self
            .read_verified_internal(
                &write.key,
                &write.expected_digest,
                put_version.as_deref(),
                Some(&binding),
            )
            .await
            .map_err(|error| {
                if idempotent_replay && error == ObjectStorageError::DigestMismatch {
                    ObjectStorageError::ImmutableConflict
                } else {
                    error
                }
            })?;
        if put_e_tag.is_some() && put_e_tag.as_ref() != readback.object.e_tag.as_ref() {
            return Err(EncryptionPolicyError::EvidenceBindingMismatch.into());
        }
        if put_version.is_some() && put_version.as_ref() != readback.object.version.as_ref() {
            return Err(ObjectStorageError::VersionMismatch);
        }
        if self.supports_attributes
            && readback.object.content_type.as_deref() != Some(write.content_type.as_str())
        {
            return Err(ObjectStorageError::ImmutableConflict);
        }
        let receipt = ObjectWriteReceipt {
            key: write.key,
            size_bytes,
            digest: write.expected_digest,
            e_tag: readback.object.e_tag,
            version: readback.object.version,
            idempotent_replay,
        };
        Ok(ImmutableWriteOutcome {
            receipt,
            evidence: readback.evidence,
        })
    }

    /// Reads and digest-verifies an object, optionally pinning the exact version
    /// preserved in an immutable receipt or artifact reference.
    pub async fn read_verified(
        &self,
        key: &ObjectKey,
        expected_digest: &Sha256Digest,
        version: Option<&str>,
    ) -> Result<VerifiedObject, ObjectStorageError> {
        self.read_verified_internal(key, expected_digest, version, None)
            .await
            .map(|readback| readback.object)
    }

    async fn read_verified_internal(
        &self,
        key: &ObjectKey,
        expected_digest: &Sha256Digest,
        expected_version: Option<&str>,
        binding: Option<&WriteBinding>,
    ) -> Result<VerifiedReadback, ObjectStorageError> {
        let location = self.location(key)?;
        let mut extensions = Extensions::new();
        if let Some(binding) = binding {
            extensions.insert(ObserverRequestBinding::readback(binding.clone()));
        }
        let options = read_options(expected_version, extensions);
        let result = self
            .store
            .get_opts(&location, options)
            .await
            .map_err(map_backend_read_error)?;
        if result.meta.size > self.max_object_bytes {
            return Err(ObjectStorageError::SizeLimitExceeded);
        }
        let declared_digest = result
            .attributes
            .get(&Attribute::Metadata(DIGEST_METADATA_KEY.into()))
            .map(AsRef::as_ref);
        if self.supports_attributes {
            let declared_digest = declared_digest
                .ok_or(ObjectStorageError::DigestMismatch)?
                .parse::<Sha256Digest>()
                .map_err(|_| ObjectStorageError::DigestMismatch)?;
            if &declared_digest != expected_digest {
                return Err(ObjectStorageError::DigestMismatch);
            }
        }
        let content_type = result
            .attributes
            .get(&Attribute::ContentType)
            .map(|value| value.as_ref().to_owned());
        let expected_size = result.meta.size;
        let e_tag = result.meta.e_tag.clone();
        let version = result.meta.version.clone();
        if expected_version.is_some() && version.as_deref() != expected_version {
            return Err(ObjectStorageError::VersionMismatch);
        }
        let evidence = result
            .extensions
            .get::<ObservedEncryptionEvidence>()
            .cloned();
        let content = result
            .bytes()
            .await
            .map_err(|_| ObjectStorageError::Backend)?;
        let actual_size =
            u64::try_from(content.len()).map_err(|_| ObjectStorageError::SizeLimitExceeded)?;
        if actual_size != expected_size || digest_bytes(&content) != *expected_digest {
            return Err(ObjectStorageError::DigestMismatch);
        }
        Ok(VerifiedReadback {
            object: VerifiedObject {
                key: key.clone(),
                content,
                digest: expected_digest.clone(),
                content_type,
                e_tag,
                version,
            },
            evidence,
        })
    }

    fn location(&self, key: &ObjectKey) -> Result<Path, ObjectStorageError> {
        let value = if self.prefix.as_ref().is_empty() {
            key.as_str().to_owned()
        } else {
            format!("{}/{}", self.prefix, key.as_str())
        };
        Path::parse(value).map_err(|_| ObjectStorageError::InvalidKey)
    }
}

fn read_options(expected_version: Option<&str>, extensions: Extensions) -> GetOptions {
    GetOptions::default()
        .with_version(expected_version.map(str::to_owned))
        .with_extensions(extensions)
}

struct ImmutableWriteOutcome {
    receipt: ObjectWriteReceipt,
    evidence: Option<ObservedEncryptionEvidence>,
}

struct VerifiedReadback {
    object: VerifiedObject,
    evidence: Option<ObservedEncryptionEvidence>,
}

fn validate_write(
    write: &ImmutableObjectWrite,
    size_bytes: u64,
    max_object_bytes: u64,
) -> Result<(), ObjectStorageError> {
    if size_bytes > max_object_bytes {
        return Err(ObjectStorageError::SizeLimitExceeded);
    }
    if digest_bytes(&write.content) != write.expected_digest {
        return Err(ObjectStorageError::DigestMismatch);
    }
    Ok(())
}

fn validate_content_type(content_type: &str) -> Result<(), ObjectStorageError> {
    if content_type.is_empty()
        || content_type.len() > 255
        || content_type != content_type.trim()
        || !content_type.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'+' | b'-' | b'.' | b';' | b'=' | b' ')
        })
    {
        return Err(ObjectStorageError::InvalidMetadata);
    }
    Ok(())
}

fn map_backend_configuration_error(error: object_store::Error) -> ObjectStorageError {
    match error {
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => {
            ObjectStorageError::UnsupportedBackend
        }
        _ => ObjectStorageError::InvalidConfiguration,
    }
}

fn map_backend_read_error(error: object_store::Error) -> ObjectStorageError {
    match error {
        object_store::Error::NotFound { .. } => ObjectStorageError::NotFound,
        _ => ObjectStorageError::Backend,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "aws")]
    use object_store::client::{HttpRequestBody, HttpResponseBody};

    fn storage(max_object_bytes: u64) -> VerifiedObjectStorage {
        VerifiedObjectStorage::from_settings(
            ObjectStoreSettings::new("memory:///tenant-artifacts")
                .with_max_object_bytes(max_object_bytes),
        )
        .expect("memory storage")
    }

    fn write(key: &str, body: &'static [u8]) -> ImmutableObjectWrite {
        ImmutableObjectWrite {
            key: ObjectKey::parse(key).expect("key"),
            content: Bytes::from_static(body),
            expected_digest: digest_bytes(body),
            content_type: "application/json".to_owned(),
        }
    }

    fn receipt(idempotent_replay: bool) -> ObjectWriteReceipt {
        ObjectWriteReceipt {
            key: ObjectKey::parse("objects/encrypted.json").expect("key"),
            size_bytes: 9,
            digest: digest_bytes(b"encrypted"),
            e_tag: Some("opaque-etag".to_owned()),
            version: Some("opaque-version".to_owned()),
            idempotent_replay,
        }
    }

    fn key_identity_fingerprint() -> &'static str {
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    fn typed_key_identity_fingerprint() -> Sha256Digest {
        key_identity_fingerprint()
            .parse()
            .expect("typed fingerprint")
    }

    #[test]
    fn encryption_requirement_has_a_provider_neutral_typed_projection() {
        let profile_id = ManagedEncryptionProfileId::from_digest(digest_bytes(b"profile"));
        let expected_observed_key_identity_fingerprint = typed_key_identity_fingerprint();
        let requirement = EncryptionRequirement::managed(
            profile_id.clone(),
            Some(expected_observed_key_identity_fingerprint.clone()),
        );
        assert_eq!(
            requirement.view(),
            EncryptionRequirementView::Managed {
                profile_id: &profile_id,
                expected_observed_key_identity_fingerprint: Some(
                    &expected_observed_key_identity_fingerprint,
                ),
            }
        );
    }

    #[tokio::test]
    async fn memory_backend_cannot_satisfy_a_managed_encryption_policy() {
        let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            ManagedEncryptionProfileId::from_digest(digest_bytes(b"managed-profile")),
            None,
        ));
        assert_eq!(
            storage(1_024)
                .put_immutable(write("objects/managed.json", b"managed"), &policy)
                .await,
            Err(ObjectStorageError::EncryptionPolicy(
                EncryptionPolicyError::ManagedEncryptionRequired,
            ))
        );
    }

    #[tokio::test]
    async fn memory_backend_requires_explicit_development_policy_for_verified_receipts() {
        let policy =
            ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext());
        let verified = storage(1_024)
            .put_immutable(write("objects/dev.json", b"dev"), &policy)
            .await
            .expect("explicit development policy");
        assert_eq!(
            verified.attestation().view(),
            EncryptionAttestationView::DevelopmentOrTestPlaintext
        );
    }

    #[test]
    fn managed_evidence_is_bound_to_method_object_and_receipt() {
        let first_receipt = receipt(false);
        let first_binding = WriteBinding::new(&first_receipt);
        let evidence = observed_s3_response(
            &ObserverRequestBinding::readback(first_binding.clone()),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                first_receipt.e_tag.as_deref(),
                first_receipt.version.as_deref(),
                "kms-key-one",
            ),
        )
        .expect("observed evidence");
        let attestation = managed_policy()
            .verify_managed_evidence(&first_receipt, &first_binding, &evidence)
            .expect("exact evidence binding");
        assert!(
            attestation
                .receipt_binding_fingerprint()
                .as_str()
                .starts_with("sha256:")
        );

        let put_only_evidence = observed_s3_response(
            &ObserverRequestBinding::put(first_binding.clone()),
            "PUT",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                first_receipt.e_tag.as_deref(),
                first_receipt.version.as_deref(),
                "kms-key-one",
            ),
        )
        .expect("PUT evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(
                &first_receipt,
                &first_binding,
                &put_only_evidence,
            ),
            Err(EncryptionPolicyError::EvidenceBindingMismatch)
        );

        let mut other_receipt = receipt(false);
        other_receipt.key = ObjectKey::parse("objects/other.json").expect("other key");
        let other_binding = WriteBinding::new(&other_receipt);
        assert_eq!(
            managed_policy().verify_managed_evidence(&other_receipt, &other_binding, &evidence,),
            Err(EncryptionPolicyError::EvidenceBindingMismatch)
        );

        let wrong_method = observed_s3_response(
            &ObserverRequestBinding::put(first_binding.clone()),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                first_receipt.e_tag.as_deref(),
                first_receipt.version.as_deref(),
                "kms-key-one",
            ),
        );
        assert!(wrong_method.is_none());
    }

    #[test]
    fn initial_and_idempotent_receipts_both_require_final_get_evidence() {
        for idempotent_replay in [false, true] {
            let receipt = receipt(idempotent_replay);
            let binding = WriteBinding::new(&receipt);
            let final_get = observed_s3_response(
                &ObserverRequestBinding::readback(binding.clone()),
                "GET",
                "/bucket/objects/encrypted.json",
                &sse_kms_headers(
                    receipt.e_tag.as_deref(),
                    receipt.version.as_deref(),
                    "kms-key-one",
                ),
            )
            .expect("final GET evidence");
            managed_policy()
                .verify_managed_evidence(&receipt, &binding, &final_get)
                .expect("final GET is the only signing evidence");

            let put_only = observed_s3_response(
                &ObserverRequestBinding::put(binding.clone()),
                "PUT",
                "/bucket/objects/encrypted.json",
                &sse_kms_headers(
                    receipt.e_tag.as_deref(),
                    receipt.version.as_deref(),
                    "kms-key-one",
                ),
            )
            .expect("PUT evidence");
            assert_eq!(
                managed_policy().verify_managed_evidence(&receipt, &binding, &put_only),
                Err(EncryptionPolicyError::EvidenceBindingMismatch)
            );

            let weak_final_get = observed_s3_response(
                &ObserverRequestBinding::readback(binding.clone()),
                "GET",
                "/bucket/objects/encrypted.json",
                &receipt_headers(receipt.e_tag.as_deref(), receipt.version.as_deref()),
            )
            .expect("weak final GET evidence");
            assert_eq!(
                managed_policy().verify_managed_evidence(&receipt, &binding, &weak_final_get),
                Err(EncryptionPolicyError::ManagedEncryptionRequired)
            );

            let mismatched_final_get = observed_s3_response(
                &ObserverRequestBinding::readback(binding.clone()),
                "GET",
                "/bucket/objects/encrypted.json",
                &sse_kms_headers(
                    Some("different-etag"),
                    Some("different-version"),
                    "kms-key-one",
                ),
            )
            .expect("mismatched final GET evidence");
            assert_eq!(
                managed_policy()
                    .verify_managed_evidence(&receipt, &binding, &mismatched_final_get,),
                Err(EncryptionPolicyError::EvidenceBindingMismatch)
            );
        }
    }

    #[test]
    fn final_get_options_pin_exact_version_and_private_binding() {
        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let mut extensions = Extensions::new();
        extensions.insert(ObserverRequestBinding::readback(binding.clone()));
        let options = read_options(receipt.version.as_deref(), extensions);

        assert_eq!(options.version.as_deref(), receipt.version.as_deref());
        assert_eq!(
            options.extensions.get::<ObserverRequestBinding>(),
            Some(&ObserverRequestBinding::readback(binding))
        );
    }

    #[test]
    fn missing_or_mismatched_s3_encryption_headers_fail_closed() {
        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let request = ObserverRequestBinding::readback(binding.clone());

        let missing = observed_s3_response(
            &request,
            "GET",
            "/bucket/objects/encrypted.json",
            &receipt_headers(receipt.e_tag.as_deref(), receipt.version.as_deref()),
        )
        .expect("bound missing observation");
        assert_eq!(
            managed_policy().verify_managed_evidence(&receipt, &binding, &missing),
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );

        let mismatched = observed_s3_response(
            &request,
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_headers(
                "AES256",
                receipt.e_tag.as_deref(),
                receipt.version.as_deref(),
                None,
            ),
        )
        .expect("bound mismatched observation");
        assert_eq!(
            managed_policy().verify_managed_evidence(&receipt, &binding, &mismatched),
            Err(EncryptionPolicyError::AlgorithmMismatch)
        );
    }

    #[cfg(feature = "aws")]
    #[tokio::test]
    async fn observer_http_service_carries_private_response_evidence_to_the_caller() {
        #[derive(Debug)]
        struct SseKmsResponseService {
            headers: object_store::HeaderMap,
        }

        #[async_trait]
        impl HttpService for SseKmsResponseService {
            async fn call(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
                let mut response =
                    HttpResponse::new(HttpResponseBody::new(HttpRequestBody::empty()));
                *response.headers_mut() = self.headers.clone();
                Ok(response)
            }
        }

        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let request_binding = ObserverRequestBinding::readback(binding.clone());
        let service = S3EncryptionObserverService {
            inner: HttpClient::new(SseKmsResponseService {
                headers: sse_kms_headers(
                    receipt.e_tag.as_deref(),
                    receipt.version.as_deref(),
                    "kms-key-one",
                ),
            }),
        };
        let mut request = HttpRequest::new(HttpRequestBody::empty());
        *request.method_mut() = "GET".parse().expect("GET method");
        *request.uri_mut() = "https://store.example/bucket/objects/encrypted.json"
            .parse()
            .expect("request URI");
        request.extensions_mut().insert(request_binding);

        let response = service.call(request).await.expect("observed response");
        let evidence = response
            .extensions()
            .get::<ObservedEncryptionEvidence>()
            .expect("private evidence extension");
        managed_policy()
            .verify_managed_evidence(&receipt, &binding, evidence)
            .expect("evidence propagated from the real response");
    }

    #[cfg(feature = "aws")]
    #[test]
    fn s3_configuration_preflight_rejects_plaintext_or_wrong_key_before_write_path() {
        let expected_canonical = digest_bytes(b"arn:aws:kms:my-first-key");
        let missing = ConfiguredS3Encryption::from_options(&BTreeMap::new(), None)
            .expect("missing encryption is a valid observed configuration state");
        assert_eq!(
            managed_policy().verify_s3_configuration(&missing),
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );

        let wrong_algorithm = ConfiguredS3Encryption::from_options(
            &BTreeMap::from([("aws_server_side_encryption".to_owned(), "AES256".to_owned())]),
            None,
        )
        .expect("supported storage option shape");
        assert_eq!(
            managed_policy().verify_s3_configuration(&wrong_algorithm),
            Err(EncryptionPolicyError::AlgorithmMismatch)
        );

        let wrong_key = ConfiguredS3Encryption::from_options(
            &BTreeMap::from([
                (
                    "aws_server_side_encryption".to_owned(),
                    "aws:kms".to_owned(),
                ),
                ("aws_sse_kms_key_id".to_owned(), "my-first-key".to_owned()),
            ]),
            Some(digest_bytes(b"arn:aws:kms:different-key")),
        )
        .expect("supported storage option shape");
        assert_eq!(
            managed_policy().verify_s3_configuration(&wrong_key),
            Err(EncryptionPolicyError::KeyIdentityMismatch)
        );

        let exact = ConfiguredS3Encryption::from_options(
            &BTreeMap::from([
                (
                    "aws_server_side_encryption".to_owned(),
                    "aws:kms".to_owned(),
                ),
                ("aws_sse_kms_key_id".to_owned(), "my-first-key".to_owned()),
            ]),
            Some(expected_canonical.clone()),
        )
        .expect("supported storage option shape");
        managed_policy_with_expected(Some(expected_canonical.clone()))
            .verify_s3_configuration(&exact)
            .expect("raw request locator is distinct from canonical observed identity");
        let wrong_profile = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            ManagedEncryptionProfileId::from_digest(digest_bytes(b"different-profile")),
            Some(expected_canonical.clone()),
        ));
        assert_eq!(
            wrong_profile.verify_s3_configuration(&exact),
            Err(EncryptionPolicyError::PolicyBackendMismatch)
        );

        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let wrong_observed_key = observed_s3_response(
            &ObserverRequestBinding::readback(binding),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                receipt.e_tag.as_deref(),
                receipt.version.as_deref(),
                "arn:aws:kms:other-key",
            ),
        )
        .expect("observed response");
        assert_eq!(
            exact.verify_observed(&wrong_observed_key),
            Err(EncryptionPolicyError::KeyIdentityMismatch)
        );

        let matching_observed_key = observed_s3_response(
            &ObserverRequestBinding::readback(WriteBinding::new(&receipt)),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                receipt.e_tag.as_deref(),
                receipt.version.as_deref(),
                "arn:aws:kms:my-first-key",
            ),
        )
        .expect("observed canonical response");
        exact
            .verify_observed(&matching_observed_key)
            .expect("canonical response identity matches typed expectation");
    }

    #[cfg(feature = "aws")]
    #[tokio::test]
    async fn public_s3_write_rejects_missing_managed_configuration_without_network_io() {
        let storage = VerifiedObjectStorage::from_settings(ObjectStoreSettings::new(
            "s3://preflight-only-bucket/private-prefix",
        ))
        .expect("S3 configuration builds without performing I/O");
        let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            storage
                .managed_encryption_profile_id()
                .expect("managed adapter profile")
                .clone(),
            None,
        ));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            storage.put_immutable(write("objects/no-plaintext.json", b"private"), &policy),
        )
        .await
        .expect("policy preflight completes without network I/O");
        assert_eq!(
            result,
            Err(ObjectStorageError::EncryptionPolicy(
                EncryptionPolicyError::ManagedEncryptionRequired,
            ))
        );
    }

    #[cfg(feature = "aws")]
    #[tokio::test]
    async fn public_s3_write_rejects_wrong_managed_algorithm_without_network_io() {
        let storage = VerifiedObjectStorage::from_settings(
            ObjectStoreSettings::new("s3://preflight-only-bucket/private-prefix")
                .with_option("aws_server_side_encryption", "AES256"),
        )
        .expect("S3 configuration builds without performing I/O");
        let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            storage
                .managed_encryption_profile_id()
                .expect("managed adapter profile")
                .clone(),
            None,
        ));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            storage.put_immutable(
                write("objects/no-weak-encryption.json", b"private"),
                &policy,
            ),
        )
        .await
        .expect("policy preflight completes without network I/O");
        assert_eq!(
            result,
            Err(ObjectStorageError::EncryptionPolicy(
                EncryptionPolicyError::AlgorithmMismatch,
            ))
        );
    }

    fn sse_kms_headers(
        e_tag: Option<&str>,
        version: Option<&str>,
        key_identity: &str,
    ) -> object_store::HeaderMap {
        sse_headers("aws:kms", e_tag, version, Some(key_identity))
    }

    fn sse_headers(
        algorithm: &'static str,
        e_tag: Option<&str>,
        version: Option<&str>,
        key_identity: Option<&str>,
    ) -> object_store::HeaderMap {
        let mut headers = receipt_headers(e_tag, version);
        headers.insert(
            "x-amz-server-side-encryption",
            object_store::HeaderValue::from_static(algorithm),
        );
        if let Some(key_identity) = key_identity {
            headers.insert(
                "x-amz-server-side-encryption-aws-kms-key-id",
                key_identity.parse().expect("key identity header"),
            );
        }
        headers
    }

    fn receipt_headers(e_tag: Option<&str>, version: Option<&str>) -> object_store::HeaderMap {
        let mut headers = object_store::HeaderMap::new();
        if let Some(e_tag) = e_tag {
            headers.insert("etag", e_tag.parse().expect("etag header"));
        }
        if let Some(version) = version {
            headers.insert("x-amz-version-id", version.parse().expect("version header"));
        }
        headers
    }

    fn managed_policy() -> ArtifactEncryptionPolicy {
        managed_policy_with_expected(Some(digest_bytes(b"kms-key-one")))
    }

    fn managed_policy_with_expected(
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> ArtifactEncryptionPolicy {
        ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            s3_managed_profile_id(),
            expected_observed_key_identity_fingerprint,
        ))
    }

    fn development_policy() -> ArtifactEncryptionPolicy {
        ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext())
    }

    #[test]
    fn observed_key_identity_is_fingerprinted_and_formatting_is_redacted() {
        let raw_key_identity = "arn:provider:kms:region:account:key/credential-token-sentinel";
        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let evidence = observed_s3_response(
            &ObserverRequestBinding::readback(binding.clone()),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                receipt.e_tag.as_deref(),
                receipt.version.as_deref(),
                raw_key_identity,
            ),
        )
        .expect("observed evidence");
        let profile_id = s3_managed_profile_id();
        let attestation = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
            profile_id.clone(),
            Some(digest_bytes(raw_key_identity.as_bytes())),
        ))
        .verify_managed_evidence(&receipt, &binding, &evidence)
        .expect("matching evidence");

        assert_eq!(
            attestation.view(),
            EncryptionAttestationView::Managed {
                profile_id: &profile_id,
                observed_key_identity_fingerprint: Some(
                    &digest_bytes(raw_key_identity.as_bytes(),)
                ),
            }
        );
        for rendered in [format!("{attestation:?}"), format!("{attestation}")] {
            assert!(!rendered.contains(raw_key_identity));
            assert!(!rendered.contains("arn:"));
            assert!(!rendered.to_ascii_lowercase().contains("credential"));
            assert!(!rendered.to_ascii_lowercase().contains("token"));
        }
    }

    #[test]
    fn expected_key_fingerprint_and_idempotent_operation_are_enforced() {
        let replay = receipt(true);
        let binding = WriteBinding::new(&replay);
        let evidence = observed_s3_response(
            &ObserverRequestBinding::readback(binding.clone()),
            "GET",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                replay.e_tag.as_deref(),
                replay.version.as_deref(),
                "different-key",
            ),
        )
        .expect("readback evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(&replay, &binding, &evidence),
            Err(EncryptionPolicyError::KeyIdentityMismatch)
        );

        let put_evidence = observed_s3_response(
            &ObserverRequestBinding::put(binding.clone()),
            "PUT",
            "/bucket/objects/encrypted.json",
            &sse_kms_headers(
                replay.e_tag.as_deref(),
                replay.version.as_deref(),
                "kms-key-one",
            ),
        )
        .expect("put evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(&replay, &binding, &put_evidence),
            Err(EncryptionPolicyError::EvidenceBindingMismatch)
        );
    }

    #[test]
    fn settings_debug_never_discloses_url_or_option_values() {
        let settings = ObjectStoreSettings::new("s3://secret-bucket/private-prefix")
            .with_option("aws_access_key_id", "SUPER-SECRET-ACCESS")
            .with_option("aws_secret_access_key", "SUPER-SECRET-KEY");
        let debug = format!("{settings:?}");
        assert!(!debug.contains("secret-bucket"));
        assert!(!debug.contains("SUPER-SECRET"));
        assert!(debug.contains("option_count: 2"));
    }

    #[test]
    fn embedded_credentials_query_and_unsupported_schemes_are_rejected() {
        for url in [
            "s3://user:password@bucket/prefix",
            "s3://bucket/prefix?secret=value",
            "memory://ambiguous-host/prefix",
            "file://remote-host/path",
            "https://bucket.example/object",
        ] {
            assert!(VerifiedObjectStorage::from_settings(ObjectStoreSettings::new(url)).is_err());
        }
        assert_eq!(
            VerifiedObjectStorage::from_settings(
                ObjectStoreSettings::new("memory:///tenant-artifacts")
                    .with_expected_observed_key_identity_fingerprint(digest_bytes(
                        b"managed-only-identity",
                    )),
            )
            .expect_err("managed identity is invalid for plaintext storage"),
            ObjectStorageError::InvalidConfiguration
        );
    }

    #[cfg(feature = "aws")]
    #[test]
    fn unknown_s3_options_fail_closed_instead_of_being_ignored() {
        let settings = ObjectStoreSettings::new("s3://bucket/prefix")
            .with_option("aws_typo_secret_key", "value");
        assert_eq!(
            settings.validate(),
            Err(ObjectStorageError::InvalidConfiguration)
        );
    }

    #[test]
    fn object_keys_reject_traversal_ambiguity_and_untrusted_unicode() {
        for key in [
            "",
            "/root",
            "root/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "a/\u{202e}b",
        ] {
            assert_eq!(ObjectKey::parse(key), Err(ObjectStorageError::InvalidKey));
        }
        assert_eq!(
            ObjectKey::parse("tenant-a/sha256/abc_123.json")
                .expect("valid key")
                .as_str(),
            "tenant-a/sha256/abc_123.json"
        );
    }

    #[tokio::test]
    async fn immutable_put_read_and_exact_replay_are_digest_verified() {
        let storage = storage(1_024);
        let policy = development_policy();
        let first = storage
            .put_immutable(write("objects/a.json", br#"{"ok":true}"#), &policy)
            .await
            .expect("first write");
        assert!(!first.receipt().idempotent_replay);
        assert!(
            first.receipt().version.is_none(),
            "unversioned backends keep an explicit unversioned receipt"
        );
        let replay = storage
            .put_immutable(write("objects/a.json", br#"{"ok":true}"#), &policy)
            .await
            .expect("exact replay");
        assert!(replay.receipt().idempotent_replay);
        let read = storage
            .read_verified(
                &first.receipt().key,
                &first.receipt().digest,
                first.receipt().version.as_deref(),
            )
            .await
            .expect("verified read");
        assert_eq!(read.content, Bytes::from_static(br#"{"ok":true}"#));
        assert_eq!(read.content_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn same_key_changed_content_is_an_immutable_conflict() {
        let storage = storage(1_024);
        let policy = development_policy();
        storage
            .put_immutable(write("objects/a.json", b"first"), &policy)
            .await
            .expect("first write");
        assert_eq!(
            storage
                .put_immutable(write("objects/a.json", b"second"), &policy)
                .await,
            Err(ObjectStorageError::ImmutableConflict)
        );
    }

    #[tokio::test]
    async fn forged_digest_and_oversized_content_fail_before_storage() {
        let storage = storage(4);
        let policy = development_policy();
        let mut forged = write("objects/forged.json", b"four");
        forged.expected_digest = digest_bytes(b"other");
        assert_eq!(
            storage.put_immutable(forged, &policy).await,
            Err(ObjectStorageError::DigestMismatch)
        );
        assert_eq!(
            storage
                .put_immutable(write("objects/large.json", b"12345"), &policy)
                .await,
            Err(ObjectStorageError::SizeLimitExceeded)
        );
    }

    #[tokio::test]
    async fn concurrent_exact_creates_converge_to_one_object() {
        let storage = storage(1_024);
        let policy = development_policy();
        let left = storage.clone();
        let right = storage.clone();
        let (left, right) = tokio::join!(
            left.put_immutable(write("objects/race.json", b"stable"), &policy),
            right.put_immutable(write("objects/race.json", b"stable"), &policy),
        );
        let receipts = [left.expect("left"), right.expect("right")];
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| receipt.receipt().idempotent_replay)
                .count(),
            1
        );
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn default_filesystem_backend_is_durable_writable_and_verified() {
        let directory = std::env::temp_dir().join(format!(
            "warpin-object-storage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temporary storage directory");
        let url = Url::from_directory_path(&directory)
            .expect("file URL")
            .to_string();
        let storage = VerifiedObjectStorage::from_settings(
            ObjectStoreSettings::new(url).with_max_object_bytes(1_024),
        )
        .expect("filesystem storage");
        let policy = development_policy();
        let receipt = storage
            .put_immutable(write("objects/local.json", b"durable"), &policy)
            .await
            .expect("filesystem immutable write");
        let read = storage
            .read_verified(
                &receipt.receipt().key,
                &receipt.receipt().digest,
                receipt.receipt().version.as_deref(),
            )
            .await
            .expect("filesystem verified read");
        assert_eq!(read.content, Bytes::from_static(b"durable"));
        assert_eq!(read.content_type, None);
        std::fs::remove_dir_all(directory).expect("temporary storage cleanup");
    }
}
