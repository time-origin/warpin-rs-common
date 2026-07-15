#[derive(Clone, Eq, Hash, PartialEq)]
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

impl fmt::Debug for ObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectKey")
            .field("length", &self.0.len())
            .field("fingerprint", &digest_bytes(self.0.as_bytes()))
            .finish()
    }
}

#[derive(Clone)]
pub struct ImmutableObjectWrite {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub content: Bytes,
    pub expected_digest: Sha256Digest,
    pub content_type: String,
}

impl fmt::Debug for ImmutableObjectWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableObjectWrite")
            .field("key", &self.key)
            .field("context_id", &self.context_id)
            .field("content_len", &self.content.len())
            .field("expected_digest", &self.expected_digest)
            .field("content_type_present", &!self.content_type.is_empty())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ObjectWriteReceipt {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub size_bytes: u64,
    pub digest: Sha256Digest,
    pub e_tag: Option<String>,
    pub version: Option<String>,
    pub idempotent_replay: bool,
}

impl fmt::Debug for ObjectWriteReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectWriteReceipt")
            .field("key", &self.key)
            .field("context_id", &self.context_id)
            .field("size_bytes", &self.size_bytes)
            .field("digest", &self.digest)
            .field("e_tag_present", &self.e_tag.is_some())
            .field("version_present", &self.version.is_some())
            .field("idempotent_replay", &self.idempotent_replay)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
enum EncryptionRequirementKind {
    Managed {
        profile_id: ManagedEncryptionProfileId,
        context_id: ArtifactEncryptionContextId,
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

/// Opaque, credential-safe identity of the canonical artifact encryption
/// context produced by the owning processing boundary.
///
/// The digest must be created from a versioned, domain-separated canonical
/// field set. Raw tenant, space, reference, manifest, schema, and
/// classification values never enter this storage contract.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactEncryptionContextId(Sha256Digest);

impl ArtifactEncryptionContextId {
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
        context_id: &'a ArtifactEncryptionContextId,
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
        context_id: ArtifactEncryptionContextId,
        expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    ) -> Self {
        Self {
            kind: EncryptionRequirementKind::Managed {
                profile_id,
                context_id,
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
                context_id,
                expected_observed_key_identity_fingerprint,
            } => EncryptionRequirementView::Managed {
                profile_id,
                context_id,
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

    pub(crate) fn verify_s3_configuration(
        &self,
        configured: &ConfiguredS3Encryption,
    ) -> Result<(), EncryptionPolicyError> {
        let EncryptionRequirementKind::Managed {
            profile_id,
            context_id: _,
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
        if configured.bucket_key_state != ObservedBucketKeyState::Disabled {
            return Err(EncryptionPolicyError::ObjectContextBindingRequired);
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

    pub(crate) fn verify_managed_evidence(
        &self,
        receipt: &ObjectWriteReceipt,
        binding: &WriteBinding,
        evidence: &ObservedEncryptionEvidence,
    ) -> Result<EncryptionAttestation, EncryptionPolicyError> {
        let EncryptionRequirementKind::Managed {
            profile_id,
            context_id,
            expected_observed_key_identity_fingerprint,
        } = &self.requirement.kind
        else {
            return Err(EncryptionPolicyError::PolicyBackendMismatch);
        };
        if !binding.matches_receipt(receipt)
            || receipt.context_id != *context_id
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
        if matches!(
            evidence.bucket_key_state,
            ObservedBucketKeyState::Enabled | ObservedBucketKeyState::Invalid
        ) {
            return Err(EncryptionPolicyError::ObjectContextBindingRequired);
        }
        if expected_observed_key_identity_fingerprint.is_some()
            && evidence.key_identity_fingerprint.as_ref()
                != expected_observed_key_identity_fingerprint.as_ref()
        {
            return Err(EncryptionPolicyError::KeyIdentityMismatch);
        }
        Ok(EncryptionAttestation::managed_from_observer(
            profile_id.clone(),
            context_id.clone(),
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
        context_id: ArtifactEncryptionContextId,
        object_path_binding_fingerprint: Sha256Digest,
        observed_key_identity_fingerprint: Option<Sha256Digest>,
    },
    DevelopmentOrTestPlaintext {
        context_id: ArtifactEncryptionContextId,
    },
}

/// Read-only typed projection of sanitized observed encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionAttestationView<'a> {
    Managed {
        profile_id: &'a ManagedEncryptionProfileId,
        context_id: &'a ArtifactEncryptionContextId,
        object_path_binding_fingerprint: &'a Sha256Digest,
        observed_key_identity_fingerprint: Option<&'a Sha256Digest>,
    },
    DevelopmentOrTestPlaintext {
        context_id: &'a ArtifactEncryptionContextId,
    },
}

/// Sanitized evidence describing encryption observed by a storage adapter.
///
/// The type intentionally cannot contain provider response bodies or raw key
/// locators, and its formatting implementations never expose identity values.
/// Managed evidence is created only by [`crate::VerifiedObjectStorage`] after a real
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
///
/// Managed writes cannot be constructed through the legacy context-free API:
///
/// ```compile_fail
/// use bytes::Bytes;
/// use warpin_integrity::digest_bytes;
/// use warpin_object_storage::{ImmutableObjectWrite, ObjectKey};
///
/// let body = Bytes::from_static(b"private");
/// let _ = ImmutableObjectWrite {
///     key: ObjectKey::parse("objects/private.json").unwrap(),
///     expected_digest: digest_bytes(&body),
///     content: body,
///     content_type: "application/json".to_owned(),
/// };
/// ```
///
/// ```compile_fail
/// use warpin_integrity::digest_bytes;
/// use warpin_object_storage::{EncryptionRequirement, ManagedEncryptionProfileId};
///
/// let profile = ManagedEncryptionProfileId::from_digest(digest_bytes(b"profile"));
/// let _ = EncryptionRequirement::managed(profile, None);
/// ```
#[derive(Eq, PartialEq)]
pub struct EncryptionAttestation {
    kind: EncryptionAttestationKind,
    receipt_binding: Sha256Digest,
}

impl EncryptionAttestation {
    fn managed_from_observer(
        profile_id: ManagedEncryptionProfileId,
        context_id: ArtifactEncryptionContextId,
        binding: &WriteBinding,
        receipt: &ObjectWriteReceipt,
        evidence: &ObservedEncryptionEvidence,
    ) -> Self {
        Self {
            kind: EncryptionAttestationKind::Managed {
                profile_id,
                context_id,
                object_path_binding_fingerprint: evidence.request_path_fingerprint.clone(),
                observed_key_identity_fingerprint: evidence.key_identity_fingerprint.clone(),
            },
            receipt_binding: binding.receipt_binding(receipt, &evidence.request_path_fingerprint),
        }
    }

    pub(crate) fn development_or_test_plaintext(
        binding: &WriteBinding,
        receipt: &ObjectWriteReceipt,
    ) -> Self {
        Self {
            kind: EncryptionAttestationKind::DevelopmentOrTestPlaintext {
                context_id: receipt.context_id.clone(),
            },
            receipt_binding: binding.receipt_binding(receipt, &digest_bytes(b"local-backend")),
        }
    }

    pub const fn view(&self) -> EncryptionAttestationView<'_> {
        match &self.kind {
            EncryptionAttestationKind::Managed {
                profile_id,
                context_id,
                object_path_binding_fingerprint,
                observed_key_identity_fingerprint,
            } => EncryptionAttestationView::Managed {
                profile_id,
                context_id,
                object_path_binding_fingerprint,
                observed_key_identity_fingerprint: observed_key_identity_fingerprint.as_ref(),
            },
            EncryptionAttestationKind::DevelopmentOrTestPlaintext { context_id } => {
                EncryptionAttestationView::DevelopmentOrTestPlaintext { context_id }
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
    pub(crate) const fn new(
        receipt: ObjectWriteReceipt,
        attestation: EncryptionAttestation,
    ) -> Self {
        Self {
            receipt,
            attestation,
        }
    }

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
    #[error("managed encryption is not proven to bind the artifact object context")]
    ObjectContextBindingRequired,
    #[error("artifact encryption context does not match the managed policy")]
    ContextMismatch,
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
pub(crate) struct WriteBinding {
    nonce: u64,
    key: ObjectKey,
    context_id: ArtifactEncryptionContextId,
    size_bytes: u64,
    digest: Sha256Digest,
}

impl WriteBinding {
    pub(crate) fn for_write(
        key: &ObjectKey,
        context_id: &ArtifactEncryptionContextId,
        size_bytes: u64,
        digest: &Sha256Digest,
    ) -> Self {
        Self {
            nonce: NEXT_WRITE_BINDING.fetch_add(1, Ordering::Relaxed),
            key: key.clone(),
            context_id: context_id.clone(),
            size_bytes,
            digest: digest.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(receipt: &ObjectWriteReceipt) -> Self {
        Self::for_write(
            &receipt.key,
            &receipt.context_id,
            receipt.size_bytes,
            &receipt.digest,
        )
    }

    #[cfg(test)]
    pub(crate) const fn key(&self) -> &ObjectKey {
        &self.key
    }

    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    pub(crate) const fn content_digest(&self) -> &Sha256Digest {
        &self.digest
    }

    fn matches_receipt(&self, receipt: &ObjectWriteReceipt) -> bool {
        self.key == receipt.key
            && self.context_id == receipt.context_id
            && self.size_bytes == receipt.size_bytes
            && self.digest == receipt.digest
    }

    fn receipt_binding(
        &self,
        receipt: &ObjectWriteReceipt,
        request_path_fingerprint: &Sha256Digest,
    ) -> Sha256Digest {
        let value = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.nonce,
            self.key.as_str(),
            self.context_id.as_digest(),
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
            .field("context", &"[FINGERPRINTED]")
            .field("size_bytes", &self.size_bytes)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedOperation {
    Put,
    Readback,
}

impl ObservedOperation {
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    pub(crate) fn matches_method(self, method: &str) -> bool {
        matches!((self, method), (Self::Put, "PUT") | (Self::Readback, "GET"))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ObserverRequestBinding {
    pub(crate) binding: Option<WriteBinding>,
    pub(crate) operation: ObservedOperation,
    pub(crate) expected_location: Path,
    pub(crate) expected_version: Option<String>,
}

impl ObserverRequestBinding {
    pub(crate) fn put(binding: WriteBinding, expected_location: Path) -> Self {
        Self {
            binding: Some(binding),
            operation: ObservedOperation::Put,
            expected_location,
            expected_version: None,
        }
    }

    pub(crate) fn readback(
        binding: WriteBinding,
        expected_location: Path,
        expected_version: Option<String>,
    ) -> Self {
        Self {
            binding: Some(binding),
            operation: ObservedOperation::Readback,
            expected_location,
            expected_version,
        }
    }

    pub(crate) fn read(expected_location: Path, expected_version: Option<String>) -> Self {
        Self {
            binding: None,
            operation: ObservedOperation::Readback,
            expected_location,
            expected_version,
        }
    }
}

impl fmt::Debug for ObserverRequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObserverRequestBinding")
            .field("write_binding_present", &self.binding.is_some())
            .field("operation", &self.operation)
            .field("expected_location", &"[REDACTED]")
            .field("expected_version_present", &self.expected_version.is_some())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedObject {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub content: Bytes,
    pub digest: Sha256Digest,
    pub content_type: Option<String>,
    pub e_tag: Option<String>,
    pub version: Option<String>,
}

impl fmt::Debug for VerifiedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedObject")
            .field("key", &self.key)
            .field("context_id", &self.context_id)
            .field("content_len", &self.content.len())
            .field("digest", &self.digest)
            .field("content_type_present", &self.content_type.is_some())
            .field("e_tag_present", &self.e_tag.is_some())
            .field("version_present", &self.version.is_some())
            .finish()
    }
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
    #[error("managed object request target does not match the reviewed storage target")]
    RequestTargetMismatch,
    #[error("managed object request does not contain the required provider signature")]
    RequestSignatureInvalid,
    #[error(transparent)]
    EncryptionPolicy(#[from] EncryptionPolicyError),
}
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use object_store::path::Path;
use thiserror::Error;
use warpin_integrity::{Sha256Digest, digest_bytes};

use crate::s3_adapter::{
    ConfiguredS3Encryption, ObservedBucketKeyState, ObservedEncryptionEvidence,
    ObservedManagedAlgorithm,
};

const MAX_KEY_BYTES: usize = 1_024;
static NEXT_WRITE_BINDING: AtomicU64 = AtomicU64::new(1);
