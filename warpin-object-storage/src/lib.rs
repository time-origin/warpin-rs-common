use std::{collections::BTreeMap, fmt, sync::Arc};

use bytes::Bytes;
use object_store::{
    Attribute, AttributeValue, Attributes, ObjectStore, ObjectStoreExt, PutMode, PutOptions,
    path::Path,
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
const MAX_ENCRYPTION_IDENTITY_BYTES: usize = 64;
const SHA256_FINGERPRINT_PREFIX: &str = "sha256:";
const SHA256_HEX_BYTES: usize = 64;

#[derive(Clone)]
pub struct ObjectStoreSettings {
    pub url: String,
    pub options: BTreeMap<String, String>,
    pub max_object_bytes: u64,
}

impl ObjectStoreSettings {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            options: BTreeMap::new(),
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
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
            "memory" | "file" if url.host_str().is_some() || !self.options.is_empty() => {
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
struct ManagedEncryptionIdentity {
    provider: String,
    algorithm: String,
    key_identity_fingerprint: Option<String>,
}

impl ManagedEncryptionIdentity {
    fn parse(
        provider: &str,
        algorithm: &str,
        key_identity_fingerprint: Option<&str>,
    ) -> Result<Self, EncryptionPolicyError> {
        if !is_safe_encryption_identity(provider) || !is_safe_encryption_identity(algorithm) {
            return Err(EncryptionPolicyError::InvalidEncryptionIdentity);
        }
        if key_identity_fingerprint.is_some_and(|value| !is_sha256_fingerprint(value)) {
            return Err(EncryptionPolicyError::InvalidKeyIdentityFingerprint);
        }
        Ok(Self {
            provider: provider.to_owned(),
            algorithm: algorithm.to_owned(),
            key_identity_fingerprint: key_identity_fingerprint.map(str::to_owned),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
enum EncryptionRequirementKind {
    Managed(ManagedEncryptionIdentity),
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
    /// Requires managed encryption with an exact provider and algorithm identity.
    ///
    /// `key_identity_fingerprint`, when present, is a non-secret SHA-256 fingerprint
    /// of the expected key identity. Raw key identifiers, ARNs, URLs, and credentials
    /// are intentionally rejected.
    pub fn managed(
        provider: &str,
        algorithm: &str,
        key_identity_fingerprint: Option<&str>,
    ) -> Result<Self, EncryptionPolicyError> {
        Ok(Self {
            kind: EncryptionRequirementKind::Managed(ManagedEncryptionIdentity::parse(
                provider,
                algorithm,
                key_identity_fingerprint,
            )?),
        })
    }

    /// Explicitly permits plaintext only for a development or test deployment.
    pub const fn development_or_test_plaintext() -> Self {
        Self {
            kind: EncryptionRequirementKind::DevelopmentOrTestPlaintext,
        }
    }

    pub const fn is_managed(&self) -> bool {
        matches!(self.kind, EncryptionRequirementKind::Managed(_))
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

    /// Verifies encryption evidence and returns a wrapper that records that the
    /// receipt passed this policy. Idempotent replays follow the same checks as new
    /// writes and therefore cannot bypass a stronger requirement.
    pub fn verify_receipt(
        &self,
        receipt: ObjectWriteReceipt,
        attestation: Option<EncryptionAttestation>,
    ) -> Result<EncryptionVerifiedObjectWriteReceipt, EncryptionPolicyError> {
        let attestation = attestation.ok_or(EncryptionPolicyError::MissingAttestation)?;
        self.verify_attestation(&attestation)?;
        Ok(EncryptionVerifiedObjectWriteReceipt {
            receipt,
            attestation,
        })
    }

    fn verify_attestation(
        &self,
        attestation: &EncryptionAttestation,
    ) -> Result<(), EncryptionPolicyError> {
        let EncryptionRequirementKind::Managed(required) = &self.requirement.kind else {
            return Ok(());
        };
        let EncryptionAttestationKind::Managed(observed) = &attestation.kind else {
            return Err(EncryptionPolicyError::ManagedEncryptionRequired);
        };
        if observed.provider != required.provider {
            return Err(EncryptionPolicyError::ProviderMismatch);
        }
        if observed.algorithm != required.algorithm {
            return Err(EncryptionPolicyError::AlgorithmMismatch);
        }
        if required.key_identity_fingerprint.is_some()
            && observed.key_identity_fingerprint != required.key_identity_fingerprint
        {
            return Err(EncryptionPolicyError::KeyIdentityMismatch);
        }
        Ok(())
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

#[derive(Clone, Eq, PartialEq)]
enum EncryptionAttestationKind {
    Managed(ManagedEncryptionIdentity),
    DevelopmentOrTestPlaintext,
}

/// Sanitized evidence describing encryption observed by a storage adapter.
///
/// The type intentionally cannot contain provider response bodies or raw key
/// locators, and its formatting implementations never expose identity values.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptionAttestation {
    kind: EncryptionAttestationKind,
}

impl EncryptionAttestation {
    pub fn managed(
        provider: &str,
        algorithm: &str,
        key_identity_fingerprint: Option<&str>,
    ) -> Result<Self, EncryptionPolicyError> {
        Ok(Self {
            kind: EncryptionAttestationKind::Managed(ManagedEncryptionIdentity::parse(
                provider,
                algorithm,
                key_identity_fingerprint,
            )?),
        })
    }

    /// Records the deliberate absence of encryption in a development/test backend.
    pub const fn plaintext_for_development_or_test() -> Self {
        Self {
            kind: EncryptionAttestationKind::DevelopmentOrTestPlaintext,
        }
    }

    pub const fn is_managed(&self) -> bool {
        matches!(self.kind, EncryptionAttestationKind::Managed(_))
    }

    /// Returns the validated semantic provider identity for durable attestation
    /// storage. This value is never a provider locator or credential.
    pub fn provider_identity(&self) -> Option<&str> {
        self.managed_identity()
            .map(|identity| identity.provider.as_str())
    }

    /// Returns the validated semantic algorithm identity for durable attestation
    /// storage.
    pub fn algorithm_identity(&self) -> Option<&str> {
        self.managed_identity()
            .map(|identity| identity.algorithm.as_str())
    }

    /// Returns the optional non-secret SHA-256 key identity fingerprint.
    pub fn key_identity_fingerprint(&self) -> Option<&str> {
        self.managed_identity()
            .and_then(|identity| identity.key_identity_fingerprint.as_deref())
    }

    fn managed_identity(&self) -> Option<&ManagedEncryptionIdentity> {
        match &self.kind {
            EncryptionAttestationKind::Managed(identity) => Some(identity),
            EncryptionAttestationKind::DevelopmentOrTestPlaintext => None,
        }
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
#[derive(Clone, Eq, PartialEq)]
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

    pub fn into_parts(self) -> (ObjectWriteReceipt, EncryptionAttestation) {
        (self.receipt, self.attestation)
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
    #[error("encryption identity is invalid")]
    InvalidEncryptionIdentity,
    #[error("encryption key identity fingerprint is invalid")]
    InvalidKeyIdentityFingerprint,
    #[error("encryption attestation is required")]
    MissingAttestation,
    #[error("managed encryption is required")]
    ManagedEncryptionRequired,
    #[error("observed encryption provider does not satisfy policy")]
    ProviderMismatch,
    #[error("observed encryption algorithm does not satisfy policy")]
    AlgorithmMismatch,
    #[error("observed encryption key identity does not satisfy policy")]
    KeyIdentityMismatch,
}

fn encryption_mode_name(managed: bool) -> &'static str {
    if managed {
        "managed"
    } else {
        "development-or-test-plaintext"
    }
}

fn is_safe_encryption_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENCRYPTION_IDENTITY_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == SHA256_FINGERPRINT_PREFIX.len() + SHA256_HEX_BYTES
        && value.starts_with(SHA256_FINGERPRINT_PREFIX)
        && value[SHA256_FINGERPRINT_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    #[error("immutable object identity conflicts with existing content")]
    ImmutableConflict,
    #[error("object was not found")]
    NotFound,
    #[error("object storage backend operation failed")]
    Backend,
}

#[derive(Clone)]
pub struct VerifiedObjectStorage {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
    max_object_bytes: u64,
    supports_attributes: bool,
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
        let (store, prefix, supports_attributes): (Box<dyn ObjectStore>, Path, bool) =
            match url.scheme() {
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
                        (Box::new(store), Path::ROOT, false)
                    }
                }
                _ => {
                    let (store, prefix) = object_store::parse_url_opts(&url, settings.options)
                        .map_err(map_backend_configuration_error)?;
                    (store, prefix, true)
                }
            };
        Ok(Self {
            store: Arc::from(store),
            prefix,
            max_object_bytes: settings.max_object_bytes,
            supports_attributes,
        })
    }

    pub async fn put_immutable(
        &self,
        write: ImmutableObjectWrite,
    ) -> Result<ObjectWriteReceipt, ObjectStorageError> {
        validate_content_type(&write.content_type)?;
        let size_bytes = u64::try_from(write.content.len())
            .map_err(|_| ObjectStorageError::SizeLimitExceeded)?;
        if size_bytes > self.max_object_bytes {
            return Err(ObjectStorageError::SizeLimitExceeded);
        }
        if digest_bytes(&write.content) != write.expected_digest {
            return Err(ObjectStorageError::DigestMismatch);
        }
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
        let put_result = self
            .store
            .put_opts(
                &location,
                write.content.clone().into(),
                PutOptions {
                    mode: PutMode::Create,
                    attributes,
                    ..PutOptions::default()
                },
            )
            .await;
        let (e_tag, version, idempotent_replay) = match put_result {
            Ok(result) => (result.e_tag, result.version, false),
            Err(object_store::Error::AlreadyExists { .. }) => (None, None, true),
            Err(_) => return Err(ObjectStorageError::Backend),
        };
        let readback = self
            .read_verified(&write.key, &write.expected_digest)
            .await
            .map_err(|error| {
                if idempotent_replay && error == ObjectStorageError::DigestMismatch {
                    ObjectStorageError::ImmutableConflict
                } else {
                    error
                }
            })?;
        if self.supports_attributes
            && readback.content_type.as_deref() != Some(write.content_type.as_str())
        {
            return Err(ObjectStorageError::ImmutableConflict);
        }
        Ok(ObjectWriteReceipt {
            key: write.key,
            size_bytes,
            digest: write.expected_digest,
            e_tag: e_tag.or(readback.e_tag),
            version: version.or(readback.version),
            idempotent_replay,
        })
    }

    pub async fn read_verified(
        &self,
        key: &ObjectKey,
        expected_digest: &Sha256Digest,
    ) -> Result<VerifiedObject, ObjectStorageError> {
        let location = self.location(key)?;
        let result = self
            .store
            .get(&location)
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
        let content = result
            .bytes()
            .await
            .map_err(|_| ObjectStorageError::Backend)?;
        let actual_size =
            u64::try_from(content.len()).map_err(|_| ObjectStorageError::SizeLimitExceeded)?;
        if actual_size != expected_size || digest_bytes(&content) != *expected_digest {
            return Err(ObjectStorageError::DigestMismatch);
        }
        Ok(VerifiedObject {
            key: key.clone(),
            content,
            digest: expected_digest.clone(),
            content_type,
            e_tag,
            version,
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

    fn managed_policy() -> ArtifactEncryptionPolicy {
        ArtifactEncryptionPolicy::new(
            EncryptionRequirement::managed(
                "portable-managed-key",
                "aes-256-gcm",
                Some(key_identity_fingerprint()),
            )
            .expect("managed requirement"),
        )
    }

    fn managed_attestation() -> EncryptionAttestation {
        EncryptionAttestation::managed(
            "portable-managed-key",
            "aes-256-gcm",
            Some(key_identity_fingerprint()),
        )
        .expect("managed attestation")
    }

    #[test]
    fn encryption_policy_rejects_absent_or_plaintext_attestation_when_managed_is_required() {
        let policy = managed_policy();
        assert_eq!(
            policy.verify_receipt(receipt(false), None),
            Err(EncryptionPolicyError::MissingAttestation)
        );
        assert_eq!(
            policy.verify_receipt(
                receipt(false),
                Some(EncryptionAttestation::plaintext_for_development_or_test()),
            ),
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );
    }

    #[test]
    fn encryption_policy_compares_managed_provider_algorithm_and_optional_key_identity() {
        let verified = managed_policy()
            .verify_receipt(receipt(false), Some(managed_attestation()))
            .expect("matching managed attestation");
        assert!(!verified.receipt().idempotent_replay);
        assert!(verified.attestation().is_managed());

        for (attestation, expected) in [
            (
                EncryptionAttestation::managed(
                    "different-provider",
                    "aes-256-gcm",
                    Some(key_identity_fingerprint()),
                )
                .expect("attestation"),
                EncryptionPolicyError::ProviderMismatch,
            ),
            (
                EncryptionAttestation::managed(
                    "portable-managed-key",
                    "different-algorithm",
                    Some(key_identity_fingerprint()),
                )
                .expect("attestation"),
                EncryptionPolicyError::AlgorithmMismatch,
            ),
            (
                EncryptionAttestation::managed(
                    "portable-managed-key",
                    "aes-256-gcm",
                    Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                )
                .expect("attestation"),
                EncryptionPolicyError::KeyIdentityMismatch,
            ),
        ] {
            assert_eq!(
                managed_policy().verify_receipt(receipt(false), Some(attestation)),
                Err(expected)
            );
        }
    }

    #[test]
    fn encryption_attestation_debug_and_display_never_disclose_identity_values() {
        let provider = "sentinel-provider-secret";
        let algorithm = "sentinel-algorithm-secret";
        let fingerprint = key_identity_fingerprint();
        let attestation = EncryptionAttestation::managed(provider, algorithm, Some(fingerprint))
            .expect("managed attestation");

        for rendered in [format!("{attestation:?}"), format!("{attestation}")] {
            assert!(!rendered.contains(provider));
            assert!(!rendered.contains(algorithm));
            assert!(!rendered.contains(fingerprint));
            assert!(!rendered.contains("arn:"));
            assert!(!rendered.contains("https://"));
            assert!(!rendered.to_ascii_lowercase().contains("credential"));
            assert!(!rendered.to_ascii_lowercase().contains("token"));
        }
    }

    #[test]
    fn encryption_attestation_exposes_only_validated_semantic_identity_for_persistence() {
        let attestation = managed_attestation();
        assert_eq!(
            attestation.provider_identity(),
            Some("portable-managed-key")
        );
        assert_eq!(attestation.algorithm_identity(), Some("aes-256-gcm"));
        assert_eq!(
            attestation.key_identity_fingerprint(),
            Some(key_identity_fingerprint())
        );

        let plaintext = EncryptionAttestation::plaintext_for_development_or_test();
        assert_eq!(plaintext.provider_identity(), None);
        assert_eq!(plaintext.algorithm_identity(), None);
        assert_eq!(plaintext.key_identity_fingerprint(), None);
    }

    #[test]
    fn encryption_identity_inputs_reject_provider_locator_shapes() {
        for unsafe_identity in [
            "arn:provider:kms:region:account:key/value",
            "https://kms.example/key",
            "provider/key",
            "provider?credential=value",
            "provider token",
        ] {
            assert!(EncryptionAttestation::managed(unsafe_identity, "aes-256-gcm", None).is_err());
            assert!(EncryptionRequirement::managed(unsafe_identity, "aes-256-gcm", None).is_err());
        }
    }

    #[test]
    fn idempotent_write_receipt_cannot_bypass_a_weaker_observed_policy() {
        let result = managed_policy().verify_receipt(
            receipt(true),
            Some(EncryptionAttestation::plaintext_for_development_or_test()),
        );
        assert_eq!(
            result,
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );
    }

    #[test]
    fn plaintext_backends_require_an_explicit_development_or_test_policy() {
        let attestation = EncryptionAttestation::plaintext_for_development_or_test();
        assert_eq!(
            managed_policy().verify_receipt(receipt(false), Some(attestation.clone())),
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );

        let policy =
            ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext());
        let verified = policy
            .verify_receipt(receipt(false), Some(attestation))
            .expect("explicit development/test plaintext policy");
        assert!(!verified.attestation().is_managed());
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
        let first = storage
            .put_immutable(write("objects/a.json", br#"{"ok":true}"#))
            .await
            .expect("first write");
        assert!(!first.idempotent_replay);
        let replay = storage
            .put_immutable(write("objects/a.json", br#"{"ok":true}"#))
            .await
            .expect("exact replay");
        assert!(replay.idempotent_replay);
        let read = storage
            .read_verified(&first.key, &first.digest)
            .await
            .expect("verified read");
        assert_eq!(read.content, Bytes::from_static(br#"{"ok":true}"#));
        assert_eq!(read.content_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn same_key_changed_content_is_an_immutable_conflict() {
        let storage = storage(1_024);
        storage
            .put_immutable(write("objects/a.json", b"first"))
            .await
            .expect("first write");
        assert_eq!(
            storage
                .put_immutable(write("objects/a.json", b"second"))
                .await,
            Err(ObjectStorageError::ImmutableConflict)
        );
    }

    #[tokio::test]
    async fn forged_digest_and_oversized_content_fail_before_storage() {
        let storage = storage(4);
        let mut forged = write("objects/forged.json", b"four");
        forged.expected_digest = digest_bytes(b"other");
        assert_eq!(
            storage.put_immutable(forged).await,
            Err(ObjectStorageError::DigestMismatch)
        );
        assert_eq!(
            storage
                .put_immutable(write("objects/large.json", b"12345"))
                .await,
            Err(ObjectStorageError::SizeLimitExceeded)
        );
    }

    #[tokio::test]
    async fn concurrent_exact_creates_converge_to_one_object() {
        let storage = storage(1_024);
        let left = storage.clone();
        let right = storage.clone();
        let (left, right) = tokio::join!(
            left.put_immutable(write("objects/race.json", b"stable")),
            right.put_immutable(write("objects/race.json", b"stable")),
        );
        let receipts = [left.expect("left"), right.expect("right")];
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| receipt.idempotent_replay)
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
        let receipt = storage
            .put_immutable(write("objects/local.json", b"durable"))
            .await
            .expect("filesystem immutable write");
        let read = storage
            .read_verified(&receipt.key, &receipt.digest)
            .await
            .expect("filesystem verified read");
        assert_eq!(read.content, Bytes::from_static(b"durable"));
        assert_eq!(read.content_type, None);
        std::fs::remove_dir_all(directory).expect("temporary storage cleanup");
    }
}
