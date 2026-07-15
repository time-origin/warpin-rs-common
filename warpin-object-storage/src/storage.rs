use std::{collections::BTreeMap, fmt, sync::Arc};

use object_store::{
    Attribute, AttributeValue, Attributes, Extensions, GetOptions, ObjectStore, PutMode,
    PutOptions, path::Path,
};
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

#[cfg(feature = "aws")]
use crate::s3_adapter::map_managed_request_error;
use crate::s3_adapter::{ConfiguredS3Encryption, ObservedEncryptionEvidence};
use crate::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, EncryptionAttestation,
    EncryptionPolicyError, EncryptionRequirementView, EncryptionVerifiedObjectWriteReceipt,
    ImmutableObjectWrite, ManagedEncryptionProfileId, ObjectKey, ObjectStorageError,
    ObjectWriteReceipt, ObserverRequestBinding, VerifiedObject, WriteBinding,
};

const DIGEST_METADATA_KEY: &str = "warpin-sha256";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_URL_BYTES: usize = 2_048;
const MAX_OPTION_KEY_BYTES: usize = 128;
const MAX_OPTION_VALUE_BYTES: usize = 4_096;
const MAX_TRUSTED_ROOT_CERTIFICATES: usize = 8;
const MAX_TRUSTED_ROOT_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_ROOT_CERTIFICATES_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct ObjectStoreSettings {
    pub url: String,
    pub options: BTreeMap<String, String>,
    pub max_object_bytes: u64,
    expected_observed_key_identity_fingerprint: Option<Sha256Digest>,
    managed_encryption_profile_id: Option<ManagedEncryptionProfileId>,
    trusted_root_certificate_pems: Vec<Vec<u8>>,
}

impl ObjectStoreSettings {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            options: BTreeMap::new(),
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            expected_observed_key_identity_fingerprint: None,
            managed_encryption_profile_id: None,
            trusted_root_certificate_pems: Vec::new(),
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

    /// Selects an opaque reviewed managed-encryption adapter profile. Custom
    /// S3-compatible endpoints fail closed unless their reviewed profile is
    /// selected explicitly.
    pub fn with_managed_encryption_profile_id(
        mut self,
        profile_id: ManagedEncryptionProfileId,
    ) -> Self {
        self.managed_encryption_profile_id = Some(profile_id);
        self
    }

    /// Adds a PEM-encoded root certificate trusted by the S3 TLS transport.
    ///
    /// The certificate remains private to the storage adapter and is parsed
    /// before backend I/O. This does not disable platform certificate
    /// validation and does not expose a provider-specific TLS type.
    pub fn with_trusted_root_certificate_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificate_pems.push(pem.into());
        self
    }

    #[cfg(all(test, feature = "aws"))]
    pub(crate) const fn managed_encryption_profile_id(
        &self,
    ) -> Option<&ManagedEncryptionProfileId> {
        self.managed_encryption_profile_id.as_ref()
    }

    fn validate(&self) -> Result<Url, ObjectStorageError> {
        if self.url.is_empty() || self.url.len() > MAX_URL_BYTES || self.max_object_bytes == 0 {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        let url = Url::parse(&self.url).map_err(|_| ObjectStorageError::InvalidConfiguration)?;
        let trusted_root_total_bytes = self
            .trusted_root_certificate_pems
            .iter()
            .try_fold(0_usize, |total, pem| total.checked_add(pem.len()))
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        if self.trusted_root_certificate_pems.len() > MAX_TRUSTED_ROOT_CERTIFICATES
            || self
                .trusted_root_certificate_pems
                .iter()
                .any(|pem| pem.is_empty() || pem.len() > MAX_TRUSTED_ROOT_CERTIFICATE_BYTES)
            || trusted_root_total_bytes > MAX_TRUSTED_ROOT_CERTIFICATES_TOTAL_BYTES
        {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
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
                    || self.expected_observed_key_identity_fingerprint.is_some()
                    || self.managed_encryption_profile_id.is_some()
                    || !self.trusted_root_certificate_pems.is_empty() =>
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
            .field(
                "managed_encryption_profile",
                &self.managed_encryption_profile_id.is_some(),
            )
            .field(
                "trusted_root_certificate_count",
                &self.trusted_root_certificate_pems.len(),
            )
            .field("max_object_bytes", &self.max_object_bytes)
            .finish()
    }
}
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum BackendSecurityMode {
    DevelopmentOrTestPlaintext,
    S3Observed {
        configured: Box<ConfiguredS3Encryption>,
    },
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
            .field(
                "prefix_fingerprint",
                &digest_bytes(self.prefix.as_ref().as_bytes()),
            )
            .field(
                "managed_encryption_profile",
                &self.managed_encryption_profile_id(),
            )
            .field("max_object_bytes", &self.max_object_bytes)
            .field("supports_attributes", &self.supports_attributes)
            .finish()
    }
}

impl VerifiedObjectStorage {
    pub fn from_settings(settings: ObjectStoreSettings) -> Result<Self, ObjectStorageError> {
        let url = settings.validate()?;
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
                    let (store, prefix, configured) = ConfiguredS3Encryption::build_store(
                        &url,
                        settings.options,
                        settings.managed_encryption_profile_id,
                        settings.expected_observed_key_identity_fingerprint,
                        settings.trusted_root_certificate_pems,
                    )?;
                    (
                        store,
                        prefix,
                        true,
                        BackendSecurityMode::S3Observed {
                            configured: Box::new(configured),
                        },
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
        if let EncryptionRequirementView::Managed { context_id, .. } = policy.requirement().view()
            && context_id != &write.context_id
        {
            return Err(EncryptionPolicyError::ContextMismatch.into());
        }
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
        let binding = WriteBinding::for_write(
            &write.key,
            &write.context_id,
            size_bytes,
            &write.expected_digest,
        );
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
        Ok(EncryptionVerifiedObjectWriteReceipt::new(
            outcome.receipt,
            attestation,
        ))
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
        let location = self.location(&write.key, &write.context_id)?;
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
        extensions.insert(ObserverRequestBinding::put(
            binding.clone(),
            location.clone(),
        ));
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
            Err(_error) => {
                #[cfg(feature = "aws")]
                if let Some(error) = map_managed_request_error(&_error) {
                    return Err(error);
                }
                return Err(ObjectStorageError::Backend);
            }
        };
        let readback = self
            .read_verified_internal(
                &write.key,
                &write.context_id,
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
            context_id: write.context_id,
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
        context_id: &ArtifactEncryptionContextId,
        expected_digest: &Sha256Digest,
        version: Option<&str>,
    ) -> Result<VerifiedObject, ObjectStorageError> {
        self.read_verified_internal(key, context_id, expected_digest, version, None)
            .await
            .map(|readback| readback.object)
    }

    async fn read_verified_internal(
        &self,
        key: &ObjectKey,
        context_id: &ArtifactEncryptionContextId,
        expected_digest: &Sha256Digest,
        expected_version: Option<&str>,
        binding: Option<&WriteBinding>,
    ) -> Result<VerifiedReadback, ObjectStorageError> {
        let location = self.location(key, context_id)?;
        let mut extensions = Extensions::new();
        let request_binding = match binding {
            Some(binding) => ObserverRequestBinding::readback(
                binding.clone(),
                location.clone(),
                expected_version.map(str::to_owned),
            ),
            None => {
                ObserverRequestBinding::read(location.clone(), expected_version.map(str::to_owned))
            }
        };
        extensions.insert(request_binding);
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
                context_id: context_id.clone(),
                content,
                digest: expected_digest.clone(),
                content_type,
                e_tag,
                version,
            },
            evidence,
        })
    }

    pub(crate) fn location(
        &self,
        key: &ObjectKey,
        context_id: &ArtifactEncryptionContextId,
    ) -> Result<Path, ObjectStorageError> {
        let digest = context_id
            .as_digest()
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(ObjectStorageError::InvalidConfiguration)?;
        let context_path = format!("contexts/sha256={digest}/{}", key.as_str());
        let value = if self.prefix.as_ref().is_empty() {
            context_path
        } else {
            format!("{}/{context_path}", self.prefix)
        };
        Path::parse(value).map_err(|_| ObjectStorageError::InvalidKey)
    }
}

pub(crate) fn read_options(expected_version: Option<&str>, extensions: Extensions) -> GetOptions {
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

pub(crate) fn map_backend_configuration_error(error: object_store::Error) -> ObjectStorageError {
    match error {
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => {
            ObjectStorageError::UnsupportedBackend
        }
        _ => ObjectStorageError::InvalidConfiguration,
    }
}

fn map_backend_read_error(error: object_store::Error) -> ObjectStorageError {
    #[cfg(feature = "aws")]
    if let Some(error) = map_managed_request_error(&error) {
        return error;
    }
    match error {
        object_store::Error::NotFound { .. } => ObjectStorageError::NotFound,
        _ => ObjectStorageError::Backend,
    }
}
