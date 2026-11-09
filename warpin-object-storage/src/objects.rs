//! Ordinary object references use the complete physical key without adding prefixes.
//! Applications own key allocation, versions, idempotency and database persistence.
use std::{ops::Range, sync::Arc};

use bytes::Bytes;
use object_store::{Attribute, Attributes, GetOptions, ObjectStore, PutOptions, path::Path};
use serde::{Deserialize, Serialize};
use warpin_integrity::digest_bytes;

use crate::{ObjectStorageError, storage::validate_content_type};

/// Persist this metadata, never an expiring provider URL or only a basename.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectReference {
    pub bucket: String,
    pub key: String,
    pub version: Option<String>,
    pub etag: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

#[derive(Clone)]
pub struct ObjectStorage {
    bucket: String,
    store: Arc<dyn ObjectStore>,
}

impl ObjectStorage {
    /// `store` is built by the shared factory; `bucket` is its configured bucket.
    pub fn new(bucket: String, store: Arc<dyn ObjectStore>) -> Result<Self, ObjectStorageError> {
        if bucket.is_empty() {
            return Err(ObjectStorageError::InvalidConfiguration);
        }
        Ok(Self { bucket, store })
    }

    /// Writes exactly `key`. This is a normal PUT, without atomic-create guarantees.
    pub async fn put(
        &self,
        key: &Path,
        bytes: Bytes,
        media_type: String,
    ) -> Result<ObjectReference, ObjectStorageError> {
        if key.as_ref().is_empty() {
            return Err(ObjectStorageError::InvalidKey);
        }
        validate_content_type(&media_type)?;
        let size_bytes = bytes.len() as u64;
        let sha256 = digest_bytes(&bytes).to_string();
        let mut attributes = Attributes::new();
        attributes.insert(Attribute::ContentType, media_type.clone().into());
        let result = self
            .store
            .put_opts(
                key,
                bytes.into(),
                PutOptions {
                    attributes,
                    ..Default::default()
                },
            )
            .await
            .map_err(map_error)?;
        Ok(ObjectReference {
            bucket: self.bucket.clone(),
            key: key.to_string(),
            version: result.version,
            etag: result.e_tag,
            sha256,
            size_bytes,
            media_type,
        })
    }

    /// Uses the stored complete key; no context or directory is reconstructed.
    pub async fn read(&self, reference: &ObjectReference) -> Result<Bytes, ObjectStorageError> {
        let (key, options) = self.selection(reference)?;
        let result = self
            .store
            .get_opts(&key, options)
            .await
            .map_err(map_error)?;
        let bytes = result.bytes().await.map_err(map_error)?;
        if bytes.len() as u64 != reference.size_bytes
            || digest_bytes(&bytes).as_str() != reference.sha256
        {
            return Err(ObjectStorageError::DigestMismatch);
        }
        Ok(bytes)
    }

    /// Range identity is pinned by the stored version or ETag, not a whole-file hash.
    pub async fn read_range(
        &self,
        reference: &ObjectReference,
        range: Range<u64>,
    ) -> Result<Bytes, ObjectStorageError> {
        let (key, mut options) = self.selection(reference)?;
        if range.start >= range.end || range.end > reference.size_bytes {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        if options.version.is_none() && options.if_match.is_none() {
            return Err(ObjectStorageError::VersionMismatch);
        }
        options.range = Some(range.clone().into());
        let result = self
            .store
            .get_opts(&key, options)
            .await
            .map_err(map_error)?;
        if result.meta.size != reference.size_bytes || result.range != range {
            return Err(ObjectStorageError::VersionMismatch);
        }
        result.bytes().await.map_err(map_error)
    }

    fn selection(
        &self,
        reference: &ObjectReference,
    ) -> Result<(Path, GetOptions), ObjectStorageError> {
        if reference.bucket != self.bucket {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        let key = Path::parse(&reference.key).map_err(|_| ObjectStorageError::InvalidKey)?;
        if key.as_ref().is_empty() || key.as_ref() != reference.key {
            return Err(ObjectStorageError::InvalidKey);
        }
        Ok((
            key,
            GetOptions {
                version: reference.version.clone(),
                if_match: reference.etag.clone(),
                ..Default::default()
            },
        ))
    }
}

fn map_error(error: object_store::Error) -> ObjectStorageError {
    match error {
        object_store::Error::NotFound { .. } => ObjectStorageError::NotFound,
        object_store::Error::Precondition { .. } => ObjectStorageError::VersionMismatch,
        _ => ObjectStorageError::Backend,
    }
}

#[cfg(test)]
mod tests;
