//! Versioned, authenticated chunk storage with bounded working memory.
//!
//! A logical file is committed only by its final immutable root. Every physical
//! write uses the ordinary managed-encryption boundary. Callers MUST persist
//! journal intents before I/O and retain receipts for recovery and retirement.
//! A range authenticates complete containing chunks against the pinned root;
//! it does not independently recompute the logical file's full SHA-256.
use std::ops::Range;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use warpin_integrity::{Sha256Digest, digest_bytes};

use crate::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, ImmutableObjectWrite, ObjectKey,
    ObjectStorageError, ObjectWriteReceipt, VerifiedObjectStorage,
};

pub const STORAGE_FORMAT: &str = "warpin-chunked/v1";
const PAGE_FORMAT: &str = "warpin-chunk-index/v1";
const PAGE_ENTRIES: usize = 256;
const MAX_PAGES: usize = 4096;
const INDEX_BYTES: u64 = 4 * 1024 * 1024;
const MIN_CHUNK: u32 = 64 * 1024;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;

/// Write configuration; the declared length and digest must describe the input
/// exactly. Chunk size is a storage format parameter, not a read buffer hint.
#[derive(Clone, Debug)]
pub struct ChunkedObjectWrite {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub size_bytes: u64,
    pub expected_digest: Sha256Digest,
    pub content_type: String,
    pub chunk_bytes: u32,
}

/// Persist this together with the application's authorized artifact identity.
/// `root.digest` hashes the physical manifest; `content_digest` hashes the file.
/// A deserialized receipt is a caller trust input, not proof by itself: opening
/// it verifies the complete root and its correspondence to these logical fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkedObjectReceipt {
    pub root: ObjectWriteReceipt,
    pub content_digest: Sha256Digest,
    pub size_bytes: u64,
    pub content_type: String,
}

#[derive(Clone, Debug)]
pub struct ChunkWriteIntent {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub digest: Sha256Digest,
    pub size_bytes: u64,
    pub content_type: String,
}

/// Implementations must durably commit before returning success. No default
/// no-op is provided: crashes and cancellation may occur during any PUT. An
/// intent without an outcome requires exact digest/context reconciliation,
/// never blind key deletion. Shared content-addressed parts require reference
/// accounting; this crate deliberately does not implement an unsafe GC sweep.
#[async_trait]
pub trait ChunkWriteJournal: Send + Sync {
    async fn before_write(&self, intent: &ChunkWriteIntent) -> Result<(), ObjectStorageError>;
    async fn after_write(&self, receipt: &ObjectWriteReceipt) -> Result<(), ObjectStorageError>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pointer {
    key: String,
    digest: String,
    size: u64,
    version: Option<String>,
    etag: Option<String>,
}
impl Pointer {
    fn from_receipt(r: &ObjectWriteReceipt) -> Self {
        Self {
            key: r.key.as_str().into(),
            digest: r.digest.to_string(),
            size: r.size_bytes,
            version: r.version.clone(),
            etag: r.e_tag.clone(),
        }
    }
    fn receipt(
        &self,
        context: &ArtifactEncryptionContextId,
    ) -> Result<ObjectWriteReceipt, ObjectStorageError> {
        if self
            .version
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 2048)
            || self
                .etag
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 2048)
        {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        Ok(ObjectWriteReceipt {
            key: ObjectKey::parse(&self.key)?,
            context_id: context.clone(),
            size_bytes: self.size,
            digest: parse_digest(&self.digest)?,
            version: self.version.clone(),
            e_tag: self.etag.clone(),
            idempotent_replay: false,
        })
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Root {
    format: String,
    key: String,
    context: String,
    digest: String,
    size: u64,
    content_type: String,
    chunk_bytes: u32,
    pages: Vec<Pointer>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    format: String,
    first_chunk: u64,
    chunks: Vec<Pointer>,
}

fn parse_digest(s: &str) -> Result<Sha256Digest, ObjectStorageError> {
    s.parse().map_err(|_| ObjectStorageError::InvalidMetadata)
}
fn finish_hash(hash: Sha256) -> Sha256Digest {
    format!("sha256:{:x}", hash.finalize())
        .parse()
        .expect("SHA-256 encoding")
}
fn part_key(
    base: &ObjectKey,
    kind: &str,
    digest: &Sha256Digest,
) -> Result<ObjectKey, ObjectStorageError> {
    ObjectKey::parse(format!(
        "{}.parts/{kind}/{}",
        base.as_str(),
        digest.as_str().trim_start_matches("sha256:")
    ))
}
fn json_bytes<T: Serialize>(value: &T) -> Result<Bytes, ObjectStorageError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ObjectStorageError::InvalidMetadata)?;
    if bytes.len() as u64 > INDEX_BYTES {
        return Err(ObjectStorageError::SizeLimitExceeded);
    }
    Ok(bytes.into())
}
fn chunk_count(size: u64, chunk_bytes: u32) -> u64 {
    size.div_ceil(u64::from(chunk_bytes))
}
fn valid_chunk_size(n: u32) -> bool {
    (MIN_CHUNK..=MAX_CHUNK).contains(&n) && n.is_power_of_two()
}

impl VerifiedObjectStorage {
    /// Reads at most one configured chunk from `input` at a time. A maximum of
    /// 4096 page pointers and 256 chunk pointers is retained, independent of the
    /// file's length (up to 16 TiB with 16 MiB chunks). The existing physical
    /// object limit must permit a chunk and the bounded index objects.
    pub async fn put_chunked<R: AsyncRead + Unpin + Send>(
        &self,
        write: ChunkedObjectWrite,
        input: &mut R,
        policy: &ArtifactEncryptionPolicy,
        journal: &dyn ChunkWriteJournal,
    ) -> Result<ChunkedObjectReceipt, ObjectStorageError> {
        if write.size_bytes > self.max_streamed_object_bytes {
            return Err(ObjectStorageError::SizeLimitExceeded);
        }
        if !valid_chunk_size(write.chunk_bytes)
            || chunk_count(write.size_bytes, write.chunk_bytes) > (PAGE_ENTRIES * MAX_PAGES) as u64
            || write.content_type.is_empty()
            || write.content_type.len() > 256
            || !write.content_type.is_ascii()
            || write.content_type.chars().any(char::is_control)
        {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        // Reject overlong derived keys before creating any physical objects.
        part_key(&write.key, "chunks", &write.expected_digest)?;
        let mut pages = Vec::new();
        let mut chunks = Vec::with_capacity(PAGE_ENTRIES);
        let mut hash = Sha256::new();
        let mut offset = 0_u64;
        let mut index = 0_u64;
        while offset < write.size_bytes {
            let len = (write.size_bytes - offset).min(u64::from(write.chunk_bytes)) as usize;
            let mut bytes = vec![0; len];
            input
                .read_exact(&mut bytes)
                .await
                .map_err(|_| ObjectStorageError::Backend)?;
            hash.update(&bytes);
            let digest = digest_bytes(&bytes);
            let receipt = self
                .write_chunk_part(
                    part_key(&write.key, "chunks", &digest)?,
                    &write.context_id,
                    bytes.into(),
                    "application/octet-stream",
                    policy,
                    journal,
                )
                .await?;
            chunks.push(Pointer::from_receipt(&receipt));
            offset += len as u64;
            index += 1;
            if chunks.len() == PAGE_ENTRIES || offset == write.size_bytes {
                let page = Page {
                    format: PAGE_FORMAT.into(),
                    first_chunk: index - chunks.len() as u64,
                    chunks: std::mem::take(&mut chunks),
                };
                let bytes = json_bytes(&page)?;
                let receipt = self
                    .write_chunk_part(
                        part_key(&write.key, "pages", &digest_bytes(&bytes))?,
                        &write.context_id,
                        bytes,
                        "application/json",
                        policy,
                        journal,
                    )
                    .await?;
                pages.push(Pointer::from_receipt(&receipt));
            }
        }
        let mut extra = [0_u8; 1];
        if input
            .read(&mut extra)
            .await
            .map_err(|_| ObjectStorageError::Backend)?
            != 0
        {
            return Err(ObjectStorageError::SizeLimitExceeded);
        }
        if finish_hash(hash) != write.expected_digest {
            return Err(ObjectStorageError::DigestMismatch);
        }
        let root = Root {
            format: STORAGE_FORMAT.into(),
            key: write.key.as_str().into(),
            context: write.context_id.as_digest().to_string(),
            digest: write.expected_digest.to_string(),
            size: write.size_bytes,
            content_type: write.content_type.clone(),
            chunk_bytes: write.chunk_bytes,
            pages,
        };
        let receipt = self
            .write_chunk_part(
                write.key,
                &write.context_id,
                json_bytes(&root)?,
                "application/vnd.warpin.chunked+json",
                policy,
                journal,
            )
            .await?;
        Ok(ChunkedObjectReceipt {
            root: receipt,
            content_digest: write.expected_digest,
            size_bytes: write.size_bytes,
            content_type: write.content_type,
        })
    }

    async fn write_chunk_part(
        &self,
        key: ObjectKey,
        context: &ArtifactEncryptionContextId,
        bytes: Bytes,
        content_type: &str,
        policy: &ArtifactEncryptionPolicy,
        journal: &dyn ChunkWriteJournal,
    ) -> Result<ObjectWriteReceipt, ObjectStorageError> {
        let digest = digest_bytes(&bytes);
        journal
            .before_write(&ChunkWriteIntent {
                key: key.clone(),
                context_id: context.clone(),
                digest: digest.clone(),
                size_bytes: bytes.len() as u64,
                content_type: content_type.into(),
            })
            .await?;
        let result = self
            .put_immutable(
                ImmutableObjectWrite {
                    key,
                    context_id: context.clone(),
                    content: bytes,
                    expected_digest: digest,
                    content_type: content_type.into(),
                },
                policy,
            )
            .await?;
        let receipt = result.receipt().clone();
        if self.managed_encryption_profile_id().is_some()
            && (receipt.version.as_deref().is_none_or(str::is_empty)
                || receipt.e_tag.as_deref().is_none_or(str::is_empty))
        {
            return Err(ObjectStorageError::VersionMismatch);
        }
        journal.after_write(&receipt).await?;
        Ok(receipt)
    }

    /// `None` requests the full file; a half-open byte range requests only its
    /// authenticated containing chunks. The supplied root is always pinned to
    /// its exact digest, size, version, ETag and encryption context.
    pub async fn open_chunked(
        &self,
        receipt: &ChunkedObjectReceipt,
        range: Option<Range<u64>>,
        policy: &ArtifactEncryptionPolicy,
    ) -> Result<ChunkedObjectReader, ObjectStorageError> {
        if receipt.size_bytes > self.max_streamed_object_bytes {
            return Err(ObjectStorageError::SizeLimitExceeded);
        }
        let bytes = self
            .read_receipt_bounded(&receipt.root, policy, INDEX_BYTES)
            .await?;
        let root: Root =
            serde_json::from_slice(&bytes).map_err(|_| ObjectStorageError::InvalidMetadata)?;
        if root.format != STORAGE_FORMAT
            || root.key != receipt.root.key.as_str()
            || root.context != receipt.root.context_id.as_digest().as_str()
            || root.digest != receipt.content_digest.as_str()
            || root.size != receipt.size_bytes
            || root.content_type != receipt.content_type
            || !valid_chunk_size(root.chunk_bytes)
            || root.pages.len() > MAX_PAGES
            || root.pages.len() as u64
                != chunk_count(root.size, root.chunk_bytes).div_ceil(PAGE_ENTRIES as u64)
        {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        for pointer in &root.pages {
            let p = pointer.receipt(&receipt.root.context_id)?;
            if p.size_bytes > INDEX_BYTES
                || p.key != part_key(&receipt.root.key, "pages", &p.digest)?
            {
                return Err(ObjectStorageError::InvalidMetadata);
            }
        }
        let full = range.is_none();
        let selected = range.unwrap_or(0..root.size);
        if selected.start > selected.end
            || selected.end > root.size
            || (!full && selected.start == selected.end)
        {
            return Err(ObjectStorageError::InvalidMetadata);
        }
        let next_chunk = selected.start / u64::from(root.chunk_bytes);
        Ok(ChunkedObjectReader {
            storage: self.clone(),
            policy: policy.clone(),
            receipt: receipt.clone(),
            root,
            selected,
            next_chunk,
            loaded_page: None,
            page: Vec::new(),
            hash: full.then(Sha256::new),
            finished: false,
            failed: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkedReadVerification {
    /// All bytes were consumed and the full logical digest was recomputed.
    WholeDigestVerified,
    /// Complete containing chunks were hashed against the pinned root. The
    /// full file digest was inherited from that root, not recomputed.
    AuthenticatedRange,
}

pub struct ChunkedObjectReader {
    storage: VerifiedObjectStorage,
    policy: ArtifactEncryptionPolicy,
    receipt: ChunkedObjectReceipt,
    root: Root,
    selected: Range<u64>,
    next_chunk: u64,
    loaded_page: Option<usize>,
    page: Vec<Pointer>,
    hash: Option<Sha256>,
    finished: bool,
    failed: bool,
}
impl ChunkedObjectReader {
    /// A verification result is available only after `next_chunk` returned
    /// `None` successfully. Dropping the reader early never verifies a file.
    pub fn verification(&self) -> Option<ChunkedReadVerification> {
        if !self.finished || self.failed {
            return None;
        }
        Some(if self.hash.is_some() {
            ChunkedReadVerification::WholeDigestVerified
        } else {
            ChunkedReadVerification::AuthenticatedRange
        })
    }
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, ObjectStorageError> {
        if self.failed {
            return Err(ObjectStorageError::DigestMismatch);
        }
        let result = self.next_inner().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn next_inner(&mut self) -> Result<Option<Bytes>, ObjectStorageError> {
        if self.finished {
            return Ok(None);
        }
        let start = self.next_chunk * u64::from(self.root.chunk_bytes);
        if start >= self.selected.end {
            if let Some(hash) = &self.hash
                && finish_hash(hash.clone()) != self.receipt.content_digest
            {
                return Err(ObjectStorageError::DigestMismatch);
            }
            self.finished = true;
            return Ok(None);
        }
        let page_index = (self.next_chunk / PAGE_ENTRIES as u64) as usize;
        if self.loaded_page != Some(page_index) {
            let p = self
                .root
                .pages
                .get(page_index)
                .ok_or(ObjectStorageError::InvalidMetadata)?;
            let bytes = self
                .storage
                .read_receipt_bounded(
                    &p.receipt(&self.receipt.root.context_id)?,
                    &self.policy,
                    INDEX_BYTES,
                )
                .await?;
            let page: Page =
                serde_json::from_slice(&bytes).map_err(|_| ObjectStorageError::InvalidMetadata)?;
            let total = chunk_count(self.root.size, self.root.chunk_bytes);
            let first = page_index as u64 * PAGE_ENTRIES as u64;
            if page.format != PAGE_FORMAT
                || page.first_chunk != first
                || page.chunks.len() as u64 != (total - first).min(PAGE_ENTRIES as u64)
            {
                return Err(ObjectStorageError::InvalidMetadata);
            }
            for (i, ptr) in page.chunks.iter().enumerate() {
                let r = ptr.receipt(&self.receipt.root.context_id)?;
                let offset = (first + i as u64) * u64::from(self.root.chunk_bytes);
                if r.key != part_key(&self.receipt.root.key, "chunks", &r.digest)?
                    || r.size_bytes
                        != (self.root.size - offset).min(u64::from(self.root.chunk_bytes))
                {
                    return Err(ObjectStorageError::InvalidMetadata);
                }
            }
            self.page = page.chunks;
            self.loaded_page = Some(page_index);
        }
        let ptr = &self.page[(self.next_chunk % PAGE_ENTRIES as u64) as usize];
        let bytes = self
            .storage
            .read_receipt_bounded(
                &ptr.receipt(&self.receipt.root.context_id)?,
                &self.policy,
                u64::from(self.root.chunk_bytes),
            )
            .await?;
        if let Some(hash) = &mut self.hash {
            hash.update(&bytes);
        }
        let from = self.selected.start.saturating_sub(start) as usize;
        let to = (self.selected.end - start).min(bytes.len() as u64) as usize;
        self.next_chunk += 1;
        Ok(Some(bytes.slice(from..to)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionRequirement, ObjectStoreSettings};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Journal(Mutex<Vec<ChunkWriteIntent>>, Mutex<Vec<ObjectWriteReceipt>>);
    #[async_trait]
    impl ChunkWriteJournal for Journal {
        async fn before_write(&self, i: &ChunkWriteIntent) -> Result<(), ObjectStorageError> {
            self.0.lock().unwrap().push(i.clone());
            Ok(())
        }
        async fn after_write(&self, r: &ObjectWriteReceipt) -> Result<(), ObjectStorageError> {
            self.1.lock().unwrap().push(r.clone());
            Ok(())
        }
    }
    fn setup() -> (VerifiedObjectStorage, ArtifactEncryptionPolicy) {
        (
            VerifiedObjectStorage::from_settings(ObjectStoreSettings::new("memory://")).unwrap(),
            ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext()),
        )
    }
    fn request(data: &[u8]) -> ChunkedObjectWrite {
        ChunkedObjectWrite {
            key: ObjectKey::parse("constructed/large.tiff").unwrap(),
            context_id: ArtifactEncryptionContextId::from_digest(digest_bytes(b"test-context")),
            expected_digest: digest_bytes(data),
            size_bytes: data.len() as u64,
            content_type: "image/tiff".into(),
            chunk_bytes: MIN_CHUNK,
        }
    }
    async fn collect(reader: &mut ChunkedObjectReader) -> Vec<u8> {
        let mut result = Vec::new();
        while let Some(chunk) = reader.next_chunk().await.unwrap() {
            result.extend_from_slice(&chunk);
        }
        result
    }
    #[tokio::test]
    async fn full_and_cross_chunk_ranges_preserve_distinct_verification() {
        let (storage, policy) = setup();
        let data: Vec<u8> = (0..MIN_CHUNK as usize * 3 + 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let journal = Journal::default();
        let receipt = storage
            .put_chunked(request(&data), &mut data.as_slice(), &policy, &journal)
            .await
            .unwrap();
        assert_ne!(receipt.root.digest, receipt.content_digest);
        assert_eq!(journal.0.lock().unwrap().len(), 6);
        assert_eq!(journal.1.lock().unwrap().len(), 6);
        let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
        fn assert_send_static<T: Send + 'static>(_: &T) {}
        assert_send_static(&reader);
        assert_eq!(reader.verification(), None);
        assert_eq!(collect(&mut reader).await, data);
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::WholeDigestVerified)
        );
        let range = 65530..131073;
        let mut reader = storage
            .open_chunked(&receipt, Some(range.clone()), &policy)
            .await
            .unwrap();
        assert_eq!(
            collect(&mut reader).await,
            data[range.start as usize..range.end as usize]
        );
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::AuthenticatedRange)
        );
        let replay = storage
            .put_chunked(request(&data), &mut data.as_slice(), &policy, &journal)
            .await
            .unwrap();
        assert!(replay.root.idempotent_replay);
        assert_eq!(replay.root.digest, receipt.root.digest);
    }
    #[tokio::test]
    async fn multiple_pages_and_empty_file_are_readable() {
        let (storage, policy) = setup();
        let data = vec![11; MIN_CHUNK as usize * (PAGE_ENTRIES + 1)];
        let receipt = storage
            .put_chunked(
                request(&data),
                &mut data.as_slice(),
                &policy,
                &Journal::default(),
            )
            .await
            .unwrap();
        let start = MIN_CHUNK as u64 * PAGE_ENTRIES as u64 - 3;
        let mut reader = storage
            .open_chunked(&receipt, Some(start..start + 9), &policy)
            .await
            .unwrap();
        assert_eq!(collect(&mut reader).await, vec![11; 9]);
        let mut empty = request(&[]);
        empty.key = ObjectKey::parse("constructed/empty").unwrap();
        let receipt = storage
            .put_chunked(empty, &mut &[][..], &policy, &Journal::default())
            .await
            .unwrap();
        let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
        assert_eq!(collect(&mut reader).await, Vec::<u8>::new());
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::WholeDigestVerified)
        );
    }
    #[tokio::test]
    async fn bad_digest_truncation_and_excess_never_publish_root() {
        for mode in 0..3 {
            let (storage, policy) = setup();
            let data = vec![3; MIN_CHUNK as usize + 1];
            let mut write = request(&data);
            match mode {
                0 => write.expected_digest = digest_bytes(b"wrong"),
                1 => write.size_bytes += 1,
                _ => write.size_bytes -= 1,
            }
            let key = write.key.clone();
            let context = write.context_id.clone();
            assert!(
                storage
                    .put_chunked(write, &mut data.as_slice(), &policy, &Journal::default())
                    .await
                    .is_err()
            );
            assert_eq!(
                storage
                    .read_verified(&key, &context, &digest_bytes(b"x"), None)
                    .await
                    .unwrap_err(),
                ObjectStorageError::NotFound
            );
        }
    }
    #[tokio::test]
    async fn root_pins_and_context_cannot_be_substituted() {
        let (storage, policy) = setup();
        let data = vec![7; MIN_CHUNK as usize + 5];
        let receipt = storage
            .put_chunked(
                request(&data),
                &mut data.as_slice(),
                &policy,
                &Journal::default(),
            )
            .await
            .unwrap();
        for mode in 0..5 {
            let mut other = receipt.clone();
            match mode {
                0 => other.root.e_tag = Some("wrong".into()),
                1 => other.content_digest = digest_bytes(b"wrong"),
                2 => {
                    other.root.context_id =
                        ArtifactEncryptionContextId::from_digest(digest_bytes(b"other"))
                }
                3 => other.root.version = Some("wrong".into()),
                _ => other.size_bytes += 1,
            }
            assert!(
                storage
                    .open_chunked(&other, Some(0..1), &policy)
                    .await
                    .is_err()
            );
        }
        assert!(
            storage
                .open_chunked(&receipt, Some(0..receipt.size_bytes + 1), &policy)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn retired_root_create_fences_late_manifest_commit() {
        let (storage, policy) = setup();
        let data = vec![7; MIN_CHUNK as usize + 5];
        let write = request(&data);
        let marker = Bytes::from_static(b"retired");
        storage
            .put_immutable(
                ImmutableObjectWrite {
                    key: write.key.clone(),
                    context_id: write.context_id.clone(),
                    content: marker.clone(),
                    expected_digest: digest_bytes(&marker),
                    content_type: "application/json".into(),
                },
                &policy,
            )
            .await
            .unwrap();
        assert_eq!(
            storage
                .put_chunked(write, &mut data.as_slice(), &policy, &Journal::default())
                .await
                .unwrap_err(),
            ObjectStorageError::ImmutableConflict
        );
    }
    #[tokio::test]
    async fn journal_failure_prevents_untracked_put() {
        struct Reject;
        #[async_trait]
        impl ChunkWriteJournal for Reject {
            async fn before_write(&self, _: &ChunkWriteIntent) -> Result<(), ObjectStorageError> {
                Err(ObjectStorageError::Backend)
            }
            async fn after_write(&self, _: &ObjectWriteReceipt) -> Result<(), ObjectStorageError> {
                panic!("no write allowed")
            }
        }
        let (storage, policy) = setup();
        let data = vec![1; 100];
        let write = request(&data);
        let part = part_key(&write.key, "chunks", &digest_bytes(&data)).unwrap();
        assert!(
            storage
                .put_chunked(write.clone(), &mut data.as_slice(), &policy, &Reject)
                .await
                .is_err()
        );
        assert_eq!(
            storage
                .read_verified(&part, &write.context_id, &digest_bytes(&data), None)
                .await
                .unwrap_err(),
            ObjectStorageError::NotFound
        );
    }

    #[tokio::test]
    async fn logical_limit_rejects_before_read_or_write() {
        let storage = VerifiedObjectStorage::from_settings(
            ObjectStoreSettings::new("memory://").with_max_streamed_object_bytes(8),
        )
        .unwrap();
        let policy =
            ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext());
        let journal = Journal::default();
        assert_eq!(
            storage
                .put_chunked(request(&[0; 9]), &mut &[][..], &policy, &journal)
                .await
                .unwrap_err(),
            ObjectStorageError::SizeLimitExceeded
        );
        assert!(journal.0.lock().unwrap().is_empty());
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn tampered_selected_chunk_fails_without_releasing_bytes() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/streaming-verification")
            .join(format!("tamper-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = VerifiedObjectStorage::from_settings(ObjectStoreSettings::new(
            url::Url::from_directory_path(&dir).unwrap().to_string(),
        ))
        .unwrap();
        let policy =
            ArtifactEncryptionPolicy::new(EncryptionRequirement::development_or_test_plaintext());
        let data = vec![7; MIN_CHUNK as usize + 5];
        let write = request(&data);
        let receipt = storage
            .put_chunked(
                write.clone(),
                &mut data.as_slice(),
                &policy,
                &Journal::default(),
            )
            .await
            .unwrap();
        let key = part_key(
            &write.key,
            "chunks",
            &digest_bytes(&data[..MIN_CHUNK as usize]),
        )
        .unwrap();
        let path = storage.location(&key, &write.context_id).unwrap();
        std::fs::write(dir.join(path.as_ref()), vec![8; MIN_CHUNK as usize]).unwrap();
        let mut reader = storage
            .open_chunked(&receipt, Some(1..10), &policy)
            .await
            .unwrap();
        assert_eq!(
            reader.next_chunk().await.unwrap_err(),
            ObjectStorageError::DigestMismatch
        );
        assert!(reader.verification().is_none());
        assert!(reader.next_chunk().await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn root_after_journal_failure_is_recoverable_from_prior_intent() {
        struct FailRoot {
            inner: Journal,
            root: ObjectKey,
        }
        #[async_trait]
        impl ChunkWriteJournal for FailRoot {
            async fn before_write(&self, i: &ChunkWriteIntent) -> Result<(), ObjectStorageError> {
                self.inner.before_write(i).await
            }
            async fn after_write(&self, r: &ObjectWriteReceipt) -> Result<(), ObjectStorageError> {
                if r.key == self.root {
                    return Err(ObjectStorageError::Backend);
                }
                self.inner.after_write(r).await
            }
        }
        let (storage, policy) = setup();
        let data = vec![9; MIN_CHUNK as usize + 3];
        let write = request(&data);
        let journal = FailRoot {
            inner: Journal::default(),
            root: write.key.clone(),
        };
        assert_eq!(
            storage
                .put_chunked(write.clone(), &mut data.as_slice(), &policy, &journal)
                .await
                .unwrap_err(),
            ObjectStorageError::Backend
        );
        assert!(
            journal
                .inner
                .1
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.key != write.key)
        );
        let intent = journal
            .inner
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.key == write.key)
            .unwrap()
            .clone();
        let recovered = storage
            .read_verified(&intent.key, &intent.context_id, &intent.digest, None)
            .await
            .unwrap();
        let receipt = ChunkedObjectReceipt {
            root: ObjectWriteReceipt {
                key: intent.key,
                context_id: intent.context_id,
                size_bytes: intent.size_bytes,
                digest: intent.digest,
                e_tag: recovered.e_tag,
                version: recovered.version,
                idempotent_replay: true,
            },
            content_digest: write.expected_digest,
            size_bytes: write.size_bytes,
            content_type: write.content_type,
        };
        let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
        assert_eq!(collect(&mut reader).await, data);
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::WholeDigestVerified)
        );
    }

    #[tokio::test]
    async fn cancelled_upload_retains_part_journal_without_root_and_early_reader_is_unverified() {
        struct PendingInput {
            remaining: usize,
        }
        impl AsyncRead for PendingInput {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.remaining == 0 {
                    return std::task::Poll::Pending;
                }
                let count = self.remaining.min(buf.remaining());
                buf.put_slice(&vec![4; count]);
                self.remaining -= count;
                std::task::Poll::Ready(Ok(()))
            }
        }
        struct NotifyingJournal {
            inner: Journal,
            notify: tokio::sync::Notify,
        }
        #[async_trait]
        impl ChunkWriteJournal for NotifyingJournal {
            async fn before_write(&self, i: &ChunkWriteIntent) -> Result<(), ObjectStorageError> {
                self.inner.before_write(i).await
            }
            async fn after_write(&self, r: &ObjectWriteReceipt) -> Result<(), ObjectStorageError> {
                self.inner.after_write(r).await?;
                self.notify.notify_one();
                Ok(())
            }
        }
        let (storage, policy) = setup();
        let data = vec![4; MIN_CHUNK as usize * 2];
        let write = request(&data);
        let journal = NotifyingJournal {
            inner: Journal::default(),
            notify: tokio::sync::Notify::new(),
        };
        let mut input = PendingInput {
            remaining: MIN_CHUNK as usize,
        };
        let mut upload =
            Box::pin(storage.put_chunked(write.clone(), &mut input, &policy, &journal));
        tokio::select! { _ = &mut upload => panic!("upload must remain pending"), _=journal.notify.notified()=>{} }
        drop(upload);
        assert_eq!(journal.inner.1.lock().unwrap().len(), 1);
        assert_eq!(
            storage
                .read_verified(&write.key, &write.context_id, &digest_bytes(b"x"), None)
                .await
                .unwrap_err(),
            ObjectStorageError::NotFound
        );
        let receipt = storage
            .put_chunked(write, &mut data.as_slice(), &policy, &Journal::default())
            .await
            .unwrap();
        let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
        assert!(reader.next_chunk().await.unwrap().is_some());
        assert_eq!(reader.verification(), None);
        drop(reader);
    }

    #[tokio::test]
    async fn malicious_page_indices_sizes_and_keys_fail_closed() {
        for mode in 0..4 {
            let (storage, policy) = setup();
            let data = vec![5; MIN_CHUNK as usize];
            let write = request(&data);
            let mut pointer = Pointer {
                key: part_key(&write.key, "chunks", &write.expected_digest)
                    .unwrap()
                    .as_str()
                    .into(),
                digest: write.expected_digest.to_string(),
                size: write.size_bytes,
                version: None,
                etag: None,
            };
            if mode == 1 {
                pointer.size = u64::MAX;
            }
            if mode == 2 {
                pointer.key = "foreign/unauthorized".into();
            }
            let page = Page {
                format: PAGE_FORMAT.into(),
                first_chunk: if mode == 0 { u64::MAX } else { 0 },
                chunks: vec![pointer],
            };
            let bytes = json_bytes(&page).unwrap();
            let digest = digest_bytes(&bytes);
            let p = storage
                .write_chunk_part(
                    part_key(&write.key, "pages", &digest).unwrap(),
                    &write.context_id,
                    bytes,
                    "application/json",
                    &policy,
                    &Journal::default(),
                )
                .await
                .unwrap();
            let root = Root {
                format: STORAGE_FORMAT.into(),
                key: write.key.as_str().into(),
                context: write.context_id.as_digest().to_string(),
                digest: write.expected_digest.to_string(),
                size: write.size_bytes,
                content_type: write.content_type.clone(),
                chunk_bytes: write.chunk_bytes,
                pages: if mode == 3 {
                    vec![]
                } else {
                    vec![Pointer::from_receipt(&p)]
                },
            };
            let root = storage
                .write_chunk_part(
                    write.key,
                    &write.context_id,
                    json_bytes(&root).unwrap(),
                    "application/json",
                    &policy,
                    &Journal::default(),
                )
                .await
                .unwrap();
            let receipt = ChunkedObjectReceipt {
                root,
                content_digest: write.expected_digest,
                size_bytes: write.size_bytes,
                content_type: write.content_type,
            };
            if mode == 3 {
                assert!(storage.open_chunked(&receipt, None, &policy).await.is_err());
            } else {
                let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
                assert_eq!(
                    reader.next_chunk().await.unwrap_err(),
                    ObjectStorageError::InvalidMetadata
                );
                assert_eq!(reader.verification(), None);
            }
        }
    }
}
