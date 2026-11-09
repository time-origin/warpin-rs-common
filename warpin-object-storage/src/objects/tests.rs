use super::*;
use object_store::{ObjectStoreExt, memory::InMemory};

#[tokio::test]
async fn persisted_reference_reads_exact_full_key_and_range() {
    let transport = Arc::new(InMemory::new());
    let storage = ObjectStorage::new("sample-bucket".into(), transport.clone()).unwrap();
    let key = Path::parse("tenants/a/projects/b/contexts/full/path/original.png").unwrap();
    let expected = Bytes::from_static(b"abcdefghijk");
    let reference = storage
        .put(&key, expected.clone(), "image/png".into())
        .await
        .unwrap();
    assert_eq!(reference.key, key.as_ref());
    assert_eq!(
        transport.head(&key).await.unwrap().size,
        expected.len() as u64
    );
    let json = serde_json::to_value(&reference).unwrap();
    let restored = serde_json::from_value::<ObjectReference>(json).unwrap();
    assert_eq!(storage.read(&restored).await.unwrap(), expected);
    assert_eq!(
        storage.read_range(&restored, 2..5).await.unwrap().as_ref(),
        b"cde"
    );
    let mut basename = restored.clone();
    basename.key = "original.png".into();
    assert_eq!(
        storage.read(&basename).await.unwrap_err(),
        ObjectStorageError::NotFound
    );
    let mut wrong_bucket = restored;
    wrong_bucket.bucket = "other-bucket".into();
    assert_eq!(
        storage.read(&wrong_bucket).await.unwrap_err(),
        ObjectStorageError::InvalidMetadata
    );
}

#[tokio::test]
async fn changed_object_is_not_returned_as_the_saved_reference() {
    let transport = Arc::new(InMemory::new());
    let storage = ObjectStorage::new("sample-bucket".into(), transport.clone()).unwrap();
    let key = Path::from("a/b/item.bin");
    let mut reference = storage
        .put(
            &key,
            Bytes::from_static(b"original"),
            "application/octet-stream".into(),
        )
        .await
        .unwrap();
    transport
        .put(&key, Bytes::from_static(b"replaced").into())
        .await
        .unwrap();
    assert_eq!(
        storage.read(&reference).await.unwrap_err(),
        ObjectStorageError::VersionMismatch
    );
    reference.etag = None;
    assert_eq!(
        storage.read(&reference).await.unwrap_err(),
        ObjectStorageError::DigestMismatch
    );
}
