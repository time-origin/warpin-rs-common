use super::*;

fn store() -> ObsObjectStore {
    ObsObjectStore::new(
        "https://obs.cn-southwest-2.myhuaweicloud.com",
        "sample-bucket".into(),
        ObsCredentials::new("constructed-ak".into(), "constructed-sk".into(), None).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap()
}

#[test]
fn complete_key_and_version_survive_request_and_signed_download() {
    let store = store();
    let key = Path::parse("tenants/a/projects/b/assets/c/original image.png").unwrap();
    let (url, resource) = store.target(&key, Some("version+one")).unwrap();
    assert_eq!(
        url.host_str(),
        Some("sample-bucket.obs.cn-southwest-2.myhuaweicloud.com")
    );
    assert_eq!(
        url.path(),
        "/tenants/a/projects/b/assets/c/original%20image.png"
    );
    assert_eq!(
        resource,
        "/sample-bucket/tenants/a/projects/b/assets/c/original%20image.png?versionId=version+one"
    );
    let signed = store
        .presign_get(
            &key,
            Some("version+one"),
            SystemTime::now() + Duration::from_secs(300),
        )
        .unwrap();
    let query: BTreeMap<_, _> = signed
        .url()
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(query["versionId"], "version+one");
    assert!(query.contains_key("Signature"));
    assert!(!format!("{signed:?}").contains("Signature"));
    assert!(!format!("{:?}", store.credentials).contains("constructed"));
}

#[test]
fn signed_headers_are_sensitive_and_do_not_use_amazon_protocol() {
    let store = store();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-obs-meta-warpin-sha256",
        HeaderValue::from_static("sample-digest"),
    );
    let authorization = store
        .authorization(
            &Method::PUT,
            "/sample-bucket/a/b.png",
            &headers,
            "Mon, 09 Nov 2026 10:00:00 GMT",
        )
        .unwrap();
    assert!(authorization.is_sensitive());
    assert!(
        authorization
            .to_str()
            .unwrap()
            .starts_with("OBS constructed-ak:")
    );
    assert!(!authorization.to_str().unwrap().contains("constructed-sk"));
}

#[test]
fn unified_factory_requires_injected_credentials_and_no_hidden_prefix() {
    let settings = crate::ObjectStoreSettings::new("obs://sample-bucket")
        .with_option(
            "obs_endpoint",
            "https://obs.cn-southwest-2.myhuaweicloud.com",
        )
        .with_option("obs_access_key_id", "constructed-ak")
        .with_option("obs_secret_access_key", "constructed-sk")
        .with_option("obs_request_timeout_seconds", "10");
    assert!(settings.clone().build_object_store().is_ok());
    let mut wrong = settings.clone();
    wrong.url.push_str("/hidden/prefix");
    assert!(wrong.build_object_store().is_err());
    let mut missing = settings;
    missing.options.remove("obs_secret_access_key");
    assert!(missing.build_object_store().is_err());
    assert!(
        crate::ObjectStoreSettings::new("memory://")
            .build_object_store()
            .is_ok()
    );
}

#[tokio::test]
async fn conditional_writes_fail_without_sending_a_request() {
    let store = store();
    let result = store
        .put_opts(
            &Path::from("a/b.bin"),
            Bytes::from_static(b"sample").into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(object_store::Error::NotSupported { .. })
    ));
}

#[tokio::test]
async fn actual_http_range_preserves_full_key_and_uses_real_response_range() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 1024];
        while !received.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            assert_ne!(n, 0);
            received.extend_from_slice(&buffer[..n]);
        }
        let received = String::from_utf8(received).unwrap().to_ascii_lowercase();
        assert!(received.starts_with("get /tenant/a/folder/sample.bin?versionid=v1 "));
        assert!(received.contains("range: bytes=2-4\r\n"));
        assert!(received.contains("authorization: obs constructed-ak:"));
        socket.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 2-4/6\r\nLast-Modified: Mon, 09 Nov 2026 10:00:00 GMT\r\nETag: \"sample-etag\"\r\nx-obs-version-id: v1\r\nConnection: close\r\n\r\ncde").await.unwrap();
    });
    let mut store = store();
    store.base = Url::parse(&format!("http://{address}/")).unwrap();
    let result = store
        .get_opts(
            &Path::from("tenant/a/folder/sample.bin"),
            GetOptions {
                range: Some((2..5).into()),
                version: Some("v1".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.meta.size, 6);
    assert_eq!(result.meta.version.as_deref(), Some("v1"));
    assert_eq!(result.bytes().await.unwrap(), Bytes::from_static(b"cde"));
    task.await.unwrap();
    // The ObjectStore convenience methods use the same implementation.
    let _trait_object: &dyn ObjectStore = &store;
}
