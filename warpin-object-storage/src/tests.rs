#[cfg(feature = "aws")]
use std::collections::BTreeMap;
#[cfg(feature = "aws")]
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use object_store::{Extensions, path::Path};
#[cfg(feature = "aws")]
use object_store::{GetOptions, ObjectStore, ObjectStoreExt, PutOptions};
#[cfg(any(feature = "aws", feature = "fs"))]
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

use super::*;
#[cfg(feature = "aws")]
use async_trait::async_trait;
#[cfg(feature = "aws")]
use object_store::aws::{AmazonS3, AmazonS3Builder, AmazonS3ConfigKey};
#[cfg(feature = "aws")]
use object_store::client::{
    ClientOptions, HttpClient, HttpConnector, HttpError, HttpRequest, HttpRequestBody,
    HttpResponse, HttpResponseBody, HttpService,
};
#[cfg(feature = "aws")]
use s3_adapter::{
    ConfiguredS3Encryption, NoRedirectReqwestConnector, ObservedEncryptionEvidence,
    map_managed_request_error, minio_kes_object_context_profile_id,
};
use s3_adapter::{
    ObservedBucketKeyState, S3_BUCKET_KEY_ENABLED_HEADER, actual_path_matches_expected,
    aws_s3_object_context_profile_id, observed_bucket_key_state, observed_s3_response,
};
use storage::read_options;
#[cfg(feature = "aws")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

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
        context_id: context_id(b"default-test-context"),
        content: Bytes::from_static(body),
        expected_digest: digest_bytes(body),
        content_type: "application/json".to_owned(),
    }
}

fn receipt(idempotent_replay: bool) -> ObjectWriteReceipt {
    ObjectWriteReceipt {
        key: ObjectKey::parse("objects/encrypted.json").expect("key"),
        context_id: context_id(b"default-test-context"),
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

fn context_id(label: &[u8]) -> ArtifactEncryptionContextId {
    ArtifactEncryptionContextId::from_digest(digest_bytes(label))
}

fn put_request(binding: WriteBinding) -> ObserverRequestBinding {
    let expected_location = Path::parse(binding.key().as_str()).expect("expected location");
    ObserverRequestBinding::put(binding, expected_location)
}

fn readback_request(binding: WriteBinding) -> ObserverRequestBinding {
    let expected_location = Path::parse(binding.key().as_str()).expect("expected location");
    ObserverRequestBinding::readback(
        binding,
        expected_location,
        Some("opaque-version".to_owned()),
    )
}

#[cfg(feature = "aws")]
const TEST_SIGV4_SIGNATURE: &str =
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
#[cfg(feature = "aws")]
const TEST_EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[cfg(feature = "aws")]
fn signed_artifact_request(
    binding: ObserverRequestBinding,
    uri: &str,
    region: &str,
) -> HttpRequest {
    let mut request = HttpRequest::new(HttpRequestBody::empty());
    *request.method_mut() = match binding.operation {
        ObservedOperation::Put => "PUT",
        ObservedOperation::Readback => "GET",
    }
    .parse()
    .expect("artifact method");
    *request.uri_mut() = uri.parse().expect("artifact URI");
    let parsed_uri = Url::parse(uri).expect("absolute artifact URI");
    let authority = &parsed_uri[url::Position::BeforeHost..url::Position::AfterPort];
    request
        .headers_mut()
        .insert("host", authority.parse().expect("Host header"));
    request.headers_mut().insert(
        "x-amz-date",
        "20260715T000000Z".parse().expect("date header"),
    );
    let content_sha = match binding.operation {
        ObservedOperation::Put => binding
            .binding
            .as_ref()
            .and_then(|binding| binding.content_digest().as_str().strip_prefix("sha256:"))
            .unwrap_or(TEST_EMPTY_SHA256_HEX),
        ObservedOperation::Readback => TEST_EMPTY_SHA256_HEX,
    };
    request.headers_mut().insert(
        "x-amz-content-sha256",
        content_sha.parse().expect("content SHA header"),
    );
    let signed_headers = match binding.operation {
        ObservedOperation::Put => {
            request.headers_mut().insert(
                "x-amz-server-side-encryption",
                "aws:kms".parse().expect("SSE header"),
            );
            request.headers_mut().insert(
                "x-amz-server-side-encryption-bucket-key-enabled",
                "false".parse().expect("bucket-key header"),
            );
            "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled"
        }
        ObservedOperation::Readback => "host;x-amz-content-sha256;x-amz-date",
    };
    request.headers_mut().insert(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential=TESTACCESS/20260715/{region}/s3/aws4_request, SignedHeaders={signed_headers}, Signature={}",
            TEST_SIGV4_SIGNATURE
        )
        .parse()
        .expect("authorization header"),
    );
    request.extensions_mut().insert(binding);
    request
}

#[cfg(feature = "aws")]
fn signed_put_request_with_kms_key(
    binding: ObserverRequestBinding,
    uri: &str,
    region: &str,
    key_id: &str,
) -> HttpRequest {
    let mut request = signed_artifact_request(binding, uri, region);
    request.headers_mut().insert(
        "x-amz-server-side-encryption-aws-kms-key-id",
        key_id.parse().expect("KMS key ID header"),
    );
    replace_test_authorization(
        &mut request,
        region,
        "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );
    request
}

#[cfg(feature = "aws")]
fn replace_test_authorization(
    request: &mut HttpRequest,
    region: &str,
    signed_headers: &str,
    signature: &str,
) {
    request.headers_mut().insert(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential=TESTACCESS/20260715/{region}/s3/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
        )
        .parse()
        .expect("authorization header"),
    );
}

#[cfg(feature = "aws")]
#[derive(Debug)]
struct CountingHttpResponseService {
    calls: Arc<AtomicUsize>,
    status: u16,
    headers: object_store::HeaderMap,
}

#[cfg(feature = "aws")]
#[async_trait]
impl HttpService for CountingHttpResponseService {
    async fn call(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut response = HttpResponse::new(HttpResponseBody::new(HttpRequestBody::empty()));
        *response.status_mut() = self.status.try_into().expect("response status");
        *response.headers_mut() = self.headers.clone();
        Ok(response)
    }
}

#[cfg(feature = "aws")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ActualRequestShape {
    method: String,
    uri: String,
    headers: BTreeMap<String, String>,
}

#[cfg(feature = "aws")]
#[derive(Debug)]
struct ActualCredentialShapeService {
    requests: Arc<Mutex<Vec<ActualRequestShape>>>,
}

#[cfg(feature = "aws")]
#[async_trait]
impl HttpService for ActualCredentialShapeService {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let uri = request.uri().to_string();
        let method = request.method().as_str().to_owned();
        let headers = request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        self.requests
            .lock()
            .expect("request-shape lock")
            .push(ActualRequestShape {
                method: method.clone(),
                uri: uri.clone(),
                headers,
            });

        let body = match uri.as_str() {
            "http://169.254.169.254/latest/api/token" => "actual-imdsv2-token".to_owned(),
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/" => {
                "Runtime_Role+=,.@-".to_owned()
            }
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/Runtime_Role+=,.@-"
            | "http://169.254.170.2/v2/credentials/task-123?role=runtime%2Fworker" => {
                r#"{"AccessKeyId":"ACTUALKEY","Code":"Success","Expiration":"2099-08-30T10:51:04Z","LastUpdated":"2026-07-16T10:21:04Z","SecretAccessKey":"ACTUALSECRET","Token":"ACTUALTOKEN","Type":"AWS-HMAC"}"#.to_owned()
            }
            _ => String::new(),
        };
        let mut response = HttpResponse::new(HttpResponseBody::new(HttpRequestBody::from(body)));
        if uri.starts_with("https://") && method == "PUT" {
            response
                .headers_mut()
                .insert("etag", "\"actual-etag\"".parse().expect("ETag response"));
        } else if uri.starts_with("https://") && method == "GET" {
            response
                .headers_mut()
                .insert("content-length", "0".parse().expect("content length"));
        }
        Ok(response)
    }
}

#[cfg(feature = "aws")]
#[derive(Clone, Debug)]
struct ActualObjectStoreShapeConnector {
    configured: ConfiguredS3Encryption,
    inner: HttpClient,
}

#[cfg(feature = "aws")]
impl HttpConnector for ActualObjectStoreShapeConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(
            self.configured.observer_service(self.inner.clone()),
        ))
    }
}

#[cfg(feature = "aws")]
fn actual_object_store_with_observer(
    url: &Url,
    options: &BTreeMap<String, String>,
    configured: ConfiguredS3Encryption,
    inner: HttpClient,
) -> AmazonS3 {
    let mut builder = AmazonS3Builder::new()
        .with_url(url.as_str())
        .with_http_connector(ActualObjectStoreShapeConnector { configured, inner });
    for (key, value) in options {
        builder = builder.with_config(
            key.parse::<AmazonS3ConfigKey>()
                .expect("reviewed S3 configuration key"),
            value,
        );
    }
    builder.build().expect("actual object_store S3 client")
}

#[test]
fn managed_requirement_has_a_required_provider_neutral_context() {
    let profile_id = ManagedEncryptionProfileId::from_digest(digest_bytes(b"profile"));
    let context_id = context_id(b"context-a");
    let requirement = EncryptionRequirement::managed(
        profile_id.clone(),
        context_id.clone(),
        Some(typed_key_identity_fingerprint()),
    );

    assert_eq!(
        requirement.view(),
        EncryptionRequirementView::Managed {
            profile_id: &profile_id,
            context_id: &context_id,
            expected_observed_key_identity_fingerprint: Some(&typed_key_identity_fingerprint(),),
        }
    );
}

#[test]
fn context_ids_derive_distinct_physical_locations_for_the_same_logical_key() {
    let storage = storage(1_024);
    let key = ObjectKey::parse("objects/same.json").expect("key");
    let context_a = context_id(b"context-a");
    let context_b = context_id(b"context-b");

    let location_a = storage.location(&key, &context_a).expect("location A");
    let location_b = storage.location(&key, &context_b).expect("location B");
    assert_ne!(location_a, location_b);
    assert!(location_a.as_ref().contains("/contexts/sha256="));
    assert!(location_a.as_ref().ends_with("/objects/same.json"));
}

#[test]
fn observed_paths_match_only_complete_expected_segments() {
    let expected = Path::parse(
            "prefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/a b.json",
        )
        .expect("expected path");

    assert!(actual_path_matches_expected(
        "/prefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/a%20b.json",
        &expected,
    ));
    assert!(!actual_path_matches_expected(
        "/bucket/prefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/a%20b.json",
        &expected,
    ));
    assert!(!actual_path_matches_expected(
        "/bucket/evilprefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/a%20b.json",
        &expected,
    ));
    assert!(!actual_path_matches_expected(
        "/bucket/prefix/contexts/sha256=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/a%20b.json",
        &expected,
    ));
}

#[test]
fn observer_emits_no_evidence_for_a_different_context_path() {
    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let expected = Path::parse(
            "contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted.json",
        )
        .expect("expected context path");
    let request = ObserverRequestBinding::readback(binding, expected, receipt.version.clone());
    let headers = sse_kms_headers(
        receipt.e_tag.as_deref(),
        receipt.version.as_deref(),
        "kms-key-one",
    );

    assert!(
            observed_s3_response(
                &request,
                "GET",
                "/bucket/contexts/sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/objects/encrypted.json",
                &headers,
            )
            .is_none()
        );
}

#[cfg(feature = "aws")]
fn exact_target_options(region: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("aws_region".to_owned(), region.to_owned()),
        (
            "aws_server_side_encryption".to_owned(),
            "aws:kms".to_owned(),
        ),
        ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
    ])
}

#[cfg(feature = "aws")]
fn with_credential_options(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut options = exact_target_options("us-east-1");
    options.extend(
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    options
}

#[cfg(feature = "aws")]
fn credential_token_file(label: &str, token: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "warpin-object-storage-{label}-{}-{nonce}.token",
        std::process::id()
    ));
    fs::write(&path, token).expect("credential token fixture");
    path
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_credentials_require_one_complete_mutually_exclusive_mode() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for options in [
        with_credential_options(&[("aws_access_key_id", "access-only")]),
        with_credential_options(&[("aws_secret_access_key", "secret-only")]),
        with_credential_options(&[("aws_session_token", "token-only")]),
        with_credential_options(&[
            ("aws_access_key_id", "access"),
            ("aws_secret_access_key", "secret"),
            (
                "aws_container_credentials_relative_uri",
                "/v2/credentials/task",
            ),
        ]),
        with_credential_options(&[(
            "aws_container_credentials_full_uri",
            "http://169.254.170.23/v1/credentials",
        )]),
        with_credential_options(&[(
            "aws_container_authorization_token_file",
            "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token",
        )]),
        with_credential_options(&[(
            "aws_web_identity_token_file",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        )]),
        with_credential_options(&[("aws_role_arn", "arn:aws:iam::123456789012:role/runtime")]),
        with_credential_options(&[(
            "aws_endpoint_url_sts",
            "https://sts.us-east-1.amazonaws.com",
        )]),
    ] {
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration)
        );
    }

    let static_pair = with_credential_options(&[
        ("aws_access_key_id", "access"),
        ("aws_secret_access_key", "secret"),
        ("aws_session_token", "session"),
    ]);
    assert!(ConfiguredS3Encryption::from_options(&url, &static_pair, None, None).is_ok());
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_rejects_every_removed_credential_surface_even_when_complete() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let token = credential_token_file("removed-modes", b"opaque-token");
    let token = token.to_str().expect("UTF-8 token path");

    let rejected = [
        with_credential_options(&[
            (
                "aws_container_credentials_full_uri",
                "http://169.254.170.23/v1/credentials",
            ),
            ("aws_container_authorization_token_file", token),
        ]),
        with_credential_options(&[
            (
                "container_credentials_full_uri",
                "http://169.254.170.23/v1/credentials",
            ),
            ("container_authorization_token_file", token),
        ]),
        with_credential_options(&[
            ("aws_web_identity_token_file", token),
            ("aws_role_arn", "arn:aws:iam::123456789012:role/runtime"),
        ]),
        with_credential_options(&[
            ("web_identity_token_file", token),
            ("role_arn", "arn:aws:iam::123456789012:role/runtime"),
        ]),
        with_credential_options(&[
            ("aws_web_identity_token_file", token),
            ("aws_role_arn", "arn:aws:iam::123456789012:role/runtime"),
            ("aws_role_session_name", "runtime-session"),
        ]),
        with_credential_options(&[
            ("web_identity_token_file", token),
            ("role_arn", "arn:aws:iam::123456789012:role/runtime"),
            ("role_session_name", "runtime-session"),
        ]),
        with_credential_options(&[
            ("aws_web_identity_token_file", token),
            ("aws_role_arn", "arn:aws:iam::123456789012:role/runtime"),
            (
                "aws_endpoint_url_sts",
                "https://sts.us-east-1.amazonaws.com",
            ),
        ]),
        with_credential_options(&[
            ("web_identity_token_file", token),
            ("role_arn", "arn:aws:iam::123456789012:role/runtime"),
            ("endpoint_url_sts", "https://sts.us-east-1.amazonaws.com"),
        ]),
    ];

    for options in rejected {
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration)
        );
    }

    fs::remove_file(token).expect("remove removed-mode token fixture");
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_imds_is_exact_link_local_and_v2_only_for_every_alias() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for (key, value) in [
        ("aws_imdsv1_fallback", "true"),
        ("imdsv1_fallback", "true"),
        ("aws_imdsv1_fallback", "TRUE"),
        ("imdsv1_fallback", "enabled"),
    ] {
        let options = with_credential_options(&[(key, value)]);
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "IMDSv1 alias must fail closed: {key}={value}"
        );
    }
    for endpoint in [
        "http://127.0.0.1",
        "http://169.254.169.254.evil.example",
        "https://169.254.169.254",
        "http://169.254.169.254@evil.example",
        "http://169.254.169.254/latest",
    ] {
        let options = with_credential_options(&[("aws_metadata_endpoint", endpoint)]);
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "nonstandard metadata endpoint must fail closed"
        );
    }

    for options in [
        with_credential_options(&[("aws_imdsv1_fallback", "false")]),
        with_credential_options(&[("aws_metadata_endpoint", "http://169.254.169.254")]),
    ] {
        assert!(ConfiguredS3Encryption::from_options(&url, &options, None, None).is_ok());
    }
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_rejects_credential_target_aliases_before_store_construction() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for relative_uri in [
        "v2/credentials/task",
        "//@evil.example/credentials",
        "/v2/credentials/task#fragment",
        "/v2/../credentials/task",
        "/v2/credentials/%2e%2e/task",
    ] {
        let options =
            with_credential_options(&[("aws_container_credentials_relative_uri", relative_uri)]);
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "malicious ECS relative URI must fail closed"
        );
    }
    for relative_uri in [
        "/v2/credentials/task",
        "/v2/credentials/task?role=runtime%2Fworker",
    ] {
        let options =
            with_credential_options(&[("aws_container_credentials_relative_uri", relative_uri)]);
        assert!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None).is_ok(),
            "AWS ECS relative URI shape must remain supported"
        );
    }
    for full_uri in [
        "http://evil.example/v1/credentials",
        "http://169.254.170.23@evil.example/v1/credentials",
        "https://credentials.internal.example/v1/credentials",
        "http://169.254.170.23/v1/credentials?token=secret",
        "http://169.254.170.23/v1/credentials#fragment",
    ] {
        let options = with_credential_options(&[
            ("aws_container_credentials_full_uri", full_uri),
            (
                "aws_container_authorization_token_file",
                "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token",
            ),
        ]);
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "untrusted EKS credential target must fail closed"
        );
    }
    let custom_sts = with_credential_options(&[
        (
            "aws_web_identity_token_file",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        ),
        ("aws_role_arn", "arn:aws:iam::123456789012:role/runtime"),
        ("aws_endpoint_url_sts", "https://sts.evil.example"),
    ]);
    assert_eq!(
        ConfiguredS3Encryption::from_options(&url, &custom_sts, None, None),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[cfg(feature = "aws")]
#[test]
fn native_aws_path_style_target_is_exact_and_percent_canonical() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("native AWS configuration");
    let binding = WriteBinding::new(&receipt(false));
    let expected_location = Path::parse(
        "private-prefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted@v1.json",
    )
    .expect("expected location");
    let request = ObserverRequestBinding::put(binding, expected_location);
    let exact = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json";

    assert!(
        configured
            .verify_request_target(&request, "PUT", exact)
            .is_ok()
    );
    for wrong in [
        "http://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://evil.example/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://s3.eu-west-1.amazonaws.com/extra/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://s3.eu-west-1.amazonaws.com/other-bucket/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256%3daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted%40v1.json",
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/encrypted@v1.json",
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/contexts/sha256%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/objects/%65ncrypted%40v1.json",
    ] {
        assert!(
            configured
                .verify_request_target(&request, "PUT", wrong)
                .is_err(),
            "non-exact target must fail"
        );
    }
}

#[cfg(feature = "aws")]
#[test]
fn native_aws_virtual_hosted_target_is_exact() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let mut options = exact_target_options("ap-southeast-2");
    options.insert(
        "aws_virtual_hosted_style_request".to_owned(),
        "true".to_owned(),
    );
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("native AWS virtual-hosted configuration");
    let expected_location = Path::parse("private-prefix/objects/encrypted.json").expect("path");
    let request =
        ObserverRequestBinding::put(WriteBinding::new(&receipt(false)), expected_location);

    assert!(
        configured
            .verify_request_target(
                &request,
                "PUT",
                "https://tenant-artifacts.s3.ap-southeast-2.amazonaws.com/private-prefix/objects/encrypted.json",
            )
            .is_ok()
    );
    assert!(
        configured
            .verify_request_target(
                &request,
                "PUT",
                "https://s3.ap-southeast-2.amazonaws.com/tenant-artifacts/private-prefix/objects/encrypted.json",
            )
            .is_err()
    );
}

#[cfg(feature = "aws")]
#[test]
fn minio_target_requires_exact_https_path_style_endpoint() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let mut options = exact_target_options("us-east-1");
    options.insert(
        "aws_endpoint".to_owned(),
        "https://minio.internal.example:9443/api".to_owned(),
    );
    let configured = ConfiguredS3Encryption::from_options(
        &url,
        &options,
        Some(minio_kes_object_context_profile_id()),
        None,
    )
    .expect("MinIO path-style configuration");
    let expected_location = Path::parse("private-prefix/objects/encrypted.json").expect("path");
    let request =
        ObserverRequestBinding::put(WriteBinding::new(&receipt(false)), expected_location);

    assert!(
        configured
            .verify_request_target(
                &request,
                "PUT",
                "https://minio.internal.example:9443/api/tenant-artifacts/private-prefix/objects/encrypted.json",
            )
            .is_ok()
    );
    assert!(
        configured
            .verify_request_target(
                &request,
                "PUT",
                "https://tenant-artifacts.minio.internal.example:9443/api/private-prefix/objects/encrypted.json",
            )
            .is_err()
    );

    options.insert(
        "aws_virtual_hosted_style_request".to_owned(),
        "true".to_owned(),
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &url,
            &options,
            Some(minio_kes_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn minio_sigv4_host_requires_the_exact_nondefault_authority_port() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let mut options = exact_target_options("us-east-1");
    options.insert(
        "aws_endpoint".to_owned(),
        "https://minio.internal.example:9443/api".to_owned(),
    );
    let configured = ConfiguredS3Encryption::from_options(
        &url,
        &options,
        Some(minio_kes_object_context_profile_id()),
        None,
    )
    .expect("MinIO path-style configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let uri = "https://minio.internal.example:9443/api/tenant-artifacts/private-prefix/objects/encrypted.json";
    let binding = || {
        ObserverRequestBinding::put(
            WriteBinding::new(&receipt(false)),
            Path::parse("private-prefix/objects/encrypted.json").expect("path"),
        )
    };

    service
        .call(signed_artifact_request(binding(), uri, "us-east-1"))
        .await
        .expect("exact nondefault Host port");

    let mut missing_port = signed_artifact_request(binding(), uri, "us-east-1");
    missing_port.headers_mut().insert(
        "host",
        "minio.internal.example".parse().expect("missing-port Host"),
    );
    assert!(service.call(missing_port).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "aws")]
#[test]
fn readback_target_allows_one_canonical_exact_version_query() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("native AWS configuration");
    let mut receipt = receipt(false);
    receipt.version = Some("opaque version+/=".to_owned());
    let location = Path::parse("private-prefix/objects/encrypted.json").expect("path");
    let request = ObserverRequestBinding::readback(
        WriteBinding::new(&receipt),
        location,
        receipt.version.clone(),
    );
    let base =
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/private-prefix/objects/encrypted.json";

    assert!(
        configured
            .verify_request_target(
                &request,
                "GET",
                &format!("{base}?versionId=opaque+version%2B%2F%3D"),
            )
            .is_ok()
    );
    for wrong in [
        base.to_owned(),
        format!("{base}?versionId=wrong"),
        format!("{base}?versionId=opaque+version%2B%2F%3D&versionId=second"),
        format!("{base}?versionId=%6Fpaque+version%2B%2F%3D"),
        format!("{base}?unexpected=value"),
    ] {
        assert!(
            configured
                .verify_request_target(&request, "GET", &wrong)
                .is_err(),
            "non-canonical or non-unique version query must fail"
        );
    }
}

#[cfg(feature = "aws")]
#[test]
fn normalized_s3_configuration_aliases_cannot_override_each_other() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let duplicate_cases = [
        ("aws_region", "region", "us-east-1", "eu-west-1"),
        (
            "aws_virtual_hosted_style_request",
            "virtual_hosted_style_request",
            "false",
            "true",
        ),
        ("allow_http", "aws_allow_http", "false", "true"),
        (
            "allow_invalid_certificates",
            "aws_allow_invalid_certificates",
            "false",
            "true",
        ),
        ("aws_skip_signature", "skip_signature", "false", "true"),
        (
            "aws_server_side_encryption",
            "server_side_encryption",
            "aws:kms",
            "AES256",
        ),
    ];
    for (first_key, second_key, first_value, second_value) in duplicate_cases {
        let mut options = exact_target_options("us-east-1");
        options.remove("aws_region");
        options.remove("aws_server_side_encryption");
        options.insert(first_key.to_owned(), first_value.to_owned());
        options.insert(second_key.to_owned(), second_value.to_owned());
        if first_key != "aws_server_side_encryption" {
            options.insert(
                "aws_server_side_encryption".to_owned(),
                "aws:kms".to_owned(),
            );
        }
        if first_key != "aws_region" {
            options.insert("aws_region".to_owned(), "us-east-1".to_owned());
        }
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "normalized duplicate aliases must fail"
        );
    }

    let mut endpoint_aliases = exact_target_options("us-east-1");
    endpoint_aliases.insert(
        "aws_endpoint".to_owned(),
        "https://minio-one.example".to_owned(),
    );
    endpoint_aliases.insert(
        "aws_endpoint_url_s3".to_owned(),
        "https://minio-two.example".to_owned(),
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &url,
            &endpoint_aliases,
            Some(minio_kes_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_transport_rejects_insecure_or_ambiguous_configuration_before_io() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for (key, value) in [
        ("allow_http", "true"),
        ("aws_allow_http", "true"),
        ("allow_invalid_certificates", "true"),
        ("aws_allow_invalid_certificates", "true"),
        ("aws_skip_signature", "true"),
        ("skip_signature", "true"),
        ("aws_bucket", "other-bucket"),
        ("bucket", "other-bucket"),
    ] {
        let mut options = exact_target_options("us-east-1");
        options.insert(key.to_owned(), value.to_owned());
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "insecure or ambiguous managed configuration must fail"
        );
    }

    let mut http_endpoint = exact_target_options("us-east-1");
    http_endpoint.insert(
        "aws_endpoint".to_owned(),
        "http://minio.internal.example:9000".to_owned(),
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &url,
            &http_endpoint,
            Some(minio_kes_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );

    let missing_region = BTreeMap::from([
        (
            "aws_server_side_encryption".to_owned(),
            "aws:kms".to_owned(),
        ),
        ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
    ]);
    assert_eq!(
        ConfiguredS3Encryption::from_options(&url, &missing_region, None, None),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn managed_http_connector_never_follows_redirects() {
    for (status, reason) in [
        (301, "Moved Permanently"),
        (302, "Found"),
        (307, "Temporary Redirect"),
        (308, "Permanent Redirect"),
    ] {
        for cross_authority in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind redirect test server");
            let address = listener.local_addr().expect("server address");
            let request_count = Arc::new(AtomicUsize::new(0));
            let server_count = Arc::clone(&request_count);
            let location = if cross_authority {
                "http://127.0.0.1:9/final".to_owned()
            } else {
                "/final".to_owned()
            };
            let server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await.expect("first request");
                let mut request = [0_u8; 2048];
                let _ = first.read(&mut request).await.expect("read first request");
                server_count.fetch_add(1, Ordering::SeqCst);
                first
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} {reason}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("write redirect");
                if let Ok(Ok((mut second, _))) =
                    timeout(Duration::from_millis(250), listener.accept()).await
                {
                    let _ = second
                        .read(&mut request)
                        .await
                        .expect("read second request");
                    server_count.fetch_add(1, Ordering::SeqCst);
                }
            });

            let client = NoRedirectReqwestConnector::default()
                .connect(
                    &object_store::ClientOptions::new()
                        .with_allow_http(true)
                        .with_config(
                            object_store::client::ClientConfigKey::RandomizeAddresses,
                            "false",
                        ),
                )
                .expect("test HTTP client");
            let mut request = HttpRequest::new(HttpRequestBody::empty());
            *request.method_mut() = "GET".parse().expect("GET method");
            *request.uri_mut() = format!("http://{address}/start")
                .parse()
                .expect("request URI");
            let response = client.execute(request).await.expect("redirect response");
            server.await.expect("server task");

            assert_eq!(response.status(), status);
            assert_eq!(request_count.load(Ordering::SeqCst), 1);
        }
    }
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn managed_http_connector_preserves_default_headers() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind header test server");
    let address = listener.local_addr().expect("server address");
    let server = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.expect("request");
        let mut request = [0_u8; 4096];
        let bytes = connection.read(&mut request).await.expect("read request");
        let request = String::from_utf8_lossy(&request[..bytes]).into_owned();
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("write response");
        request
    });
    let mut headers = object_store::HeaderMap::new();
    headers.insert(
        "x-managed-default",
        "present".parse().expect("header value"),
    );
    let options = object_store::ClientOptions::new()
        .with_allow_http(true)
        .with_default_headers(headers)
        .with_config(
            object_store::client::ClientConfigKey::RandomizeAddresses,
            "false",
        );
    let client = NoRedirectReqwestConnector::default()
        .connect(&options)
        .expect("test HTTP client");
    let mut request = HttpRequest::new(HttpRequestBody::empty());
    *request.method_mut() = "GET".parse().expect("GET method");
    *request.uri_mut() = format!("http://{address}/headers")
        .parse()
        .expect("request URI");
    client.execute(request).await.expect("header response");
    let received = server.await.expect("server task");

    assert!(
        received
            .to_ascii_lowercase()
            .contains("x-managed-default: present")
    );
}

#[cfg(feature = "aws")]
#[test]
fn managed_s3_configuration_rejects_unreviewed_security_options() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for (key, value) in [
        ("aws_unsigned_payload", "true"),
        ("aws_checksum_algorithm", "sha256"),
        ("aws_sse_customer_key_base64", "opaque-secret"),
        ("aws_disable_tagging", "true"),
        ("aws_request_payer", "true"),
        ("disable_system_certificates", "true"),
        ("proxy_url", "https://proxy.internal.example"),
        ("proxy_ca_certificate", "opaque-certificate"),
        ("proxy_excludes", "storage.internal.example"),
    ] {
        let mut options = exact_target_options("us-east-1");
        options.insert(key.to_owned(), value.to_owned());
        assert_eq!(
            ConfiguredS3Encryption::from_options(&url, &options, None, None),
            Err(ObjectStorageError::InvalidConfiguration),
            "unreviewed managed option must fail closed: {key}"
        );
    }
}

#[test]
fn bucket_key_response_true_or_invalid_fails_object_context_binding() {
    for value in ["true", "TRUE", "invalid"] {
        let headers = sse_headers_with_bucket_key(
            "aws:kms",
            Some("opaque-etag"),
            Some("opaque-version"),
            Some("kms-key-one"),
            Some(value),
        );
        assert!(matches!(
            observed_bucket_key_state(&headers),
            ObservedBucketKeyState::Enabled | ObservedBucketKeyState::Invalid
        ));
    }
    assert_eq!(
        observed_bucket_key_state(&sse_headers_with_bucket_key(
            "aws:kms",
            None,
            None,
            None,
            Some("false"),
        )),
        ObservedBucketKeyState::Disabled
    );
    assert_eq!(
        observed_bucket_key_state(&object_store::HeaderMap::new()),
        ObservedBucketKeyState::Missing
    );
}

#[test]
fn final_get_with_enabled_or_invalid_bucket_key_cannot_sign_attestation() {
    for bucket_key_enabled in ["true", "invalid"] {
        let receipt = receipt(false);
        let binding = WriteBinding::new(&receipt);
        let evidence = observed_s3_response(
            &readback_request(binding.clone()),
            "GET",
            "/objects/encrypted.json",
            &sse_headers_with_bucket_key(
                "aws:kms",
                receipt.e_tag.as_deref(),
                receipt.version.as_deref(),
                Some("kms-key-one"),
                Some(bucket_key_enabled),
            ),
        )
        .expect("path-bound evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(&receipt, &binding, &evidence),
            Err(EncryptionPolicyError::ObjectContextBindingRequired)
        );
    }
}

#[test]
fn encryption_requirement_has_a_provider_neutral_typed_projection() {
    let profile_id = ManagedEncryptionProfileId::from_digest(digest_bytes(b"profile"));
    let context_id = context_id(b"projection-context");
    let expected_observed_key_identity_fingerprint = typed_key_identity_fingerprint();
    let requirement = EncryptionRequirement::managed(
        profile_id.clone(),
        context_id.clone(),
        Some(expected_observed_key_identity_fingerprint.clone()),
    );
    assert_eq!(
        requirement.view(),
        EncryptionRequirementView::Managed {
            profile_id: &profile_id,
            context_id: &context_id,
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
        context_id(b"default-test-context"),
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
async fn managed_policy_context_mismatch_fails_before_backend_selection_or_write() {
    let mut write = write("objects/context-mismatch.json", b"private");
    write.context_id = context_id(b"write-context");
    let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        ManagedEncryptionProfileId::from_digest(digest_bytes(b"managed-profile")),
        context_id(b"different-policy-context"),
        None,
    ));

    assert_eq!(
        storage(1_024).put_immutable(write, &policy).await,
        Err(ObjectStorageError::EncryptionPolicy(
            EncryptionPolicyError::ContextMismatch,
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
        EncryptionAttestationView::DevelopmentOrTestPlaintext {
            context_id: &context_id(b"default-test-context"),
        }
    );
}

#[test]
fn managed_evidence_is_bound_to_method_object_and_receipt() {
    let first_receipt = receipt(false);
    let first_binding = WriteBinding::new(&first_receipt);
    let evidence = observed_s3_response(
        &readback_request(first_binding.clone()),
        "GET",
        "/objects/encrypted.json",
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
        &put_request(first_binding.clone()),
        "PUT",
        "/objects/encrypted.json",
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

    let mut other_context_receipt = first_receipt.clone();
    other_context_receipt.context_id = context_id(b"other-context");
    let other_context_binding = WriteBinding::new(&other_context_receipt);
    let other_context_policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        aws_s3_object_context_profile_id(),
        other_context_receipt.context_id.clone(),
        Some(digest_bytes(b"kms-key-one")),
    ));
    assert_eq!(
        other_context_policy.verify_managed_evidence(
            &other_context_receipt,
            &other_context_binding,
            &evidence,
        ),
        Err(EncryptionPolicyError::EvidenceBindingMismatch)
    );

    let wrong_method = observed_s3_response(
        &put_request(first_binding.clone()),
        "GET",
        "/objects/encrypted.json",
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
            &readback_request(binding.clone()),
            "GET",
            "/objects/encrypted.json",
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
            &put_request(binding.clone()),
            "PUT",
            "/objects/encrypted.json",
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
            &readback_request(binding.clone()),
            "GET",
            "/objects/encrypted.json",
            &receipt_headers(receipt.e_tag.as_deref(), receipt.version.as_deref()),
        )
        .expect("weak final GET evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(&receipt, &binding, &weak_final_get),
            Err(EncryptionPolicyError::ManagedEncryptionRequired)
        );

        let mismatched_final_get = observed_s3_response(
            &readback_request(binding.clone()),
            "GET",
            "/objects/encrypted.json",
            &sse_kms_headers(
                Some("different-etag"),
                Some("different-version"),
                "kms-key-one",
            ),
        )
        .expect("mismatched final GET evidence");
        assert_eq!(
            managed_policy().verify_managed_evidence(&receipt, &binding, &mismatched_final_get,),
            Err(EncryptionPolicyError::EvidenceBindingMismatch)
        );
    }
}

#[test]
fn final_get_options_pin_exact_version_and_private_binding() {
    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let mut extensions = Extensions::new();
    extensions.insert(readback_request(binding.clone()));
    let options = read_options(receipt.version.as_deref(), extensions);

    assert_eq!(options.version.as_deref(), receipt.version.as_deref());
    assert_eq!(
        options.extensions.get::<ObserverRequestBinding>(),
        Some(&readback_request(binding))
    );
}

#[test]
fn missing_or_mismatched_s3_encryption_headers_fail_closed() {
    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let request = readback_request(binding.clone());

    let missing = observed_s3_response(
        &request,
        "GET",
        "/objects/encrypted.json",
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
        "/objects/encrypted.json",
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
            let mut response = HttpResponse::new(HttpResponseBody::new(HttpRequestBody::empty()));
            *response.headers_mut() = self.headers.clone();
            Ok(response)
        }
    }

    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let request_binding = readback_request(binding.clone());
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let service = configured.observer_service(HttpClient::new(SseKmsResponseService {
        headers: sse_kms_headers(
            receipt.e_tag.as_deref(),
            receipt.version.as_deref(),
            "kms-key-one",
        ),
    }));
    let request = signed_artifact_request(
        request_binding,
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version",
        "eu-west-1",
    );

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
#[tokio::test]
async fn observer_rejects_nonexact_or_unsigned_artifact_requests_before_io() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let receipt = receipt(false);

    let binding = readback_request(WriteBinding::new(&receipt));
    let mut unsigned = HttpRequest::new(HttpRequestBody::empty());
    *unsigned.method_mut() = "GET".parse().expect("GET method");
    *unsigned.uri_mut() = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version"
        .parse()
        .expect("request URI");
    unsigned.extensions_mut().insert(binding);
    let unsigned_error = service.call(unsigned).await.expect_err("unsigned request");
    assert_eq!(
        map_managed_request_error(&unsigned_error),
        Some(ObjectStorageError::RequestSignatureInvalid)
    );

    let wrong_target = signed_artifact_request(
        readback_request(WriteBinding::new(&receipt)),
        "https://evil.example/tenant-artifacts/objects/encrypted.json?versionId=opaque-version",
        "eu-west-1",
    );
    let wrong_target_error = service.call(wrong_target).await.expect_err("wrong target");
    assert_eq!(
        map_managed_request_error(&wrong_target_error),
        Some(ObjectStorageError::RequestTargetMismatch)
    );

    let wrong_scope = signed_artifact_request(
        readback_request(WriteBinding::new(&receipt)),
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version",
        "us-east-1",
    );
    let wrong_scope_error = service.call(wrong_scope).await.expect_err("wrong scope");
    assert_eq!(
        map_managed_request_error(&wrong_scope_error),
        Some(ObjectStorageError::RequestSignatureInvalid)
    );

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_rejects_artifact_signatures_that_do_not_cover_required_sse_shape() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let receipt = receipt(false);
    let mut weak_put = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json",
        "eu-west-1",
    );
    weak_put.headers_mut().insert(
        "x-amz-server-side-encryption",
        "aws:kms".parse().expect("SSE header"),
    );
    weak_put.headers_mut().insert(
        "x-amz-server-side-encryption-bucket-key-enabled",
        "false".parse().expect("bucket-key header"),
    );
    weak_put.headers_mut().insert(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential=TESTACCESS/20260715/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={}",
            TEST_SIGV4_SIGNATURE
        )
        .parse()
        .expect("weak authorization"),
    );

    let error = service
        .call(weak_put)
        .await
        .expect_err("unsigned SSE headers");
    assert_eq!(
        map_managed_request_error(&error),
        Some(ObjectStorageError::RequestSignatureInvalid)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_requires_exact_signed_put_sse_and_get_content_hash() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let mut options = exact_target_options("eu-west-1");
    options.insert("aws_sse_kms_key_id".to_owned(), "kms-key-one".to_owned());
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let receipt = receipt(false);
    let put_binding = || put_request(WriteBinding::new(&receipt));
    let put_uri = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json";

    service
        .call(signed_put_request_with_kms_key(
            put_binding(),
            put_uri,
            "eu-west-1",
            "kms-key-one",
        ))
        .await
        .expect("exact signed PUT SSE shape");

    let mut invalid_puts = Vec::new();
    let mut missing_algorithm =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    missing_algorithm
        .headers_mut()
        .remove("x-amz-server-side-encryption");
    invalid_puts.push(missing_algorithm);

    let mut wrong_algorithm =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    wrong_algorithm.headers_mut().insert(
        "x-amz-server-side-encryption",
        "AES256".parse().expect("wrong SSE header"),
    );
    invalid_puts.push(wrong_algorithm);

    let mut wrong_bucket_key =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    wrong_bucket_key.headers_mut().insert(
        "x-amz-server-side-encryption-bucket-key-enabled",
        "true".parse().expect("wrong bucket-key header"),
    );
    invalid_puts.push(wrong_bucket_key);

    let wrong_key =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "different-key");
    invalid_puts.push(wrong_key);

    let mut unsigned_key =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    replace_test_authorization(
        &mut unsigned_key,
        "eu-west-1",
        "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );
    invalid_puts.push(unsigned_key);

    let mut unsigned_bucket_key =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    replace_test_authorization(
        &mut unsigned_bucket_key,
        "eu-west-1",
        "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id",
        TEST_SIGV4_SIGNATURE,
    );
    invalid_puts.push(unsigned_bucket_key);

    let mut unsigned_content =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    replace_test_authorization(
        &mut unsigned_content,
        "eu-west-1",
        "host;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );
    invalid_puts.push(unsigned_content);

    let mut weak_content =
        signed_put_request_with_kms_key(put_binding(), put_uri, "eu-west-1", "kms-key-one");
    weak_content.headers_mut().insert(
        "x-amz-content-sha256",
        "UNSIGNED-PAYLOAD".parse().expect("weak content hash"),
    );
    invalid_puts.push(weak_content);

    for invalid in invalid_puts {
        assert!(service.call(invalid).await.is_err());
    }

    let get_uri = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version";
    service
        .call(signed_artifact_request(
            readback_request(WriteBinding::new(&receipt)),
            get_uri,
            "eu-west-1",
        ))
        .await
        .expect("exact signed GET");
    let mut unsigned_get = signed_artifact_request(
        readback_request(WriteBinding::new(&receipt)),
        get_uri,
        "eu-west-1",
    );
    replace_test_authorization(
        &mut unsigned_get,
        "eu-west-1",
        "host;x-amz-date",
        TEST_SIGV4_SIGNATURE,
    );
    assert!(service.call(unsigned_get).await.is_err());

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_rejects_host_digest_binding_and_kms_presence_forgery_before_io() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let receipt = receipt(false);
    let put_uri = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json";
    let get_uri = "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version";

    let mut missing_host = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    missing_host.headers_mut().remove("host");

    let mut conflicting_host = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    conflicting_host
        .headers_mut()
        .insert("host", "s3.evil.example".parse().expect("conflicting Host"));

    let mut random_put_digest = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    random_put_digest.headers_mut().insert(
        "x-amz-content-sha256",
        "4e8fb7a4fca2e6eb16bca3ad2c6ec3dbf7bf86f91cc7b16e05e37977134f8491"
            .parse()
            .expect("random content digest"),
    );

    let mut random_get_digest = signed_artifact_request(
        readback_request(WriteBinding::new(&receipt)),
        get_uri,
        "eu-west-1",
    );
    random_get_digest.headers_mut().insert(
        "x-amz-content-sha256",
        "4e8fb7a4fca2e6eb16bca3ad2c6ec3dbf7bf86f91cc7b16e05e37977134f8491"
            .parse()
            .expect("random content digest"),
    );

    let mut unexpected_kms_key = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    unexpected_kms_key.headers_mut().insert(
        "x-amz-server-side-encryption-aws-kms-key-id",
        "kms-key-one".parse().expect("unexpected KMS key"),
    );
    replace_test_authorization(
        &mut unexpected_kms_key,
        "eu-west-1",
        "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );

    let missing_binding = ObserverRequestBinding {
        binding: None,
        operation: ObservedOperation::Put,
        expected_location: Path::parse("objects/encrypted.json").expect("location"),
        expected_version: None,
    };
    let missing_binding = signed_artifact_request(missing_binding, put_uri, "eu-west-1");

    let mut nonexistent_signed_header = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    replace_test_authorization(
        &mut nonexistent_signed_header,
        "eu-west-1",
        "host;x-amz-content-sha256;x-amz-date;x-amz-meta-forged;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );

    let mut duplicate_authorization = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    duplicate_authorization.headers_mut().append(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential=TESTACCESS/20260715/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled, Signature={TEST_SIGV4_SIGNATURE}"
        )
        .parse()
        .expect("duplicate authorization"),
    );

    let mut duplicate_signed_name = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    replace_test_authorization(
        &mut duplicate_signed_name,
        "eu-west-1",
        "host;host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );

    let mut noncanonical_signed_name = signed_artifact_request(
        put_request(WriteBinding::new(&receipt)),
        put_uri,
        "eu-west-1",
    );
    replace_test_authorization(
        &mut noncanonical_signed_name,
        "eu-west-1",
        "Host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-bucket-key-enabled",
        TEST_SIGV4_SIGNATURE,
    );

    for forged in [
        missing_host,
        conflicting_host,
        random_put_digest,
        random_get_digest,
        unexpected_kms_key,
        missing_binding,
        nonexistent_signed_header,
        duplicate_authorization,
        duplicate_signed_name,
        noncanonical_signed_name,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
            calls: Arc::clone(&calls),
            status: 200,
            headers: object_store::HeaderMap::new(),
        }));
        assert!(service.call(forged).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn actual_object_store_artifact_requests_retain_exact_host_digest_and_kms_signature_shape() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let mut options = exact_target_options("eu-west-1");
    options.extend([
        ("aws_access_key_id".to_owned(), "ACTUALKEY".to_owned()),
        (
            "aws_secret_access_key".to_owned(),
            "ACTUALSECRET".to_owned(),
        ),
        ("aws_sse_kms_key_id".to_owned(), "kms-key-one".to_owned()),
    ]);
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("static managed S3 configuration");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let store = actual_object_store_with_observer(
        &url,
        &options,
        configured,
        HttpClient::new(ActualCredentialShapeService {
            requests: Arc::clone(&requests),
        }),
    );
    let receipt = receipt(false);
    let location = Path::parse("objects/encrypted.json").expect("location");
    let mut put_extensions = Extensions::new();
    put_extensions.insert(ObserverRequestBinding::put(
        WriteBinding::new(&receipt),
        location.clone(),
    ));

    store
        .put_opts(
            &location,
            Bytes::from_static(b"encrypted").into(),
            PutOptions {
                extensions: put_extensions,
                ..PutOptions::default()
            },
        )
        .await
        .expect("actual object_store signed PUT");

    let mut get_extensions = Extensions::new();
    get_extensions.insert(ObserverRequestBinding::read(location.clone(), None));
    store
        .get_opts(
            &location,
            GetOptions {
                extensions: get_extensions,
                ..GetOptions::default()
            },
        )
        .await
        .expect("actual object_store signed GET");

    let requests = requests.lock().expect("request-shape lock").clone();
    assert_eq!(requests.len(), 2);
    let expected_host = "s3.eu-west-1.amazonaws.com";
    let expected_put_sha = receipt
        .digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("typed digest prefix");
    assert_eq!(requests[0].method, "PUT");
    assert_eq!(requests[1].method, "GET");
    assert_eq!(
        requests[0].headers.get("host").map(String::as_str),
        Some(expected_host)
    );
    assert_eq!(
        requests[1].headers.get("host").map(String::as_str),
        Some(expected_host)
    );
    assert_eq!(
        requests[0]
            .headers
            .get("x-amz-content-sha256")
            .map(String::as_str),
        Some(expected_put_sha)
    );
    assert_eq!(
        requests[1]
            .headers
            .get("x-amz-content-sha256")
            .map(String::as_str),
        Some(TEST_EMPTY_SHA256_HEX)
    );
    assert_eq!(
        requests[0]
            .headers
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .map(String::as_str),
        Some("kms-key-one")
    );
    let put_authorization = requests[0]
        .headers
        .get("authorization")
        .expect("actual PUT authorization");
    assert!(put_authorization.contains("SignedHeaders="));
    assert!(put_authorization.contains("host"));
    assert!(put_authorization.contains("x-amz-content-sha256"));
    assert!(put_authorization.contains("x-amz-server-side-encryption-aws-kms-key-id"));
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_accepts_explicit_ordinary_read_binding_without_attestation_evidence() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: sse_kms_headers(None, Some("opaque-version"), "kms-key-one"),
    }));
    let binding = ObserverRequestBinding::read(
        Path::parse("objects/encrypted.json").expect("location"),
        Some("opaque-version".to_owned()),
    );
    let request = signed_artifact_request(
        binding,
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version",
        "eu-west-1",
    );

    let response = service.call(request).await.expect("ordinary exact GET");
    assert!(
        response
            .extensions()
            .get::<ObservedEncryptionEvidence>()
            .is_none()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_rejects_imdsv1_style_unbound_credential_requests_before_io() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let mut request = HttpRequest::new(HttpRequestBody::empty());
    *request.method_mut() = "GET".parse().expect("GET method");
    *request.uri_mut() = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        .parse()
        .expect("metadata URI");

    let error = service
        .call(request)
        .await
        .expect_err("IMDS request without a v2 token");
    assert_eq!(
        map_managed_request_error(&error),
        Some(ObjectStorageError::RequestTargetMismatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_rejects_all_unbound_requests_for_static_credentials() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let options = with_credential_options(&[
        ("aws_access_key_id", "access"),
        ("aws_secret_access_key", "secret"),
    ]);
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("static credential configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));
    let mut request = HttpRequest::new(HttpRequestBody::empty());
    *request.method_mut() = "GET".parse().expect("GET method");
    *request.uri_mut() = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        .parse()
        .expect("metadata URI");

    let error = service.call(request).await.expect_err("unbound request");
    assert_eq!(
        map_managed_request_error(&error),
        Some(ObjectStorageError::RequestTargetMismatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_allows_only_exact_imdsv2_request_shapes() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("us-east-1"), None, None)
            .expect("IMDSv2 credential configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));

    let mut token = HttpRequest::new(HttpRequestBody::empty());
    *token.method_mut() = "PUT".parse().expect("PUT method");
    *token.uri_mut() = "http://169.254.169.254/latest/api/token"
        .parse()
        .expect("token URI");
    token.headers_mut().insert(
        "x-aws-ec2-metadata-token-ttl-seconds",
        "600".parse().expect("TTL header"),
    );
    service.call(token).await.expect("exact token exchange");

    let mut role = HttpRequest::new(HttpRequestBody::empty());
    *role.method_mut() = "GET".parse().expect("GET method");
    *role.uri_mut() = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        .parse()
        .expect("role URI");
    role.headers_mut().insert(
        "x-aws-ec2-metadata-token",
        "opaque-imdsv2-token".parse().expect("token header"),
    );
    service.call(role).await.expect("exact role request");

    let mut credentials = HttpRequest::new(HttpRequestBody::empty());
    *credentials.method_mut() = "GET".parse().expect("GET method");
    *credentials.uri_mut() =
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/Runtime_Role+=,.@-"
            .parse()
            .expect("credentials URI");
    credentials.headers_mut().insert(
        "x-aws-ec2-metadata-token",
        "opaque-imdsv2-token".parse().expect("token header"),
    );
    service
        .call(credentials)
        .await
        .expect("exact one-segment IAM role-name request");

    for target in [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1/latest/api/token",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/role?leak=true",
    ] {
        let mut malicious = HttpRequest::new(HttpRequestBody::empty());
        *malicious.method_mut() = "GET".parse().expect("GET method");
        *malicious.uri_mut() = target.parse().expect("malicious URI");
        assert!(service.call(malicious).await.is_err());
    }
    for role_name in [
        "role/nested",
        "role:invalid",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let mut malicious = HttpRequest::new(HttpRequestBody::empty());
        *malicious.method_mut() = "GET".parse().expect("GET method");
        *malicious.uri_mut() =
            format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}")
                .parse()
                .expect("invalid role URI");
        malicious.headers_mut().insert(
            "x-aws-ec2-metadata-token",
            "opaque-imdsv2-token".parse().expect("token header"),
        );
        assert!(service.call(malicious).await.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn actual_object_store_imdsv2_provider_uses_only_the_frozen_three_request_shapes() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let options = exact_target_options("us-east-1");
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("IMDSv2 credential configuration");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let store = actual_object_store_with_observer(
        &url,
        &options,
        configured,
        HttpClient::new(ActualCredentialShapeService {
            requests: Arc::clone(&requests),
        }),
    );

    let _ = store
        .get(&Path::parse("objects/probe").expect("probe path"))
        .await;

    let requests = requests.lock().expect("request-shape lock").clone();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "PUT");
    assert_eq!(requests[0].uri, "http://169.254.169.254/latest/api/token");
    assert_eq!(
        requests[0]
            .headers
            .get("x-aws-ec2-metadata-token-ttl-seconds")
            .map(String::as_str),
        Some("600")
    );
    assert_eq!(requests[1].method, "GET");
    assert_eq!(
        requests[1].uri,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    );
    assert_eq!(
        requests[2].uri,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/Runtime_Role+=,.@-"
    );
    for request in &requests[1..] {
        assert_eq!(
            request
                .headers
                .get("x-aws-ec2-metadata-token")
                .map(String::as_str),
            Some("actual-imdsv2-token")
        );
        assert!(!request.headers.contains_key("authorization"));
    }
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_binds_ecs_method_authority_and_relative_path() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let options = with_credential_options(&[(
        "aws_container_credentials_relative_uri",
        "/v2/credentials/task-123",
    )]);
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("ECS credential configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 200,
        headers: object_store::HeaderMap::new(),
    }));

    let mut exact = HttpRequest::new(HttpRequestBody::empty());
    *exact.method_mut() = "GET".parse().expect("GET method");
    *exact.uri_mut() = "http://169.254.170.2/v2/credentials/task-123"
        .parse()
        .expect("ECS URI");
    service.call(exact).await.expect("exact ECS request");

    for target in [
        "http://169.254.170.2@evil.example/v2/credentials/task-123",
        "http://169.254.170.2/v2/credentials/task-123?secret=true",
        "http://169.254.170.23/v2/credentials/task-123",
    ] {
        let mut malicious = HttpRequest::new(HttpRequestBody::empty());
        *malicious.method_mut() = "GET".parse().expect("GET method");
        *malicious.uri_mut() = target.parse().expect("malicious URI");
        assert!(service.call(malicious).await.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn actual_object_store_ecs_provider_preserves_relative_query_at_fixed_authority() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let options = with_credential_options(&[(
        "aws_container_credentials_relative_uri",
        "/v2/credentials/task-123?role=runtime%2Fworker",
    )]);
    let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
        .expect("ECS credential configuration");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let store = actual_object_store_with_observer(
        &url,
        &options,
        configured,
        HttpClient::new(ActualCredentialShapeService {
            requests: Arc::clone(&requests),
        }),
    );

    let _ = store
        .get(&Path::parse("objects/probe").expect("probe path"))
        .await;

    let requests = requests.lock().expect("request-shape lock").clone();
    assert_eq!(
        requests,
        [ActualRequestShape {
            method: "GET".to_owned(),
            uri: "http://169.254.170.2/v2/credentials/task-123?role=runtime%2Fworker".to_owned(),
            headers: BTreeMap::new(),
        }]
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn observer_emits_no_evidence_for_redirect_responses() {
    let url = Url::parse("s3://tenant-artifacts").expect("S3 URL");
    let configured =
        ConfiguredS3Encryption::from_options(&url, &exact_target_options("eu-west-1"), None, None)
            .expect("managed S3 configuration");
    let calls = Arc::new(AtomicUsize::new(0));
    let receipt = receipt(false);
    let service = configured.observer_service(HttpClient::new(CountingHttpResponseService {
        calls: Arc::clone(&calls),
        status: 307,
        headers: sse_kms_headers(
            receipt.e_tag.as_deref(),
            receipt.version.as_deref(),
            "kms-key-one",
        ),
    }));
    let request = signed_artifact_request(
        readback_request(WriteBinding::new(&receipt)),
        "https://s3.eu-west-1.amazonaws.com/tenant-artifacts/objects/encrypted.json?versionId=opaque-version",
        "eu-west-1",
    );

    let response = service.call(request).await.expect("redirect response");
    assert_eq!(response.status(), 307);
    assert!(
        response
            .extensions()
            .get::<ObservedEncryptionEvidence>()
            .is_none()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "aws")]
#[test]
fn s3_configuration_preflight_rejects_plaintext_or_wrong_key_before_write_path() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let expected_canonical = digest_bytes(b"arn:aws:kms:my-first-key");
    let missing = ConfiguredS3Encryption::from_options(
        &url,
        &BTreeMap::from([("aws_region".to_owned(), "us-east-1".to_owned())]),
        None,
        None,
    )
    .expect("missing encryption is a valid observed configuration state");
    assert_eq!(
        managed_policy().verify_s3_configuration(&missing),
        Err(EncryptionPolicyError::ManagedEncryptionRequired)
    );

    let wrong_algorithm = ConfiguredS3Encryption::from_options(
        &url,
        &BTreeMap::from([
            ("aws_region".to_owned(), "us-east-1".to_owned()),
            ("aws_server_side_encryption".to_owned(), "AES256".to_owned()),
        ]),
        None,
        None,
    )
    .expect("supported storage option shape");
    assert_eq!(
        managed_policy().verify_s3_configuration(&wrong_algorithm),
        Err(EncryptionPolicyError::AlgorithmMismatch)
    );

    let wrong_key = ConfiguredS3Encryption::from_options(
        &url,
        &BTreeMap::from([
            ("aws_region".to_owned(), "us-east-1".to_owned()),
            (
                "aws_server_side_encryption".to_owned(),
                "aws:kms".to_owned(),
            ),
            ("aws_sse_kms_key_id".to_owned(), "my-first-key".to_owned()),
            ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
        ]),
        None,
        Some(digest_bytes(b"arn:aws:kms:different-key")),
    )
    .expect("supported storage option shape");
    assert_eq!(
        managed_policy().verify_s3_configuration(&wrong_key),
        Err(EncryptionPolicyError::KeyIdentityMismatch)
    );

    let exact = ConfiguredS3Encryption::from_options(
        &url,
        &BTreeMap::from([
            ("aws_region".to_owned(), "us-east-1".to_owned()),
            (
                "aws_server_side_encryption".to_owned(),
                "aws:kms".to_owned(),
            ),
            ("aws_sse_kms_key_id".to_owned(), "my-first-key".to_owned()),
            ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
        ]),
        None,
        Some(expected_canonical.clone()),
    )
    .expect("supported storage option shape");
    managed_policy_with_expected(Some(expected_canonical.clone()))
        .verify_s3_configuration(&exact)
        .expect("raw request locator is distinct from canonical observed identity");
    let wrong_profile = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        ManagedEncryptionProfileId::from_digest(digest_bytes(b"different-profile")),
        context_id(b"default-test-context"),
        Some(expected_canonical.clone()),
    ));
    assert_eq!(
        wrong_profile.verify_s3_configuration(&exact),
        Err(EncryptionPolicyError::PolicyBackendMismatch)
    );

    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let wrong_observed_key = observed_s3_response(
        &readback_request(binding),
        "GET",
        "/objects/encrypted.json",
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
        &readback_request(WriteBinding::new(&receipt)),
        "GET",
        "/objects/encrypted.json",
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
#[test]
fn s3_configuration_requires_explicitly_disabled_bucket_keys() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    for bucket_key_value in [None, Some("true"), Some("invalid")] {
        let mut options = BTreeMap::from([
            ("aws_region".to_owned(), "us-east-1".to_owned()),
            (
                "aws_server_side_encryption".to_owned(),
                "aws:kms".to_owned(),
            ),
        ]);
        if let Some(value) = bucket_key_value {
            options.insert("aws_sse_bucket_key_enabled".to_owned(), value.to_owned());
        }
        let configured = ConfiguredS3Encryption::from_options(&url, &options, None, None)
            .expect("configuration shape");
        assert_eq!(
            managed_policy_with_expected(None).verify_s3_configuration(&configured),
            Err(EncryptionPolicyError::ObjectContextBindingRequired)
        );
    }

    let configured = ConfiguredS3Encryption::from_options(
        &url,
        &BTreeMap::from([
            ("aws_region".to_owned(), "us-east-1".to_owned()),
            (
                "aws_server_side_encryption".to_owned(),
                "aws:kms".to_owned(),
            ),
            ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
        ]),
        None,
        None,
    )
    .expect("configuration shape");
    managed_policy_with_expected(None)
        .verify_s3_configuration(&configured)
        .expect("explicitly disabled bucket keys");
}

#[cfg(feature = "aws")]
#[test]
fn native_aws_and_minio_context_guarantees_use_distinct_reviewed_profiles() {
    let url = Url::parse("s3://tenant-artifacts/private-prefix").expect("S3 URL");
    let base_options = BTreeMap::from([
        ("aws_region".to_owned(), "us-east-1".to_owned()),
        (
            "aws_server_side_encryption".to_owned(),
            "aws:kms".to_owned(),
        ),
        ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
    ]);
    let native = ConfiguredS3Encryption::from_options(&url, &base_options, None, None)
        .expect("native AWS profile");
    assert_eq!(native.profile_id, aws_s3_object_context_profile_id());

    let mut custom_options = base_options.clone();
    custom_options.insert(
        "aws_endpoint".to_owned(),
        "https://minio.internal.example".to_owned(),
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(&url, &custom_options, None, None),
        Err(ObjectStorageError::InvalidConfiguration)
    );
    let minio_profile = minio_kes_object_context_profile_id();
    let minio = ConfiguredS3Encryption::from_options(
        &url,
        &custom_options,
        Some(minio_profile.clone()),
        None,
    )
    .expect("explicit reviewed MinIO/KES profile");
    assert_eq!(minio.profile_id, minio_profile);
    assert_ne!(minio.profile_id, native.profile_id);

    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &url,
            &base_options,
            Some(minio_kes_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &url,
            &custom_options,
            Some(aws_s3_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[cfg(feature = "aws")]
#[test]
fn minio_adapter_factory_avoids_an_opaque_profile_bootstrap_deadlock() {
    let settings = s3_adapter::with_minio_kes_object_context_profile(
        ObjectStoreSettings::new("s3://artifacts/private-prefix")
            .with_option("aws_endpoint", "https://minio.internal.example"),
    );
    assert_eq!(
        settings.managed_encryption_profile_id(),
        Some(&minio_kes_object_context_profile_id())
    );
    assert_eq!(
        settings
            .options
            .get("aws_sse_bucket_key_enabled")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        settings
            .options
            .get("aws_server_side_encryption")
            .map(String::as_str),
        Some("aws:kms")
    );
}

#[cfg(feature = "aws")]
#[test]
fn native_aws_adapter_factory_installs_object_context_safety_configuration() {
    let settings = s3_adapter::with_aws_s3_object_context_profile(ObjectStoreSettings::new(
        "s3://artifacts/private-prefix",
    ));
    assert_eq!(
        settings.managed_encryption_profile_id(),
        Some(&aws_s3_object_context_profile_id())
    );
    assert_eq!(
        settings
            .options
            .get("aws_sse_bucket_key_enabled")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        settings
            .options
            .get("aws_server_side_encryption")
            .map(String::as_str),
        Some("aws:kms")
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn public_s3_write_rejects_missing_managed_configuration_without_network_io() {
    let storage = VerifiedObjectStorage::from_settings(
        ObjectStoreSettings::new("s3://preflight-only-bucket/private-prefix")
            .with_option("aws_region", "us-east-1"),
    )
    .expect("S3 configuration builds without performing I/O");
    let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        storage
            .managed_encryption_profile_id()
            .expect("managed adapter profile")
            .clone(),
        context_id(b"default-test-context"),
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
            .with_option("aws_region", "us-east-1")
            .with_option("aws_server_side_encryption", "AES256"),
    )
    .expect("S3 configuration builds without performing I/O");
    let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        storage
            .managed_encryption_profile_id()
            .expect("managed adapter profile")
            .clone(),
        context_id(b"default-test-context"),
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
    sse_headers_with_bucket_key(algorithm, e_tag, version, key_identity, None)
}

fn sse_headers_with_bucket_key(
    algorithm: &'static str,
    e_tag: Option<&str>,
    version: Option<&str>,
    key_identity: Option<&str>,
    bucket_key_enabled: Option<&str>,
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
    if let Some(bucket_key_enabled) = bucket_key_enabled {
        headers.insert(
            S3_BUCKET_KEY_ENABLED_HEADER,
            bucket_key_enabled.parse().expect("bucket key header"),
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
        aws_s3_object_context_profile_id(),
        context_id(b"default-test-context"),
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
        &readback_request(binding.clone()),
        "GET",
        "/objects/encrypted.json",
        &sse_kms_headers(
            receipt.e_tag.as_deref(),
            receipt.version.as_deref(),
            raw_key_identity,
        ),
    )
    .expect("observed evidence");
    let profile_id = aws_s3_object_context_profile_id();
    let attestation = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        profile_id.clone(),
        receipt.context_id.clone(),
        Some(digest_bytes(raw_key_identity.as_bytes())),
    ))
    .verify_managed_evidence(&receipt, &binding, &evidence)
    .expect("matching evidence");

    assert_eq!(
        attestation.view(),
        EncryptionAttestationView::Managed {
            profile_id: &profile_id,
            context_id: &receipt.context_id,
            object_path_binding_fingerprint: &digest_bytes(b"/objects/encrypted.json"),
            observed_key_identity_fingerprint: Some(&digest_bytes(raw_key_identity.as_bytes(),)),
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
        &readback_request(binding.clone()),
        "GET",
        "/objects/encrypted.json",
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
        &put_request(binding.clone()),
        "PUT",
        "/objects/encrypted.json",
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
fn trusted_root_pem_is_private_bounded_and_s3_scoped() {
    let sentinel_pem =
        b"-----BEGIN CERTIFICATE-----\nSIGNED_URL_SECRET\n-----END CERTIFICATE-----\n";
    let settings = ObjectStoreSettings::new("s3://tenant-artifacts/private-prefix")
        .with_option("aws_region", "us-east-1")
        .with_trusted_root_certificate_pem(sentinel_pem.to_vec());
    let debug = format!("{settings:?}");
    assert!(debug.contains("trusted_root_certificate_count"));
    assert!(!debug.contains("SIGNED_URL_SECRET"));
    #[cfg(feature = "aws")]
    assert_eq!(
        VerifiedObjectStorage::from_settings(settings).map(|_| ()),
        Err(ObjectStorageError::InvalidConfiguration),
        "invalid PEM must fail before any backend I/O"
    );

    assert_eq!(
        VerifiedObjectStorage::from_settings(
            ObjectStoreSettings::new("memory:///private")
                .with_trusted_root_certificate_pem(sentinel_pem.to_vec()),
        )
        .map(|_| ()),
        Err(ObjectStorageError::InvalidConfiguration),
        "trusted roots are scoped to S3 TLS"
    );

    let mut too_many = ObjectStoreSettings::new("s3://tenant-artifacts/private-prefix")
        .with_option("aws_region", "us-east-1");
    for _ in 0..9 {
        too_many = too_many.with_trusted_root_certificate_pem(sentinel_pem.to_vec());
    }
    assert_eq!(
        VerifiedObjectStorage::from_settings(too_many).map(|_| ()),
        Err(ObjectStorageError::InvalidConfiguration)
    );

    let oversized = ObjectStoreSettings::new("s3://tenant-artifacts/private-prefix")
        .with_option("aws_region", "us-east-1")
        .with_trusted_root_certificate_pem(vec![b'A'; 64 * 1024 + 1]);
    assert_eq!(
        VerifiedObjectStorage::from_settings(oversized).map(|_| ()),
        Err(ObjectStorageError::InvalidConfiguration)
    );
}

#[test]
fn public_debug_matrix_never_discloses_artifact_or_backend_sentinels() {
    let key = ObjectKey::parse("MODEL_RESPONSE/object.json").expect("sentinel key");
    let context_id = context_id(b"debug-sentinel-context");
    let write = ImmutableObjectWrite {
        key: key.clone(),
        context_id: context_id.clone(),
        content: Bytes::from_static(b"PRIVATE_QUERY"),
        expected_digest: digest_bytes(b"PRIVATE_QUERY"),
        content_type: "application/SECRET".to_owned(),
    };
    let receipt = ObjectWriteReceipt {
        key: key.clone(),
        context_id: context_id.clone(),
        size_bytes: 11,
        digest: digest_bytes(b"PRIVATE_QUERY"),
        e_tag: Some("SIGNED_URL".to_owned()),
        version: Some("PROVIDER_BODY".to_owned()),
        idempotent_replay: true,
    };
    let object = VerifiedObject {
        key: key.clone(),
        context_id,
        content: Bytes::from_static(b"TOOL_RESULT"),
        digest: digest_bytes(b"TOOL_RESULT"),
        content_type: Some("application/SECRET".to_owned()),
        e_tag: Some("SIGNED_URL".to_owned()),
        version: Some("PROVIDER_BODY".to_owned()),
    };
    let storage = VerifiedObjectStorage::from_settings(ObjectStoreSettings::new(
        "memory:///SIGNED_URL/PROVIDER_BODY",
    ))
    .expect("memory storage with sentinel prefix");
    let rendered = [
        format!("{key:?}"),
        format!("{write:?}"),
        format!("{receipt:?}"),
        format!("{object:?}"),
        format!("{storage:?}"),
    ];

    for debug in &rendered {
        for sentinel in [
            "MODEL_RESPONSE",
            "PRIVATE_QUERY",
            "SECRET",
            "SIGNED_URL",
            "PROVIDER_BODY",
            "TOOL_RESULT",
        ] {
            assert!(
                !debug.contains(sentinel),
                "Debug output leaked sentinel {sentinel}: {debug}"
            );
        }
    }
    assert!(rendered[0].contains("fingerprint"));
    assert!(rendered[1].contains("content_len"));
    assert!(rendered[2].contains("e_tag_present"));
    assert!(rendered[3].contains("content_len"));
    assert!(rendered[4].contains("prefix_fingerprint"));
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
    let settings =
        ObjectStoreSettings::new("s3://bucket/prefix").with_option("aws_typo_secret_key", "value");
    assert_eq!(
        VerifiedObjectStorage::from_settings(settings).map(|_| ()),
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
            &first.receipt().context_id,
            &first.receipt().digest,
            first.receipt().version.as_deref(),
        )
        .await
        .expect("verified read");
    assert_eq!(read.content, Bytes::from_static(br#"{"ok":true}"#));
    assert_eq!(read.content_type.as_deref(), Some("application/json"));
}

#[tokio::test]
async fn the_same_logical_key_isolated_by_context_has_distinct_immutable_objects() {
    let storage = storage(1_024);
    let policy = development_policy();
    let mut first_write = write("objects/contextual.json", b"context-a-content");
    first_write.context_id = context_id(b"context-a");
    let first = storage
        .put_immutable(first_write, &policy)
        .await
        .expect("context A write");

    let mut second_write = write("objects/contextual.json", b"context-b-content");
    second_write.context_id = context_id(b"context-b");
    let second = storage
        .put_immutable(second_write, &policy)
        .await
        .expect("context B write");

    assert!(!first.receipt().idempotent_replay);
    assert!(!second.receipt().idempotent_replay);
    assert_ne!(first.receipt().context_id, second.receipt().context_id);
    let first_read = storage
        .read_verified(
            &first.receipt().key,
            &first.receipt().context_id,
            &first.receipt().digest,
            first.receipt().version.as_deref(),
        )
        .await
        .expect("context A read");
    let second_read = storage
        .read_verified(
            &second.receipt().key,
            &second.receipt().context_id,
            &second.receipt().digest,
            second.receipt().version.as_deref(),
        )
        .await
        .expect("context B read");
    assert_eq!(first_read.content, Bytes::from_static(b"context-a-content"));
    assert_eq!(
        second_read.content,
        Bytes::from_static(b"context-b-content")
    );
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
            &receipt.receipt().context_id,
            &receipt.receipt().digest,
            receipt.receipt().version.as_deref(),
        )
        .await
        .expect("filesystem verified read");
    assert_eq!(read.content, Bytes::from_static(b"durable"));
    assert_eq!(read.content_type, None);
    std::fs::remove_dir_all(directory).expect("temporary storage cleanup");
}
