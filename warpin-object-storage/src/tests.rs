#[cfg(feature = "aws")]
use std::collections::BTreeMap;

use bytes::Bytes;
use object_store::{Extensions, path::Path};
#[cfg(feature = "fs")]
use url::Url;
use warpin_integrity::{Sha256Digest, digest_bytes};

use super::*;
#[cfg(feature = "aws")]
use async_trait::async_trait;
#[cfg(feature = "aws")]
use object_store::client::{
    HttpClient, HttpError, HttpRequest, HttpRequestBody, HttpResponse, HttpResponseBody,
    HttpService,
};
#[cfg(feature = "aws")]
use s3_adapter::{
    ConfiguredS3Encryption, ObservedEncryptionEvidence, S3EncryptionObserverService,
    minio_kes_object_context_profile_id,
};
use s3_adapter::{
    ObservedBucketKeyState, S3_BUCKET_KEY_ENABLED_HEADER, actual_path_matches_expected,
    aws_s3_object_context_profile_id, observed_bucket_key_state, observed_s3_response,
};
use storage::read_options;

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
    ObserverRequestBinding::readback(binding, expected_location)
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
    assert!(actual_path_matches_expected(
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
    let request = ObserverRequestBinding::readback(binding, expected);
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
            "/bucket/objects/encrypted.json",
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
        &put_request(first_binding.clone()),
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
            &readback_request(binding.clone()),
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
            &put_request(binding.clone()),
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
            &readback_request(binding.clone()),
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
            &readback_request(binding.clone()),
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
            let mut response = HttpResponse::new(HttpResponseBody::new(HttpRequestBody::empty()));
            *response.headers_mut() = self.headers.clone();
            Ok(response)
        }
    }

    let receipt = receipt(false);
    let binding = WriteBinding::new(&receipt);
    let request_binding = readback_request(binding.clone());
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
    let missing = ConfiguredS3Encryption::from_options(&BTreeMap::new(), None, None)
        .expect("missing encryption is a valid observed configuration state");
    assert_eq!(
        managed_policy().verify_s3_configuration(&missing),
        Err(EncryptionPolicyError::ManagedEncryptionRequired)
    );

    let wrong_algorithm = ConfiguredS3Encryption::from_options(
        &BTreeMap::from([("aws_server_side_encryption".to_owned(), "AES256".to_owned())]),
        None,
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
        &BTreeMap::from([
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
        &readback_request(WriteBinding::new(&receipt)),
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
#[test]
fn s3_configuration_requires_explicitly_disabled_bucket_keys() {
    for bucket_key_value in [None, Some("true"), Some("invalid")] {
        let mut options = BTreeMap::from([(
            "aws_server_side_encryption".to_owned(),
            "aws:kms".to_owned(),
        )]);
        if let Some(value) = bucket_key_value {
            options.insert("aws_sse_bucket_key_enabled".to_owned(), value.to_owned());
        }
        let configured = ConfiguredS3Encryption::from_options(&options, None, None)
            .expect("configuration shape");
        assert_eq!(
            managed_policy_with_expected(None).verify_s3_configuration(&configured),
            Err(EncryptionPolicyError::ObjectContextBindingRequired)
        );
    }

    let configured = ConfiguredS3Encryption::from_options(
        &BTreeMap::from([
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
    let base_options = BTreeMap::from([
        (
            "aws_server_side_encryption".to_owned(),
            "aws:kms".to_owned(),
        ),
        ("aws_sse_bucket_key_enabled".to_owned(), "false".to_owned()),
    ]);
    let native = ConfiguredS3Encryption::from_options(&base_options, None, None)
        .expect("native AWS profile");
    assert_eq!(native.profile_id, aws_s3_object_context_profile_id());

    let mut custom_options = base_options.clone();
    custom_options.insert(
        "aws_endpoint".to_owned(),
        "https://minio.internal.example".to_owned(),
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(&custom_options, None, None),
        Err(ObjectStorageError::InvalidConfiguration)
    );
    let minio_profile = minio_kes_object_context_profile_id();
    let minio =
        ConfiguredS3Encryption::from_options(&custom_options, Some(minio_profile.clone()), None)
            .expect("explicit reviewed MinIO/KES profile");
    assert_eq!(minio.profile_id, minio_profile);
    assert_ne!(minio.profile_id, native.profile_id);

    assert_eq!(
        ConfiguredS3Encryption::from_options(
            &base_options,
            Some(minio_kes_object_context_profile_id()),
            None,
        ),
        Err(ObjectStorageError::InvalidConfiguration)
    );
    assert_eq!(
        ConfiguredS3Encryption::from_options(
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
    let storage = VerifiedObjectStorage::from_settings(ObjectStoreSettings::new(
        "s3://preflight-only-bucket/private-prefix",
    ))
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
        "/bucket/objects/encrypted.json",
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
            object_path_binding_fingerprint: &digest_bytes(b"objects/encrypted.json"),
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
        &put_request(binding.clone()),
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
