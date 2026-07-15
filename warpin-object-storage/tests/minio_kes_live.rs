#![cfg(feature = "aws")]

use std::{env, fs, process::Command, time::SystemTime};

use bytes::Bytes;
use warpin_integrity::digest_bytes;
use warpin_object_storage::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, EncryptionAttestationView,
    EncryptionRequirement, ImmutableObjectWrite, ObjectKey, ObjectStoreSettings,
    VerifiedObjectStorage, s3_adapter::with_minio_kes_object_context_profile,
};

const MINIO_GATE_KEY_IDENTITY: &[u8] = b"arn:aws:kms:minio-r4-default";
const CONTEXT_A_DOMAIN: &[u8] = b"warpin:r4:minio-kes-live-gate:context:v1";
const CONTEXT_B_DOMAIN: &[u8] = b"warpin:r4:minio-kes-live-gate:context:v2";

#[test]
fn live_gate_shell_self_check_enforces_identity_and_cleanup_contracts() {
    let output = Command::new("bash")
        .arg(format!(
            "{}/scripts/minio-kes-live-gate.sh",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg("--self-check")
        .output()
        .expect("execute live-gate shell self-check");
    assert!(
        output.status.success(),
        "shell self-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("minio_kes_live_gate_self_check=true"));
    assert!(!stdout.contains("ephemeral_resources_cleaned=true"));
}

fn gate_run_id() -> String {
    let value = env::var("WARPIN_MINIO_GATE_RUN_ID").unwrap_or_else(|_| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
            .to_string()
    });
    assert!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "live-gate run id must contain only ASCII alphanumerics or hyphens"
    );
    value
}

fn managed_policy(
    profile_id: warpin_object_storage::ManagedEncryptionProfileId,
    context_id: &ArtifactEncryptionContextId,
) -> ArtifactEncryptionPolicy {
    ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
        profile_id,
        context_id.clone(),
        Some(digest_bytes(MINIO_GATE_KEY_IDENTITY)),
    ))
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required for the ignored live gate"))
}

#[tokio::test]
#[ignore = "requires an ephemeral TLS MinIO + KES compatibility environment"]
async fn tls_minio_kes_managed_write_is_attested_and_readable() {
    let endpoint = required_env("WARPIN_MINIO_ENDPOINT");
    let bucket = required_env("WARPIN_MINIO_BUCKET");
    let access_key = required_env("WARPIN_MINIO_ACCESS_KEY");
    let secret_key = required_env("WARPIN_MINIO_SECRET_KEY");
    let ca_pem = fs::read(required_env("WARPIN_MINIO_CA_PEM"))
        .expect("read the ephemeral MinIO CA certificate");
    let settings = with_minio_kes_object_context_profile(
        ObjectStoreSettings::new(format!("s3://{bucket}/live-gate"))
            .with_option("aws_region", "us-east-1")
            .with_option("aws_endpoint", endpoint)
            .with_option("aws_access_key_id", access_key)
            .with_option("aws_secret_access_key", secret_key)
            .with_expected_observed_key_identity_fingerprint(digest_bytes(MINIO_GATE_KEY_IDENTITY))
            .with_trusted_root_certificate_pem(ca_pem),
    );
    let storage = VerifiedObjectStorage::from_settings(settings).expect("managed MinIO storage");
    let profile_id = storage
        .managed_encryption_profile_id()
        .expect("managed adapter profile")
        .clone();
    let context_a = ArtifactEncryptionContextId::from_digest(digest_bytes(CONTEXT_A_DOMAIN));
    let context_b = ArtifactEncryptionContextId::from_digest(digest_bytes(CONTEXT_B_DOMAIN));
    let policy_a = managed_policy(profile_id.clone(), &context_a);
    let policy_b = managed_policy(profile_id, &context_b);
    let run_id = gate_run_id();
    let key = ObjectKey::parse(format!("objects/live-{run_id}.json")).expect("live object key");
    let content_a = Bytes::from_static(b"warpin-minio-kes-live-gate-a");
    let content_b = Bytes::from_static(b"warpin-minio-kes-live-gate-b");
    let digest_a = digest_bytes(&content_a);
    let digest_b = digest_bytes(&content_b);

    if env::var("WARPIN_MINIO_GATE_MODE").as_deref() == Ok("read") {
        let version_a = required_env("WARPIN_MINIO_VERSION_A");
        let version_b = required_env("WARPIN_MINIO_VERSION_B");
        let read_a = storage
            .read_verified(&key, &context_a, &digest_a, Some(&version_a))
            .await
            .expect("post-restart exact-version read for context A");
        let read_b = storage
            .read_verified(&key, &context_b, &digest_b, Some(&version_b))
            .await
            .expect("post-restart exact-version read for context B");
        assert_eq!(read_a.content, content_a);
        assert_eq!(read_b.content, content_b);
        return;
    }
    assert!(
        env::var("WARPIN_MINIO_GATE_MODE").is_err()
            || env::var("WARPIN_MINIO_GATE_MODE").as_deref() == Ok("write"),
        "live-gate mode must be write or read"
    );

    let missing_key = ObjectKey::parse("objects/live-gate-missing.json").expect("missing key");
    assert_eq!(
        storage
            .read_verified(&missing_key, &context_a, &digest_bytes(b"missing"), None,)
            .await,
        Err(warpin_object_storage::ObjectStorageError::NotFound),
        "trusted-root TLS and static credentials must reach MinIO before the bound write"
    );

    let verified_a = storage
        .put_immutable(
            ImmutableObjectWrite {
                key: key.clone(),
                context_id: context_a.clone(),
                content: content_a.clone(),
                expected_digest: digest_a.clone(),
                content_type: "application/json".to_owned(),
            },
            &policy_a,
        )
        .await
        .expect("TLS MinIO/KES managed write for context A");
    let verified_b = storage
        .put_immutable(
            ImmutableObjectWrite {
                key: key.clone(),
                context_id: context_b.clone(),
                content: content_b.clone(),
                expected_digest: digest_b.clone(),
                content_type: "application/json".to_owned(),
            },
            &policy_b,
        )
        .await
        .expect("TLS MinIO/KES managed write for context B");
    assert!(verified_a.attestation().is_managed());
    assert!(verified_b.attestation().is_managed());
    assert!(matches!(
        verified_a.attestation().view(),
        EncryptionAttestationView::Managed {
            observed_key_identity_fingerprint: Some(fingerprint),
            ..
        } if fingerprint == &digest_bytes(MINIO_GATE_KEY_IDENTITY)
    ));
    assert!(matches!(
        verified_b.attestation().view(),
        EncryptionAttestationView::Managed {
            observed_key_identity_fingerprint: Some(fingerprint),
            ..
        } if fingerprint == &digest_bytes(MINIO_GATE_KEY_IDENTITY)
    ));
    assert!(!verified_a.receipt().idempotent_replay);
    assert!(!verified_b.receipt().idempotent_replay);
    assert_ne!(
        verified_a.attestation().receipt_binding_fingerprint(),
        verified_b.attestation().receipt_binding_fingerprint(),
        "the two context-bound physical writes need distinct receipt bindings"
    );

    let readback_a = storage
        .read_verified(
            &key,
            &context_a,
            &digest_a,
            verified_a.receipt().version.as_deref(),
        )
        .await
        .expect("version-pinned verified readback for context A");
    let readback_b = storage
        .read_verified(
            &key,
            &context_b,
            &digest_b,
            verified_b.receipt().version.as_deref(),
        )
        .await
        .expect("version-pinned verified readback for context B");
    assert_eq!(readback_a.content, content_a);
    assert_eq!(readback_b.content, content_b);
}
