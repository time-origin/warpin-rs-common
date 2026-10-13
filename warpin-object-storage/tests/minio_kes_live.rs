#![cfg(feature = "aws")]

use std::{env, fs, process::Command, time::SystemTime};

use bytes::Bytes;
use warpin_integrity::digest_bytes;
use warpin_object_storage::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, EncryptionAttestationView,
    EncryptionRequirement, ImmutableObjectWrite, ObjectDeleteOutcome, ObjectKey,
    ObjectStoreSettings, VerifiedObjectDelete, VerifiedObjectStorage,
    s3_adapter::with_minio_kes_object_context_profile,
};

const MINIO_GATE_KEY_IDENTITY: &[u8] = b"arn:aws:kms:minio-r4-default";
const CONTEXT_A_DOMAIN: &[u8] = b"warpin:r4:minio-kes-live-gate:context:v1";
const CONTEXT_B_DOMAIN: &[u8] = b"warpin:r4:minio-kes-live-gate:context:v2";

#[test]
fn live_gate_shell_self_check_enforces_identity_and_cleanup_contracts() {
    let script_path = format!(
        "{}/scripts/minio-kes-live-gate.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new("bash")
        .arg(&script_path)
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
    let script = fs::read_to_string(script_path).expect("read live-gate script");
    assert!(
        script.contains("\"s3:DeleteObject\""),
        "pinned MinIO also checks the base DeleteObject action"
    );
    assert!(
        script.contains("\"s3:DeleteObjectVersion\""),
        "the versioned live gate principal must be able to exercise exact-version cleanup"
    );
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
        for (context_id, digest, version) in [
            (context_a, digest_a, version_a),
            (context_b, digest_b, version_b),
        ] {
            let request = VerifiedObjectDelete {
                key: key.clone(),
                context_id,
                expected_digest: digest,
                expected_version: Some(version),
            };
            assert_eq!(
                storage
                    .delete_verified(request.clone())
                    .await
                    .expect("exact-version live cleanup")
                    .outcome,
                ObjectDeleteOutcome::Deleted
            );
            assert_eq!(
                storage
                    .delete_verified(request)
                    .await
                    .expect("idempotent exact-version live cleanup replay")
                    .outcome,
                ObjectDeleteOutcome::AlreadyAbsent
            );
        }
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

#[cfg(feature = "streaming")]
mod streaming_live {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use tokio::io::AsyncReadExt;
    use warpin_object_storage::streaming::{
        ChunkWriteIntent, ChunkWriteJournal, ChunkedObjectReceipt, ChunkedObjectWrite,
        ChunkedReadVerification,
    };
    use warpin_object_storage::{ObjectStorageError, ObjectWriteReceipt};

    struct DurableJournal(std::path::PathBuf);
    #[async_trait::async_trait]
    impl ChunkWriteJournal for DurableJournal {
        async fn before_write(&self, i: &ChunkWriteIntent) -> Result<(), ObjectStorageError> {
            let value = serde_json::json!({"kind":"intent", "key":i.key.as_str(),
                "context":i.context_id.as_digest().as_str(),"digest":i.digest.as_str(),"size":i.size_bytes,"content_type":i.content_type});
            append(&self.0, &value)
        }
        async fn after_write(&self, r: &ObjectWriteReceipt) -> Result<(), ObjectStorageError> {
            append(&self.0, &receipt_json(r))
        }
    }
    fn append(path: &std::path::Path, value: &serde_json::Value) -> Result<(), ObjectStorageError> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| ObjectStorageError::Backend)?;
        writeln!(file, "{value}").map_err(|_| ObjectStorageError::Backend)?;
        file.sync_all().map_err(|_| ObjectStorageError::Backend)?;
        fs::File::open(
            path.parent()
                .ok_or(ObjectStorageError::InvalidConfiguration)?,
        )
        .and_then(|dir| dir.sync_all())
        .map_err(|_| ObjectStorageError::Backend)
    }
    fn receipt_json(r: &ObjectWriteReceipt) -> serde_json::Value {
        serde_json::json!({"kind":"receipt","key":r.key.as_str(),"context":r.context_id.as_digest().as_str(),
            "digest":r.digest.as_str(),"size":r.size_bytes,"version":r.version,"etag":r.e_tag})
    }
    fn parse_receipt(v: &serde_json::Value) -> ObjectWriteReceipt {
        ObjectWriteReceipt {
            key: ObjectKey::parse(v["key"].as_str().unwrap()).unwrap(),
            context_id: ArtifactEncryptionContextId::from_digest(
                v["context"].as_str().unwrap().parse().unwrap(),
            ),
            digest: v["digest"].as_str().unwrap().parse().unwrap(),
            size_bytes: v["size"].as_u64().unwrap(),
            version: v["version"].as_str().map(str::to_owned),
            e_tag: v["etag"].as_str().map(str::to_owned),
            idempotent_replay: false,
        }
    }
    #[tokio::test]
    #[ignore = "requires an ephemeral TLS MinIO + KES compatibility environment"]
    async fn tls_minio_kes_chunked_restart_range_and_cleanup() {
        let size = 256 * 1024 * 1024 + 17_u64;
        let receipt_path = std::path::PathBuf::from(required_env("WARPIN_STREAM_RECEIPT_PATH"));
        let journal = DurableJournal(receipt_path.with_extension("journal"));
        let settings = with_minio_kes_object_context_profile(
            ObjectStoreSettings::new(format!(
                "s3://{}/live-gate",
                required_env("WARPIN_MINIO_BUCKET")
            ))
            .with_option("aws_region", "us-east-1")
            .with_option("aws_endpoint", required_env("WARPIN_MINIO_ENDPOINT"))
            .with_option("aws_access_key_id", required_env("WARPIN_MINIO_ACCESS_KEY"))
            .with_option(
                "aws_secret_access_key",
                required_env("WARPIN_MINIO_SECRET_KEY"),
            )
            .with_trusted_root_certificate_pem(
                fs::read(required_env("WARPIN_MINIO_CA_PEM")).unwrap(),
            )
            .with_expected_observed_key_identity_fingerprint(digest_bytes(MINIO_GATE_KEY_IDENTITY))
            .with_max_object_bytes(4 * 1024 * 1024)
            .with_max_streamed_object_bytes(size),
        );
        let storage = VerifiedObjectStorage::from_settings(settings).unwrap();
        let context = ArtifactEncryptionContextId::from_digest(digest_bytes(CONTEXT_A_DOMAIN));
        let policy = managed_policy(
            storage.managed_encryption_profile_id().unwrap().clone(),
            &context,
        );
        let mut hash = Sha256::new();
        let buffer = [23_u8; 65536];
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(buffer.len() as u64) as usize;
            hash.update(&buffer[..n]);
            remaining -= n as u64;
        }
        let digest = format!("sha256:{:x}", hash.finalize()).parse().unwrap();
        let receipt = if env::var("WARPIN_MINIO_GATE_MODE").as_deref() == Ok("read") {
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
            ChunkedObjectReceipt {
                root: parse_receipt(&value),
                content_digest: digest,
                size_bytes: size,
                content_type: "image/tiff".into(),
            }
        } else {
            let write = ChunkedObjectWrite {
                key: ObjectKey::parse(format!("objects/stream-{}.tiff", gate_run_id())).unwrap(),
                context_id: context.clone(),
                size_bytes: size,
                expected_digest: digest,
                content_type: "image/tiff".into(),
                chunk_bytes: 1024 * 1024,
            };
            let receipt = storage
                .put_chunked(
                    write.clone(),
                    &mut tokio::io::repeat(23).take(size),
                    &policy,
                    &journal,
                )
                .await
                .unwrap();
            let replay = storage
                .put_chunked(
                    write,
                    &mut tokio::io::repeat(23).take(size),
                    &policy,
                    &journal,
                )
                .await
                .unwrap();
            assert!(replay.root.idempotent_replay);
            assert_eq!(receipt.root.version, replay.root.version);
            assert_eq!(receipt.root.digest, replay.root.digest);
            let mut file = fs::File::create(&receipt_path).unwrap();
            file.write_all(
                serde_json::to_string(&receipt_json(&receipt.root))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            file.sync_all().unwrap();
            receipt
        };
        let mut reader = storage.open_chunked(&receipt, None, &policy).await.unwrap();
        let mut read = 0_u64;
        while let Some(bytes) = reader.next_chunk().await.unwrap() {
            assert!(bytes.iter().all(|v| *v == 23));
            assert!(bytes.len() <= 1024 * 1024);
            read += bytes.len() as u64;
        }
        assert_eq!(read, size);
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::WholeDigestVerified)
        );
        let mut reader = storage
            .open_chunked(&receipt, Some(1024 * 1024 - 5..1024 * 1024 + 7), &policy)
            .await
            .unwrap();
        let mut count = 0;
        while let Some(bytes) = reader.next_chunk().await.unwrap() {
            assert!(bytes.iter().all(|v| *v == 23));
            count += bytes.len();
        }
        assert_eq!(count, 12);
        assert_eq!(
            reader.verification(),
            Some(ChunkedReadVerification::AuthenticatedRange)
        );
        let mut page_range = storage
            .open_chunked(&receipt, Some(256 * 1024 * 1024 - 5..size), &policy)
            .await
            .unwrap();
        let mut page_range_bytes = 0;
        while let Some(bytes) = page_range.next_chunk().await.unwrap() {
            assert!(bytes.iter().all(|v| *v == 23));
            page_range_bytes += bytes.len();
        }
        assert_eq!(page_range_bytes, 22);
        assert_eq!(
            page_range.verification(),
            Some(ChunkedReadVerification::AuthenticatedRange)
        );
        let mut wrong = receipt.clone();
        wrong.root.e_tag = Some("wrong".into());
        assert!(
            storage
                .open_chunked(&wrong, Some(0..1), &policy)
                .await
                .is_err()
        );
        wrong = receipt.clone();
        wrong.root.version = Some("wrong".into());
        assert!(
            storage
                .open_chunked(&wrong, Some(0..1), &policy)
                .await
                .is_err()
        );
        wrong = receipt.clone();
        wrong.root.context_id =
            ArtifactEncryptionContextId::from_digest(digest_bytes(CONTEXT_B_DOMAIN));
        assert!(
            storage
                .open_chunked(&wrong, Some(0..1), &policy)
                .await
                .is_err()
        );
        if env::var("WARPIN_MINIO_GATE_MODE").as_deref() == Ok("read") {
            // The gate owns every object and has no external references. Retire
            // the root first; then exact-delete only journaled versioned parts.
            let entries = fs::read_to_string(&journal.0).unwrap();
            let mut seen = std::collections::BTreeSet::new();
            for line in entries.lines().rev() {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                if value["kind"] != "receipt" {
                    continue;
                }
                let r = parse_receipt(&value);
                if !seen.insert((
                    r.context_id.as_digest().to_string(),
                    r.key.as_str().to_owned(),
                    r.version.clone(),
                    r.digest.to_string(),
                )) {
                    continue;
                }
                storage
                    .delete_verified(VerifiedObjectDelete {
                        key: r.key,
                        context_id: r.context_id,
                        expected_digest: r.digest,
                        expected_version: r.version,
                    })
                    .await
                    .unwrap();
            }
        }
    }
}
