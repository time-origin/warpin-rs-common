# warpin-object-storage

`warpin-object-storage` is the provider-neutral immutable object boundary for
Warpin artifacts. Version 0.2 binds every object to a typed artifact encryption
context and requires managed S3 writes to return observed, policy-verified
encryption evidence.

The crate does not own a KMS implementation or expose provider key locators in
its public contract. Storage adapters implement deployment-specific
`ArtifactEncryptionPolicy` behavior. Application services provide only opaque
profile, context, digest, and optional key-identity fingerprints.

## Security contract

- Managed S3 writes require a reviewed adapter profile, SSE-KMS, explicitly
  disabled S3 Bucket Keys, an exact HTTPS request target, and valid SigV4
  request evidence.
- The final version-pinned GET response, not request configuration alone,
  produces the managed encryption attestation.
- A canonical provider key identity may be required by digest. Raw key
  locators are never stored in the attestation and are redacted from formatting.
- The same logical `ObjectKey` under two `ArtifactEncryptionContextId` values
  resolves to two physical object paths.
- `memory://` and `file://` are explicit development/test plaintext backends.
  A managed policy cannot be used with either backend.
- Redirects, unsigned payloads, insecure HTTP, invalid certificates, signature
  skipping, customer-provided encryption keys, proxies, and unknown S3 options
  fail closed.
- Debug and error formatting omits raw object keys, content, credentials,
  provider bodies, signed URLs, ETags, versions, and certificate contents.

## Features

```toml
[dependencies]
warpin-object-storage = { version = "0.2", features = ["aws"] }
```

`fs` is enabled by default. Enable `aws` for native AWS S3 or the reviewed
MinIO/KES compatibility profile.

## Managed S3 usage

```rust
use bytes::Bytes;
use warpin_integrity::digest_bytes;
use warpin_object_storage::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, EncryptionRequirement,
    ImmutableObjectWrite, ObjectKey, ObjectStoreSettings, VerifiedObjectStorage,
    s3_adapter::with_aws_s3_object_context_profile,
};

# async fn example() -> Result<(), warpin_object_storage::ObjectStorageError> {
let context_id = ArtifactEncryptionContextId::from_digest(digest_bytes(
    b"example:artifact-encryption-context:v1:opaque-canonical-fields",
));
let settings = with_aws_s3_object_context_profile(
    ObjectStoreSettings::new("s3://artifact-bucket/processing")
        .with_option("aws_region", "eu-west-1"),
);
let storage = VerifiedObjectStorage::from_settings(settings)?;
let profile_id = storage
    .managed_encryption_profile_id()
    .ok_or(warpin_object_storage::ObjectStorageError::InvalidConfiguration)?
    .clone();
let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
    profile_id,
    context_id.clone(),
    None,
));
let content = Bytes::from_static(b"immutable artifact");
let receipt = storage
    .put_immutable(
        ImmutableObjectWrite {
            key: ObjectKey::parse("objects/artifact.json")?,
            context_id,
            expected_digest: digest_bytes(&content),
            content,
            content_type: "application/json".to_owned(),
        },
        &policy,
    )
    .await?;
assert!(receipt.attestation().is_managed());
# Ok(())
# }
```

Use `with_minio_kes_object_context_profile` only for a deployment that passes
the pinned compatibility gate below. A private CA can be added with
`ObjectStoreSettings::with_trusted_root_certificate_pem`; this merges trust
roots and never disables normal certificate verification.

## MinIO/KES compatibility gate

Run from the workspace root:

```bash
./warpin-object-storage/scripts/minio-kes-live-gate.sh
```

The ignored Rust integration test and wrapper script verify:

- fixed MinIO, KES, and `mc` image RepoDigests;
- TLS for S3, mTLS for KES, and provider-neutral private-root injection;
- a random, least-privilege processing identity (root is bootstrap-only);
- two context-bound physical objects for one logical key;
- SSE-KMS response identity and attestation fingerprint equality;
- absent/false Bucket Key acceptance plus true/invalid fail-closed tests;
- exact version reads before and after a MinIO restart; and
- complete cleanup of containers, networks, credentials, and temporary
  certificates.

The pinned KES release exposes only status-labelled aggregate request metrics;
it has no route labels and does not emit audit events for data-key generate or
decrypt handlers. Therefore the script reports isolated write-phase and
post-restart-read success deltas, plus clearly labelled inferred operation
minimums. Those deltas are supporting evidence; the Rust attestation, MinIO
SSE-KMS metadata, exact-version reads, and restart boundary are the primary
proof. Background traffic can increase an aggregate delta but cannot create a
passing Rust write or read result.

The gate uses KES's filesystem keystore only as an ephemeral compatibility
fixture. Production deployments must supply their approved KMS-backed
`ArtifactEncryptionPolicy` through the Processing storage adapter.

See [MIGRATION.md](MIGRATION.md) for the v0.1 to v0.2 API changes.
