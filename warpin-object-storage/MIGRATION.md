# Migrating `warpin-object-storage` from 0.1 to 0.2

Version 0.2 intentionally breaks context-free artifact writes. It replaces
configuration-as-proof with an observed, receipt-bound encryption attestation.

## Required changes

### 1. Derive a typed artifact encryption context

Construct `ArtifactEncryptionContextId` from a versioned, domain-separated
canonical digest owned by the caller. The raw tenant, space, artifact,
classification, purpose, and retention fields must not be passed into this
crate or concatenated into storage logs.

```rust
let context_id = ArtifactEncryptionContextId::from_digest(context_digest);
```

Reuse the same typed context in `ImmutableObjectWrite`,
`EncryptionRequirement::managed`, and `read_verified`. The crate rejects a
write whose policy and object contexts differ.

### 2. Select a reviewed managed adapter profile

Native AWS S3:

```rust
let settings = with_aws_s3_object_context_profile(
    ObjectStoreSettings::new("s3://bucket/prefix")
        .with_option("aws_region", "eu-west-1"),
);
```

Reviewed MinIO/KES deployment:

```rust
let settings = with_minio_kes_object_context_profile(
    ObjectStoreSettings::new("s3://bucket/prefix")
        .with_option("aws_region", "us-east-1")
        .with_option("aws_endpoint", "https://minio.internal.example"),
);
```

Custom S3 endpoints no longer inherit the native AWS guarantee. They fail
closed unless the explicit MinIO/KES profile is selected. The deployment must
pass `scripts/minio-kes-live-gate.sh` before that profile is enabled.

### 3. Build a managed policy from the adapter's opaque profile

```rust
let storage = VerifiedObjectStorage::from_settings(settings)?;
let profile_id = storage
    .managed_encryption_profile_id()
    .ok_or(ObjectStorageError::InvalidConfiguration)?
    .clone();
let policy = ArtifactEncryptionPolicy::new(EncryptionRequirement::managed(
    profile_id,
    context_id.clone(),
    expected_key_identity_fingerprint,
));
```

The optional key identity value is the digest of the exact canonical identity
observed in the provider response. It is not the request-side alias and it is
never an authorization token.

### 4. Pass context through writes and reads

`ImmutableObjectWrite` now requires `context_id`:

```rust
let write = ImmutableObjectWrite {
    key,
    context_id: context_id.clone(),
    content,
    expected_digest,
    content_type,
};
let verified_receipt = storage.put_immutable(write, &policy).await?;
```

`read_verified` now requires the same context and should pin the exact version
from the immutable receipt:

```rust
let object = storage
    .read_verified(
        &key,
        &context_id,
        &expected_digest,
        verified_receipt.receipt().version.as_deref(),
    )
    .await?;
```

Do not persist or reconstruct a physical bucket/object URL. Persist the logical
key, typed context identity, digest, and opaque version through the owning
artifact-reference contract.

### 5. Make plaintext development/test use explicit

For `memory://` and `file://`, use:

```rust
let policy = ArtifactEncryptionPolicy::new(
    EncryptionRequirement::development_or_test_plaintext(),
);
```

Managed policy cannot be downgraded to a local plaintext backend. Conversely,
development/test plaintext policy cannot be used with managed S3.

### 6. Replace provider error/body logging

Handle `ObjectStorageError` and `EncryptionPolicyError` as stable categories.
Do not log backend source chains, raw response bodies, object keys, ETags,
versions, URLs, credentials, or signed request material. `Debug` and `Display`
are sanitized, but callers must preserve the same boundary in their own error
wrapping.

## S3 configuration changes

- `aws_region` is mandatory; no region is guessed.
- `aws_sse_bucket_key_enabled=false` is installed by the reviewed profile
  factories and is mandatory for object-context proof.
- HTTP, invalid-certificate acceptance, signature skipping, unsigned payloads,
  customer-provided encryption keys, proxy options, and unknown options fail
  closed.
- Redirects are never followed.
- A private CA is provided as PEM bytes through
  `with_trusted_root_certificate_pem`; do not use provider-specific custom-CA
  options.
- Exact target verification uses the S3 SigV4 canonical path encoding. Do not
  pre-encode object keys or compare decoded URI aliases.

## Rollout guidance

Upgrade consumers before producers. During rollout, keep existing artifact
references readable, but write new artifacts only through the context-bound
0.2 contract. Before enabling the MinIO/KES profile in a deployment, run the
packaged live gate and retain its sanitized PASS matrix as verification
evidence.
