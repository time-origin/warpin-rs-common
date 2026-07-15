# Object Storage Credential and SSE Hardening Implementation Plan

> **For Codex:** Execute this plan test-first. Do not publish, merge, or modify the AstroNexus repository.

**Goal:** Close the remaining public `warpin-object-storage` security findings by making S3 credential acquisition a typed, mutually exclusive, fail-closed contract; proving SSE requirements are SigV4-signed; and splitting live KES identities with verifiable cleanup.

**Architecture:** Keep artifact request verification and credential acquisition verification separate inside the existing S3 connector. Parse environment-style options into one complete credential mode before constructing `object_store`; validate every unbound outbound credential request against that mode. Extend artifact request bindings with the expected signed encryption shape, and keep deployment-specific KES behavior in the live gate rather than library business logic.

**Tech Stack:** Rust 2024, `object_store` 0.14, `reqwest`, `tower::Service`, Tokio tests, Bash live gate, MinIO, KES.

---

## Task 1: Freeze the typed credential configuration contract

**Files:**
- Modify: `warpin-object-storage/src/tests.rs`
- Modify: `warpin-object-storage/src/s3_adapter.rs`
- Create: `warpin-object-storage/src/s3_adapter/credential.rs`

1. Add failing tests for incomplete static credentials, token-only static configuration, mixed credential modes, arbitrary IMDS endpoints, every IMDSv1 alias, malformed ECS relative URI, untrusted EKS full URI, unsafe/oversized token files, and custom STS endpoints.
2. Run the focused configuration tests and record the expected failures.
3. Add a private typed credential mode with complete variants only:

```rust
enum CredentialMode {
    Static,
    ImdsV2,
    EcsRelative { path: String },
    EksFullUri { target: CredentialTarget, token_file: BoundedTokenFile },
    WebIdentity { target: StsTarget, token_file: BoundedTokenFile },
}
```

4. Reject incomplete or mixed configuration before `AmazonS3Builder::build` and before network I/O.
5. Re-run the focused tests and confirm green.

## Task 2: Bind every credential outbound request

**Files:**
- Modify: `warpin-object-storage/src/tests.rs`
- Modify: `warpin-object-storage/src/s3_adapter.rs`
- Modify: `warpin-object-storage/src/s3_adapter/credential.rs`

1. Add a counting mock connector and failing tests proving malicious ECS `@evil`, arbitrary metadata/full/custom STS endpoints, IMDSv1, and mixed-mode configurations reach the inner connector zero times.
2. Verify method, scheme, authority, path, query shape, and required headers independently for each supported mode. IMDS must use only `169.254.169.254` with the IMDSv2 token exchange; ECS must use only `169.254.170.2`; EKS must use standard loopback/link-local targets or a typed trusted HTTPS origin; web identity must use official partition/region STS endpoints.
3. Make unbound requests fail closed and keep redirect policy disabled.
4. Re-run malicious and positive outbound tests.

## Task 3: Prove SSE requirements are signed

**Files:**
- Modify: `warpin-object-storage/src/tests.rs`
- Modify: `warpin-object-storage/src/s3_adapter.rs`

1. Add failing PUT tests for missing, wrong, or unsigned `x-amz-server-side-encryption`, bucket-key, KMS key-id, and content SHA headers; add GET tests for unsigned host/date/content SHA and wrong object version.
2. Extend the operation binding with the configured expected SSE shape:

```rust
struct ExpectedSignedSseShape {
    algorithm: &'static str,
    bucket_key_enabled: bool,
    kms_key_id_digest: Option<[u8; 32]>,
}
```

3. Require artifact PUT signatures to cover exact `aws:kms`, `false`, content SHA, and configured key identity. Require GET signatures to cover host/date/content SHA and the exact version reference.
4. Reject weak syntactic signatures and all mismatches before inner I/O.
5. Re-run focused verifier tests and existing object-store path tests.

## Task 4: Split live KES identities and make cleanup attestable

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`
- Modify: `warpin-object-storage/tests/minio_kes_live.rs`

1. Add a failing shell behavior/self-check test that inspects generated policies and simulates cleanup failures.
2. Create separate bootstrap, runtime, and metrics identities. Bootstrap may create only the exact key; runtime may generate/decrypt only the exact key; metrics may read status/metrics only. No wildcard permissions.
3. Keep trap cleanup best-effort, but make the success path explicitly remove and verify containers, networks, and temp directory before printing `cleanup=true`.
4. Ensure cleanup failure exits nonzero and never emits a false success attestation.
5. Run the script self-check and the live gate when the local container runtime is available.

## Task 5: Documentation, packaging, and release gates

**Files:**
- Modify: `warpin-object-storage/README.md`
- Modify: `warpin-object-storage/MIGRATION.md`
- Modify: `warpin-object-storage/Cargo.toml` only if package metadata requires it

1. Document supported credential modes, trusted EKS HTTPS origins, token-file limits, signed SSE proof, and deployment identity separation without exposing secrets.
2. Run `cargo fmt --check`, crate and workspace checks/tests/clippy, archive/tree secret scans, package verification, and publish dry-run only.
3. Run an external public-consumer build and forge probes for malicious credential targets and unsigned SSE headers.
4. Record clean-tree state, commit the completed change, and report tree/archive/crate checksums. Do not publish or merge.
