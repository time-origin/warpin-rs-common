# Object Storage Public Encryption Contract Freeze Implementation Plan

> **For Codex:** Execute this plan test-first. Do not publish, merge, run Codex review, or modify the AstroNexus repository.

**Goal:** Freeze `warpin-object-storage` 0.2.0 to the narrow, publicly supportable encryption contract: static, strict IMDSv2, or fixed-authority ECS-relative credentials; request-bound SigV4 verification; and process-separated KES secret mounts.

**Architecture:** Remove the previously introduced EKS full-URI, web-identity, trusted-origin, token-file, and STS surfaces instead of retaining dormant compatibility paths. Parse and reject every removed option before builder or network activity. Bind each artifact request to its exact URI, method, operation, body digest, Host authority, signed-header set, and configured KMS-key presence. Keep KES server, bootstrap, runtime, and metrics credentials in distinct mounts and prove the visible mount sets.

**Tech Stack:** Rust 2024, exactly pinned `object_store` 0.14.0, `reqwest`, `tower::Service`, Tokio tests, Bash live gate, MinIO, KES.

---

## Task 1: Remove unsupported credential APIs and reject their options

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `warpin-object-storage/src/storage.rs`
- Modify: `warpin-object-storage/src/s3_adapter.rs`
- Modify: `warpin-object-storage/src/s3_adapter/credential.rs`
- Modify: `warpin-object-storage/src/tests.rs`

- [ ] Add RED matrices for all full-URI, authorization-token-file, web-identity, role, session, and STS canonical keys and aliases, including mixed configurations.
- [ ] Prove rejected configurations fail before builder construction or connector I/O.
- [ ] Reduce `CredentialMode` to `Static`, `ImdsV2`, and `EcsRelative` only.
- [ ] Delete `TrustedCredentialHttpsOrigin`, token-file, IPv6, web-identity, role, and STS code and public settings surfaces.
- [ ] Pin `object_store` to `=0.14.0`, whose real signed request retains Host for this observer contract.
- [ ] Re-run focused tests and confirm GREEN.

## Task 2: Freeze actual IMDSv2 and ECS request shapes

**Files:**
- Modify: `warpin-object-storage/src/s3_adapter/credential.rs`
- Modify: `warpin-object-storage/src/tests.rs`

- [ ] Add RED request tests for exact IMDS token/list/role endpoints and AWS IAM role-name grammar/64-byte bound.
- [ ] Add RED positive and negative ECS-relative tests using fixed `169.254.170.2`, exact path/query, no authorization header, and no authority aliases.
- [ ] Implement a dedicated one-segment IMDS role-name validator.
- [ ] Preserve valid ECS relative-URI query syntax while rejecting fragments, userinfo, alternative authorities, and malformed aliases.
- [ ] Re-run request-shape and zero-I/O tests and confirm GREEN.

## Task 3: Bind SigV4 to the actual request and write digest

**Files:**
- Modify: `warpin-object-storage/src/s3_adapter.rs`
- Modify: `warpin-object-storage/src/tests.rs`

- [ ] Add RED tests for missing/conflicting Host, noncanonical authority/port, wrong method/URI, missing PUT binding, wrong PUT digest, wrong GET empty digest, KMS-key signed-header presence mismatches, and extra signed KMS keys.
- [ ] Pass actual URI, method, and `ObserverRequestBinding` into SigV4 verification.
- [ ] Require Host to equal the exact normalized URI authority.
- [ ] Require PUT content SHA to equal the private `WriteBinding` digest raw hex and GET to equal the SHA-256 of empty content.
- [ ] Require KMS key header and signed-header membership together when configured, and require both absent otherwise.
- [ ] Remove the noncryptographic repeated-signature heuristic and use realistic signature fixtures.
- [ ] Re-run focused observer tests and confirm GREEN with real `object_store` 0.14.0 request shape.

## Task 4: Separate every KES secret mount

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`
- Modify: `warpin-object-storage/README.md`

- [ ] Extend the shell self-check with RED assertions for server/bootstrap/runtime/metrics directory and mount separation.
- [ ] Mount only server config/certificate/key plus keystore into KES server.
- [ ] Run bootstrap and metrics as distinct one-shot clients with only their own certificate/key and server trust.
- [ ] Mount only runtime certificate/key into MinIO.
- [ ] Inspect exact mount sets and reject wildcard or cross-identity visibility.
- [ ] Preserve strict cleanup behavior and run self-check GREEN.

## Task 5: Public documentation and immutable verification

**Files:**
- Modify: `warpin-object-storage/README.md`
- Modify: `warpin-object-storage/MIGRATION.md`

- [ ] State that EKS full URI, IRSA/web identity, token-file credentials, custom STS, and trusted credential origins are unsupported in 0.2.0.
- [ ] State that any future support requires a typed, self-owned, pinned credential provider; Astro R4 does not promise EKS/IRSA.
- [ ] Document exact IMDSv2/ECS and SigV4 contracts plus KES mount separation.
- [ ] Run fmt, crate all-feature/no-default check/test/clippy/doc gates, then workspace check/test/clippy.
- [ ] Run fresh MinIO/KES two-object/two-restart-read/full-cleanup gate.
- [ ] Run package, dry-run publish, unpacked external consumer, removed-API and forge compile-fail probes, and tree/archive scans.
- [ ] Commit once, regenerate the package from the clean commit, and prove `.cargo_vcs_info.json` SHA/dirty state matches HEAD before reporting checksums.
