# Verified Object Deletion and Unified 0.2.6 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish all `warpin-rs-common` crates as `0.2.6` with a context-, digest-, and version-bound verified object deletion API, then let AstroNexus Processing close its fenced orphan cleanup lifecycle.

**Architecture:** `warpin-object-storage` supplies only the reusable verified delete primitive. AstroNexus Processing owns the durable cleanup fact, mutable claim/lease state, retries, and immutable cleanup receipt. All deletion requests remain bound to the same contextual physical location used by immutable writes and verified reads.

**Tech Stack:** Rust 2024, `object_store 0.14.0`, Tokio, SeaORM/PostgreSQL, crates.io, Cargo workspaces.

## Global Constraints

- Publish every public crate at exactly `0.2.6`.
- Never expose a raw key-only delete operation.
- Never add an AstroNexus local `path` or `[patch.crates-io]` dependency.
- Processing must preserve immutable source facts and write separate mutable claim state and immutable terminal receipts.
- A stale cleanup worker must not delete or acknowledge an object.
- `akr-fusion-analyze` remains unchanged.

---

### Task 1: Public verified deletion contract

**Files:**
- Modify: `warpin-object-storage/src/contract.rs`
- Modify: `warpin-object-storage/src/lib.rs`
- Test: `warpin-object-storage/src/tests.rs`

**Interfaces:**
- Produces: `VerifiedObjectDelete`, `ObjectDeleteOutcome`, and `ObjectDeleteReceipt`.
- Consumes: existing `ObjectKey`, `ArtifactEncryptionContextId`, and `Sha256Digest`.

- [ ] **Step 1: Write failing public contract tests**

Add tests that construct `VerifiedObjectDelete`, compare typed outcomes, and
assert redacted debug output contains no raw key/context sentinel.

- [ ] **Step 2: Run the focused tests and observe the missing-type failure**

Run: `cargo test -p warpin-object-storage verified_delete --all-features`

Expected: compilation fails because the three public delete types do not exist.

- [ ] **Step 3: Implement the three public types and redacted Debug**

Define exact context/key/digest/version fields and re-export them from
`warpin-object-storage/src/lib.rs`.

- [ ] **Step 4: Run the focused tests**

Run: `cargo test -p warpin-object-storage verified_delete --all-features`

Expected: contract and debug tests pass.

- [ ] **Step 5: Commit**

```bash
git add warpin-object-storage/src/contract.rs warpin-object-storage/src/lib.rs warpin-object-storage/src/tests.rs
git commit -m "feat(object-storage): define verified deletion contract"
```

### Task 2: Verified delete storage operation

**Files:**
- Modify: `warpin-object-storage/src/storage.rs`
- Modify: `warpin-object-storage/src/s3_adapter.rs`
- Test: `warpin-object-storage/src/tests.rs`

**Interfaces:**
- Consumes: `VerifiedObjectDelete`.
- Produces: `VerifiedObjectStorage::delete_verified(...) -> Result<ObjectDeleteReceipt, ObjectStorageError>`.

- [ ] **Step 1: Write failing behavior tests**

Cover matching delete, exact replay, wrong context, wrong digest, wrong
version, concurrent replay convergence, and absence after deletion.

- [ ] **Step 2: Run focused tests and observe the missing-method failure**

Run: `cargo test -p warpin-object-storage delete_verified --all-features`

Expected: compilation fails because `VerifiedObjectStorage::delete_verified`
does not exist.

- [ ] **Step 3: Implement verified read-before-delete**

Resolve the contextual location, perform `read_verified` with the exact
version, return `AlreadyAbsent` for `NotFound`, issue one backend delete after
verification, and map backend failures to typed redacted errors.

- [ ] **Step 4: Bind managed S3 DELETE requests**

Extend the private observer operation binding so managed DELETE requests must
match the expected method, authority, contextual path, and optional exact
version before the connector sends them.

- [ ] **Step 5: Run focused and crate tests**

Run:

```bash
cargo test -p warpin-object-storage delete_verified --all-features
cargo test -p warpin-object-storage --all-features
```

Expected: all tests pass; the live MinIO/KES test remains explicitly ignored
unless its environment is supplied.

- [ ] **Step 6: Commit**

```bash
git add warpin-object-storage/src/storage.rs warpin-object-storage/src/s3_adapter.rs warpin-object-storage/src/tests.rs
git commit -m "feat(object-storage): delete only verified contextual objects"
```

### Task 3: Unified public version 0.2.6

**Files:**
- Modify: `Cargo.toml`
- Modify: all public crate manifests through workspace dependency versions
- Create: `docs/releases/2026-07-16-warpin-rs-common-0.2.6.md`

**Interfaces:**
- Produces: all public crates at version `0.2.6`.

- [ ] **Step 1: Add a failing version consistency check**

Run a script that asserts the workspace package and every internal
`warpin-*` dependency is `0.2.6`.

Expected: failure while the workspace remains `0.2.5`.

- [ ] **Step 2: Upgrade workspace and internal dependency versions**

Change `workspace.package.version` and every internal dependency version from
`0.2.5` to `0.2.6`.

- [ ] **Step 3: Add release notes**

Document the verified delete API, Processing adoption requirement, compatibility,
and publication order.

- [ ] **Step 4: Verify packages**

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all commands exit zero.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml docs/releases/2026-07-16-warpin-rs-common-0.2.6.md
git commit -m "release: unify public crates at 0.2.6"
```

### Task 4: Publish and verify public crates

**Files:**
- No source changes unless packaging verification finds a defect.

**Interfaces:**
- Produces: crates.io versions `0.2.6` for every workspace crate.

- [ ] **Step 1: Run package dry-runs in dependency order**

Use `cargo publish --dry-run -p <crate>` for all workspace crates in the same
order used for `0.2.5`.

- [ ] **Step 2: Publish dependency layers**

Publish foundational crates first, wait for crates.io visibility, then publish
dependent crates. Never use `--no-verify`.

- [ ] **Step 3: Verify crates.io**

Run `cargo info <crate>@0.2.6` for every published crate and confirm the
reported version and repository metadata.

- [ ] **Step 4: Push public repository branch**

Fetch, verify the remote base is an ancestor, then push the release branch and
update `main` only by non-force fast-forward or reviewed merge.

### Task 5: AstroNexus Processing orphan cleanup lifecycle

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `services/processing-service/src/artifact_storage.rs`
- Modify: `services/processing-service/src/external_job_store.rs`
- Modify: `services/processing-service/src/external_job_store_tests.rs`
- Modify: `services/processing-service/src/migrations.rs`
- Modify: `services/processing-service/src/state.rs`

**Interfaces:**
- Consumes: `warpin-object-storage 0.2.6` verified delete API.
- Produces: durable claim, retry, and terminal receipt behavior for every orphan cleanup fact.

- [ ] **Step 1: Write failing migration and lifecycle tests**

Prove claim uniqueness, monotonically increasing fencing, stale-worker
rejection, transient retry, exact replay, immutable receipt, restart recovery,
and tenant/space isolation.

- [ ] **Step 2: Run focused Processing tests and observe failures**

Run the exact new PostgreSQL tests with
`PROCESSING_TEST_DATABASE_URL`.

Expected: failures because cleanup state, receipt tables, and repository
operations do not exist.

- [ ] **Step 3: Add append-only migration**

Add mutable cleanup work state keyed by the immutable source fact and an
immutable terminal receipt table. Add constraints for state transitions,
leases, fencing tokens, digest/version identity, and scoped foreign keys.

- [ ] **Step 4: Add storage adapter deletion**

Wrap the public `delete_verified` API in `ProcessingArtifactStorage` using
`ArtifactStorageScope`, expected digest, and expected version.

- [ ] **Step 5: Implement claim, execute, retry, and receipt transactions**

Claim with database time and `SKIP LOCKED`, validate the current fence before
storage I/O, revalidate the fence before recording success, persist retry state
for transient failures, and preserve the immutable source fact.

- [ ] **Step 6: Supervise the cleanup worker**

Start the bounded worker from Processing state only when the database and
artifact storage are configured. Expose readiness as unhealthy on fatal
invariant failures without logging object keys or backend bodies.

- [ ] **Step 7: Run focused tests**

Run all new PostgreSQL lifecycle tests and memory-storage deletion tests.

Expected: all pass.

### Task 6: AstroNexus verification, review, merge, and cleanup

**Files:**
- Modify only files required by review findings.

**Interfaces:**
- Produces: reviewed `main` containing AKR and R4 while preserving `akr-fusion-analyze`.

- [ ] **Step 1: Run required AstroNexus verification**

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 -m compileall services/langgraph-orchestrator-service/app
bash contracts/tests/contract_tests/run_runtime_r4_closure.sh
```

- [ ] **Step 2: Run functional verification and independent review**

Apply the Processing, Governance, tenant isolation, replay, retry, and audit
checklists. Resolve every reproducible P0/P1.

- [ ] **Step 3: Run Codex adversarial review**

Run `codex review --uncommitted` against the exact staged merge candidate and
resolve every reproducible P0/P1.

- [ ] **Step 4: Commit and push AstroNexus main**

Verify both `akr-fusion-analyze` and the R4 branch are ancestors, fetch remote
state, commit the merge, and push `main` without force.

- [ ] **Step 5: Cleanup only task-owned worktrees and branches**

Remove the temporary public and AstroNexus integration worktrees and merged
task branches. Preserve `akr-fusion-analyze` locally and remotely and preserve
the saved R4 stash.
