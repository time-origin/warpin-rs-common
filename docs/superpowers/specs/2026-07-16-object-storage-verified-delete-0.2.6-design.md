# Verified Object Deletion and Unified 0.2.6 Release Design

## Context

AstroNexus Processing writes immutable artifacts through
`warpin-object-storage`. If a worker loses its fenced materialization lease
after an object write succeeds, Processing records an immutable orphan cleanup
fact. The current public storage contract supports verified immutable writes
and verified reads but cannot delete the obsolete object, so the fact cannot
progress to a durable cleanup receipt.

`warpin-object-storage 0.2.5` is already published and immutable. The public
workspace therefore requires a unified `0.2.6` release before AstroNexus can
close the cleanup lifecycle.

## Decision

Add one provider-neutral verified deletion operation to
`warpin-object-storage`:

```rust
pub struct VerifiedObjectDelete {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub expected_digest: Sha256Digest,
    pub expected_version: Option<String>,
}

pub enum ObjectDeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

pub struct ObjectDeleteReceipt {
    pub key: ObjectKey,
    pub context_id: ArtifactEncryptionContextId,
    pub digest: Sha256Digest,
    pub version: Option<String>,
    pub outcome: ObjectDeleteOutcome,
}

impl VerifiedObjectStorage {
    pub async fn delete_verified(
        &self,
        delete: VerifiedObjectDelete,
    ) -> Result<ObjectDeleteReceipt, ObjectStorageError>;
}
```

The operation resolves the physical location through the same
`ArtifactEncryptionContextId + ObjectKey` boundary as write and read. It first
performs an exact verified read, including the optional version. It deletes
only after digest, context, and version validation succeeds.

If the object is absent, the operation returns `AlreadyAbsent`, making an
exact cleanup replay idempotent. Digest or version mismatches fail closed and
must not issue a delete.

## Ownership Boundary

The public crate owns only safe object-store mechanics:

- typed context, key, digest, and version binding;
- verified-read-before-delete;
- provider-neutral typed outcome and receipt;
- redacted `Debug` and stable typed errors.

Processing owns lifecycle policy:

- immutable orphan cleanup facts;
- claim state, worker lease, lease fencing token, attempts, and backoff;
- tenant/space/job/attempt authority checks;
- durable terminal cleanup receipts;
- scheduler supervision, readiness, and audit metadata.

The public crate must not contain tenant policy, Processing table knowledge,
job scheduling, retry policy, or Governance semantics.

## Alternatives Considered

### Raw public delete by key

Rejected. A key-only operation could delete another tenant/context object or
delete content that has changed since the cleanup fact was recorded.

### Processing-local direct `object_store` usage

Rejected. It bypasses the published public storage boundary, duplicates
backend configuration and credential handling, and violates the public-module
reuse rule.

### Verified public deletion plus Processing lifecycle

Selected. It keeps the reusable safety primitive in the public crate while
preserving Processing as the content lifecycle authority.

## Concurrency and Backend Semantics

The portable `object_store` API does not expose an atomic compare-and-delete
primitive. Processing must therefore serialize cleanup with all writers that
could target the same contextual object, and immutable object keys must never
be reused for different content.

The public method verifies immediately before delete. A concurrent exact
delete converges to `Deleted` or `AlreadyAbsent`. A concurrent replacement is
outside the immutable-key contract; digest/version verification prevents a
known replacement from being deleted before the delete request is issued.

For a versioned backend, `expected_version` is mandatory for Processing orphan
facts created from a versioned write receipt. For an unversioned backend it is
`None`.

## Security and Observability

- No bucket, endpoint, signed URL, credential, content bytes, or provider body
  appears in public receipts, errors, or debug output.
- S3 delete requests continue through the reviewed managed transport and
  credential configuration.
- Processing persists only typed identifiers, digest, version fingerprint,
  outcome, attempt count, and timestamps.
- Cleanup errors are classified without formatting backend response bodies.

## Test Contract

Public crate tests must prove:

- matching context/key/digest/version deletes the object;
- exact replay returns `AlreadyAbsent`;
- wrong context cannot delete another contextual object;
- wrong digest preserves the object;
- wrong version preserves the object;
- concurrent exact deletes converge safely;
- public debug/error surfaces do not disclose sentinels.

Processing tests must prove:

- one worker claims an orphan fact with a monotonically increasing fence;
- stale workers cannot record success or delete an object;
- exact retries are idempotent;
- transient storage failures return the claim to retryable state;
- terminal success writes one immutable receipt while preserving the source
  fact;
- cross-tenant and cross-space claims are impossible;
- a restart can resume pending or expired cleanup claims.

## Release

All public crates use the workspace version and will be released together as
`0.2.6`. Internal workspace dependency versions must also become `0.2.6`.
Publication follows dependency order, verifies crates.io visibility, and then
AstroNexus upgrades every `warpin-*` dependency to `0.2.6`.
