# warpin-rs-common 0.2.6

All public workspace crates are released at version `0.2.6`.

## Object storage lifecycle

`warpin-object-storage` adds a provider-neutral verified deletion contract:

- `VerifiedObjectDelete` binds the logical key, encryption context, SHA-256
  digest, and optional immutable backend version.
- `VerifiedObjectStorage::delete_verified` verifies the exact contextual
  object before deletion and returns a typed `ObjectDeleteReceipt`.
- Exact replays converge to `ObjectDeleteOutcome::AlreadyAbsent`.
- Digest, context, target, signature, and version mismatches fail closed.
- Managed S3 deletion uses the existing reviewed credential provider and
  transport boundary, signs a canonical exact-version `DELETE`, and requires
  the response version to match.
- Filesystem deletion synchronizes the surviving parent directory so absence
  is durable across restart.

The public crate deliberately does not expose a raw key-only delete operation.
Applications remain responsible for durable claims, leases, fencing, retry
policy, and immutable cleanup receipts.

## Compatibility

- Existing immutable write and verified read APIs remain source compatible.
- AstroNexus Processing must consume the published crates.io version and must
  not use a local path override or `[patch.crates-io]`.
- Managed S3 deployments must continue to pass the TLS MinIO/KES or native AWS
  compatibility gate. The ignored live gate now verifies exact-version cleanup
  and idempotent replay after restart.

## Publication order

Publish dependency layers in this order:

1. `warpin-integrity`, `warpin-types`
2. `warpin-errors`, `warpin-config`, `warpin-dingtalk`
3. `warpin-http`, `warpin-grpc`, `warpin-auth`, `warpin-context`,
   `warpin-observability`, `warpin-storage`, `warpin-object-storage`,
   `warpin-event-bus`, `warpin-capability`

Every crate must be visible from crates.io at `0.2.6` before dependent
application repositories are upgraded.
