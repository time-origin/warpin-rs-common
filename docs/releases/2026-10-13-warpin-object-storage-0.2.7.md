# warpin-object-storage 0.2.7

This release adds optional `streaming` APIs. Other public crates remain at
0.2.6; `warpin-integrity` is resolved from the published 0.2.6 dependency.

## Contract

- `put_chunked` accepts `AsyncRead` plus exact logical length/SHA-256 and a
  mandatory durable `ChunkWriteJournal`. Intents include physical key, context,
  digest, size and content type before I/O; outcomes preserve exact receipts.
- `warpin-chunked/v1` uses authenticated immutable chunks, bounded index pages
  and a final root. Managed writes retain the reviewed TLS/SigV4/MinIO-KES
  encryption observer and require exact version/ETag pins at every level.
- `ChunkedObjectReceipt.root.digest` describes the physical manifest.
  `content_digest` describes the complete logical file. Consumers must retain
  both identities and an explicit format discriminator.
- `open_chunked` returns an owned `Send + 'static` pull reader suitable for
  backpressure. A full read declares `WholeDigestVerified` only after EOF and
  incremental SHA-256 verification. A range declares `AuthenticatedRange`,
  authenticating complete containing chunks without claiming full-file rehash.
- Policy/context and missing managed pins are rejected before backend I/O.
  Each root/page/chunk is independently bounded and checks current encryption
  evidence, physical digest/length/version/ETag and inherited context.
- Logical limits use `with_max_streamed_object_bytes`. Physical limits remain
  separate; the format's structural ceiling is 16 TiB at 16 MiB per chunk.
- The final root uses the original logical key. An application retirement
  marker atomically created at that same key/context fences a late root commit.
  Failed/cancelled uploads leave journaled parts, never a success receipt.
  Shared parts require application reference accounting before verified cleanup.
- Existing immutable Bytes writes, verified legacy reads and exact deletion
  APIs remain supported. Upgrade readers before enabling chunked producers.

## Verification

The fixed candidate was verified on Linux with a repository-local Cargo cache:

- 82 library tests, one gate shell self-check and seven documentation tests.
- 41 tests with only `streaming` enabled and no default features.
- All-feature/all-target and no-default Clippy with warnings denied; format.
- Dedicated TLS MinIO/KES gate with a generated 256 MiB + 17 byte input:
  incremental write, idempotent replay, full read, cross-chunk and cross-page
  ranges, wrong pins/context rejection, MinIO restart and exact-version cleanup.
  Both live tests passed in both write/read phases; KES request deltas were
  1315 and 278. Ephemeral resources were verified removed.
- Registry-dependency `cargo package` verification and publish dry-run passed.

The fixed gate image (MinIO commit
`0d7408fc9969caf07de6a8c3a84f9fbb10a6739e`) authorizes versioned deletion through
both the base DeleteObject allowance and DeleteObjectVersion restrictions.
The gate principal now grants both actions only within its owned ephemeral
`r4-artifacts/live-gate/*` prefix. No production IAM policy was changed.
[Upstream authorization implementation](https://github.com/minio/minio/blob/0d7408fc9969caf07de6a8c3a84f9fbb10a6739e/cmd/auth-handler.go#L430)

Candidate source archive SHA-256:
`3ad034cf044f4198552957284bda5c7462ff402c8a00ed953e36e3d2db1d5245`.
Verified package SHA-256:
`b7d17119dab020ece845abe860dab0e0198dc0ffc5f217b30d2f49c7ee9a944d`.

These are synthetic library/adapter checks. They do not establish application
end-to-end streaming, a real production run, or power-loss fault tolerance.
