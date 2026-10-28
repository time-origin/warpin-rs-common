# warpin-rs-common 0.2.10

## Unified version

All 15 workspace members inherit version `0.2.10` from the root manifest.
All internal Warpin dependency requirements are managed in workspace.dependencies
at the same version. Third-party dependency requirements and features are unchanged.

This release includes the previously published HTTP status preservation,
Integrity document/object-table codecs, raw Kafka records and bounded object
storage streaming APIs. Existing local 409/422 ServiceError and ApiError
constructors and their regression tests are also included.
The object-storage shell self-check now accepts BSD wc whitespace padding
without relaxing byte-count or file-integrity validation.

## Development candidate

`warpin-workspace` is included at the unified version for its first publication.
It remains a development candidate, not production qualified. See its README
for required Linux management-plane and PostgreSQL validation. Version alignment
is not a production-readiness statement.

## Consumer migration

Update only the Warpin crates already used by the consuming application to
`0.2.10` in its root workspace.dependencies, regenerate and commit its lockfile,
and run its full checks. Consume crates.io releases, never local path overrides.
No HTTP/TCP/UDP/MQTT/Modbus protocol expansion is included in this release.

## Validation scope

Version and lockfile checks cover all 15 members. Release checks use formatting,
all-target/all-feature Clippy, workspace all-feature tests and build, and
`cargo tree -d`. Live PostgreSQL, MinIO/KES and Linux privileged integration
gates require their dedicated environments; ignored tests are not live-gate passes.
`cargo-audit` is unavailable on this host and was not run.
The library repository continues to ignore its local Cargo.lock; consuming
application repositories must track their own lockfiles.

Verified locally: 310 tests/doctests passed, 12 ignored, zero failures.
Formatting, all-target/all-feature Clippy and all-feature build passed.
Shell verification used Bash 5.3 and GNU coreutils 9.7 from temporary tools.
