# warpin-rs-common 0.2.5 Unified Release Design

**Date:** 2026-07-16
**Status:** Approved design, pending implementation plan
**Owners:** Public Rust Modules, AstroNexus Runtime R4

## 1. Objective

Publish every crate in the `warpin-rs-common` workspace at one coherent version,
`0.2.5`, and then move every AstroNexus `warpin-*` dependency to that published
version. The release includes the already reviewed `warpin-object-storage`
security contract required by Runtime R4.

The release is complete only when crates.io exposes all 14 packages at `0.2.5`
and the AstroNexus business workspace resolves them without a path override or
local source copy.

## 2. Version Decision

The crates.io inventory performed on 2026-07-16 found that the highest existing
public version is `0.2.4`, used by `warpin-types` and `warpin-event-bus`.
Crates.io releases are immutable, so neither `0.2.3` nor `0.2.4` can be used as
the new unified release. `0.2.5` is not occupied and is therefore the next
valid patch version.

`warpin-dingtalk` is a workspace member but is not currently present on
crates.io. It is included in the unified release and will use `0.2.5` as its
first public version.

Every package archive must include the repository's MIT license text. Because
`warpin-dingtalk` is a first publication, its archive must also include a README
that documents its API purpose and secret-safe error and logging contract.

The DingTalk client treats configuration values, access tokens, request URLs,
provider response bodies, and provider messages as sensitive boundary data.
Its `Debug` implementations and returned `ServiceError` values may expose only
stable error kinds, numeric HTTP or provider codes, and retryability; sentinel
tests must prove that raw values cannot cross those boundaries.

Its outbound transport is fail closed: official HTTPS origins are the default;
private origins require an explicit purpose-bound trusted-origin policy; URL
userinfo, query, fragment, cross-origin path escape, redirects, ambient proxies,
unbounded timeouts, and arbitrary HTTP-client injection are forbidden. Public
provider/user-content DTOs do not implement `Debug`; signed URL DTOs expose
redacted debug output only.

## 3. Release Scope

The public release contains all workspace members:

1. `warpin-integrity`
2. `warpin-types`
3. `warpin-errors`
4. `warpin-config`
5. `warpin-http`
6. `warpin-grpc`
7. `warpin-auth`
8. `warpin-context`
9. `warpin-observability`
10. `warpin-storage`
11. `warpin-object-storage`
12. `warpin-event-bus`
13. `warpin-capability`
14. `warpin-dingtalk`

The business-side adoption scope is the active AstroNexus Runtime R4 worktree.
Every direct `warpin-*` dependency in its root workspace manifest will be pinned
to the published `0.2.5` release, and its lockfile will be regenerated through
Cargo. Feature selections remain unchanged.

## 4. Manifest Contract

The public workspace is the sole version authority:

```toml
[workspace.package]
version = "0.2.5"
```

Every member crate uses `version.workspace = true`. Explicit member versions
are removed so a future workspace release cannot silently produce mixed crate
versions.

Every internal public-module dependency keeps its local `path` for workspace
development and declares `version = "0.2.5"` for package publication. Cargo
therefore substitutes the crates.io dependency when packaging without allowing
the release archive to rely on a local path.

AstroNexus uses registry dependencies only. It must not add `[patch]`, local
`path`, vendored public-module source, or unpublished compatibility shims.

## 5. Dependency Topology and Publication Order

Publishing follows internal dependency layers. Packages in the same layer are
independent and may be published sequentially in any deterministic order.

### Layer 0: public-module roots

- `warpin-integrity`
- `warpin-types`
- `warpin-errors`
- `warpin-config`
- `warpin-grpc`
- `warpin-auth`
- `warpin-observability`
- `warpin-storage`
- `warpin-event-bus`
- `warpin-capability`

### Layer 1: single-root consumers

- `warpin-object-storage` depends on `warpin-integrity`
- `warpin-context` depends on `warpin-types`
- `warpin-dingtalk` depends on `warpin-errors`

### Layer 2: multi-root consumer

- `warpin-http` depends on `warpin-config` and `warpin-errors`

Before publishing a dependent layer, every required `0.2.5` dependency must be
visible through the crates.io registry. This prevents a package from being
uploaded with an unresolved public dependency.

## 6. Release Procedure

The release uses the following gates:

1. Confirm all 14 package names and verify that `0.2.5` is unoccupied.
2. Apply the unified workspace and internal dependency versions.
3. Regenerate the ignored public workspace lockfile as local verification
   input; the library repository intentionally does not commit `Cargo.lock`.
4. Run formatting, workspace check, tests, all-target/all-feature clippy, and
   package-content inspection.
5. Run `cargo package` and `cargo publish --dry-run` wherever the current
   registry state permits resolution.
6. Run an external consumer build against packaged or registry-resolved crates,
   including `warpin-object-storage` with its supported features.
7. Complete independent security and correctness review with no P0 or P1
   findings before the first upload.
8. Publish one dependency layer at a time and confirm registry visibility before
   continuing.
9. Confirm all 14 exact `name@0.2.5` versions through crates.io.
10. Update and verify AstroNexus only after the complete public release is
    visible.

`cargo publish` is irreversible. A partial release cannot be rolled back. If a
publish fails after earlier packages succeeded, the process records the exact
published set, fixes only the blocking package, repeats its package and review
gates, and resumes from the first unpublished package. Already published
archives are never overwritten.

## 7. Security and Compatibility Constraints

The version unification must not weaken the independently reviewed
`warpin-object-storage` security boundary. Its managed encryption enforcement,
credential restrictions, immutable integrity checks, KES verification, and
secret-safe diagnostics remain release gates.

This is a patch release of every crate. Existing public APIs and feature names
remain compatible unless a previously approved Runtime R4 security correction
requires fail-closed behavior. No unrelated dependency upgrades or API redesign
are part of the version-unification change.

The first `warpin-dingtalk` publication must pass the same package, license,
metadata, compile, test, clippy, and external-consumer checks as the existing
public crates.

## 8. Business-Side Adoption

After all public packages are visible, AstroNexus changes every root workspace
entry from its current mixed set (`0.1.1`, `0.1.0`, `0.2.2`, and `0.2.4`) to
`0.2.5`. Cargo updates the lockfile from crates.io.

Adoption acceptance requires:

- no `warpin-*` path dependency or local patch;
- all direct `warpin-*` manifest requirements equal `0.2.5`;
- all resolved direct public modules come from crates.io at `0.2.5`;
- Runtime R4 object-storage features remain enabled;
- AstroNexus minimum workspace verification passes; and
- no unrelated business dependency or source change is introduced by this
  release task.

## 9. Acceptance Criteria

The unified release is successful when all of the following are true:

- all 14 public manifests report version `0.2.5` from the workspace;
- all internal public-module dependency requirements are `0.2.5`;
- public workspace formatting, check, tests, and strict clippy pass;
- every crate package contains its required source, license, readme, and test or
  script assets without local-only paths;
- independent review reports P0 = 0 and P1 = 0;
- crates.io returns all 14 exact `0.2.5` releases;
- AstroNexus declares and resolves every direct public module at `0.2.5`;
- AstroNexus verification passes; and
- release evidence records package names, checksums, publication order,
  commands, and final registry state.

## 10. Non-Goals

This release does not redesign unrelated public APIs, upgrade unrelated
third-party dependencies, publish AstroNexus itself, push Git branches, create
GitHub releases, or introduce a general release platform. Those actions require
separate scope and authorization.
