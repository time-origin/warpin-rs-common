# warpin-rs-common Unified 0.2.5 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Publish all 14 warpin-rs-common crates at version 0.2.5, then migrate every existing AstroNexus warpin dependency requirement to the published 0.2.5 release.

**Architecture:** The public workspace owns one version through workspace.package, while member crates inherit it and internal path dependencies carry the same registry version. Publication proceeds in dependency layers, waiting for crates.io visibility between layers; AstroNexus moves only after the complete public set is available.

**Tech Stack:** Rust 2024, Cargo workspaces, crates.io, jq, SHA-256 release evidence, AstroNexus Rust workspace.

## Global Constraints

- The release version is exactly 0.2.5.
- The public release contains exactly 14 workspace members, including warpin-object-storage and the first crates.io release of warpin-dingtalk.
- Every member crate uses version.workspace = true.
- Every internal warpin dependency declares registry version 0.2.5 and retains its workspace path only in warpin-rs-common.
- AstroNexus uses crates.io dependencies only; local paths, patch sections, copied public source, and unpublished compatibility shims are forbidden.
- Existing feature selections remain unchanged.
- No upload occurs before local verification and independent review report P0 = 0 and P1 = 0.
- Publishing is sequential and irreversible; registry visibility is confirmed before publishing a dependent layer.
- The reviewed warpin-object-storage credential, encryption, integrity, KES, privacy, and fail-closed contracts must remain unchanged.
- No unrelated API redesign, third-party dependency upgrade, Git push, tag, or GitHub release is in scope.

---

### Task 1: Prove the mixed-version state and unify the public manifests

**Files:**
- Modify: Cargo.toml
- Regenerate locally: Cargo.lock (intentionally ignored by this library repository)
- Modify: warpin-integrity/Cargo.toml
- Modify: warpin-types/Cargo.toml
- Modify: warpin-object-storage/Cargo.toml
- Modify: warpin-event-bus/Cargo.toml

**Interfaces:**
- Consumes: the 14-member workspace and existing crates.io maximum version 0.2.4.
- Produces: one local public workspace whose package versions and internal dependency requirements are all 0.2.5.

- [ ] **Step 1: Run the version contract against the current tree and require RED**

    cargo metadata --format-version 1 --no-deps |
      jq -e '([.packages[] | select(.name | startswith("warpin-"))] | length == 14) and
             ([.packages[] | select(.name | startswith("warpin-")) | .version] |
              all(.[]; . == "0.2.5"))'

Expected: exit status 1 because the current tree contains 0.1.1, 0.2.0, 0.2.3, and 0.2.4 member versions.

- [ ] **Step 2: Apply the exact manifest contract**

Set workspace.package.version to 0.2.5. Set the workspace dependency versions for warpin-types, warpin-errors, warpin-config, warpin-dingtalk, and warpin-integrity to 0.2.5. Replace the four explicit member versions with:

    version.workspace = true

No source, feature, or third-party dependency entry changes in this task.

- [ ] **Step 3: Regenerate the ignored local lockfile through Cargo**

    cargo check --workspace --all-targets --all-features

Expected: success and local workspace package entries at 0.2.5. Cargo.lock is
used by the locked verification commands but remains ignored and is not added
to the release commit.

- [ ] **Step 4: Run the unified member and internal dependency contracts and require GREEN**

    cargo metadata --format-version 1 --no-deps |
      jq -e '([.packages[] | select(.name | startswith("warpin-"))] | length == 14) and
             ([.packages[] | select(.name | startswith("warpin-")) | .version] |
              all(.[]; . == "0.2.5")) and
             ([.packages[].dependencies[] |
                select(.name | startswith("warpin-")) | .req] |
              all(.[]; . == "^0.2.5"))'

    if rg -n '^version\s*=\s*"' --glob '*/Cargo.toml'; then
      echo 'member-specific package version found' >&2
      exit 1
    fi
    git diff --check

Expected: JSON true, no member-specific package version, and no whitespace error.

- [ ] **Step 5: Commit the unified public manifests**

    git add Cargo.toml \
      warpin-integrity/Cargo.toml warpin-types/Cargo.toml \
      warpin-object-storage/Cargo.toml warpin-event-bus/Cargo.toml
    git commit -m "release: unify public crates at 0.2.5"

Expected: one version-only release commit.

### Task 2: Verify the complete public workspace and security candidate

**Files:**
- Verify: all public Rust sources and tests
- Verify: warpin-object-storage/scripts/minio-kes-live-gate.sh

**Interfaces:**
- Consumes: the clean unified 0.2.5 commit from Task 1.
- Produces: fresh local correctness and security evidence suitable for independent review.

- [ ] **Step 1: Run mandatory workspace gates**

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Expected: every command exits 0; clippy emits no warning.

- [ ] **Step 2: Exercise every supported object-storage feature shape**

    cargo check -p warpin-object-storage --no-default-features --locked
    cargo test -p warpin-object-storage --no-default-features --locked
    cargo test -p warpin-object-storage --no-default-features --features fs --locked
    cargo test -p warpin-object-storage --no-default-features --features aws --locked
    cargo test -p warpin-object-storage --all-features --locked
    cargo clippy -p warpin-object-storage --all-targets --all-features --locked -- -D warnings

Expected: every supported feature combination succeeds.

- [ ] **Step 3: Run the KES security self-check and live gate**

    ./warpin-object-storage/scripts/minio-kes-live-gate.sh --self-check
    ./warpin-object-storage/scripts/minio-kes-live-gate.sh

Expected: self-check success; the live gate writes and reads two encrypted objects across two MinIO restarts and reports complete cleanup without residual containers, networks, or secret artifacts.

- [ ] **Step 4: Confirm release-tree integrity**

    git diff --check
    test -z "$(git status --short)"
    git rev-parse HEAD
    git rev-parse HEAD^{tree}
    git archive --format=tar HEAD | sha256sum

Expected: clean tree and recorded commit, tree, and archive hashes.

### Task 3: Package and dry-run every dependency-root crate

**Files:**
- Generate: target/package/warpin-*-0.2.5.crate

**Interfaces:**
- Consumes: the clean, verified public release commit.
- Produces: verified Layer 0 archives that have no unpublished internal dependency.

- [ ] **Step 1: Reconfirm registry availability immediately before packaging**

Run cargo info --registry crates-io NAME@0.2.5 for all 14 names.

Expected before first upload: every exact version is not found. If any version exists, stop and compare registry checksum and source provenance; never overwrite or assume ownership of an existing archive.

- [ ] **Step 2: Package and dry-run the ten Layer 0 crates**

For each package in this order, run cargo package --locked -p NAME followed by cargo publish --dry-run --locked -p NAME:

    warpin-integrity
    warpin-types
    warpin-errors
    warpin-config
    warpin-grpc
    warpin-auth
    warpin-observability
    warpin-storage
    warpin-event-bus
    warpin-capability

Expected: every package verification and publish dry-run succeeds without upload.

- [ ] **Step 3: Inspect package metadata and local path elimination**

For each generated archive, inspect its normalized Cargo.toml with tar and require package version 0.2.5. Any registry dependency on another warpin crate must have version requirement ^0.2.5 and must not rely on a local path. Record:

    sha256sum target/package/warpin-*-0.2.5.crate

Expected: valid normalized manifests and a checksum for every generated Layer 0 archive.

### Task 4: Complete independent pre-publish review

**Files:**
- Review: public branch diff from the last independently approved object-storage commit through the unified release commit

**Interfaces:**
- Consumes: Tasks 1 through 3 evidence and package archives.
- Produces: explicit P0/P1/P2 findings and PUBLISH GO or NO-GO.

- [ ] **Step 0: Verify first-publication security and legal packaging gates**

    cargo test -p warpin-dingtalk --all-features --locked

Require secret-bearing configuration, cached tokens, OAuth payloads, request
URLs, provider response bodies, and provider messages to remain absent from
all tested `Debug`, `Display`, transport, decode, HTTP-status, and OAPI error
paths. Require every one of the 14 package archives to contain the exact MIT
license text, and require the first `warpin-dingtalk` archive to contain its
README and normalized `readme = "README.md"` metadata.

Expected: sentinel leakage count is zero; all package license hashes match; the
DingTalk README and security contract are present in the archive.

Also require outbound endpoint and transport tests to prove, before sensitive
egress, that the default client accepts only official HTTPS origins; explicit
private origins are purpose-bound; request routes reject absolute references,
dot segments, encoded ambiguity, and base-path escape; redirects are never
followed; connect/request/read timeouts are bounded; concurrent token misses
atomically bind to one immutable generation result (success or typed failure),
every waiter has a fixed whole-operation deadline, supervised panic/cancellation
releases the generation, and provider token TTL arithmetic is bounded;
all provider JSON decode paths enforce streaming hard byte limits; arbitrary
HTTP-client injection is absent; and signed attachment URLs and untrusted
provider fields cannot enter `Debug` output.

- [ ] **Step 1: Run Functional Verification independently**

Verify member count, version consistency, internal dependency requirements, workspace gates, object-storage security gates, package contents, normalized manifests, checksums, and the unpublished state of all 14 exact versions.

Expected: no unexplained missing test, version drift, path leak, or security regression.

- [ ] **Step 2: Run Independent Code Review**

Review correctness, crates.io immutability handling, dependency ordering, first-publication metadata for warpin-dingtalk, feature compatibility, secret leakage, and the final release diff.

Expected: P0 = 0 and P1 = 0. Any P0 or P1 returns to the owning task and repeats all affected verification.

- [ ] **Step 3: Run the repository Codex adversarial review workflow**

Run the codex-review skill against the release diff. A timeout without a final verdict is recorded as INCONCLUSIVE and never represented as a pass; any concrete finding must be resolved or explicitly dispositioned before publication.

### Task 5: Publish Layer 0 and wait for registry visibility

**Files:**
- External state: crates.io releases for ten Layer 0 packages

**Interfaces:**
- Consumes: a clean release commit and P0/P1-free pre-publish review.
- Produces: ten immutable crates.io 0.2.5 roots that unblock dependent package verification.

- [ ] **Step 1: Publish each root package sequentially**

For each Layer 0 package in Task 3 order, run:

    cargo publish --locked -p NAME
    cargo info --registry crates-io NAME@0.2.5

Expected: upload success followed by exact registry visibility. Do not start the next package until the current package is visible.

- [ ] **Step 2: Record partial-publication state after every upload**

Maintain an evidence list containing package name, version, local crate SHA-256, publication result, and registry visibility. If an upload fails, stop the current layer, preserve the successfully published list, fix only the blocker, and resume at the first unpublished package.

### Task 6: Package, verify, and publish dependent layers

**Files:**
- Generate: dependent target/package/warpin-*-0.2.5.crate archives
- External state: four dependent crates.io releases

**Interfaces:**
- Consumes: registry-visible Layer 0 dependencies at 0.2.5.
- Produces: complete 14-package public release.

- [ ] **Step 1: Verify and publish Layer 1 sequentially**

For warpin-object-storage, warpin-context, and warpin-dingtalk in that order, run:

    cargo package --locked -p NAME
    cargo publish --dry-run --locked -p NAME
    sha256sum target/package/NAME-0.2.5.crate
    cargo publish --locked -p NAME
    cargo info --registry crates-io NAME@0.2.5

Expected: package and dry-run resolve the newly published dependency; upload succeeds and becomes visible before the next package.

- [ ] **Step 2: Verify and publish Layer 2**

    cargo package --locked -p warpin-http
    cargo publish --dry-run --locked -p warpin-http
    sha256sum target/package/warpin-http-0.2.5.crate
    cargo publish --locked -p warpin-http
    cargo info --registry crates-io warpin-http@0.2.5

Expected: warpin-http resolves warpin-config and warpin-errors at 0.2.5, publishes, and becomes visible.

- [ ] **Step 3: Verify the complete public set**

Run exact cargo info checks for all 14 NAME@0.2.5 versions and record the registry checksum of each.

Expected: exactly 14 successful exact-version lookups and no unpublished workspace member.

### Task 7: Move AstroNexus to the complete registry release

**Files:**
- Modify: /home/gyq/workspace/projects/astro_nexus_cloud/.worktrees/p1-runtime-r4-remediation/Cargo.toml
- Modify: /home/gyq/workspace/projects/astro_nexus_cloud/.worktrees/p1-runtime-r4-remediation/Cargo.lock

**Interfaces:**
- Consumes: all 14 crates.io packages visible at 0.2.5.
- Produces: an AstroNexus workspace with every existing direct warpin dependency requirement set to 0.2.5 and registry-resolved.

- [ ] **Step 1: Prove the business manifest is still mixed and require RED**

    test "$(rg -c '^warpin-[a-z-]+\s*=' Cargo.toml)" = \
         "$(rg -c '^warpin-[a-z-]+\s*=.*0\.2\.5' Cargo.toml)"

Expected: failure because the current requirements include 0.1.0, 0.1.1, 0.2.2, and 0.2.4.

- [ ] **Step 2: Change every existing root requirement to 0.2.5**

Set all 13 existing warpin dependency entries to 0.2.5. Preserve:

    warpin-object-storage = { version = "0.2.5", features = ["aws", "fs"] }

Do not add an unused warpin-dingtalk business dependency.

- [ ] **Step 3: Resolve only from crates.io and regenerate the lockfile**

    for crate in \
      warpin-types warpin-errors warpin-config warpin-http \
      warpin-observability warpin-grpc warpin-auth warpin-storage \
      warpin-context warpin-event-bus warpin-capability \
      warpin-integrity warpin-object-storage
    do
      cargo update -p "$crate" --precise 0.2.5
    done
    cargo metadata --format-version 1 > /tmp/astro-metadata.json

Expected: public modules resolve from the crates.io registry; no warpin package
has a path source, and unrelated lockfile packages are not opportunistically
upgraded.

- [ ] **Step 4: Require the business manifest and resolution contracts GREEN**

    test "$(rg -c '^warpin-[a-z-]+\s*=' Cargo.toml)" = \
         "$(rg -c '^warpin-[a-z-]+\s*=.*0\.2\.5' Cargo.toml)"
    jq -e '[.packages[] |
             select(.name | startswith("warpin-")) |
             select(.source != null) |
             {name, version, source}] |
           all(.[]; .version == "0.2.5" and
                     (.source | startswith("registry+")))' \
      /tmp/astro-metadata.json
    if rg -n '^\[patch\.|path\s*=.*warpin-rs-common' Cargo.toml; then
      exit 1
    fi

Expected: every existing direct requirement is 0.2.5 and every resolved public package is registry-backed at 0.2.5.

- [ ] **Step 5: Run AstroNexus minimum verification**

    cargo fmt --all -- --check
    cargo check --workspace --locked
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Expected: every command succeeds. Any pre-existing unrelated failure is separated with exact command and evidence; a release-induced failure blocks adoption.

- [ ] **Step 6: Commit the business dependency migration**

    git add Cargo.toml Cargo.lock
    git commit -m "build: align warpin crates at 0.2.5"

Expected: one dependency-only AstroNexus commit.

### Task 8: Final independent verification and release evidence

**Files:**
- Create: docs/releases/2026-07-16-warpin-rs-common-0.2.5.md
- Review: AstroNexus dependency-only commit

**Interfaces:**
- Consumes: complete crates.io release and verified AstroNexus adoption.
- Produces: auditable final release and Runtime R4 unblock evidence.

- [ ] **Step 1: Perform independent AstroNexus Functional Verification and Code Review**

Confirm registry-only resolution, exact versions, preserved object-storage features, lockfile consistency, no unrelated source change, and all minimum verification results.

Expected: P0 = 0 and P1 = 0 before adoption is declared complete.

- [ ] **Step 2: Write immutable release evidence**

Record public and AstroNexus commit SHAs; all 14 package names and versions; dependency-layer publication order; local crate SHA-256 values and registry checksums; exact verification outcomes; independent review dispositions; the Codex adversarial review result; clean-tree states; and the Runtime R4 dependency unblocked by the public release.

- [ ] **Step 3: Self-check and commit the evidence**

    if rg -n 'T[B]D|T[O]DO|F[I]XME|PLACEH[O]LDER' \
      docs/releases/2026-07-16-warpin-rs-common-0.2.5.md; then
      exit 1
    fi
    git diff --check
    git add docs/releases/2026-07-16-warpin-rs-common-0.2.5.md
    git commit -m "docs: record warpin-rs-common 0.2.5 release"

Expected: complete evidence with no placeholder and a clean public worktree after commit.
