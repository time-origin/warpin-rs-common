# KES One-Shot Ledger Ordering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the untracked-container interruption window by registering every validated one-shot KES container name before Docker create is allowed.

**Architecture:** The live gate owns a private append-only ledger of internally generated Docker-safe names. Name validation and reliable single-line registration precede every Docker side effect; create failures leave harmless ledger entries, while any interruption after create is recoverable by the existing trap. Shell failure injection exercises each boundary without sleep-based timing.

**Tech Stack:** Bash 5, Docker CLI, MinIO/KES live fixtures, Rust 2024 Cargo workspace.

## Global Constraints

- Baseline is clean commit `1e8031d6129cc02a41820c570d5fb6627623cd8a`; it becomes RED evidence and is not the final candidate.
- Modify only `warpin-object-storage/scripts/minio-kes-live-gate.sh`, `warpin-object-storage/README.md`, and this plan when documentation is required.
- Do not modify AstroNexus, publish, merge, or run Codex review.
- Do not use sleep or processing delay to close the create-to-ledger race.
- Preserve exact `object_store = "=0.14.0"` and all existing public encryption-contract behavior.

---

### Task 1: Prove the create-before-ledger interruption window

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: existing `run_kes_client`, `cleanup_best_effort`, `ONE_SHOT_LEDGER`.
- Produces: self-check failure injection for `ledger-append-failure`, `create-failure`, `create-empty-id`, and `after-create-interruption`.

- [x] **Step 1: Add failure-state recording and a post-create injection hook**

Use a self-check-only fake Docker state directory outside `WORK_DIR` so the simulated trap may remove `WORK_DIR` without erasing evidence of an unremoved container. Add a default no-op hook used immediately after successful `docker create`:

```bash
after_one_shot_create() {
    :
}
```

Override it inside `self_check` so `after-create-interruption` invokes `cleanup_best_effort` and returns status 130.

- [x] **Step 2: Add the RED interruption assertion**

```bash
fake_docker_state='after-create-interruption'
if run_kes_client metrics metric >/dev/null 2>&1; then
    echo 'self-check accepted an interrupted one-shot create' >&2
    return 1
fi
if [[ -e "${fake_container_marker}" ]]; then
    echo 'self-check left an unregistered interrupted container' >&2
    return 1
fi
```

- [x] **Step 3: Run RED twice**

Run:

```bash
./warpin-object-storage/scripts/minio-kes-live-gate.sh --self-check
./warpin-object-storage/scripts/minio-kes-live-gate.sh --self-check
```

Expected on baseline ordering: both runs fail because the fake container exists but its name was not yet present in `ONE_SHOT_LEDGER` when cleanup executed.

---

### Task 2: Register a validated name before Docker create

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: names from `allocate_one_shot_container_name`.
- Produces: `validate_one_shot_container_name NAME IDENTITY` and `register_one_shot_container NAME IDENTITY`.

- [x] **Step 1: Add focused registration boundary tests**

The self-check must assert:

```text
registration succeeds + create fails -> ledger retains one valid name
registration succeeds + create returns empty id -> ledger retains the name and cleanup removes the fake container
ledger append fails -> docker create call count remains zero
after-create interruption -> trap removes the ledger-registered fake container
newline, slash, leading punctuation, wrong prefix, and overlong names -> registration fails
```

- [x] **Step 2: Verify the new focused tests fail under the old ordering/API**

Run:

```bash
./warpin-object-storage/scripts/minio-kes-live-gate.sh --self-check
```

Expected: FAIL because create occurs before registration or because the registration validator does not exist.

- [x] **Step 3: Implement strict name validation and append**

```bash
validate_one_shot_container_name() {
    local client_name="$1"
    local identity_name="$2"
    [[ "${client_name}" == "${KES_ONE_SHOT_PREFIX}-${identity_name}-"* ]] \
        && [[ "${client_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]
}

register_one_shot_container() {
    local client_name="$1"
    local identity_name="$2"
    validate_one_shot_container_name "${client_name}" "${identity_name}" \
        || return 1
    if [[ -e "${ONE_SHOT_LEDGER}" && ! -f "${ONE_SHOT_LEDGER}" ]]; then
        return 1
    fi
    local next_ledger
    next_ledger="$(mktemp "${WORK_DIR}/one-shot-containers.next.XXXXXX")" \
        || return 1
    if [[ -f "${ONE_SHOT_LEDGER}" ]] \
        && ! cp -- "${ONE_SHOT_LEDGER}" "${next_ledger}"; then
        rm -f -- "${next_ledger}"
        return 1
    fi
    if ! printf '%s\n' "${client_name}" >>"${next_ledger}" \
        || ! mv -f -- "${next_ledger}" "${ONE_SHOT_LEDGER}"; then
        rm -f -- "${next_ledger}"
        return 1
    fi
}
```

- [x] **Step 4: Reorder `run_kes_client`**

The exact state transition must be:

```text
allocate internal name
validate and append one ledger line
docker create
post-create hook / mount inspection / start
explicit docker rm
verified cleanup checks every ledger line
```

If append fails, emit a structured error and return before `docker create`. If create fails or returns an empty ID, retain the ledger entry; removal of a nonexistent name is safe.

- [x] **Step 5: Run focused GREEN twice**

Run the shell self-check twice. Expected: `minio_kes_live_gate_self_check=true` twice, with every failure injection accepted only as a fail-closed path.

---

### Task 3: Preserve the live security path and document the invariant

**Files:**
- Modify: `warpin-object-storage/README.md`
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: pre-create ledger registration from Task 2.
- Produces: two independent live PASS matrices and documentation of the trap invariant.

- [x] **Step 1: Record candidate-owned resource baseline**

Capture names matching the gate's container/network prefixes and count `/tmp/warpin-minio-kes-gate.*`. Do not delete or change the five pre-existing shared directories.

- [x] **Step 2: Run fresh live twice**

```bash
./warpin-object-storage/scripts/minio-kes-live-gate.sh
./warpin-object-storage/scripts/minio-kes-live-gate.sh
```

Each run must report:

```text
context_bound_physical_objects=2
exact_version_post_restart_reads=2
consecutive_metrics_snapshots=12
ephemeral_resources_cleaned=true
```

- [x] **Step 3: Compare post-run resource delta**

Expected: no new matching containers, networks, or `/tmp/warpin-minio-kes-gate.*` directories relative to the recorded baseline.

- [x] **Step 4: Update README**

Document that a validated single-line name is registered before create; absent containers in the ledger are harmless; and every post-create exit, signal, or failure is recoverable by trap-driven ledger cleanup.

---

### Task 4: Run release gates and create a new immutable candidate

**Files:**
- Verify: entire Cargo workspace
- Package: `warpin-object-storage`

**Interfaces:**
- Consumes: final clean diff from Tasks 1-3.
- Produces: new commit and independently reproducible package provenance.

- [x] **Step 1: Run complete pre-commit gates**

Run `cargo fmt --all -- --check`; crate all-features and no-default-features check/test/clippy/doc; workspace check/test/clippy; shell syntax/self-check; secret and removed-pattern scans.

- [ ] **Step 2: Commit only the scoped files**

```bash
git add docs/superpowers/plans/2026-07-16-kes-one-shot-ledger-ordering.md \
  warpin-object-storage/README.md \
  warpin-object-storage/scripts/minio-kes-live-gate.sh
git commit -m "close KES one-shot registration race"
```

- [ ] **Step 3: Regenerate release evidence from the new clean HEAD**

Delete only stale generated `target/package/warpin-object-storage-0.2.0*`, then run `cargo package --locked` and `cargo publish --dry-run --locked` without uploading.

- [ ] **Step 4: Verify external consumers and forges**

Compile and run an unpacked normal consumer, prove `object_store v0.14.0`, and require all four negative forge cases to fail: removed import, removed settings method, forged encryption attestation construction, and forged verified receipt construction.

- [ ] **Step 5: Report immutable provenance**

Report new HEAD, tree SHA, `git archive` SHA-256, crate SHA-256, `.cargo_vcs_info.json`, exactly 15 package files, secret scan, and clean worktree status. Any failed gate prevents a completion claim.
