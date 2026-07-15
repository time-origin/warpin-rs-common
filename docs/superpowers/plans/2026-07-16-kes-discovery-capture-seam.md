# KES Discovery Capture Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make discovery write/partial-failure self-checks deterministic for ordinary and privileged EUIDs without weakening the production byte-aware loader.

**Architecture:** `discover_labeled_one_shot_containers` retains private-workdir and regular-file preflight, then delegates only Docker stdout capture to a production `capture_labeled_one_shot_discovery PATH` seam. The production seam repeats the path/type preflight and writes real Docker stdout directly to the allowlisted file while discarding stderr. `self_check` replaces that seam only inside the short-lived self-check process so fixed nonzero capture outcomes cannot depend on DAC permissions.

**Tech Stack:** Bash 5, Docker CLI, sudo/capability probes, MinIO/KES live fixtures, Rust 2024 Cargo workspace.

## Global Constraints

- Baseline is clean commit `a79b369e561848efb317391db41e62309ab20936`; do not amend it.
- Modify only the public `warpin-rs-common` worktree; never modify AstroNexus.
- Do not publish, merge, or run Codex Review.
- Preserve the R10 byte matrix, R9 ledger and label fallback matrix, and R8 registration-before-create matrix.
- Preserve same-`WORK_DIR` allowlisting, lstat-style symlink/non-regular rejection, direct stdout file capture, silent stderr, exact byte counts, zero-byte success, and no malformed Docker operands.
- No EUID 0 skip or capability-dependent fixture is allowed.
- Preserve exact `object_store v0.14.0` behavior and the 15-file package contract.

---

### Task 1: Freeze the privileged-EUID regression

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: `discover_labeled_one_shot_containers OUTPUT_ARRAY`, self-check fake Docker state, and discovery temp tracking.
- Produces: deterministic capture-write and partial-failure tests that fail before the seam exists.

- [x] **Step 1: Record the untouched baseline behavior**

Run ordinary self-check twice and `sudo -n ... --self-check` twice. Require ordinary status 0 and privileged status 1 with exactly:

```text
self-check accepted unwritable discovery temp
self-check published names after unwritable discovery temp
```

- [x] **Step 2: Prove the permission-model root cause**

Create a root-owned mode-0400 probe, show EUID 0 and effective `CAP_DAC_OVERRIDE`, prove root writes it successfully, and prove the ordinary user cannot. This evidence scopes the defect to the fixture rather than `load_validated_one_shot_record_file`.

- [x] **Step 3: Add the desired capture-seam tests first**

Add a self-check-local replacement with this behavioral surface:

```bash
capture_labeled_one_shot_discovery() {
    local discovery_file="$1"
    case "${fake_docker_state}" in
        discovery-capture-write-failure)
            printf '%s\n' '--help' >"${discovery_file}"
            return 81
            ;;
        discovery-capture-partial-failure)
            printf '%s\n' "${fake_created_name}" >"${discovery_file}"
            printf '%s\n' 'FORBIDDEN_CAPTURE_SECRET_42' >&2
            return 82
            ;;
        *)
            docker container ls --all \
                --filter "${KES_ONE_SHOT_LABEL_FILTER}" \
                --format '{{.Names}}' \
                2>/dev/null >"${discovery_file}"
            ;;
    esac
}
```

Before installing the replacement, assert the production seam exists and directly exercise its real Docker-nonzero path. For each injected nonzero state, require discovery failure, zero published names, no derived Docker operand, no temp residue, no leaked sentinel, and verified cleanup failure when a simulated residual exists.

- [x] **Step 4: Replace the chmod fixture and retain non-regular coverage**

Delete `unwritable`; add a discovery FIFO fixture alongside mktemp failure, symlink, and directory. FIFO, symlink, and directory must fail before capture.

- [x] **Step 5: Run RED twice**

Run ordinary self-check twice. Both must fail because `capture_labeled_one_shot_discovery` is absent or unused; the failure must point at the new seam contract rather than the production loader.

---

### Task 2: Extract the production capture seam

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`
- Modify: `warpin-object-storage/README.md`

**Interfaces:**
- Produces: `capture_labeled_one_shot_discovery DISCOVERY_FILE`.
- Consumed by: `discover_labeled_one_shot_containers OUTPUT_ARRAY`.

- [x] **Step 1: Implement the minimal production seam**

Add an internal function that validates the private workdir and label contract, then preflights `DISCOVERY_FILE` through:

```bash
load_validated_one_shot_record_file \
    "${discovery_file}" require-existing empty_preflight
```

It must require zero existing records before executing real `docker container ls`, redirect stdout directly to the file, redirect stderr to `/dev/null` first, and return Docker/redirection status unchanged.

- [x] **Step 2: Route discovery through the seam**

Keep discovery's existing preflight before delegation. Call the seam with stderr suppressed; if it returns nonzero, remove the allowlisted temp and return nonzero before loading any record. Only capture success may reach the byte-aware loader.

- [x] **Step 3: Run GREEN in both privilege modes**

Run `bash -n`, ordinary self-check twice, and `sudo -n ... --self-check` twice. Every self-check must emit only `minio_kes_live_gate_self_check=true` and exit 0. Confirm no root-owned gate temp remains.

- [x] **Step 4: Document the seam contract**

Update the README to state that capture status gates parsing, self-check uses deterministic capture injection rather than filesystem DAC, and production still accepts only same-workdir preflighted regular files.

---

### Task 3: Re-run live and complete pre-commit verification

**Files:**
- Verify: entire Cargo workspace.

**Interfaces:**
- Consumes: Task 2 implementation.
- Produces: evidence that R8-R10 behavior and live cleanup remain unchanged.

- [x] **Step 1: Run two fresh live gates**

For each run require 12 metrics snapshots, two context-bound objects, two exact restart reads, cleanup true, zero candidate container/network/discovery-temp delta, and unchanged set plus complete mtime tree for shared directories `3kpvSA`, `E8Xd73`, `lB7ho6`, `oi2ROE`, and `vufULH`.

- [x] **Step 2: Run all pre-commit gates**

Run shell syntax/self-check in both EUID modes, `cargo fmt --check`, diff check, high-confidence secret scan, crate all-features and no-default check/test/clippy/doc, and workspace all-features check/test/clippy.

- [x] **Step 3: Review the final diff**

Confirm only the R11 plan, live-gate script, and README changed; confirm loader semantics, package dependencies, Rust sources, and AstroNexus are untouched.

---

### Task 4: Seal and verify the immutable candidate

**Files:**
- Package: `warpin-object-storage`.

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: one new clean commit and post-commit release evidence.

- [ ] **Step 1: Create one new commit**

Commit only the three scoped public files with no amend, publish, merge, or Codex Review action.

- [ ] **Step 2: Rebuild the release artifact**

Run `cargo package --locked` and `cargo publish --dry-run --locked`; require exactly 15 files and no upload.

- [ ] **Step 3: Verify the external contract**

From the unpacked package run the redacted-debug consumer, require exact `object_store v0.14.0`, and require the four import/method/attestation/receipt privacy forges to fail with their frozen diagnostics.

- [ ] **Step 4: Report immutable provenance**

Require clean HEAD, tree, parent=`a79b369e561848efb317391db41e62309ab20936`, deterministic git-archive and crate SHA-256, package VCS SHA matching HEAD with dirty=false, exactly 15 package files, passing secret scans, and a clean worktree.
