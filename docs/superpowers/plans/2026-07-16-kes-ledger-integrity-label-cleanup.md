# KES Ledger Integrity and Label Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the one-shot KES cleanup ledger fail closed for every filesystem and record-integrity attack while retaining safe cleanup through a run-scoped Docker label.

**Architecture:** One typed Bash loader is the only path from ledger bytes to validated container-name arrays. Registration validates the private work directory, rejects symlinks and non-regular ledgers with lstat semantics, reconstructs and revalidates an atomic candidate before `docker create`, while cleanup unions trusted ledger names with strictly validated names discovered through one internally generated run label. A damaged ledger is never sent to Docker; best-effort cleanup uses the label fallback, and verified cleanup always fails the attestation even when fallback removal succeeds.

**Tech Stack:** Bash 5, Docker CLI, MinIO/KES live fixtures, Rust 2024 Cargo workspace.

## Global Constraints

- Baseline is clean commit `22446fd5c1ea8e7eb031d72ca782c2d62a8498bd`; it is RED evidence and not the final candidate.
- Modify only the public `warpin-rs-common` worktree; never modify AstroNexus.
- Do not publish, merge, or run Codex Review.
- Preserve registration-before-create and exact `object_store = "=0.14.0"` behavior.
- Reject all ledger symlinks, including dangling links, without changing the link target.
- Reject empty records, duplicate records, missing final newline, controls, whitespace, option-like names, invalid Docker characters, wrong run prefixes, unsupported identities, and names longer than 128 bytes.
- Any registration failure must leave the original ledger bytes unchanged and produce zero `docker create` calls.
- Cleanup must never pass unvalidated ledger bytes to any Docker command.
- A corrupt ledger makes verified cleanup fail even if label fallback removes every run-owned container.

---

### Task 1: Prove the complete baseline attack matrix

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: `register_one_shot_container`, `run_kes_client`, `cleanup_best_effort`, `cleanup_verified`.
- Produces: self-check fixtures for lstat types, record corruption, zero-create, Docker-argument, and cleanup-attestation assertions.

- [x] **Step 1: Add reusable self-check fixtures**

Add helpers that reset the private work directory, snapshot regular ledger bytes, count fake `docker create` calls, mark any exact forbidden argument received by fake Docker, and exercise one registration failure without changing its fixture.

- [x] **Step 2: Add filesystem RED cases**

Exercise a symlink to a regular target containing `--help`, a dangling symlink, a directory, and a FIFO. Every case must reject registration, leave the original object/target unchanged, and record zero create calls.

- [x] **Step 3: Add record-integrity RED cases**

Exercise regular ledgers containing `--help`, a wrong run prefix, unsupported identity, blank line, tab/control, space, more than 128 bytes, slash/invalid Docker syntax, a valid unterminated final record, and duplicate valid records. Freeze all listed cases as rejected.

- [x] **Step 4: Add cleanup RED assertions**

Prove that best-effort cleanup receives none of the malicious records and that verified cleanup rejects a corrupt ledger rather than reporting success.

- [x] **Step 5: Run the baseline RED matrix**

Run `./warpin-object-storage/scripts/minio-kes-live-gate.sh --self-check`. Expected: FAIL on `22446fd` because symlinked and malformed historical records reach the old `mapfile`/Docker path or registration accepts them.

---

### Task 2: Implement the single trusted ledger boundary

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Produces: `validate_private_work_dir`, `validate_one_shot_container_name NAME IDENTITY`, and `load_validated_one_shot_ledger PATH OUTPUT_ARRAY`.
- Consumed by: registration, `cleanup_best_effort`, and `cleanup_verified`.

- [x] **Step 1: Implement lstat-type rejection**

Reject `WORK_DIR` or ledger paths when `[[ -L ... ]]` is true. Require the existing work directory to be a real directory and every existing ledger candidate to be a real regular file before reading.

- [x] **Step 2: Implement strict record parsing**

Read records one at a time, validate the current run prefix, `bootstrap|metrics` identity, nonempty suffix, Docker grammar `[A-Za-z0-9][A-Za-z0-9_.-]*`, maximum 128-byte length, and uniqueness. Reject a nonempty final buffer after `read` reaches EOF, which freezes missing-final-newline as invalid.

- [x] **Step 3: Rebuild registration from validated records**

Load and validate the entire old ledger before creating the candidate, reject a duplicate append, write only validated records to a same-directory `mktemp`, reload the candidate through the same loader, then atomically replace with `mv -fT --`. On any error remove only the candidate and leave the original path or external symlink target unchanged.

- [x] **Step 4: Run focused GREEN for loader and registration**

Run the self-check and confirm all filesystem/record fixtures fail closed with zero create calls while the 12-entry valid history and R8 pre-create interruption coverage remain green.

---

### Task 3: Add run-label fallback and safe Docker boundaries

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Produces: `discover_labeled_one_shot_containers OUTPUT_ARRAY`, safe-name union logic, and the fixed `com.warpin.live-gate.one-shot-run=<RUN_TOKEN>` label.

- [x] **Step 1: Record real Docker parser evidence**

Against an absent `--help` object, prove without side effects that Docker accepts option termination for `container inspect --`, `rm -f --`, `start --attach --`, `network inspect --`, and `network rm --`. Do not add separators at unsupported positions.

- [x] **Step 2: Label every one-shot create**

Validate the internal label key/value/filter and add the fixed current-run label to `docker create`. The label is discovery metadata only; a discovered name must still pass the same strict name validator before use.

- [x] **Step 3: Refactor both cleanup paths**

Load only trusted ledger names, independently discover and validate labeled names, form a duplicate-free union, and use `--` only at parser-proven Docker operand boundaries. `cleanup_best_effort` skips corrupt ledger bytes but removes safely discovered run containers. `cleanup_verified` performs the same fallback, records ledger corruption as failure, and checks for labeled residuals before it can attest success.

- [x] **Step 4: Test damaged-ledger fallback**

Create a fake run-labeled one-shot that is absent from a corrupt ledger. Prove best effort removes it without receiving malicious ledger bytes; prove verified cleanup removes it but returns failure and cannot produce `ephemeral_resources_cleaned=true`.

- [x] **Step 5: Run focused GREEN twice**

Run the shell self-check twice consecutively. Each must print `minio_kes_live_gate_self_check=true`.

---

### Task 4: Preserve the live security path and release evidence

**Files:**
- Modify: `warpin-object-storage/README.md`
- Verify: entire Cargo workspace and packaged `warpin-object-storage` crate.

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: a new clean immutable commit and reproducible package provenance.

- [x] **Step 1: Document the frozen ledger contract**

Document lstat symlink/non-regular rejection, strict newline-delimited unique records, run-label fallback, and verified-cleanup failure on ledger corruption.

- [x] **Step 2: Run fresh live twice with resource deltas**

Each run must report 12/12 metrics snapshots, two context-bound objects, two exact restart reads, and cleanup true. Candidate container/network/tmp deltas must be zero and the five shared temporary directories must remain unchanged.

- [x] **Step 3: Run complete pre-commit gates**

Run shell syntax/self-check, fmt, crate all-features and no-default check/test/clippy/doc, workspace check/test/clippy, and secret/removed-pattern scans.

- [ ] **Step 4: Commit only scoped public files**

Create one new commit after all pre-commit gates pass. Do not amend `22446fd`.

- [ ] **Step 5: Regenerate and verify post-commit package evidence**

Run `cargo package --locked` and `cargo publish --dry-run --locked` without upload. Test the unpacked consumer, exact `object_store v0.14.0`, and all four negative privacy forges. Report clean HEAD/tree/archive/crate hashes, clean VCS metadata, exactly 15 package files, secret scans, and zero resource delta.
