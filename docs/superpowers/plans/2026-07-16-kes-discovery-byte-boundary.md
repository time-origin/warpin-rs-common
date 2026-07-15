# KES Discovery Byte Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve and validate the exact Docker label-discovery stdout byte stream before any container name may reach cleanup.

**Architecture:** Docker discovery stdout is written directly to a private same-directory temporary regular file; raw bytes never pass through a Bash scalar. Ledger, atomic registration candidates, and discovery files share one byte-counting record-file loader with explicit path/existence policy. Discovery publishes names only after complete validation and temp removal; every error is silent, fail-closed, and leaves no temp or Docker operand derived from malformed bytes.

**Tech Stack:** Bash 5, Docker CLI, MinIO/KES live fixtures, Rust 2024 Cargo workspace.

## Global Constraints

- Baseline is clean commit `aa3b6787dbca56f30aef2ae56b93a74741bd37f1`; it is RED evidence and not the final candidate.
- Modify only the public `warpin-rs-common` worktree; never modify AstroNexus.
- Do not publish, merge, or run Codex Review.
- Preserve R9 ledger/symlink/label fallback and R8 registration-before-create behavior.
- Zero-byte discovery means zero records and is valid.
- Every nonempty record file must contain only unique, final-newline-terminated, current-run validated names.
- Single newline, internal or trailing empty records, missing final newline, NUL/control bytes, invalid names, and duplicate records are malformed.
- No malformed discovery-derived value may reach any Docker operand.
- Preserve exact `object_store = "=0.14.0"` behavior and the 15-file package contract.

---

### Task 1: Prove command-substitution byte loss

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Consumes: `discover_labeled_one_shot_containers`, fake Docker output states, and cleanup operand recording.
- Produces: raw-byte self-check matrix and stable R10 RED evidence.

- [x] **Step 1: Add exact fake Docker byte streams**

Add states that emit zero bytes, one newline, valid plus an extra trailing newline, a valid name without final newline, a valid name split by NUL, a valid name containing a tab, duplicate names, an invalid name, and one canonical valid record.

- [x] **Step 2: Add direct discovery status/count assertions**

Freeze `empty_output` as status 0/count 0 and `valid` as status 0/count 1. Every malformed state must return nonzero and publish count 0.

- [x] **Step 3: Prove malformed cleanup consequences**

For newline-only output, simulate a run-owned residual and prove the old path can report verified cleanup success without seeing it. For trailing-empty, missing-final-newline, and NUL output, mark the normalized valid name as forbidden and prove the old path passes it to inspect/remove.

- [x] **Step 4: Run RED twice**

Run the shell self-check twice. Both runs must fail on `aa3b678` because command substitution strips trailing newlines and NUL before validation.

---

### Task 2: Generalize the byte-aware record-file loader

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`

**Interfaces:**
- Produces: `load_validated_one_shot_record_file PATH EXISTENCE_POLICY OUTPUT_ARRAY`.
- Consumed by: cleanup ledger loading, registration candidate validation, and label discovery.

- [x] **Step 1: Freeze path and existence policies**

Allow only the exact ledger path, same-directory `one-shot-containers.next.*`, and same-directory `one-shot-discovery.*`. Ledger uses `allow-absent`; candidate/discovery files use `require-existing`. Reject work-dir/file symlinks and all existing non-regular objects before reading.

- [x] **Step 2: Preserve exact byte semantics**

Read records directly from the file, validate every name and duplicate boundary, count expected record bytes including one newline each, and compare against `wc -c`. This rejects missing final newline, NUL bytes discarded by Bash `read`, and all controls/empty records.

- [x] **Step 3: Add bounded parsing**

Reject files larger than 65536 bytes or more than 256 records before output publication. These limits exceed the live gate's normal one-shot volume and bound corrupted-file work.

- [x] **Step 4: Migrate ledger and candidate callers**

Replace the ledger-specific loader calls with the generalized loader while retaining all R9 symlink, immutable-original, duplicate, and 12-history tests.

---

### Task 3: Make discovery file-backed and fail closed

**Files:**
- Modify: `warpin-object-storage/scripts/minio-kes-live-gate.sh`
- Modify: `warpin-object-storage/README.md`

**Interfaces:**
- Consumes: Task 2 record-file loader.
- Produces: file-backed `discover_labeled_one_shot_containers OUTPUT_ARRAY`.

- [x] **Step 1: Add discovery temp failure injection**

Test mktemp failure, a symlink temp pointing at an unchanged external target, a directory temp, an unwritable regular temp, Docker nonzero with secret-bearing stderr, validation failure, and success. Every path must leave no `one-shot-discovery.*` object.

- [x] **Step 2: Redirect Docker stdout directly to the temp**

Create the temp under `WORK_DIR`, preflight it as a real regular allowlisted file, run Docker with stdout redirected directly to that path and stderr suppressed, then reload exact bytes through Task 2. Never assign discovery stdout to a shell variable.

- [x] **Step 3: Publish only after cleanup**

On Docker, write, loader, or removal failure, remove the temp, clear output, and return nonzero. On success, remove and verify absence before assigning validated names.

- [x] **Step 4: Run focused GREEN twice**

Both self-checks must print `minio_kes_live_gate_self_check=true`, with all R8/R9 and new R10 cases green.

- [x] **Step 5: Document exact discovery bytes**

Document zero-byte versus empty-record semantics, final newline requirements, direct file capture, byte/record limits, and fail-closed temp cleanup.

---

### Task 4: Verify and seal the new candidate

**Files:**
- Verify: entire Cargo workspace.
- Package: `warpin-object-storage`.

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: a new clean immutable commit and post-commit package provenance.

- [x] **Step 1: Run fresh live twice**

Require 12/12 metrics snapshots, two context-bound objects, two exact restart reads, cleanup true, zero candidate container/network/tmp delta, and the exact five shared directories unchanged.

- [x] **Step 2: Run complete pre-commit gates**

Run shell syntax/self-check, fmt, crate all-features and no-default check/test/clippy/doc, workspace check/test/clippy, and high-confidence secret scans.

- [ ] **Step 3: Commit only scoped public files**

Create one new commit after every pre-commit gate passes. Do not amend `aa3b678`.

- [ ] **Step 4: Regenerate package and external evidence**

Run `cargo package --locked` and `cargo publish --dry-run --locked` without upload. Test the unpacked consumer, exact `object_store v0.14.0`, and all four negative privacy forges.

- [ ] **Step 5: Report immutable provenance**

Report clean HEAD/tree/archive/crate hashes, clean VCS metadata, exactly 15 package files, secret scan, resource deltas, and clean worktree. Any failed gate blocks completion.
