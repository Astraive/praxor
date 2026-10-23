# V5 active WAL tail classifier implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify a synthetic installed v5 WAL's last bytes as complete, a proven canonical active terminal prefix, corrupt, or unsupported, without granting repair or owner authority.

**Architecture:** Validate H80, scan each complete frame with the existing read-only H64/typed-frame codec and its exact sequence/hash context, then inspect only the unique final suffix with a bounded grammar-feasibility state machine. The state machine must prove a canonical completion exists before returning `EligibleTerminalPrefix`; unknown or over-budget feasibility returns `Unsupported`. It never allocates from a declared frame length or mutates a file.

**Tech Stack:** Rust 1.99, existing `blake3` dependency, checked-in `wal_v5_r6.json` bytes, `cargo --locked --jobs 2` on D:/F: targets when physical free RAM permits, hosted Linux/Windows CI otherwise.

**Spec:** Praxor issue #100, `docs/provenance/wal-v5-h64.md` (PR #101), `docs/provenance/wal-v5-h80.md`, and the frozen R6 v5 wire design. This plan does not give #84 installed-effect proof or #94 writer/provenance authority.

## Global constraints

- Keep `inspect_installed_v5_wal` crate-private, read-only, and explicit about `Complete`, `IncompleteUnclassified`, `EligibleTerminalPrefix`, `Corrupt`, and `Unsupported`.
- Installed H80 must be complete and match the descriptor; sealed WALs cannot have a terminal frame prefix. Pending H80 is handled by its separate API.
- H64 shell: `total_len=100+payload_len`, payload ≤67,108,864, catalog total ≤1,048,576, count ≤4096; expected sequence/hash are fixed from H80 or prior complete frame.
- Payload has one closed kind-specific control of 0/88/120/64 bytes, followed by exactly `batch_count` ordinal operations with closed tags, bounds, and valid UTF-8 names.
- No whole-frame allocation from a claimed size. Limit one synthetic WAL image to 134,217,728 bytes (128 MiB), one scan to 1,000,000 complete-frame visits, and symbolic prefix feasibility to 1,048,576 state transitions; return named `Unsupported` if any budget is exhausted. Charge byte reads to the image bound and branch work to the symbolic counter.
- A complete invalid CRC, hash, control, or operation is `Corrupt` even at EOF. An incomplete suffix may be eligible only if it is a **proper** prefix of at least one canonical next frame under all visible constraints.
- A required sequence through the supplied retained-history watermark cannot disappear into an incomplete suffix or clean EOF.

## Review focus

1. A partial LE field whose visible residue has no value in its allowed set must be `Corrupt`; exercise control length, CF name length, and H64 total/payload coupling.
2. A prefix ending in an incomplete UTF-8 codepoint can be eligible only when the fixed or possible name length leaves enough bytes; an impossible lead byte must be `Corrupt`.
3. The first visible CRC or trailer byte is already fixed after the body or CRC; it cannot be waved through as a tear when wrong.
4. A valid complete frame followed by a malformed one-byte next header must be `Corrupt`; the prior frame cannot absorb the suffix.
5. At a frame boundary, the retained-history requirement must hold; no incomplete S can satisfy a required S.

### Task 1: Complete the test-first boundary matrix

**Files:** Modify `src/wal/v5_tail/tests.rs`; keep the `Unsupported` production seam in `src/wal/v5_tail.rs`.

**Interfaces:** The existing `inspect_installed_v5_wal(&[u8], &H80Descriptor, InstalledWalState, u64) -> TailInspection` is the assertion surface.

- [ ] Add tests for wrong H64 chain bytes, complete bad trailer, resealed illegal operation/control, partial LE name-length and key/value caps, UTF-8 prefix feasibility, ordinal, reserved bytes, and an oversized declared payload without allocating the body.
- [ ] Run the focused tests on a D:/F: target with `cargo test --locked --jobs 2 --lib v5_tail` only when free physical RAM is at least 4 GiB; otherwise use exact-head hosted CI. Confirm failures are the intentional `Unsupported` seam, not test setup errors.
- [ ] Have an independent reviewer inspect the exact test patch and raw RED evidence before production integration.
- [ ] Commit `test(wal): cover v5 terminal prefix conflicts` with exact NeerajCodz author and committer, no coauthor trailer; push to attached draft PR #102.

### Task 2: Validate installed H80 and scan complete frames

**Files:** Modify `src/wal/v5_tail.rs`, and if needed add a small scan helper module under `src/wal/v5_tail/`.

**Interfaces:** Consume `v5_header::decode_h80`, `v5_frame::{inspect_h64_prefix, decode_complete_frame, FrameContext}`, and produce the unchanged `TailInspection` API.

- [ ] Add one failing test for installed H80 mismatch and one for two chained complete frames with exact last sequence.
- [ ] Implement checked offsets and sequence successor; reject malformed complete frames and suffixes. Check the required watermark at clean EOF.
- [ ] Run focused and full locked suites under the RAM gate or hosted CI; review and commit this independently testable scanner slice.

### Task 3: Prove H64 and typed-control prefix feasibility

**Files:** Modify `src/wal/v5_tail.rs` or a focused `prefix.rs` helper; test in `src/wal/v5_tail/tests.rs`.

**Interfaces:** Consume verified `FrameContext` and the observed proper suffix; return a private `Feasible`, `Impossible`, or `Undecided` result with a bounded work counter.

- [ ] Add one failing test for each golden H64/control cut and the cut-29 coupled-length falsifier.
- [ ] Implement exact low-byte residue congruence and kind/control-length coupling. For fixed control fields, enforce visible magic, ID, version, flags, epoch, sequence, and checked arithmetic feasibility. Return `Undecided` if work budget cannot prove or disprove existence.
- [ ] Recheck all golden cuts and false prefixes, run the full suite, independently review, and commit a conventional `feat(wal): ...` slice.

### Task 4: Prove operation, integrity, and terminal-state feasibility

**Files:** Modify the same focused prefix helper and `src/wal/v5_tail/tests.rs`.

**Interfaces:** The private feasibility result from Task 3 and the public-to-crate `TailInspection` mapping stay unchanged.

- [ ] Add failing tests for exact physical ordinals, closed tags, partial length residues, UTF-8 completion, exact payload consumption, CRC/trailer visible prefixes, active/sealed distinction, and required watermark.
- [ ] Exercise the per-call work counter through a small injected test limit, including a prefix that becomes `Unsupported` when the limit is exhausted.
- [ ] Implement a bounded state machine that consumes only observed bytes, tracks residual payload length and operation count, and proves a legal completion for at least one branch. Never treat independent field-range overlap as joint feasibility; return `Unsupported` on budget exhaustion.
- [ ] Verify every cut of all four frozen frames, adversarial tests, focused and full locked suites, strict lint/format, feature and benchmark checks on Linux and Windows. Have an independent raw-evidence and source review at the final exact head.
- [ ] Update PR #102 body with final design and validation, mark it ready only when complete, sync with the latest main using a locally authored normal merge, rerun exact-head CI/review, then normal-merge and close issue #100.
