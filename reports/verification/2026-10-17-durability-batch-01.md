# Engine durability batch 1 — 2026-10-17

## Baseline and scope

Branch `codex/phase-01-engine-durability` starts at default main `3a5c4a2`. Original dirty Praxor, Poiesis and Pit checkouts remain unchanged. Sixteen initial issues were created across the three existing repositories; no preexisting open or draft PRs needed merging.

The default engine suite passed 323 tests with 7 ignored before changes. This batch addresses engine issues [4](https://github.com/Astraive/praxor/issues/4), [5](https://github.com/Astraive/praxor/issues/5), [6](https://github.com/Astraive/praxor/issues/6), [7](https://github.com/Astraive/praxor/issues/7) and [8](https://github.com/Astraive/praxor/issues/8).

## Changes verified

- Primary compaction persists relocated RID mappings before retiring source segments, including recovery with a lost directory.
- Both WALs repair incomplete terminal appends before accepting later writes, reject complete checksum corruption, and recover matching partial file headers without hiding invalid versions.
- Flush preserves version chains, keeps immutable data visible until installation, retains retryable state after IO errors, and records durable WAL reclamation boundaries.
- Scans share point-read resolution for tombstones, TTL and merges. Convenience scans and point reads pin snapshots for their operation lifetimes.
- Compaction retains pinned views and merge dependencies, keeps deletion/expiry barriers, and retires all segments represented by its full-index output.
- Recovery handles overlapping legacy WAL/segment groups without collapsing repeated operands from one batch.
- File writes, WALs, value logs, primary segments and new directory trees receive the required file/directory syncing on Unix.
- CAS and optimistic conflict validation execute inside the mutation publication boundary.
- The storage logging gate no longer mistakes `catalog::` for the external `log::` namespace.

## Verification evidence

Executed on Windows with Rust 1.95.0 and build artifacts in `D:/target`:

| Check | Result |
| --- | --- |
| `cargo test -p praxis` | 364 passed, 0 failed, 7 ignored |
| `cargo fmt -p praxis --check` | Passed |
| `cargo clippy -p praxis --all-targets -- -D warnings` | Passed |
| `cargo check -p praxis --benches --tests --all-features` | Passed |
| `scripts/verify_slog_storage.ps1` | Passed; namespace fixture check also passed |
| `scripts/verify_storage_boundary.ps1` | Passed |
| `git diff --check` | Passed |

The same 364 passed / 0 failed / 7 ignored result was independently repeated with `cargo test --locked` in a standalone verification worktree on D:, using this repository's own Cargo.lock. That check exposed a preexisting lock entry still naming `trident` 0.1.0; it was synchronized to `praxis` 0.0.1 without changing dependency versions. CI now requires locked resolution.

GitHub CI had been automatically disabled for inactivity. It was reenabled for the branch checks. Linux CI remains a separate gate to inspect on [PR #9](https://github.com/Astraive/praxor/pull/9).

Red-to-green regressions cover primary relocation, scan/immutable visibility, torn WAL append followed by a second recovery, partial file-header rotation, flush failure/retry, pinned and merged history, legacy overlap, and read pin lifetime. Maintenance tests additionally cover concurrent writes/flush/GC, large value pointers through GC/restart, failed WAL publication and reserved versus visible sequences.

Independent review found and drove fixes for orphan partial WAL headers, file and ancestor-directory persistence, primary relocation publication, point-read pinning, and legacy overlap persistence. Review did not substitute for test execution.

## Remaining release work

This is a verified repair batch, not completion of the engine or ecosystem. No actual machine power-cut test has run; non-Unix directory sync remains a documented no-op. Subprocess crash matrices, longer concurrency/fault workloads, snapshot lifetime for transactions, atomic storage WAL batches, bounded-memory/disk-resident access and performance measurements remain release gates. The existing 7 ignored tests are not counted as passing.

Mutation publication is currently serialized for correctness. Group commit concurrency and incremental compaction need subsequent measured work. The repository crate remains named `praxis`; integrating the unpublished `praxor` rename and other local architecture changes is a separate phase.
