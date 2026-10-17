# Page collection ownership verification — 2026-10-17

Verified Windows worktree: `D:/poiesis-worktrees/phase-04-page-collection-state`, branch `codex/phase-04-page-collection-state`, on default base `5fb3435f8a0ddfc5abd0efb72b61d30f5cb18b22` plus the uncommitted candidate patch. The prior complete patch was retained in backup stash `9c9d33902419392b0e98f3469c5b729230fd522a` while fast-forwarding from `4259302`; reapplication had no conflicts. No worker commits, pushes, or GitHub mutations were performed.

## Result

The locked full suite passed **634 tests, 0 failed, 8 ignored**, including the ignored doctest, across 75 test-result summaries. The full Cargo process exited 0. All-target/all-feature Clippy with warnings denied, formatting, the slog and storage-boundary gates, and diff checks exited 0. Production and test sources were unchanged between these final checks; only documentation was completed afterward.

| Verification | External evidence under `D:/poiesis-benchmarks/` | Result |
| --- | --- | --- |
| Full locked suite | `page-final-full.log` | 634/0/8, exit 0 |
| All targets/features strict Clippy | `page-final-clippy.log` | exit 0 |
| Formatting | `page-final-fmt.log` | exit 0 |
| Slog gate | `page-final-slog.log` | exit 0 |
| Storage boundary gate | `page-final-boundary.log` | exit 0 |
| Diff check | `page-final-diffcheck.log` | exit 0 |

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-04-page-collection-state --no-fail-fast
cargo clippy --locked --jobs 2 --target-dir D:/poiesis-targets/phase-04-page-collection-state --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

## Behavior and regression evidence

An explicit `PageDatabase` retains the common base writer lease, shared collection directory/RID allocator, entity/frame cursors, canonical WAL writer, and root mutex. Entity, service, SDK, and WAL handles retain that same owner. Reopen reconstructs checked cursors from physical slots and preserves tombstones. Wrong-entity operations stop before foreign page/blob IO. Mutations prepare an unpublished state candidate and fail closed across all views after uncertain IO.

Earlier RED evidence is retained externally rather than embedded as test fixtures that mirror implementation:

- Original public interleaving/state tests: `page-collection-state-red.log` (1 passed/6 failed) and `page-record-boundaries-red.log` (1/15) on the pre-ownership base. Ownership controls: `page-ownership-425-red.log` (1/5).
- Typed preflight/page parser: `page-review-fixes-red.log`, followed by `page-review-fixes-green.log` (27/0). All fields, fixed pointer shapes, canonical record size, placement, and checked offsets are validated before blob IO; page decoding bounds allocation by actual envelope bytes.
- Replay review blockers: `page-task3-review-red.log` (36 passed/6 failed, exit 101), then `page-task3-review-green.log` (42/0). Unknown deletes are terminal, repeated log puts compare complete field tuples, and checksum-valid directory aliases to a single physical slot are refused without changing the tree.
- Public format-hook matrix: `page-format-hook-red.log` (2/4, exit 101). Five public facades now refuse foreign engine roots, reserved/incomplete evidence, namespace aliases, and misplaced leases before layout/WAL IO; AlreadyOpen priority and ordinary application siblings are covered.
- Empty managed WAL: `page-empty-wal-admission-red.log` (0/1, exit 101). The pure inspector now admits only the exact regular 16-byte v1 header on an otherwise complete exact scaffold. Blank-owner and entity-created/no-Put reopen controls pass; malformed/truncated/extra bytes, unknown WAL names, and logs-only partial roots remain refused.

Task4 adds three private per-writer fault tests covering partial WAL append, EveryBatch/GroupCommit sync failure, and Never's explicit sync failure. Seven real filesystem obstructions cover failures after WAL append and through page, slot metadata, RID directory, sidecar, and manifest publication. They assert the original IO error, no retry IO, root-wide poisoning, retained writer exclusion, and unpublished in-memory allocation state. A stale manifest/page checksum refuses both ordinary reopen and explicit recovery. The initial Task4 integration run exposed a Windows test-snapshot read of the live OS-locked lease; the snapshot now excludes only that exact regular base lease. `page-task4-io-green.log` has 2/0; the final full suite covers all cases.

Eight barrier-started service/SDK clone threads mutate two entities in two collections. Every returned receipt and payload, wrong-entity absence, deletes, collection RID uniqueness, manifest checksum, and two subsequent reopen/append cycles are checked. This verifies serialized correctness; no concurrency throughput or crash-atomicity claim is made.

Prior kernel review approved Tasks1/2; parent final source review approved the replay fixes, Task4, page hook, and exact-header inspector amendment before final verification.

## Compatibility and limits

See [the compatibility note](../../docs/page-record-ownership.md) for the fallible service/SDK opens, shared-owner constructors, fallible directory snapshots, and managed WAL handle migration. Page, directory, manifest, and PageWal v1 bytes retain their existing IEEE CRC32 contract. EveryBatch and GroupCommit sync each operation; Never requires explicit sync.

- Normal open strictly validates the canonical log but never replays it automatically. Healthy in-place recovery requires an intact validated canonical directory/high-water and preserves non-WAL records/tombstones. Missing identity/high-water cannot be inferred from payloads or LSNs; ambiguous histories are refused. A partial namespace may be rejected earlier with a typed format error.
- Existing raw v1 slots contain concatenated bodies, so checking a logged put against an existing slot cannot verify field layout. Repeated puts within a log do verify complete field tuples.
- [#39](https://github.com/Astraive/praxor/issues/39) owns framing and torn-tail repair. Raw `PageWal::replay` remains a forensic prefix API and does not authorize complete recovery or writing.
- [#41](https://github.com/Astraive/praxor/issues/41) owns multi-file publication/crash recovery and a durable completeness witness. An errored operation can have an unknown durable outcome; this patch adds no cross-file rollback guarantee.
- [#40](https://github.com/Astraive/praxor/issues/40) remains open because [#48](https://github.com/Astraive/praxor/issues/48) separately owns catalog constructor admission/ownership. The page hook is partial progress for #40. [#49](https://github.com/Astraive/praxor/issues/49) tracks the pre-existing malformed typed-value decoder allocation/narrowing issue; no additional codec redesign is included here.

## Verified worktree source hashes

SHA-256 of the frozen Windows worktree bytes (before Git newline normalization):

| Source | SHA-256 |
| --- | --- |
| `src/record/database.rs` | `F8612B0A060A1F263355B5123E646E7EA15AE9B84455C29B90010A99F50B58C1` |
| `src/record/recovery.rs` | `AED63086408577236970A59C4CE5029C6143C9989FFE76824B3151F588CA3487` |
| `src/record/mod.rs` | `BC91571FFDA1229BD184044DF62F04EF18E4AAD1F1D06635F1A1224DF008675C` |
| `src/wal/page.rs` | `64C8607611FCB7F34AA1B12A88364676BC138FF67598B94BB2A451B0E8EC2DFC` |
| `src/page/mod.rs` | `0575E075F4DD9C5500B09E6AA4FA9524CB44ACE459271431F84995B6EA1B55B5` |
| `src/storage/root_format.rs` | `F7693281BCB1D066F3726688CD71ACA2F405B20383E2F34D77251FEAF8630AC3` |
