# Catalog ownership verification — 2026-10-17

`CatalogStore::open` could initialize a page namespace inside an incompatible or already owned engine root, while catalog save/load bypassed page state coordination. The candidate makes CatalogStore an explicit PageDatabase view, prepares every catalog before publication, and shares the root health/lease across catalog, page, service, SDK, and WAL handles.

This record covers worktree `D:/poiesis-worktrees/phase-04-page-catalog-ownership`, branch `codex/phase-04-page-catalog-ownership`, at merged default **7d0525bff492261d5ad597cc76cc79be29abcf8f** plus the reviewed candidate. The branch was safely fast-forwarded first with retained complete stash **3c04bb3c2aa4989e5e1bc45c2175db7ed58b37b3**, then with **6cf7849ca2199bd02b6e5691c961c1e81a43e379**, reapplied by exact hashes without conflicts. Incoming #49 readers and #42 backup/source/ownership-test changes were preserved. The owned catalog patch had no source hunk conflicts.

Reviewed source and regressions are committed as
`d35b088f8b62990e4e04e9886c8125b517c9bfe4`; documentation follows separately.

## Verified results

The final locked Windows suite exited **0: 703 passed, 0 failed, 8 ignored**, across 84 test-result summaries including the ignored doctest. All-target/all-feature strict Clippy exited0 in12.86seconds; formatting, slog, storage boundary and diff checks exited0. Source/tests were frozen throughout these final checks. Documentation/report completion followed. Historical661/fb49 and676/f9fed83 results remain separate in their original logs.

All logs below are in `D:/poiesis-benchmarks/`:

| Check | Log | Result |
| --- | --- | --- |
| Full locked suite | catalog-final-default-full.log | 703/0/8, exit 0 |
| All targets/features Clippy, warnings denied | catalog-final-default-clippy.log | exit 0 |
| Formatting, slog/boundary and diff checks | Parent final tool output after this full run | exit 0 |

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-04-page-catalog-ownership --no-fail-fast
cargo clippy --locked --jobs 2 --target-dir D:/poiesis-targets/phase-04-page-catalog-ownership --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

## Regression and concurrency evidence

- Actual baseline RED before product edits: **2 controls passed / 10 intended failures**, exit101, `catalog-tasks12-red.log`. Six live/closed core/pointer/record roots wrongly accepted catalog initialization; independent catalog/page owners and retained clones lacked exclusion; a last users-catalog destination error changed earlier files. A first snapshot helper attempted to read a live Windows primary lock; the retained rerun excludes only the exact regular base/primary lease artifacts, and its failures are behavioral.
- Before edits, `catalog-wire-baseline.log` captured complete v1 bytes for all ten tables and confirmed zero/duplicate IDs. Permanent golden tests assert those exact literal files. Optional empty strings retain the existing empty-to-None behavior; no new catalog semantic schema or ID policy is introduced.
- Focused ownership/admission/preflight/wire/legacy/root checks passed; sizing tests use the production checked-preparation path with a private per-call smaller ceiling, plus direct u32/usize boundary arithmetic, without giant allocations. The existing persistence test still independently reopens after explicitly dropping its first owner.
- `catalog-task3-unit.log`: **6/0**, including two sizing controls and four publication/health tests. After the first real catalog rename, a hook creates a later users.tmp directory; subsequent actual IO fails. All supported views then fail PageRecoveryRequired, poisoned retries perform no IO, and a final catalog clone retains the lease. Existing page publication and WAL-sync uncertainty also poison already-created catalog views, reusing the existing private WAL fault seam.
- The pause test inspects a real collections-B/entities-A disk window after the first publication. Supported catalog load, page put, and WAL sync remain blocked behind the same guard and return only after release. Bounded channels and a release-on-drop guard prevent stranded workers. This exercises the live serialization contract, not crash atomicity.
- `catalog-task3-integration.log`: **4/0**. Eight barrier-started threads load/save all ten catalog epoch markers while four page writers span two collections/entities and a WAL handle syncs. Every acknowledged receipt, payload, delete and identity is checked against exactly 24 Puts plus 8 Deletes in 32 consecutive WAL records. Two subsequent reopen/append cycles validate RID allocation, wrong-entity absence, directory addresses and manifest checksums. A separate corrupted-checksum read test proves no repair/create/poison side effect on healthy page data.
- All new versioned runtime fixtures use portable temporary directories; D: paths appear only in local build/log methodology. No production interfaces changed for the test hooks, no global mutable fault state or second coordinator was added.

The parent independently reviewed Tasks1/2 and the publication/pause/concurrency source without finding an additional bounded blocker. The parent whole-branch source review is ready; conflict-free default integration and the combined verification above satisfy the remaining composition checks. Documentation/report completion changes no tested source. The parent owns commit and PR creation.

## API and durability limits

See [page-record-ownership.md](../../docs/page-record-ownership.md) and [storage-root-formats.md](../../docs/storage-root-formats.md).

- `CatalogStore::open(base)` now independently owns the common page root; `CatalogStore::new(database.clone())` shares it. Clone retains ownership, `layout()` keeps its return shape, and resource Eq/PartialEq derives were removed. Snapshot equality and v1 TCAT bytes are unchanged.
- Catalog-only legacy roots remain valid without a page manifest/RID directory. Load/save use the existing health-checking root mutex once, with no reentry. Read helpers do not initialize or repair files. Preparation checks every count/string/payload/envelope shape and all target/temp destinations before any publication. Pure preparation errors remain healthy; publication errors retain their original error then poison shared views.
- Catalog files retain buffered per-file temp/rename publication. PageWal policies do not sync catalog saves, and live serialization does not make ten files crash-atomic. V1 lacks a durable catalog generation/completeness witness and can contain individually valid files from different attempts after all owners drop. [#41](https://github.com/Astraive/praxor/issues/41) owns this boundary.
- Catalog decoder count reserves, raw ID narrowing and trailing-data hardening remain unchanged and separately tracked in [#51](https://github.com/Astraive/praxor/issues/51). [#48](https://github.com/Astraive/praxor/issues/48) addresses catalog ownership/admission within [#40](https://github.com/Astraive/praxor/issues/40); the parent determines issue closure after final merge checks.

## Source authority at this verification point

SHA-256 of the frozen Windows worktree bytes before Git newline normalization:

| Source | SHA-256 |
| --- | --- |
| src/catalog/mod.rs | D4F8442DDA96F6C05788E884FFB3CA1C45C8B004C96476A0B0522259AEE996CC |
| src/catalog/prepare.rs | 45058B209D0589A7718EE414844F6B328B21D4F4A01077E043A4715168D036A7 |
| src/catalog/publication_tests.rs | 92EFB1F008858CB3BC20BEA4A4E8D59B56E25840CFE8BAF02E9637B1C1AFFFCF |
| src/record/database.rs | 91FEF5B66CBE39EEED66B875CBDC231E7F3FDD63E52AEF33CE51ECE14D10029A |

## Earlier base evidence

Before integration, the same logical catalog patch passed661/0/8 on fb49a216 and676/0/8 on f9fed833, with all strict gates passing in the separate `catalog-final-*.log` and `catalog-combined-*.log` files. Those results are historical and are not substituted for final703/0/8 on7d0525b. Physical Windows source hashes changed on the first stash reapplication due to Git newline filtering; the primary hashes above remained unchanged through final integration. Both retained stash snapshots remain available for recovery.
