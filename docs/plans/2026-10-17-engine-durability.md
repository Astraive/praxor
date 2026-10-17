# Phase 1: engine durability and visibility

## Scope and intent

Build the existing SQL, document, graph, vector and relational database ecosystem from its engine upward. This phase hardens the existing storage core before expanding features. Praxor (package `praxis`) owns the canonical query semantic pipeline and catalog rules above its storage kernel; Poiesis owns product/session/authorization/protocol context; PoiesiSQL provides optional tooling consuming engine contracts; Pit owns separately reviewed durable version history; Poietica consumes public product APIs. The engine depends on neither runtime nor optional tooling.

The [engine architecture](../architecture.md) and [query readiness](../query-readiness.md)
now state this ownership consistently. [Q0 #60](https://github.com/Astraive/praxor/issues/60)
preserves current experimental public imports/serde and characterizes readiness;
ownership and parse/plan success do not establish complete execution, a fallible
retained-view backend or persisted atomic catalog DDL/data. Those bounded gates
remain [Q1 #61](https://github.com/Astraive/praxor/issues/61),
[Q2 #62](https://github.com/Astraive/praxor/issues/62) and
[Q3 #63](https://github.com/Astraive/praxor/issues/63). This correction supersedes
the earlier conflicting parser/planner ownership wording, without importing or
rewriting preserved dirty workspace/PQL sources.

## Repository baseline

At the initial inventory on 2026-10-17, the identified remotes were Astraive/praxor (the original Astraive/praxis URL now redirects), NeerajCodz/poiesis and NeerajCodz/pit, all with default branch main and no preexisting open or draft PRs. Existing local main checkouts contain substantial uncommitted changes and are preserved. Separate worktrees start from fetched origin/main. The engine package on the remote is still named praxis; renaming it to match local praxor requires an explicit integration change. At that inventory, Poietica and PoiesiSQL had local source but no standalone remote, and poiesis-wasm was empty. Separate private Astraive remotes now exist as README-only baselines; importing and verifying their preserved source remains open work.

## Required invariants

- A successfully acknowledged durable write survives reopen, including after rotation, maintenance and a previous torn WAL append.
- Compaction preserves logical record IDs and recovery cannot restore obsolete physical locations.
- A pinned snapshot returns the same sequence-visible values across flush and compaction.
- Scans and point lookups agree on deletes, expiration and merge operands.
- Flush keeps immutable data readable until its replacement is installed; errors retain recoverable state.
- WAL reclamation requires a durable checkpoint covering the reclaimed records.
- Performance improvements must preserve these guarantees and have measured evidence.

## Implementation plan

- [x] Inventory repositories, default branches, dirty state, open PRs and existing roadmap.
- [x] Fetch remotes and create branches/worktrees without modifying dirty original checkouts.
- [x] Create phase epics and concrete defect issues in the existing repositories; track unversioned components under Poiesis until repository ownership is resolved.
- [x] Run and record the default-branch engine baseline separately from the dirty local baseline (default: 323 passed, 7 ignored; dirty local library: 326 passed, 6 ignored).
- [x] Reproduce and fix compacted primary-record relocation recovery.
- [x] Reproduce and fix scan visibility for tombstones, TTL and merges.
- [x] Reproduce and fix WAL append after a recovered torn suffix.
- [x] Reproduce and fix WAL retention and flush snapshot-history loss.
- [x] Verify flush installation/failure/concurrent-write boundaries and sequence publication.
- [x] Run the complete engine suite, formatting and targeted fault/restart regressions; obtain independent code review.
- [x] Commit independently reviewable changes as type(scope): message without co-author trailers; push a linked PR with exact verification results ([PR #9](https://github.com/Astraive/praxor/pull/9)).
- [ ] Verify Linux CI and merge the first batch before starting the next default-based implementation branch.

No phase is complete merely because code compiles. The broader effort remains active until protocol consistency, query semantics, persistent history, UI/SDK contracts, WASM and release verification have their own passing gates. Commit count and changed-line count are outcomes of substantive work, not substitutes for correctness.

## Research informing the checks

- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html): persistence ordering and crash testing around filesystem operations.
- [RocksDB WAL recovery modes](https://github.com/facebook/rocksdb/wiki/WAL-Recovery-Modes): distinguish incomplete terminal writes from corruption of durable history.
- [ARIES](https://people.eecs.berkeley.edu/~brewer/cs262/Aries2.pdf): log ordering, recovery sequence boundaries and repeatable recovery.

These references inform invariants and tests; the existing implementation remains independently written Rust.

## Tracking

- [Engine epic](https://github.com/Astraive/praxor/issues/3)
- [Primary relocation](https://github.com/Astraive/praxor/issues/4)
- [Scan visibility](https://github.com/Astraive/praxor/issues/5)
- [WAL tail recovery](https://github.com/Astraive/praxor/issues/6)
- [Snapshot and merge retention](https://github.com/Astraive/praxor/issues/7)
- [Flush and WAL reclamation](https://github.com/Astraive/praxor/issues/8)
- [Poiesis and client integration epic](https://github.com/NeerajCodz/poiesis/issues/1)
- [Pit completion epic](https://github.com/NeerajCodz/pit/issues/1)

## Limits of this batch

Restart and corruption regressions do not establish power-loss correctness. Unix file and directory syncing has been added, but machine power-cut testing and platform-specific persistence validation remain release gates. The directory-sync helper is explicitly a no-op on non-Unix platforms.

This batch serializes mutation publication to fix visibility and flush races. Group commit concurrency, incremental compaction, disk-resident indexes and bounded scan memory still need measured optimization. Full-index compaction now truthfully retires every segment represented by its output; it must not pretend to be an incremental rewrite. Existing dual engine surfaces and unpublished repository-boundary changes remain integration work.
