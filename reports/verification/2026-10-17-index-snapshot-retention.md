# Index snapshot retention and capability checks

Issue: [#22](https://github.com/Astraive/praxor/issues/22). Final integration base:
`f3ae6c47c6a5ffde7cdd2861717f0c0256cd463f`, including merged CF, cache and WAL
repairs.

Canonical LSM/B-tree compaction discarded all but the last append and removed
tombstoned keys. Historical reads could therefore change after maintenance.
The IndexPlugin default also returned the latest RID for any historical ceiling,
and maintenance mislabeled required history as reclaimable versions.

## Contract and repair

These plugins accept arbitrary sequence ceilings without a snapshot registry or
persisted reclamation horizon. Compaction must preserve every read decision.
The shared helper scans reverse append order and retains a record only when its
sequence is below every retained later append. A later append at S shadows an
earlier append at T >= S for every ceiling where the earlier append is eligible.
The retained subsequence keeps its original order, including tombstone barriers.
An optional minimum preserves zero and u64::MAX correctly.

Required monotonic history remains; this is not bounded history reclamation.
The reclaimable estimate applies the same predicate as actual pruning, and the
maintenance planner suppresses zero-reduction jobs even at threshold zero.
Current-live Bloom/fence/page metadata never gates historical reads.

LSM and B-tree explicitly declare raw-ceiling snapshot capability. Checked
StorageEngine lookups return a typed unsupported error for other plugins; the
legacy Option-returning default fails closed. Existing custom implementations
compile via default methods, but versioned custom plugins must explicitly opt in
for checked reads and implement the full mutation/retention contract. The binary
and legacy JSON layouts remain compatible.

## Regression evidence

All seven original regressions failed before production changes: discarded
history, an empty legacy-history panic, a future RID through the default method,
unchecked StorageEngine fallback, incorrect pruning estimates and unnecessary
monotonic-history maintenance. Eleven final public tests cover both plugins,
delete/reinsert, current tombstones, equal/decreasing sequences, randomized
ceilings, zero/MAX, JSON/binary reopen, custom capability and maintenance hooks,
and error/reopen handle health.

An independent exhaustive model selects append identities by forward visibility
at all relevant ceiling intervals across **271,453** histories. It verifies the
retained decisions, exact pruning estimate and compaction idempotence. Existing
maintenance sorting, limits, runtime and persistence-failure tests retain useful
work through real replay duplicate appends rather than unsafe pruning assumptions.

## Verification

The frozen patch on CF-generation base `a3a2137` passed **463/0/8**. After a clean
fast-forward to merged default `f3ae6c4`, Windows Rust 1.99.0 verification with
locked dependencies, two jobs and the isolated
`F:/poiesis-targets/phase-03-index-snapshot-retention` target passed:

- Full combined suite: **486 passed, 0 failed, 8 ignored**, 62 test targets.
- Format, diff, storage slog and storage boundary gates.
- Strict all-target/all-feature warnings-denied Clippy.
- Independent read-only review: ready, no blockers.

Logs: `D:/poiesis-worktrees/index-snapshot-{red,first-green,focused,full,clippy,integrated-full,integrated-clippy}.log`.
No new performance or physical power-loss claim is made.

## Remaining scope

Retaining an index mapping does not retain a deleted primary payload.
`StorageEngine::fetch` remains a current-liveness read. Registered storage
snapshots, historical primary visibility and safe bounded reclamation are tracked
in [#29](https://github.com/Astraive/praxor/issues/29), alongside the live-engine
consolidation design. This patch does not create a second row-MVCC subsystem.

Primary references: [RocksDB snapshots](https://github.com/facebook/rocksdb/wiki/Snapshot)
describe supplying registered snapshots to compaction; [PostgreSQL vacuuming](https://www.postgresql.org/docs/current/routine-vacuuming.html)
describes preserving row versions still potentially visible to transactions.
The conservative contract here follows from the existing raw-ceiling API's lack
of such registered reclamation information.
