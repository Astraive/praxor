# Praxis

Praxis is the standalone Rust storage engine core for Poiesis. It is not a wrapper over an existing database and it does not carry Poiesis entity semantics inside the core. Praxis owns durable value IO, RAM-resident value IO, WAL recovery, immutable segments, cache behavior, snapshots, compaction hooks, and acceleration boundaries.

## Storage-Layer Contract: No Duplicate Value Bytes

Praxis now exposes a storage-only orchestration API (`store::StorageEngine`) built around a single primary `RecordStore`. Raw bytes are written once, assigned a stable logical `RecordId`, and every index overlay stores only `key -> RecordId` pointers.

- **Primary store**: append-only record segments with logical RID indirection (`RecordId -> physical location`) for compaction-safe address stability.
- **Segmented storage WAL**: rotated WAL segments replay in sequence for all index updates using entries shaped as `[sequence | index_type | key | RID | operation]`.
- **Grouped WAL commit path**: multi-index writes are appended as one WAL batch with monotonic contiguous sequence assignment.
- **Pointer-only plugins**: LSM, B-tree, adjacency, and vector indexes reference records by RID and never duplicate value bytes.
- **Snapshot-capable indexes**: LSM and B-tree plugins keep sequence-aware key histories and support point lookups at a specific sequence.
- **LSM metadata surfaces**: LSM plugin materializes persisted probabilistic bloom metadata and fence bounds (`min/max`) for scan planning.
- **B-tree page metadata**: B-tree plugin materializes persisted deterministic page metadata (page id, key count, min/max key).
- **Graph/vector durability hooks**: adjacency supports atomic bidirectional edge insertion; vector index uses persisted layered graph search with snapshot/reload support.
- **Manifest + cache primitives**: storage manifest versioning tracks segment/index files and plugin namespaces; unified block cache keys are tagged by data/index type.
- **Observability surface**: `StorageEngine::stats()` reports live-record totals, WAL replay backlog, compaction budget, and per-index key/version counters.
- **Maintenance hints**: `StorageEngine::suggest_index_compactions(...)` proposes index compaction jobs from stale-version pressure.
- **End-to-end maintenance cycle**: `StorageEngine::run_maintenance_cycle(...)` performs suggest+execute compaction workflow and returns execution reports.
- **Deterministic maintenance planning**: compaction suggestions are stable-ordered by prune potential, with `run_maintenance_cycle_with_options(...)` supporting max-jobs caps per cycle.
- **Strict write validation**: storage writes pre-validate all referenced index plugins before data/WAL mutation to avoid partial invalid state.
- **Snapshot index lookups**: `StorageEngine::lookup_rid_at(...)` exposes sequence-consistent index reads for recovery/snapshot semantics.

## Core Shape

Page primitive users should read the [shared ownership and v1 compatibility contract](docs/page-record-ownership.md).

- Sync-first engine API with async wrappers.
- WAL-backed atomic write batches.
- MVCC sequence numbers for consistent snapshots.
- RAM memtable plus immutable disk segments.
- Segment block checksums and manifest-driven recovery.
- CPU-complete acceleration interface with optional GPU backends.

## First Commands

```powershell
cargo test
cargo run -- put --data-dir .praxis-dev hello world
cargo run -- get --data-dir .praxis-dev hello
```
