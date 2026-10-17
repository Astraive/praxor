# Praxis Engine and Storage Kernel Architecture

Page primitive ownership and v1 compatibility are documented in [Page database ownership](page-record-ownership.md).

Astraive/praxor (package `praxis`) owns the canonical query semantic pipeline
and the low-level storage kernel beneath it. Query/parser, binding/type rules,
planner, executor and semantic catalog responsibilities stay in the engine;
their current public modules remain experimental. Ownership does not imply
complete language execution or durable catalog/query integration. See
[query readiness](query-readiness.md) for executed observations, known gaps and
the bounded follow-on gates in [#60](https://github.com/Astraive/praxor/issues/60).

The core design is:

```text
Storage kernel = shared durability + shared recovery + shared canonical storage
        + shared MVCC/snapshots + shared cache/memory/IO
        + composable specialized physical engines
```

Poiesis owns product/session/authorization/protocol context and consumes engine
contracts. Optional PQL tooling also consumes those contracts; the engine
depends on neither. The engine's semantic modules use its storage primitives,
without moving parser/planner logic into WAL, cache or physical storage paths.

See [storage source ownership](storage-source-ownership.md) for the compiled
owners, module-graph evidence and the boundary between dead-source cleanup and
the separate migration of the two live engine/WAL protocols.

```text
+--------------------------------------------------+
|                 POIESIS PRODUCT                  |
| Sessions / Authorization / Protocols / Runtime   |
+--------------------------------------------------+
|         PRAXOR ENGINE (package praxis)            |
| Query Syntax / Binding / Planning / Execution     |
| Semantic Catalog (experimental; readiness gates) |
+--------------------------------------------------+
|              LOW-LEVEL STORAGE KERNEL            |
| WAL / MVCC / Recovery / Cache / Indexes          |
| BTree / LSM / Graph / Vector / Columnar          |
| Unified Record Store + Replication Primitives    |
+--------------------------------------------------+
|                OS / Hardware                     |
+--------------------------------------------------+
```

## Kernel Invariants

These rules are non-negotiable. A feature that violates them belongs outside the kernel.

- Canonical values exist exactly once except for replicas, snapshots, backups, erasure-coded redundancy, and lossy/vector summaries.
- Indexes are pointer-oriented by default: `Key -> RecordId`, never `Key -> full value`.
- WAL is the source of durability truth before checkpoint.
- Every durable structure is checksummed, versioned, and independently recoverable.
- Reads must not block writes on normal paths.
- Crash recovery is deterministic.
- Storage formats support forward-compatible evolution.
- Compaction never violates snapshot visibility.
- Memory ownership is explicit: arena, slab, epoch, refcount, and page lifetime are visible in the subsystem contract.
- No subsystem bypasses manifest and format-version tracking.
- Every storage operation is measurable: latency, amplification, IO cost, memory cost, and CPU cost.

## Storage Engine Laws

- Law 1: Durability Before Visibility. No write becomes visible before its WAL durability guarantee is satisfied.
- Law 2: Immutable Structures Scale Better. Immutable segments, SSTables, postings, and columnar parts are preferred when they reduce contention and recovery risk.
- Law 3: Background Work Must Be Bounded. Compaction, GC, repair, tier migration, and cleanup run under explicit budgets.
- Law 4: Pointer Stability Matters. Stable `RecordId` values reduce rewrite amplification and allow indexes to survive value relocation.
- Law 5: Data Temperature Determines Layout. Hot data favors row/locality layouts; cold data favors compressed analytical layouts.
- Law 6: Hardware Awareness Is Mandatory. The engine adapts to SSD, NVMe, PMEM, NUMA, GPU, object storage, and eventually ZNS SSDs.
- Law 7: Specialization Wins Physical Layouts. LSM, B+tree, vector, graph, search, and columnar structures should share kernel services, not one physical representation.

## Physical Storage Model

Praxis uses a hybrid physical model where canonical data ownership is separated from access structures.

| Layer | Responsibility |
|---|---|
| WAL | Durability before checkpoint |
| Value Store | Canonical bytes |
| Record Directory | Stable `RecordId` to physical location indirection |
| Specialized Indexes | Access acceleration |
| Materialized Layouts | Workload optimization |
| Analytical Projections | Optional derived cold/scan layouts |
| Replication Log | Storage-layer shipping primitive |
| Manifest | Durable file inventory, versions, checkpoints |

The central innovation is not one physical engine. It is a composable storage kernel where specialized physical engines share durability, recovery, snapshots, transactions, caching, and replication primitives.

## Storage Responsibilities

The low-level storage kernel owns:

- WAL, redo logging, checkpoints, crash recovery, snapshots.
- Pages, SSTables, segments, blocks, compression, checksums, file layouts.
- Buffer pool, block cache, row cache, compressed cache, memory allocators.
- Snapshot isolation, visibility rules, rollback primitives, commit ordering.
- B+tree, LSM, ART, bitmap, inverted, HNSW, graph adjacency, and columnar projection structures.
- Replication log, snapshot transfer, PITR, raft-ready persistence primitives.
- Direct IO, async IO, SIMD, GPU acceleration, NUMA awareness.
- `RecordId`, single-copy value storage, pointer-only indexes.

Above that kernel, the engine owns query syntax, binding/type rules, planning,
execution and semantic catalog rules. Current implementation limits are
documented in [query readiness](query-readiness.md); there is one semantic
authority, without a second compiler or catalog writer in optional tooling.

The low-level storage kernel does not own:

- SQL parser, Cypher parser, GraphQL parser, vector query language.
- Query optimizer, planner, or cost-based query semantics.
- Cluster topology, routing, coordinator behavior, distributed transactions.
- Product sessions, authorization and user-facing policy.
- REST, gRPC, SQL wire protocol, or user-facing database APIs.

The kernel supplies storage primitives to engine semantics. Product-facing
protocol/session context belongs in Poiesis. A clean engine checkout requires
no sibling repository or absolute-path product/tooling dependency.

## Performance Targets

| Metric | Goal |
|---|---|
| Write amplification | Less than 10x worst-case for target LSM workloads |
| Read amplification | Bounded by explicit level/index policy |
| Space amplification | Less than 1.5x excluding replicas/backups/snapshots |
| Point read P99 | Sub-millisecond on NVMe for warm metadata/cache |
| WAL fsync latency | Amortized through group commit |
| Compaction stalls | Near-zero under normal configured load |
| Recovery time | Proportional to dirty window, not full database size |
| Snapshot creation | O(1) logical snapshot |
| Cache accounting | Per-domain hit/miss/eviction/bytes |
| Background work | Bounded by IO, CPU, memory, and tenant budgets |

Benchmarks must state hardware, durability mode, cache size, compression, dataset shape, concurrency, and correctness level. Praxis should beat class-specific engines only on comparable workloads, not by mixing incompatible benchmark claims.

## Memory Architecture

Target memory model:

- Arena allocators for memtables, postings builders, graph builders, and transient compaction state.
- Slab allocators for fixed-size pages, cache metadata, WAL records, and block handles.
- NUMA-local caches and per-shard memory budgets.
- Epoch-based reclamation for lock-free readers.
- RCU read paths for metadata and immutable structure swaps.
- Lock-free read iterators where ownership/lifetime is explicit.
- SIMD-aligned vector memory.
- Huge-page aware caches for large hot indexes.
- Spill-to-disk policies for builders and sort/merge work.
- Adaptive memory quotas by subsystem, tenant, and workload class.

No subsystem may hide unbounded memory growth behind convenience collections.

## WAL, Manifest, And Recovery

The WAL is the durable truth until a checkpoint makes state independently recoverable.

Required WAL behavior:

- Segmented append-only log with record checksums.
- Group commit and configurable sync policy.
- Commit markers for atomic batches.
- Idempotent replay records.
- Replay-safe index mutations.
- Torn suffix detection.
- Optional recycling after checkpoint.

Required manifest behavior:

- Atomic manifest edits.
- File inventory for value segments, SSTables, index files, columnar parts, replication checkpoints.
- Format versions for every durable structure.
- Checkpoint pointers and GC horizons.
- No file becomes live without manifest tracking.

Recovery must handle process crash, power loss, partial WAL write, torn page, checksum mismatch, compaction interruption, partial manifest update, disk corruption, replica lag, and network partition at the replication layer. Recovery output must be structurally valid, snapshot-consistent, and replay-safe.

## MVCC Model

Every record version should carry:

- Create sequence.
- Delete sequence.
- Transaction visibility metadata.
- Commit timestamp when enabled.
- Optional TTL.

Every snapshot should carry:

- Visibility watermark.
- Active transaction set.
- GC horizon.

GC policy should use:

- Epoch reclamation.
- Tombstone cleanup.
- Snapshot pinning.
- Compaction-aware version elision.

The first stable target is snapshot isolation. Serializable validation can be layered later.

## LSM And SSTable Design

LSM is the primary write-heavy storage/index family.

Each SSTable should contain:

- Data blocks.
- Restart intervals.
- Prefix-compressed keys.
- Partition index.
- Bloom filter.
- Compression dictionary.
- Metadata block.
- Range tombstones.
- Checksums.
- Footer.
- Format version.

Required support:

- Mutable and immutable memtables.
- Skiplist, hash, and B-tree memtable variants.
- Partitioned indexes and partitioned blooms.
- Prefix blooms and range filters.
- Fence pointers.
- Block cache pinning.
- Zero-copy reads where lifetimes are explicit.
- Leveled, tiered, universal, and time-window compaction.
- Tombstones, TTL, range tombstones, and snapshot-safe compaction.
- Read/write/space amplification accounting.

## B+Tree Page Engine

B+tree is the ordered/page-based engine for relational and range-heavy storage workloads.

Each page should contain:

- Page header.
- Page checksum.
- Page LSN.
- Slot directory.
- Free-space pointer.
- Variable-length cells.
- Sibling links.
- Fence keys.

Required support:

- Prefix compression.
- Overflow pages.
- Ghost records.
- Online defragmentation.
- Compressed pages.
- Page splits and merges.
- Clustered primary mode.
- Pointer-only secondary mode.
- MVCC visibility checks.
- Buffer pool integration.

## Specialized Engines

Specialized physical/index engines should remain composable and pointer-oriented.

- Wide-column: partition-aware SSTables, clustering keys, sparse rows, TTL, tombstone compaction.
- Document: structural field indexes, path indexes, compressed binary document blocks.
- Search: Lucene-style term dictionary, postings blocks, skip data, roaring bitmaps, segment merge.
- Graph: compressed adjacency lists, CSR pages, bidirectional edge indexes, traversal locality.
- Vector: HNSW, IVF-flat, PQ, OPQ, scalar quantization, SIMD/GPU scoring, metadata filtering.
- Time-series: time partitions, delta encoding, Gorilla-style compression, retention compaction.
- Analytical: columnar segments, zone maps, late materialization, vectorized scans, adaptive encoding.
- Log/stream: segmented append log with retention and compaction.

These engines share WAL, recovery, snapshots, transactions, cache policy, manifest tracking, and `RecordId`.

## Tiered Storage

| Tier | Medium | Use |
|---|---|---|
| Hot | RAM/NVMe | Active working set |
| Warm | SSD | Operational data |
| Cold | HDD/Object store | Historical/archive data |
| Frozen | Compressed object segments | Snapshots/backups |

Policies:

- Automatic migration.
- Workload-aware placement.
- Heat scoring.
- Compression escalation.
- Tenant-aware quotas.
- Read-repair or prefetch on promotion.

## IO And Hardware

Target IO and hardware support:

- Buffered IO and direct IO.
- Async IO abstraction.
- Linux `io_uring`.
- Optional SPDK.
- RDMA-ready replication buffers.
- Zero-copy replication.
- PMEM-aware persistence.
- NUMA-aware scheduling.
- SIMD checksum, compression, bloom probing, vector distance, and column filtering.
- GPU offload for vector scoring, ANN candidate scoring, columnar predicates, compression batches, and checksums.
- ZNS SSD support for append-friendly regions.
- Object storage integration for cold/frozen tiers.

Correctness always belongs to the scalar CPU fallback; acceleration may only change speed.

## Failure Model

The engine must remain correct under:

- Process crash.
- Power loss.
- Partial WAL write.
- Torn page.
- Checksum mismatch.
- Compaction interruption.
- Partial manifest update.
- Disk corruption.
- Replica lag.
- Network partition in the replication layer.

Recovery must always produce:

- Structurally valid state.
- Snapshot-consistent state.
- Replay-safe state.

## Logging And Observability

Production storage paths must use `slog` only.

- Use `slog::Storage::emit`, `slog::Index::emit`, `slog::Compaction::emit`, `slog::Warning::emit`, `slog::Error::emit`, or lowercase `slog::<domain>` helpers.
- Do not use `println!`, `eprintln!`, `dbg!`, ad hoc `format!` strings as log messages, `log`, or `tracing` directly in production storage paths.
- Emit structured JSON wide events at operation completion.
- Include `request_id`, `operation`, `record_id`, `snapshot_id`, `segment_id`, `index_type`, `duration_ms`, `bytes_read`, `bytes_written`, `rows_scanned`, `backend`, `fallback_used`, `outcome`, and `error_code` when applicable.
- Measure latency, amplification, IO cost, memory cost, CPU cost, cache behavior, and background-work budgets.

## Implementation Roadmap

### Short Term

- Lock kernel invariants in docs and public internal contracts.
- Wire `StorageKernel`, `RecordDirectory`, WAL, manifest, and index mutation accounting together.
- Keep indexes pointer-only by default.
- Expand SSTable writer/reader into the LSM flush path.
- Add page manager scaffolding around the B+tree page format.
- Add storage-operation wide events through `slog`.
- Add sharded cache adoption in read paths.

### Medium Term

- Add full LSM flush, immutable memtables, compaction picker, range tombstones, TTL, and amplification budgets.
- Add B+tree page splits/merges, free list, buffer pool, and page LSN recovery.
- Add formal MVCC snapshot registry, GC horizon, transaction visibility, and rollback primitives.
- Add manifest edit log and checkpoint lifecycle.
- Add replication snapshot transfer and raft-ready persistence primitives.
- Add memory arenas, slabs, epoch reclamation, and NUMA-local cache partitions.

### Long Term

- Add persistent search, graph, vector, time-series, wide-column, document, analytical, and log/stream engines.
- Add tier migration, object storage, PITR, repair/scrub tools, and online upgrades.
- Add async IO, `io_uring`, optional SPDK, PMEM, RDMA, ZNS SSD, and zero-copy replication.
- Add GPU kernels behind deterministic CPU fallback.
- Add multi-tenant isolation, workload admission control, and bounded background work.

### Research Grade

- Adaptive indexing.
- Learned indexes.
- Fractal/B-epsilon trees.
- Bw-tree/latch-free ordered indexes.
- Cache-oblivious structures.
- Adaptive row/column layout switching.
- AI-assisted compaction tuning with deterministic safety bounds.
- Semantic caching for vector/search metadata.
- Disaggregated storage with local hot cache and remote cold state.

## Non-Goals

- No parser/planner logic inside low-level storage paths; engine semantic modules own that pipeline.
- No distributed coordinator in Praxis.
- No duplicated full-value secondary indexes by default.
- No blocking global locks on normal paths.
- No hidden memory ownership.
- No storage-format instability.
- No workload-specific hacks that violate kernel invariants.

## North Star

Praxis should evolve toward:

- RocksDB durability and LSM maturity.
- ScyllaDB sharding and scheduling discipline.
- InnoDB transactional/page-engine rigor.
- Lucene segment indexing.
- Faiss/HNSW vector capability.
- DuckDB-style analytical locality.
- Neo4j-style traversal locality.
- FoundationDB-style determinism.

All of that should share one canonical value layer, one WAL/recovery system, one snapshot/MVCC model, one cache/memory/IO architecture, and one replication primitive layer.

Supported durable writers follow the [exclusive ownership contract](writer-ownership.md).
Independent handles retain OS leases; legitimate sharing uses explicit owners
and clones. Raw physical utilities remain offline building blocks.

Writable engine opens also follow the [storage root format contract](storage-root-formats.md)
before mutable initialization; read-only diagnostics preserve explicit inspection limits.
