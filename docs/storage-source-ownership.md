# Storage source ownership

The compiled crate root is `src/lib.rs`; the CLI in `src/main.rs` uses that
library. Both the core KV engine and pointer-based StorageEngine remain live.
Their WAL protocols and recovery APIs have distinct owners:

| Responsibility | Compiled owner | Reachability |
| --- | --- | --- |
| Core KV engine | `src/engine/core/engine.rs` | `lib -> engine -> core -> engine` |
| Core batch WAL, durability and page WAL | `src/wal/` | `lib -> wal`; core engine imports `crate::wal::{Wal, WalRecord}` |
| Pointer-based StorageEngine and primary records | `src/store/` | `lib -> store`; public engine/record types are re-exported by `store/mod.rs` |
| Pointer-storage WAL | `src/store/wal.rs` | `store/mod.rs` declares private `mod wal` and re-exports `StorageWal` types; `store/engine.rs` imports `super::wal` |
| Pointer-oriented LSM plugin, SSTables and flush pipeline | `src/storage/lsm/` | `lib -> storage -> lsm`; `lib.rs` also re-exports `LsmIndex` |
| Other index plugins and shared plugin contract | `src/index/` | `lib -> index`; includes live B-tree, HNSW, adjacency and specialized plugins |
| Binary format utilities | `src/formats/` and declared plugin binary modules | `lib -> formats -> binary`; index/LSM parents declare their binary modules |

Core WAL records carry core write batches. Pointer-storage WAL records carry
index/key/RecordId mutations, including its grouped-record protocol. Neither
protocol is interchangeable with the other. Existing legacy/recovery paths and
tests remain in place. Consolidating these live engines requires an explicit
survivor-engine, public API and data-migration design before further format
work; issue #29 is separate from the dead-source cleanup in issue #31.

## Removed uncompiled copies

Issue #31 removed exactly these 14 tracked files, verified against merged
default `912362462f77446846b465ff4497593b0c2f6d34`:

```text
src/storage/wal/mod.rs
src/storage/wal/record.rs
src/storage/wal/writer.rs
src/engine/indexes/mod.rs
src/engine/indexes/btree/mod.rs
src/engine/indexes/btree/binary/mod.rs
src/engine/indexes/hnsw/mod.rs
src/engine/indexes/hnsw/binary/mod.rs
src/engine/indexes/hnsw/adjacency/mod.rs
src/engine/indexes/hnsw/adjacency/binary/mod.rs
src/engine/indexes/lsm/mod.rs
src/engine/indexes/lsm/binary/mod.rs
src/index/lsm.rs
src/libs/lib.rs
```

The same inventory and parent-module/include evidence were reconfirmed after
fast-forwarding to `f3ae6c47c6a5ffde7cdd2861717f0c0256cd463f`; the incoming core
WAL framing changes did not touch any removed file or its module parents.

Module-graph evidence before removal:

- `storage/mod.rs` declared only `lsm` and `tiered`, leaving its WAL copy outside
  the graph. `engine/mod.rs` did not declare `indexes`; `index/mod.rs` did not
  declare `lsm`. No parent declared `libs`.
- Cargo used its default library/binary roots, with no alternate library path
  or build script. Tests, benchmarks, tooling and repository-wide source-path
  searches found no references that connected these files to another target.
- The sole `#[path]` attribute selected live CF-generation tests. The two
  `include_str!` invocations embedded protobuf files. The two local declarative
  macros generated identity types and metric checks, not modules.
- Fifteen tests embedded in the dead binary copies were also outside the graph.
  Their corresponding live codec tests, along with storage compatibility and
  recovery tests, were preserved. No compiled module or public export changed.

This cleanup removes stale source ownership without changing persisted data,
formats, manifests, recovery behavior or engine selection. `cargo tree` shows
package dependencies; module declarations and explicit source includes establish
Rust source reachability.

## Verification

Pinned Rust 1.99.0, locked dependencies, two Cargo jobs and isolated target
`D:/poiesis-targets/phase-03-canonical-storage-sources`:

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-03-canonical-storage-sources
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features --jobs 2 --target-dir D:/poiesis-targets/phase-03-canonical-storage-sources -- -D warnings
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check HEAD
```

The full suite passed 457 tests with zero failures and eight ignored on
`9123624`, preserving that baseline's compiled test count. After the fast-forward
to `f3ae6c4`, the fresh full suite passed 474 tests with zero failures and eight
ignored. Final-base formatting, strict all-target/all-feature Clippy, both
storage gates and diff checks passed. No live tests or source were edited, and
no deletion-mirroring tests were added.

After integration with retention default `5a3e2ef`, the combined suite passed
486 tests with zero failures and eight ignored across 62 test targets. Format,
strict all-target/all-feature Clippy and both storage gates also passed on that
composition. Independent review found no module-reachability or deletion blocker.
