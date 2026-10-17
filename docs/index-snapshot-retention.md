# Index snapshot retention

The canonical `LsmIndex` and `BTreeIndex` preserve key-to-`RecordId` mappings at
every raw sequence ceiling through compaction, flush, and snapshot reopen.
These APIs have no registered snapshot lifetime or persisted history horizon.
Consequently, compaction retains ordinary increasing sequence histories,
including older puts and tombstone barriers for currently deleted keys.
Required history can grow with writes; this change does not bound that growth.

## Append order and safe pruning

Reads visit a key's append history in reverse append order and select the first
record whose sequence is at or below the supplied ceiling. They do not select
the greatest eligible sequence. Caller-supplied sequences can repeat or decrease.

A later append at sequence `S` dominates an earlier append at sequence `T >= S`:
whenever the earlier record is eligible, the later record is also eligible and
wins by append order. Compaction visits records newest to oldest, retaining the
first record and then only records strictly below the minimum retained sequence.
It preserves the original order of that subsequence. An optional minimum,
rather than a sentinel, allows a first sequence of `u64::MAX` to survive.
Tombstones participate in the same rule as puts.

The reclaimable-version estimate uses precisely this dominance rule. Maintenance
requires a positive estimate even when the configured threshold is zero.
Monotonic histories therefore produce no pruning job; duplicate replay records
and dominated nonmonotonic appends can produce useful jobs. Manual compaction
remains available. Sorting, maximum job limits, and runtime options are unchanged.

Bloom filters, fence bounds, and B-tree page metadata describe current live keys.
They cannot reject historical reads. A current tombstone can leave this metadata
empty while an older put still resolves at an earlier ceiling.

## Custom index plugins

`IndexPlugin::snapshot_read_capability` defaults to
`IndexSnapshotCapability::Unsupported`. `get_at_checked` returns the typed
`PraxisError::UnsupportedIndexSnapshotRead` error for an unsupported plugin, and
`StorageEngine::lookup_rid_at` uses that checked API. This validation error leaves
the storage handle usable. The legacy `Option`-returning `get_at` default now
returns `None`; it never substitutes current data for a historical read.

A versioned custom plugin must explicitly declare `RawSequenceCeilings` for
checked snapshot reads, implement sequence-aware mutations and reads, and retain
all mappings visible at any ceiling during compaction. Implementing `get_at`
alone no longer enables checked storage snapshot reads. This is a source-level
contract change. The new trait methods have defaults, so existing implementations
still compile. Custom plugins can provide `reclaimable_version_count` for their
own safe maintenance; its conservative default is zero.

## Persistence and scope

LSM and B-tree binary snapshot magic, version, and record layout are unchanged.
Legacy JSON snapshots remain readable and migrate on flush. Compaction preserves
the existing assigned sequence counter even when its highest-sequence record is
dominated and removed. Empty histories can be removed safely.

This contract concerns index mappings. `StorageEngine::fetch` still reads current
primary record liveness: preserving an old RID does not preserve a deleted row
payload. Primary historical row visibility and retention are tracked separately
by issue #29. No full row MVCC or power-loss durability guarantee is added here.
