# Durable write amplification matrix

`engine_write_path` keeps the original independent-puts workload under the
accurate `independent_durable_puts` name. `actual_write_batches` submits one
1/16/256-operation `WriteBatch` to a new empty engine per Criterion iteration.
Engine setup, batch cloning and returned engine/directory destruction are
outside its timed closure. These cases measure the first commit, not steady
state. Sequence IDs advance once per submitted batch in both workloads.

`write_amplification_matrix` measures a steady, single-threaded `EveryBatch`
workload against **1/16/256 total active column-family descriptors**, including
default. All writes target default; the other descriptors are real, persisted,
unused active families. This controls manifest cardinality without preparing
segments or introducing L0 pressure. It is not a segment-cardinality study.

Each sample performs 16 warmup batches followed by 256 measured batches, with
1/16/256 operations per batch and 128-byte values. Keys are deterministic and
unique within each phase. Both phases' owned batches are constructed before
measurement; submitted batch construction and cloning are excluded. Internal
engine allocation, batch consumption/destruction, normal production logging
and the individual call clock reads are included. The latency vector is
reserved before timing. Three repetitions rotate the nine-case grid by three
positions so each cardinality leads once. Preparation, CF creation, hash/stats
checkpoints, sorting latency samples, recovery, reads and cleanup are excluded.

The automatic memtable threshold is `usize::MAX`; WAL segments are 1 GiB.
Every checkpoint asserts zero segments, one WAL, and the requested number of
active CFs. Metrics must show no flush or pressure compaction. This keeps the
prepared manifest cardinality stable and avoids rotation inside measurement.
Before/after checkpoints record manifest bytes and BLAKE3, physical WAL bytes,
sequence and application metrics. Current writes require an unchanged manifest
hash with `--expect-stable-manifest`. An older baseline may rewrite sequence
digits, changing both bytes and hash; those observations are reported rather
than asserted equal. Every case reopens and checks sequence = warmup batches +
measured batches and every expected value in both phases.

The timing binary uses the normal allocator. The separate
`write_amplification_allocations` binary instruments allocations/reallocations
on the submitting thread only. Its allocated byte total counts requested bytes
(including replacement reallocations), not peak live or resident memory.
Preparation/checkpoints/recovery are outside its allocation window; internal
engine and ordinary logging allocation are included. No probe timing is used
as performance evidence. Missing baseline metric fields remain null.

Build with pinned Rust 1.99.0, `--locked`, an explicit external target and two
jobs. For example:

```powershell
cargo bench --locked --jobs 2 --target-dir F:\poiesis-targets\phase-03-write-matrix --bench engine_write_path --bench write_amplification_matrix --bench write_amplification_allocations --no-run
```

Invoke the built `write_amplification_matrix-*.exe` with stdout redirected to a
file or NUL and stderr to JSONL. stdout retains ordinary production logging in
both revisions; JSON summaries and optional syscall markers use stderr. The
default grid/repetitions are the reported protocol; `--batches 2
--warmup-batches 1 --repetitions 1` is only a correctness smoke. Always supply
`--label`, exact `--source-revision`, `--harness-hash`, and `--data-dir`.

For a source comparison, copy this same harness into an external clean archive
of baseline `636d2ddee1ba82966212a4d4bfbb06497ec3a871`, append only the two benchmark
targets to its manifest, and build in a separate target. Record source SHA,
Cargo.lock hash, harness hashes, toolchain, OS, filesystem/storage and order.
This compares aggregate old/new behavior, including sizing, per-write manifest
removal, cache/metadata ownership, coordinator/CF policy work and record format
changes present at the recorded candidate. It does not isolate one change.

`--probe` emits explicit BEGIN/END markers without timing output. An untimed
Linux `strace -f -yy -s 4096 -e trace=write,fsync,fdatasync,rename,renameat,renameat2,openat,close`
probe can count file and parent-directory sync calls inside those markers with
`scripts/parse_write_matrix_strace.py`. The parser counts successful and failed
calls separately and rejects missing markers or unparsed syncs. Trace evidence
belongs to its disclosed Linux filesystem, independently of native Windows
timing. Application commit-sync counters exclude creation/rotation/manifest
syncs; neither counters nor OS calls prove physical device flushes or power-cut
durability. An unchanged manifest hash alone does not prove zero disk I/O.

Report raw samples, batches/s, operations/s, mean per-batch elapsed latency and
per-call p50/p95/p99. With only three rotated samples, present medians and ranges
as local descriptive measurements, without statistical significance claims.
