# Incremental LSM metadata

This batch fixes issue #20 on merged default
`dbde4766aec881637a66c3aba86073e96a49b493`. Independent review found no blockers.

Every put/delete previously scanned all history, cloned every live key and
rebuilt the Bloom filter. Building N distinct keys therefore did quadratic work;
hot overwrites also scaled with the resident key count.

The canonical LSM now maintains exact current membership in a separate sorted
set and caches its version count. Live/dead transitions update this set and
Bloom membership incrementally. Geometric Bloom rebuilds account for both
growth and reinsertion churn, shrink after substantial contraction, and reset
when empty. Deletes never clear shared bits. Fence bounds come from the exact
set. Historical reads keep the existing reverse-append selection, including
equal/decreasing supplied sequences, and never use the current-live Bloom filter
to reject historical keys. Derived caches rebuild once on open or compaction.

Binary v1 and legacy JSON snapshots remain readable; persisted fields are
unchanged. The extra exact set retains one additional key copy per live key.
Historical versions remain in memory as before. This change does not fix the
separate snapshot-compaction contract tracked in issue #22.

## Verification

Windows, pinned Rust 1.99.0, locked dependencies:

```powershell
cargo test --locked --jobs 2
cargo fmt --check
cargo clippy --locked --jobs 2 --all-targets --all-features -- -D warnings
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
```

The full suite passed 422 tests, failed none, and ignored eight. Formatting,
strict Clippy, storage logging and boundary checks passed. Seven focused tests
cover allocation scaling, hot overwrites, exact counters/fences, live/dead and
boundary transitions, Bloom growth/shrink/churn, append-order snapshots, and
binary/legacy reopen.

Before the fix, doubling distinct keys from 512 to 1,024 increased measured
allocation calls from 268,376 to 1,062,063. Afterward, building 1,024 keys used
3,417 allocations. A 256-overwrite probe changed from 527,367 calls / 17.1 MB
requested to 263 calls / 26.4 KB. Both resource regressions failed before the
production change and pass afterward. Reproduce these checks with:

```powershell
cargo test --locked --release --test lsm_metadata -- --nocapture
```

## Release measurements

A separate counting-allocator probe ran three samples per cardinality with
eight-byte keys. Setup, legacy fixture generation/open, WAL, value IO and index
destruction were excluded. At 8,192 distinct keys, the same probe measured:

| Measurement | Before | After |
| --- | ---: | ---: |
| Median build time | 5,428.3 ms | 4.10 ms |
| Allocation calls | 67,241,305 | 27,310 |
| Cumulative requested bytes | 2.726 GB | 2.09 MB |
| Median 1,024 hot overwrites | 1,411.3 ms | 0.070 ms |

These timings include allocator instrumentation. Requested bytes include
successive allocation/reallocation requests; they are not retained memory, RSS,
or bytes copied. The result demonstrates removal of repeated whole-index work,
not database-wide throughput or durable-commit performance.

The committed Criterion workloads cover distinct inserts, hot overwrites and
absent deletes over tombstoned history at increasing cardinalities. All twelve
new cases completed successfully with:

```powershell
cargo bench --locked --jobs 2 --bench kv_storage -- lsm_mutations --sample-size 10 --warm-up-time 1 --measurement-time 1
```

On this machine, the uninstrumented new 8,192-key cases measured 3.49–3.58 ms
for distinct construction, 55.6–58.2 us for 1,024 overwrites, and 121.7–137.1 us
for 1,024 absent deletes. These short local intervals do not establish production
tail latency or behavior of the separate SSTable/flush pipeline.
