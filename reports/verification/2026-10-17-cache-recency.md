# Indexed cache recency

Issue #21 replaces per-access owned-key events with safe indexed LRU links.
Hits clone only the returned `Bytes`; occupied insertions consume the caller's
key without an internal key clone. New entries keep one map key clone and move
the caller's key into the arena. Vacancies are reused before growth. Substantial
contraction reclaims arena and lookup storage, and an empty cache releases both.
Lookup capacity high-water tracking accounts for tombstones reducing reported
HashMap capacity without freeing its allocation. Admission remains based on
payload bytes, charging at least one byte per entry; zero budgets admit nothing.
The payload budget does not include metadata or owned-key memory.

The arena retains at most `max(4 * live_entries, 64)` slots after each operation;
lookup allocation capacity uses the same contraction threshold. Its free chain
shares the arena allocation. Recency has no generation counter to exhaust.
Existing exact LRU, empty/zero-value and retain behavior remain covered, with
long-history link/vacancy tests replacing the old counter-overflow test.

## Sources and provenance

The original measurement base was
`dbde4766aec881637a66c3aba86073e96a49b493`; combined verification uses merged main
`c0934652ea1572094b2f48a284cf0115d8d6efe4`. Incoming group-commit/LSM changes did
not edit cache code. The candidate was measured as an uncommitted patch.
The measured `src/cache/block_cache.rs` file SHA256 identifies that source:
`3311328aacc9c76bc1aeb5184db4d27c8cf057b688dca572f0303cbc7c3fc92d`.

The external harness copied these controls without changing their algorithms:

| Control | Commit | Canonical cache source Git blob |
| --- | --- | --- |
| Bounded event queue | `da0521908e6c4f0d13547c539e36a3e0bcb8a87e` | `fa878cb8728312b401d1fbaf9944a4c3dfcc1269` |
| Unbounded event queue | `636d2ddee1ba82966212a4d4bfbb06497ec3a871` | `73a218f46bc292f8d8f9f9e31b58019b066706e3` |

The copied bounded fixture SHA256 is
`90823d3c967fec9a8c6ac5384c8952f226bd5a48b91538d1b8807b1a2c6f4fca`;
the unbounded fixture is
`36012bfb0c87bf04bfe34447788263a9d89e82ea6000cb91310bae53a9eba418`.
These file hashes include local line endings; Git blobs identify canonical
repository contents. The unbounded control retains obsolete key events without
a bound and is included only to quantify the earlier algorithm's cost.

External workload sources under `D:/poiesis-benchmarks/cache-profile`:

| Source | SHA256 |
| --- | --- |
| `src/main.rs` (single-thread timing/allocator probes) | `6c3ee95be3a56b3c844952800a904333f054ec21090c291c963af92a250e094a` |
| `src/bin/contention.rs` (including clean-rerun selection) | `5489f95911837923566046e80c41fa37586b52caf09c3c6d04089cafcf33b739` |

The current-tree [cache_recency benchmark](../../benches/cache/recency_bench.rs) preserves these workload rules for
future comparisons without copying historical implementations into the repo.

## Release methodology

Windows, pinned Rust 1.99.0, Intel i7-13650HX (14 cores/20 logical CPUs), 16 GB
RAM. External builds used release optimization, one codegen unit and thin LTO.
There was no allocator instrumentation in either timing binary and no CPU
affinity setting. Each implementation ran sequentially; order rotated by
repetition. All values were static eight-byte `Bytes` (`payload8`). Keys were
owned `Box<[u8]>`: the first eight bytes encoded a unique little-endian integer,
with `0x5a` filling the remaining bytes. Two resident sets of keys were prepared.

Single-thread probes used 256/4,096/65,536 resident entries, 8/64/256-byte keys
and 1,048,576 cache calls per sample, with five timing repetitions (405 samples).
Hits walked resident keys round-robin. Overwrites replaced resident keys in
round-robin order. Mixed traffic alternated insertion from a two-resident-set
working set with an immediate read of that key. Cache prefill/input-pool setup
and destruction were outside timing. Caller-owned write keys were cloned inside
the timed single-thread loop. Final residency/payload accounting was checked.

A separate System counting-allocator binary ran three repetitions (243 samples).
Input pools were created before tracking. Cache setup was tracked to establish
initial owned live bytes, then traffic counters/peak were reset before workload.
Cache drop occurred while tracking; every sample returned live bytes to zero.
Requested-byte traffic includes full new/old sizes for reallocations. It is
neither bytes copied nor RSS. Retained bytes are requested allocations still
owned by the cache at sample end; peak includes temporary overlap. Static value
storage and precreated input pools are excluded. Peak reflects tracked live
requests, excluding allocator-internal realloc overlap and RSS. Allocation results agreed
exactly across the three repetitions.

External build/run commands (from the external harness directory):

```powershell
cargo build --release --locked --offline --bin poiesis-cache-profile --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
Copy-Item D:/poiesis-targets/phase-03-cache-profile/release/poiesis-cache-profile.exe D:/poiesis-benchmarks/cache-recency-timing.exe
cargo build --release --locked --offline --bin poiesis-cache-profile --features alloc-counts --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
Copy-Item D:/poiesis-targets/phase-03-cache-profile/release/poiesis-cache-profile.exe D:/poiesis-benchmarks/cache-recency-allocations.exe
& D:/poiesis-benchmarks/cache-recency-timing.exe 5 1048576
& D:/poiesis-benchmarks/cache-recency-allocations.exe 3 1048576
cargo build --release --locked --offline --bin contention --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
Copy-Item D:/poiesis-targets/phase-03-cache-profile/release/contention.exe D:/poiesis-benchmarks/cache-recency-contention.exe
& D:/poiesis-benchmarks/cache-recency-contention.exe 3 65536
```

The copied executables and raw CSV/log artifacts are retained outside the
checkout under `D:/poiesis-benchmarks`. Versioned [timing medians](cache-recency/single-medians.csv),
[timing comparisons](cache-recency/single-comparison.csv) and
[allocation summaries](cache-recency/allocations.csv) preserve the reported data.

## Single-thread results

Indexed recency was faster in all 27 timing cases versus both controls:

| Workload | Speedup over bounded | Speedup over unbounded |
| --- | ---: | ---: |
| Hit | 2.65–5.70x | 1.75–3.18x |
| Overwrite | 1.99–3.55x | 1.62–2.27x |
| Mixed eviction | 1.22–1.54x | 1.21–1.60x |

At 65,536 residents, median hit ns/call were:

| Key bytes | Indexed | Bounded | Unbounded |
| ---: | ---: | ---: | ---: |
| 8 | 48.30 | 275.18 | 153.63 |
| 64 | 74.14 | 292.24 | 169.20 |
| 256 | 188.36 | 544.22 | 329.06 |

Indexed hits allocated zero keys/buffers. Indexed overwrites allocated once per
call, entirely the caller's owned input; occupied cache insertion added none.
Bounded overwrites allocated approximately twice per call plus queue buffers.
Mixed traffic fell from approximately 2 to 1.5 allocations/call. Its remaining
eviction-result Vec allocation belongs to the existing unit-returning insert
wrapper, which discards that output; it is cache-internal overhead rather than
required caller output. This patch does not remove it.

Requested allocation bytes at 65,536 residents and 256-byte keys:

| Hit workload | Indexed | Bounded | Unbounded |
| --- | ---: | ---: | ---: |
| Retained at end | 42,074,128 | 60,947,216 | 359,792,656 |
| Peak live | 42,074,128 | 105,513,232 | 359,792,656 |
| Cumulative requested during calls | 0 | 389,545,984 | 365,953,024 |

The bounded hit run with eight-byte keys requested 129,499,136 bytes: 8,388,608
for key clones and 121,110,528 for buffer allocations/reallocations. A smaller
in-place compaction change could reuse those buffers but would retain owned-key
clones and periodic hashing. Indexed recency removes both recurring sources.

## Shared-Mutex contention

All three caches used the same `parking_lot::Mutex` as the production sharded
cache, with 1/2/4/8/16 threads, 256 residents/eight-byte keys and 65,536
residents/256-byte keys. Each thread made 65,536 cache calls per sample; three
repetitions rotated implementation order. Input pools, owned write inputs,
threads and barriers were prepared outside timing. Ready rendezvous and joining
were excluded. Timing included start/finish barrier overhead, cache calls,
mutex waiting and hit validation. Input buffers dropped after the measured
rendezvous. Final residency, payload accounting and values were checked outside
timing. All 54,853,632 timed hits returned the expected payload.

Mixed contention holds one mutex guard for an insert and its immediate get,
preventing competing eviction before validation. Each pair counts as two cache
calls. These are not independently locked calls. The per-worker mean in the CSV
is sum of worker-loop wall times divided by total calls: it includes waiting,
loop and validation cost, and is not a call-latency percentile.

An initial run overlapped another Cargo job beginning at local 17:33:50. Its
earlier 180 samples (all small-cache cases and large-cache hits) finished before
that overlap. All 90 large-cache overwrite/mixed samples were conservatively
replaced by a clean run from 17:36:10–17:37:09, with no Cargo/rustc observed at
start, during, or end. Both runs exited zero. The initial raw CSV remains saved
as `cache-recency-contention-initial-with-build-overlap.csv`; replacements are
`cache-recency-contention-clean-replacements.csv`. Final data combines 180
unaffected rows and 90 replacements, with exactly three distinct repetitions
per implementation/configuration (270 samples). Rerun selector:

```powershell
& D:/poiesis-benchmarks/cache-recency-contention.exe 3 65536 --large-writes-only
```

Versioned [contention comparisons](cache-recency/contention-comparison.csv) and
[medians/ranges](cache-recency/contention-medians.csv) contain all 30 cases.
Median hit throughput, million cache calls/s:

| Residents / key bytes | Threads | Indexed | Bounded | Unbounded |
| --- | ---: | ---: | ---: | ---: |
| 256 / 8 | 1 | 41.513 | 12.703 | 19.796 |
| 256 / 8 | 2 | 23.117 | 8.113 | 8.824 |
| 256 / 8 | 4 | 6.494 | 2.734 | 3.001 |
| 256 / 8 | 8 | 2.384 | 1.397 | 1.672 |
| 256 / 8 | 16 | 1.418 | 0.904 | 0.951 |
| 65,536 / 256 | 1 | 2.914 | 1.687 | 1.753 |
| 65,536 / 256 | 2 | 2.495 | 1.892 | 1.916 |
| 65,536 / 256 | 4 | 1.632 | 0.903 | 1.051 |
| 65,536 / 256 | 8 | 0.730 | 0.462 | 0.548 |
| 65,536 / 256 | 16 | 1.133 | 0.443 | 0.744 |

Indexed wins 29/30 median cases against bounded and 30/30 against unbounded.
The exception is large-cache mixed pairs at 16 threads: indexed 0.592M calls/s
versus bounded 0.661M (10.4% lower), with unbounded at 0.515M. The three-repeat
ranges overlap: indexed 0.547–0.664M, bounded 0.580–0.692M. Worker mean cost was
26.64 us indexed versus 24.03 us bounded, including mutex wait. Overall speedup
ranges are 0.896–3.268x bounded and 1.055–2.620x unbounded.

The single shared lock limits throughput for all implementations as contention
rises. These short local results do not establish production tail latency,
sharded-cache/DB scalability, RSS bounds, or durable IO throughput. Single-thread
and mutex probes also differ in caller-input allocation and history length;
their absolute call times should not be directly equated.

## Current-tree reproduction and verification

The `cache_recency` benchmark runs only the checked-out implementation, emits
CSV, and has no counting allocator. It uses the same keys/values and workload
definitions. Single mode includes caller key construction inside timing; mutex
mode precreates owned inputs and validates all timed hits. Setup/teardown and
final full residency/value/accounting validation are outside timing.

```powershell
$env:CARGO_PROFILE_BENCH_CODEGEN_UNITS = '1'
$env:CARGO_PROFILE_BENCH_LTO = 'thin'
$env:PRAXIS_CACHE_BENCH_MODE = 'single'
$env:PRAXIS_CACHE_BENCH_CALLS = '1048576'
$env:PRAXIS_CACHE_BENCH_REPETITIONS = '5'
cargo bench --locked --bench cache_recency --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
$env:PRAXIS_CACHE_BENCH_MODE = 'mutex'
$env:PRAXIS_CACHE_BENCH_CALLS = '65536'
$env:PRAXIS_CACHE_BENCH_REPETITIONS = '3'
cargo bench --locked --bench cache_recency --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
```

Before repair, 4,096 hits and occupied inserts each allocated 4,543 times. Both
now allocate zero with static values and preconstructed inputs. Retain/mass
eviction map-retention regressions also failed before repair. A collision-heavy
896-to-one retain probe exposed 17,496 retained bytes when tombstones hid lookup
allocation; high-water tracking fixes it. A 50,000-operation independent LRU
reference and 100,000-eviction structural history pass.

Fresh combined locked verification on `c093465` passed 444 tests, failed none,
and ignored eight. Formatting, all-target/all-feature warnings-denied Clippy
(including the new benchmark), storage logging and storage boundary gates all
passed. Optimized current-tree benchmark smoke runs at 1,024 calls/thread and
one repetition passed all 27 single-thread and 30 shared-Mutex configurations.
These smoke timings are not part of the performance tables above.

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features --jobs 2 --target-dir D:/poiesis-targets/phase-03-cache-profile -- -D warnings
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
```

The full suite ran after the fast-forward integration and before the benchmark
artifact was added. Subsequent strict Clippy and optimized smoke runs covered
the artifact. Cache implementation and regression tests were unchanged between
that full suite and these final checks. This verification base excludes the
later CF-generation patch.
