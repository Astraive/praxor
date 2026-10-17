# Bounded concurrent core commits

This batch implements the concurrent coordinator portion of issue #14 and fixes
issue #24. It is integrated on merged default
`15d5b5961b75f910e696fef9643a56e5e0af301d`. Independent concurrency review found
no additional blockers. See `docs/group-commit.md` for the contract and limits.

Followers now admit owned requests without holding the writer mutex. One leader
drains a closed FIFO prefix, appends independent checksummed records, syncs once,
publishes the entire cohort, and completes exactly its members. CAS/optimistic
requests are singleton validation barriers. Admission includes in-flight work,
with count/byte backpressure and an oversized singleton path. Unwinding or
uncertain IO poisons writes/maintenance and wakes waiters; reads keep the last
published state. Recovery can contain complete records from unsuccessful calls.

Column-family create/drop now save a cloned manifest before installing live
changes. Persistence errors require reopen; ordinary validation errors remain
non-poisoning. The separate drop/recreate generation issue remains tracked in
issue #25 and is not fixed by this persistence transition alone.

## Verification

Windows, pinned Rust 1.99.0, locked dependencies:

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-03-group-commit
cargo fmt --check
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-03-group-commit --all-targets --all-features -- -D warnings
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
```

The integrated suite passed 438 tests, failed none, and ignored eight.
Formatting, strict Clippy and both storage gates passed. New tests cover forced
eight-writer grouping (RED eight syncs, GREEN one), FIFO conditions and conflicts,
unpublished visibility, arrivals after cohort closure, admission limits and
oversized requests, leader unwind, real read-only-file append failure, device
sync failure, poison gates, sequence exhaustion, rotation/reopen, and failed CF
create/drop installation. The CF failures also demonstrated RED before repair.
Sync attempts and elapsed time include failed syncs; success counts exclude them.

## Local release policy comparison

The committed `group_commit` benchmark compares EveryBatch and GroupCommit on
the new implementation. It is not a before/after comparison against the old
coordinator. Three optimized trials used 256 one-operation commits per thread,
128-byte values, a fresh database for each case, and data on F:. Setup, cleanup
and full read-back recovery verification are outside timing. Existing logging
is enabled, with stdout discarded. All reported commit-sync attempts succeeded.

```powershell
$env:PRAXIS_BENCH_WRITES_PER_THREAD = '256'
$env:PRAXIS_BENCH_DATA_DIR = 'F:/poiesis-bench-data'
cargo bench --locked --jobs 2 --bench group_commit > $null 2> group-commit.jsonl
```

Repeat the command to compare trials. The local machine has 16 GB RAM, an Intel
i7-13650HX with 20 logical CPUs and a Lenovo LN8601TB SSD. Median per-trial results:

| Threads | EveryBatch commits/s | GroupCommit commits/s | GroupCommit syncs/commit |
| ---: | ---: | ---: | ---: |
| 1 | 331 | 343 | 1.000 |
| 2 | 331 | 334 | 0.996 |
| 4 | 334 | 741 | 0.498 |
| 8 | 380 | 1,441 | 0.248 |
| 16 | 361 | 2,671 | 0.125 |

At 16 threads, the median of per-trial call p99 values was 49.92 ms for
EveryBatch and 7.10 ms for GroupCommit. There is no meaningful demonstrated gain
at one or two threads. These are short local policy comparisons in fixed case
order, with other work on the same machine; they do not establish production
tail latency or power-loss safety. Header/rotation syncs are separate from the
commit-sync counters.

Issue #14 remains open for broader batch-size/manifest-cardinality measurements
and storage/query amplification work. This batch makes concurrent sync sharing
real and measured without claiming that the entire performance program is done.
