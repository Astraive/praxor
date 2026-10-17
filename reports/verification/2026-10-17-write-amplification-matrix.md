# Actual write batches and manifest cardinality

This report supplies the remaining actual-batch/cardinality measurements for
issue #14. The maintained harness submits real 1/16/256-operation `WriteBatch`
values against 1/16/256 active CF descriptors. All writes target default.
The local aggregate candidate/baseline median batch-rate ratios were 1.99–2.18×.
The [full matrix](write-amplification-matrix/matrix-summary.md) retains rates,
latencies, ranges, WAL bytes and separate allocation results.

## Controls and provenance

Baseline is `636d2ddee1ba82966212a4d4bfbb06497ec3a871`, after the first durability
fixes and before sizing, manifest and coordinator changes. Candidate is merged
default `f3ae6c47c6a5ffde7cdd2861717f0c0256cd463f`. Baseline engine sources came from
an isolated Git archive; only the three identical harness files and their two
benchmark declarations were added. No old implementation was copied into the
product. Archive, dependency lock, source and executable hashes are recorded in
the [baseline archive provenance](write-amplification-matrix/baseline-archive-provenance.json)
and per-control provenance files alongside the raw samples.

Both native executables used Rust 1.99.0 (`b940084d7`) and Cargo 1.99.0
(`5f94df478`), locked dependencies and optimized builds with two jobs. Their
shared harness SHA256 is
`717ac06423bd418586b7204119df788410b5d6c0712522ba3bd8a88810b0f656`;
Cargo.lock SHA256 is
`df982808577cfed40d4c88f13aacb873dcd4b39e8e60c772d3a404fe97e18dce`.
Native timing ran on Windows 10.0.26300, an Intel i7-13650HX (14 cores,
20 logical CPUs, 16 GB RAM), with data on F: NTFS on a Lenovo SSD LN860 1TB
NVMe drive. stdout production logs were redirected to D: files in both controls;
no logging path was disabled in the candidate.

Each sample had 16 warmup batches and 256 measured batches of 128-byte values.
Thus measured operation budgets were 256/4,096/65,536, while the batch budget was
fixed. Batches were prepared as owned values before timing and moved into
`write_batch`; preparation and submitted-batch cloning are excluded. Internal
engine work, normal logging, batch consumption/destruction and individual call
clock reads are included. Setup, CF creation, stats/hash reads, latency sorting,
recovery, value verification and cleanup are excluded. The latency vector is
reserved before timing. Full protocol and reusable commands are in
[the harness guide](../../docs/write-amplification-matrix.md).

The automatic memtable threshold was `usize::MAX`, WAL segments 1 GiB, and
`EveryBatch` was used in a single thread. Every checkpoint had exactly the
requested active CF count, zero segments and one WAL file, with no flush or
pressure compaction. These are real active CF descriptors, not padded manifest
bytes or a segment/L0-pressure matrix.

Three repetitions rotated the nine-case grid by three positions. Baseline's
three repetitions ran first, followed by candidate's three; controls were not
interleaved. Preserve that temporal-order limitation when interpreting ratios.
The [quiet-window record](write-amplification-matrix/timing-window.json) covers
12:36:23.55–12:38:03.26 UTC on 2026-10-17. Native compiler checks before/after and
195 samples at 500 ms intervals observed no cargo/rustc processes. The Windows
process-start subscription was unavailable, so this was a sampled check.
Ubuntu compiler checks before/after were also empty; no WSL builds ran during
the interval. Other workers deferred compiler, large-copy and checkout work.

## Observations

All 54 timing samples reopened successfully and verified every warmup and
measured value. Sequence was 272 (=16 warmup batches +256 measured batches),
independent of operations per batch. Every one of the 27 candidate manifest
hashes remained unchanged between timed checkpoints. All 27 baseline hashes
changed. Descriptor counts stayed constant in both versions; baseline bytes
grew by one as the persisted last sequence changed from 16 to 272.

| Active CFs | Baseline manifest bytes before → after | Candidate bytes before = after |
|---:|---:|---:|
| 1 | 1,196 → 1,197 | 1,300 |
| 16 | 4,406 → 4,407 | 5,552 |
| 256 | 55,766 → 55,767 | 73,869 |

Individual BLAKE3 hashes and file sizes are preserved in
[baseline raw timing](write-amplification-matrix/baseline-timing.jsonl) and
[candidate raw timing](write-amplification-matrix/candidate-timing.jsonl).
An unchanged manifest hash is a correctness checkpoint, not a claim of zero
disk I/O. Physical WAL growth was 191/2,696/42,776 bytes per baseline batch
versus 195/2,700/42,780 in the candidate. The four extra bytes per batch are the
new authenticated V2 header checksum. Application counters recorded exactly one
WAL record, admission, commit batch, successful sync and sync attempt per
candidate batch; baseline lacks the added coordinator metrics and reports null.
The matrix summary normalizes bytes and current syncs by batch and operation.

The [separate allocation probe](write-amplification-matrix/candidate-allocations.jsonl)
uses a counting allocator on the submitting thread, with no timing claims.
For one-operation batches the baseline used approximately 120/367/4,238
allocation calls per batch at 1/16/256 CFs, compared with 61 at every candidate
cardinality. Requested bytes were approximately 15.6/47.5/617.8 KB per baseline
batch versus 7.4 KB current. This counts allocation/reallocation requests,
including replacement sizes, not peak live memory or resident memory. Batch
preparation, checkpoint and recovery allocations are outside its window;
internal engine and ordinary logging allocations are included. All 18 probe
cases also recovered and verified every value.

## Untimed Linux syscall evidence

An independent strace 6.8 probe ran under Ubuntu/WSL2 Linux
6.6.87.2-microsoft-standard-WSL2, glibc 2.39, with the same pinned Rust and
identical harness. Probe databases used ext4 `/dev/sdd` under `/home/neeraj`,
a WSL virtual disk; this is separate filesystem/storage evidence from native
Windows NTFS timing. Setup/warmup/recovery stayed outside explicit BEGIN/END
markers. Each of the nine cells used four measured batches and one warmup batch.

Observed calls inside every cell's markers were identical after normalization:

| Observed Linux call | Baseline per batch | Candidate per batch |
|---|---:|---:|
| successful WAL `fdatasync` | 1 | 1 |
| successful `MANIFEST.tmp` `fsync` | 1 | 0 |
| successful manifest parent-directory `fsync` | 2 | 0 |
| successful manifest rename | 1 | 0 |
| failed observed syncs/renames | 0 | 0 |

At 1/16/256 operations per batch, candidate WAL sync calls per operation were
1 /0.0625 /0.00390625. Baseline observed total file/directory sync calls per
operation were 4 /0.25 /0.015625. Parent-directory calls are counted separately
from file calls; application commit counters do not include these manifest,
header or rotation operations. These are successful OS syscall observations,
not measured hardware flushes, a Windows syscall claim or power-cut proof.

Parsed [baseline](write-amplification-matrix/linux-baseline-syscalls.json) and
[candidate](write-amplification-matrix/linux-candidate-syscalls.json) artifacts
contain case counts and SHA256 of the full external traces. Raw traces remain
at `D:/poiesis-worktrees/write-matrix-results/linux/{baseline,candidate}.strace`.
The parser tests cover split/short/failed marker writes, excluded setup/recovery
calls, failed syncs, file/directory classification, and malformed/missing markers. Unparsed
syncs in the measured region fail parsing instead of silently undercounting.

## Scope and reproduction

This is an aggregate comparison of configured engine revisions, including
allocation-free sizing, removal of ordinary manifest persistence, the bounded
coordinator, CF-generation normalization and authenticated V2 framing. The
history also includes snapshot/read-staging, primary StorageWal, LSM metadata
and cache changes. This default-family core write workload does not separately
isolate those changes. It does not measure segment cardinality, remote devices,
concurrent group commit, long-running steady thermal behavior or power loss.
Three short rotated samples support descriptive medians/ranges, not confidence
or production tail-latency claims. A few faster samples are retained in ranges.

The older [sizing allocation/independent-put report](2026-10-17-write-path-batch-02.md)
and [1/2/4/8/16-thread group-commit policy report](2026-10-17-concurrent-group-commit.md)
remain separate evidence. The misleading Criterion `durable_commits` workload
name is now `independent_durable_puts`. New Criterion `actual_write_batches`
cases use a new empty engine for each iteration, unlike this steady matrix;
their smoke succeeded at 1/16/256 operations, each at sequence 1.

`scripts/prepare_write_matrix_baseline.ps1` prepares a fresh pinned archive.
`scripts/run_write_matrix.ps1` captures native Smoke, Timing or Allocations with
full provenance. `scripts/run_write_matrix_linux_probe.sh` builds and traces
the Linux probe. Invoke it through a WSL login shell so rustup is on PATH, then
parse with `scripts/parse_write_matrix_strace.py`. Generate the published tables
with `scripts/summarize_write_matrix.py`; it requires the complete nine-cell,
three-repetition protocol and identical recorded harness hashes.

## Verification checklist

- [x] Accurately named independent-put Criterion workload and true batches.
- [x] Maintained current-tree actual-batch / real-descriptor matrix.
- [x] Three raw timing repetitions per cell/control, order and provenance.
- [x] Separate native allocator probes and untimed Linux OS-call evidence.
- [x] Actual manifest counts/bytes/hashes, WAL bytes and recovery verification.
- [x] Candidate and pinned baseline optimized builds; Criterion `--test` smoke.
- [x] Final current-tree nine-cell smoke, format and both storage gates.
- [x] Strict locked all-target/all-feature Clippy with two jobs and external target.
- [x] Parser unit tests and complete real traces parsed without missing markers.

Commands used the required explicit targets under
`F:/poiesis-targets/phase-03-write-matrix` (native candidate),
`phase-03-write-matrix-baseline` (native control), and `phase-03-write-matrix-linux`
(serialized Linux builds). Strict Clippy exited 0, both release controls/probes
exited 0, and four parser tests passed. No product algorithm changes were
made, so the unchanged full engine suite was not repeated for benchmark/prose
work. External logs are `D:/poiesis-worktrees/write-matrix-*.log`; raw artifacts
and their capture provenance are retained with this report.

The maintained artifacts were subsequently rebased onto default `66ab7c4`.
Strict all-target/all-feature Clippy, formatting, both storage gates, four
parser tests, Linux shell syntax and all three optimized benchmark smokes
passed again. This integration check does not relabel the historical measured
candidate `f3ae6c4` or add new performance samples.
