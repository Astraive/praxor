# WAL sizing and manifest write amplification

This batch partially addresses issue #14. It removes sizing allocations and
per-commit manifest replacement. Actual concurrent group commit remains open.

## Durability behavior

Ordinary batches still follow the configured WAL sync policy. Their WAL records
are authoritative between structural manifest checkpoints. Recovery raises the
in-memory manifest sequence to the maximum recovered or flushed watermark, so
a subsequent flush can retire WAL files without resetting the sequence on the
next restart. Flush and rotation retain their structural manifest persistence.
No disk format changes are introduced.

`WalRecord::encoded_len` now counts bytes rather than encoding a temporary
record. The allocation regression measured nine sizing allocations before the
change and zero afterward. Byte-exact comparisons cover all operation variants,
mixed operations, empty fields and non-ASCII column family names.

Independent review found a missing watermark reconciliation in the initial
patch. The new put / reopen / flush / reopen regression failed with sequence
zero before that correction and passes afterward. Additional regressions verify
unchanged manifest bytes over sixteen durable writes and recovery when a
manifest temporary-file path is blocked.

## Verification

Integrated on merged default `b992159737f825dfcd27cd6a56ccf9ff8e620200`, using
Windows and pinned Rust 1.99.0:

```powershell
cargo test --locked --jobs 2 --target-dir D:/target
cargo fmt --check
cargo clippy --locked --jobs 2 --target-dir D:/target --all-targets --all-features -- -D warnings
./scripts/verify_slog_storage.ps1
```

The locked suite passed 387 tests, failed none, and ignored eight. Formatting,
strict Clippy and the storage logging gate passed.

## Local release measurements

The added Criterion benchmark measures length calculation for 1/16/256 puts and
1/16/256 consecutive independent durable commits. Each value is 128 bytes; the
durable workload uses `EveryBatch`, one operation per commit, default manifest
size, and a new database per iteration. Setup and output destruction are outside
the timed routine. The existing write logger remains enabled in both versions.
Data directories use the Windows system temporary directory on C:, while build
and measurement artifacts use D:.

Build the same benchmark source against baseline `636d2dd` and this patch with:

```powershell
cargo bench --locked --jobs 2 --bench engine_write_path --no-run
```

The optimized executables were copied outside the target directory and run in
the order before / after / after / before, with separate logs and baselines:

```powershell
$env:CRITERION_HOME = 'D:/poiesis-benchmarks/criterion'
./engine-write-path-before.exe --bench --noplot --sample-size 15 --warm-up-time 0.5 --measurement-time 1 --save-baseline phase02-before
./engine-write-path-after.exe --bench --noplot --sample-size 15 --warm-up-time 0.5 --measurement-time 1 --baseline phase02-before
./engine-write-path-after.exe --bench --noplot --sample-size 15 --warm-up-time 0.5 --measurement-time 1 --save-baseline phase02-after-repeat
./engine-write-path-before.exe --bench --noplot --sample-size 15 --warm-up-time 0.5 --measurement-time 1 --save-baseline phase02-before-repeat
```

The first baseline includes the first durability fixes. The measured after
binary predates the recovery-watermark correction, which changes database open
initialization outside this timed routine; it exercises the final sizing and
ordinary commit paths. The later transaction-pin ancestor does not participate
in this benchmark. Final recovery correctness was tested separately above.

The following ranges are the central estimates from the two runs of each
version, not confidence intervals or per-request latency percentiles:

| Durable commits per iteration | Before | After |
| --- | ---: | ---: |
| 1 | 1.888–2.448 ms | 0.559–0.776 ms |
| 16 | 26.885–29.354 ms | 5.127–7.032 ms |
| 256 | 441.59–448.35 ms | 75.068–104.31 ms |

The representative local workload improves after removing a whole manifest
rewrite, sync and rename per commit. Other builds ran on this 16-GB Windows
machine during parts of the experiment, and repeated estimates vary. These
results do not establish production throughput, tail latency, behavior with
large manifests, real power-loss safety, or concurrent group commit gains.
