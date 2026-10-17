# Benchmarking and Heavy-Load Validation

Praxis benchmark coverage is organized by workload type:

- `benches/accel/*_bench.rs`: CPU and GPU acceleration paths.
- `benches/kv/*_bench.rs`: LSM and key-value storage behavior.
- `benches/sql/*_bench.rs`: secondary index and relational access paths.
- `benches/graph/*_bench.rs`: adjacency and traversal workloads.
- `benches/vector/*_bench.rs`: ANN/vector search workloads.
- `benches/concurrency/*_bench.rs`: mixed workload, hybrid query planning, and thread scaling.
- `benches/durability/*_bench.rs`: WAL, recovery, and compaction behavior.

Baseline captures write timestamped artifacts under `docs/benchmarks/baselines/`.

## Commands

```powershell
# Capture regular stress output plus all non-soak benchmark suites.
./scripts/capture_baseline.ps1

# Include the long-running 1M-operation soak benchmark.
./scripts/capture_baseline.ps1 -IncludeSoak

# Benchmark-only capture when stress tests were already validated separately.
./scripts/capture_baseline.ps1 -SkipStress
```

Each capture records:

- `hardware.json`: OS, CPU, memory, Rust, Cargo, and Git commit metadata.
- `stress-tests.log`: ignored stress test output, unless `-SkipStress` is used.
- benchmark logs grouped by workload type.
- `summary.txt`: capture location.

Criterion HTML reports remain under `target/criterion/` for charting and visual inspection.

The maintained [durable write amplification matrix](write-amplification-matrix.md)
separates actual 1/16/256-operation batches from independent puts and controls
real active manifest descriptor counts. It includes isolated allocation and
Linux syscall probes; report their evidence separately from native timing.
