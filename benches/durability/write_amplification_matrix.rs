//! Uninstrumented single-writer EveryBatch matrix. See docs/write-amplification-matrix.md.
mod write_matrix_support;

use praxis::{PraxisEngine, WriteBatch};
use serde_json::json;
use std::time::Instant;

fn measure(engine: &PraxisEngine, batches: Vec<WriteBatch>, probe: bool) -> serde_json::Value {
    let mut latencies = Vec::with_capacity(batches.len());
    let started = Instant::now();
    for batch in batches {
        let call_started = Instant::now();
        engine.write_batch(batch).unwrap();
        latencies.push(call_started.elapsed().as_nanos() as u64);
    }
    let elapsed_ns = started.elapsed().as_nanos() as u64;
    latencies.sort_unstable();
    let percentile = |percent| latencies[(latencies.len() - 1) * percent / 100];
    if probe {
        json!({ "measurement": "untimed_syscall_probe" })
    } else {
        json!({
            "measurement": "uninstrumented_timing",
            "elapsed_ns": elapsed_ns,
            "call_p50_ns": percentile(50),
            "call_p95_ns": percentile(95),
            "call_p99_ns": percentile(99),
        })
    }
}

fn main() {
    write_matrix_support::run(measure);
}
