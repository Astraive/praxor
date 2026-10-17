//! Run with stdout redirected to NUL to keep ordinary write logs out of the
//! report. JSON benchmark summaries use stderr. Setup/recovery are not timed.
use bytes::Bytes;
use praxis::{PraxisConfig, PraxisEngine, WalSyncPolicy};
use serde_json::json;
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn main() {
    let writes = std::env::var("PRAXIS_BENCH_WRITES_PER_THREAD")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(256);
    assert!(writes > 0);
    for threads in [1, 2, 4, 8, 16] {
        for policy in [WalSyncPolicy::EveryBatch, WalSyncPolicy::GroupCommit] {
            run(threads, writes, policy);
        }
    }
}

fn run(threads: usize, writes: usize, policy: WalSyncPolicy) {
    let dir = match std::env::var_os("PRAXIS_BENCH_DATA_DIR") {
        Some(path) => tempfile::tempdir_in(path).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = policy;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let ready = Arc::new(Barrier::new(threads + 1));
    let start = Arc::new(Barrier::new(threads + 1));
    let workers: Vec<_> = (0..threads)
        .map(|thread| {
            let engine = engine.clone();
            let ready = ready.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                let keys: Vec<_> = (0..writes)
                    .map(|index| Bytes::from(format!("key/{thread}/{index}")))
                    .collect();
                let value = Bytes::from(vec![42; 128]);
                let mut latencies = Vec::with_capacity(writes);
                ready.wait();
                start.wait();
                for key in keys {
                    let started = Instant::now();
                    engine.put(key, value.clone()).unwrap();
                    latencies.push(started.elapsed().as_nanos() as u64);
                }
                latencies
            })
        })
        .collect();
    ready.wait();
    let started = Instant::now();
    start.wait();
    let mut latencies: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    let seconds = started.elapsed().as_secs_f64();
    let metrics = engine.stats()["metrics"].clone();
    let commits = (threads * writes) as u64;
    assert_eq!(metrics["commit_batches"].as_u64().unwrap(), commits);
    let syncs = metrics["commit_syncs"].as_u64().unwrap();
    assert!(syncs > 0 && syncs <= commits);
    assert_eq!(metrics["commit_sync_attempts"].as_u64().unwrap(), syncs);
    if matches!(policy, WalSyncPolicy::EveryBatch) {
        assert_eq!(syncs, commits);
    }
    latencies.sort_unstable();
    let percentile = |percent: usize| latencies[(latencies.len() - 1) * percent / 100];
    eprintln!(
        "{}",
        json!({
            "benchmark": "group_commit", "policy": format!("{policy:?}"),
            "threads": threads, "commits": commits, "seconds": seconds,
            "commits_per_second": commits as f64 / seconds,
            "commit_syncs": syncs, "syncs_per_commit": syncs as f64 / commits as f64,
        "commit_sync_attempts": metrics["commit_sync_attempts"],
            "batches_per_group": commits as f64 / metrics["commit_groups"].as_u64().unwrap() as f64,
            "mean_queue_wait_ns": metrics["commit_queue_wait_ns"].as_u64().unwrap() / commits,
            "mean_sync_ns": metrics["commit_sync_ns"].as_u64().unwrap() / syncs,
            "call_p50_ns": percentile(50), "call_p95_ns": percentile(95), "call_p99_ns": percentile(99),
        })
    );
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.snapshot().sequence, commits);
    for thread in 0..threads {
        for index in 0..writes {
            assert_eq!(
                engine
                    .get(format!("key/{thread}/{index}"))
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                &[42; 128]
            );
        }
    }
}
