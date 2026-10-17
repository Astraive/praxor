//! Shared source is copied unchanged into the pinned baseline, never its engine code.
use bytes::Bytes;
use clap::Parser;
use praxis::manifest::ColumnFamilyDescriptor;
use praxis::{PraxisConfig, PraxisEngine, WalSyncPolicy, WriteBatch};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Options {
    #[arg(long, default_value_t = 256)]
    batches: usize,
    #[arg(long, default_value_t = 16)]
    warmup_batches: usize,
    #[arg(long, default_value_t = 3)]
    repetitions: usize,
    #[arg(long, value_delimiter = ',', default_value = "1,16,256")]
    batch_ops: Vec<usize>,
    /// Total active descriptors, including the default family.
    #[arg(long, value_delimiter = ',', default_value = "1,16,256")]
    active_cfs: Vec<usize>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "candidate")]
    label: String,
    #[arg(long, default_value = "unrecorded")]
    source_revision: String,
    #[arg(long, default_value = "unrecorded")]
    harness_hash: String,
    /// Emit syscall markers and no timing values. Use with an external tracer.
    #[arg(long)]
    probe: bool,
    #[arg(long)]
    expect_stable_manifest: bool,
}

fn batches(count: usize, ops: usize, phase: &str) -> Vec<WriteBatch> {
    let value = Bytes::from_static(&[42; 128]);
    (0..count)
        .map(|batch_id| {
            let mut batch = WriteBatch::new();
            for op in 0..ops {
                batch.put_default(format!("{phase}/{batch_id:06}/{op:03}"), value.clone());
            }
            batch
        })
        .collect()
}

fn checkpoint(engine: &PraxisEngine, root: &Path) -> Value {
    let manifest_bytes = std::fs::read(root.join("MANIFEST")).unwrap();
    let stats = engine.stats();
    let wal_files: Vec<_> = std::fs::read_dir(root.join("wal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "wal"))
        .collect();
    let wal_bytes: u64 = wal_files
        .iter()
        .map(|path| std::fs::metadata(path).unwrap().len())
        .sum();
    json!({
        "manifest_bytes": manifest_bytes.len(),
        "manifest_blake3": blake3::hash(&manifest_bytes).to_hex().to_string(),
        "active_cfs": stats["manifest"]["column_families"].as_array().unwrap().len(),
        "segments": stats["manifest"]["segments"].as_array().unwrap().len(),
        "wal_file_count": wal_files.len(), "physical_wal_bytes": wal_bytes,
        "sequence": engine.snapshot().sequence,
        "metrics": stats["metrics"],
    })
}

fn marker(kind: &str, id: &str) {
    let line = format!("PRAXIS_WRITE_MATRIX_{kind} {id}\n");
    std::io::stderr().lock().write_all(line.as_bytes()).unwrap();
}

fn emit(value: Value) {
    let line = format!("{value}\n");
    std::io::stderr().lock().write_all(line.as_bytes()).unwrap();
}

pub fn run(mut measure: impl FnMut(&PraxisEngine, Vec<WriteBatch>, bool) -> Value) {
    let options = Options::parse();
    assert!(options.batches > 0 && options.warmup_batches > 0 && options.repetitions > 0);
    assert!(!options.batch_ops.is_empty() && !options.active_cfs.is_empty());
    assert!(
        options
            .batch_ops
            .iter()
            .all(|&count| (1..=256).contains(&count))
    );
    assert!(
        options
            .active_cfs
            .iter()
            .all(|&count| (1..=256).contains(&count))
    );
    let grid: Vec<_> = options
        .active_cfs
        .iter()
        .flat_map(|&cfs| options.batch_ops.iter().map(move |&ops| (cfs, ops)))
        .collect();
    for repetition in 0..options.repetitions {
        // Rotate by a third of the grid: each cardinality leads one default repetition.
        for offset in 0..grid.len() {
            let position = (offset + repetition * grid.len().div_ceil(3)) % grid.len();
            let (active_cfs, ops) = grid[position];
            let dir = match &options.data_dir {
                Some(parent) => tempfile::tempdir_in(parent).unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let mut config = PraxisConfig::new(dir.path());
            config.wal_sync_policy = WalSyncPolicy::EveryBatch;
            config.memtable_flush_threshold_bytes = usize::MAX;
            config.wal_segment_size = 1024 * 1024 * 1024;
            // Equal metadata values in both revisions, independent of caller environment.
            config.logging.commit = "write-matrix".into();
            config.logging.region = "local".into();
            config.logging.node = "single-writer".into();
            let engine = PraxisEngine::open(config.clone()).unwrap();
            for index in 1..active_cfs {
                engine
                    .create_column_family(ColumnFamilyDescriptor {
                        name: format!("cf{index:03}"),
                        ..ColumnFamilyDescriptor::default()
                    })
                    .unwrap();
            }
            let warmup = batches(options.warmup_batches, ops, "warmup");
            let prepared = batches(options.batches, ops, "measured");
            for batch in warmup {
                engine.write_batch(batch).unwrap();
            }
            let before = checkpoint(&engine, dir.path());
            let id = format!("{}-r{repetition}-cf{active_cfs}-ops{ops}", options.label);
            if options.probe {
                marker("BEGIN", &id);
            }
            let measurement = measure(&engine, prepared, options.probe);
            if options.probe {
                marker("END", &id);
            }
            let after = checkpoint(&engine, dir.path());
            for checkpoint in [&before, &after] {
                assert_eq!(checkpoint["active_cfs"], active_cfs);
                assert_eq!(checkpoint["segments"], 0);
                assert_eq!(checkpoint["wal_file_count"], 1);
            }
            assert_eq!(before["sequence"], options.warmup_batches);
            assert_eq!(after["sequence"], options.warmup_batches + options.batches);
            let unchanged = before["manifest_blake3"] == after["manifest_blake3"];
            if options.expect_stable_manifest {
                assert!(
                    unchanged,
                    "ordinary current-tree writes changed the manifest"
                );
            }
            let mut deltas = serde_json::Map::new();
            for name in [
                "writes",
                "wal_records",
                "wal_bytes",
                "write_admissions",
                "commit_groups",
                "commit_batches",
                "commit_syncs",
                "commit_sync_attempts",
                "commit_sync_ns",
                "segment_flushes",
                "automatic_flushes",
                "l0_pressure_compactions",
            ] {
                let delta = before["metrics"][name]
                    .as_u64()
                    .zip(after["metrics"][name].as_u64())
                    .map(|(before, after)| after.checked_sub(before).unwrap());
                deltas.insert(name.into(), json!(delta));
            }
            assert_eq!(deltas["wal_records"], options.batches);
            for name in [
                "segment_flushes",
                "automatic_flushes",
                "l0_pressure_compactions",
            ] {
                assert_eq!(deltas[name], 0);
            }
            for name in [
                "write_admissions",
                "commit_groups",
                "commit_batches",
                "commit_syncs",
                "commit_sync_attempts",
            ] {
                if !deltas[name].is_null() {
                    assert_eq!(deltas[name], options.batches);
                }
            }
            let root = dir.path().to_path_buf();
            drop(engine);
            let reopened = PraxisEngine::open(config).unwrap();
            assert_eq!(
                reopened.snapshot().sequence,
                (options.warmup_batches + options.batches) as u64
            );
            for (phase, count) in [
                ("warmup", options.warmup_batches),
                ("measured", options.batches),
            ] {
                for batch_id in 0..count {
                    for op in 0..ops {
                        assert_eq!(
                            reopened
                                .get(format!("{phase}/{batch_id:06}/{op:03}"))
                                .unwrap()
                                .unwrap()
                                .as_ref(),
                            &[42; 128]
                        );
                    }
                }
            }
            emit(json!({
                "benchmark": "write_amplification_matrix", "schema_version": 1,
                "id": id, "label": options.label, "source_revision": options.source_revision,
                "harness_hash": options.harness_hash, "repetition": repetition,
                "order_position": offset, "active_cfs": active_cfs, "batch_ops": ops,
                "batches": options.batches, "operations": options.batches * ops,
                "warmup_batches": options.warmup_batches, "value_bytes": 128,
                "wal_sync_policy": "EveryBatch", "data_dir": root,
                "submitted_batch_construction_timed": false, "submitted_batch_cloning_timed": false,
                "before": before, "after": after, "manifest_unchanged": unchanged,
                "metric_deltas": deltas, "measurement": measurement,
                "recovery_verified": true,
            }));
        }
    }
}
