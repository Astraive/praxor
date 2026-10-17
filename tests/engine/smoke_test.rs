use bytes::Bytes;
use praxis::manifest::{ColumnFamilyDescriptor, CompactionJobStatus, Manifest};
use praxis::{
    AsyncPraxisEngine, ColumnFamily, JobPriority, MaintenanceRuntimeConfig, PraxisConfig,
    PraxisEngine, PraxisError, RuntimeLaneConfig, WriteBatch,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

#[test]
fn put_get_delete_and_recover_from_wal() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("hello"), Bytes::from("world"))
        .unwrap();
    assert_eq!(engine.get("hello").unwrap().unwrap(), Bytes::from("world"));
    drop(engine);

    let recovered = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    assert_eq!(
        recovered.get("hello").unwrap().unwrap(),
        Bytes::from("world")
    );
    recovered.delete(Bytes::from("hello")).unwrap();
    assert_eq!(recovered.get("hello").unwrap(), None);
}

#[test]
fn write_batch_is_one_sequence_and_flushes_to_segment() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut batch = WriteBatch::new();
    batch.put_default(Bytes::from("a"), Bytes::from("1"));
    batch.put_default(Bytes::from("b"), Bytes::from("2"));
    let sequence = engine.write_batch(batch).unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(engine.flush().unwrap(), Some(1));
    drop(engine);

    let reopened = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    assert_eq!(reopened.get("a").unwrap().unwrap(), Bytes::from("1"));
    assert_eq!(reopened.get("b").unwrap().unwrap(), Bytes::from("2"));
}

#[test]
fn scan_returns_sorted_visible_values() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("k3"), Bytes::from("v3")).unwrap();
    engine.put(Bytes::from("k1"), Bytes::from("v1")).unwrap();
    engine.put(Bytes::from("k2"), Bytes::from("v2")).unwrap();
    let rows = engine.scan(Some(b"k1"), Some(b"k3"), 10).unwrap();
    assert_eq!(
        rows,
        vec![
            (Bytes::from("k1"), Bytes::from("v1")),
            (Bytes::from("k2"), Bytes::from("v2"))
        ]
    );
}

#[test]
fn large_values_move_to_value_log_and_survive_restart() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 8;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let value = Bytes::from(vec![42_u8; 4096]);
    engine.put(Bytes::from("large"), value.clone()).unwrap();
    engine.flush().unwrap();
    drop(engine);

    let reopened = PraxisEngine::open(config).unwrap();
    assert_eq!(reopened.get("large").unwrap().unwrap(), value);
}

#[test]
fn compaction_collapses_overwrites_and_tombstones() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("keep"), Bytes::from("old")).unwrap();
    engine.flush().unwrap();
    engine.put(Bytes::from("keep"), Bytes::from("new")).unwrap();
    engine
        .put(Bytes::from("gone"), Bytes::from("soon"))
        .unwrap();
    engine.flush().unwrap();
    engine.delete(Bytes::from("gone")).unwrap();
    engine.flush().unwrap();

    assert_eq!(engine.compact().unwrap(), 1);
    assert_eq!(engine.get("keep").unwrap().unwrap(), Bytes::from("new"));
    assert_eq!(engine.get("gone").unwrap(), None);

    let stats = engine.stats();
    assert_eq!(stats["manifest"]["segments"].as_array().unwrap().len(), 1);
}

#[test]
fn compare_and_swap_enforces_expected_value() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("cas"), Bytes::from("v1")).unwrap();
    let err = engine
        .compare_and_swap(Bytes::from("cas"), Some(b"wrong"), Bytes::from("v2"))
        .unwrap_err();
    assert!(matches!(err, PraxisError::CompareAndSwapFailed));
    engine
        .compare_and_swap(Bytes::from("cas"), Some(b"v1"), Bytes::from("v2"))
        .unwrap();
    assert_eq!(engine.get("cas").unwrap().unwrap(), Bytes::from("v2"));
}

#[test]
fn compare_and_swap_is_atomic_under_concurrent_writers() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("cas-race"), Bytes::from("seed"))
        .unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let left_engine = engine.clone();
    let left_barrier = barrier.clone();
    let left = std::thread::spawn(move || {
        left_barrier.wait();
        left_engine.compare_and_swap(Bytes::from("cas-race"), Some(b"seed"), Bytes::from("left"))
    });

    let right_engine = engine.clone();
    let right_barrier = barrier.clone();
    let right = std::thread::spawn(move || {
        right_barrier.wait();
        right_engine.compare_and_swap(Bytes::from("cas-race"), Some(b"seed"), Bytes::from("right"))
    });

    barrier.wait();
    let left_result = left.join().unwrap();
    let right_result = right.join().unwrap();
    let success_count = usize::from(left_result.is_ok()) + usize::from(right_result.is_ok());
    assert_eq!(success_count, 1, "exactly one CAS should succeed");

    if let Err(error) = left_result {
        assert!(matches!(error, PraxisError::CompareAndSwapFailed));
    }
    if let Err(error) = right_result {
        assert!(matches!(error, PraxisError::CompareAndSwapFailed));
    }

    let final_value = engine.get("cas-race").unwrap().unwrap();
    assert!(
        final_value.as_ref() == b"left" || final_value.as_ref() == b"right",
        "final value must come from the winning CAS"
    );
}

#[test]
fn torn_wal_suffix_is_ignored_during_recovery() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("safe"), Bytes::from("value"))
        .unwrap();
    drop(engine);

    let wal_path = dir.path().join("wal").join("00000000000000000001.wal");
    let mut wal = OpenOptions::new().append(true).open(wal_path).unwrap();
    wal.write_all(&[0x4c, 0x41, 0x57]).unwrap();
    wal.flush().unwrap();

    let reopened = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    assert_eq!(reopened.get("safe").unwrap().unwrap(), Bytes::from("value"));
}

#[test]
fn wal_rotates_by_configured_segment_size_and_replays_all_segments() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.page_size = 4096;
    config.wal_segment_size = 4096;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    for i in 0..4 {
        engine
            .put(
                Bytes::from(format!("wal-rotate/{i}")),
                Bytes::from(vec![b'w'; 1800]),
            )
            .unwrap();
    }
    let active_wal = engine.stats()["active_wal"]["id"].as_u64().unwrap();
    assert!(active_wal > 1, "expected WAL rotation");
    drop(engine);

    let reopened = PraxisEngine::open(config).unwrap();
    for i in 0..4 {
        assert_eq!(
            reopened
                .get(format!("wal-rotate/{i}").as_bytes())
                .unwrap()
                .unwrap(),
            Bytes::from(vec![b'w'; 1800])
        );
    }
}

#[test]
fn group_commit_writes_survive_restart_under_concurrency() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = praxis::WalSyncPolicy::GroupCommit;
    let engine = PraxisEngine::open(config.clone()).unwrap();

    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();
    for i in 0..4 {
        let engine = engine.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            engine
                .put(
                    Bytes::from(format!("group/{i}")),
                    Bytes::from(format!("value/{i}")),
                )
                .unwrap();
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }
    drop(engine);

    let reopened = PraxisEngine::open(config).unwrap();
    for i in 0..4 {
        assert_eq!(
            reopened
                .get(format!("group/{i}").as_bytes())
                .unwrap()
                .unwrap(),
            Bytes::from(format!("value/{i}"))
        );
    }
}

#[test]
fn deterministic_operation_stream_matches_btree_oracle() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut oracle = BTreeMap::new();

    for i in 0..500_u32 {
        let key = format!("key/{:03}", (i * 37) % 91);
        if i % 7 == 0 {
            engine.delete(Bytes::from(key.clone())).unwrap();
            oracle.remove(&key);
        } else {
            let value = format!("value/{i:04}");
            engine
                .put(Bytes::from(key.clone()), Bytes::from(value.clone()))
                .unwrap();
            oracle.insert(key, value);
        }
        if i % 53 == 0 {
            engine.flush().unwrap();
        }
    }

    engine.compact().unwrap();
    for (key, value) in oracle {
        assert_eq!(
            engine.get(key.as_bytes()).unwrap().unwrap(),
            Bytes::from(value)
        );
    }
}

#[test]
fn checkpoint_and_gc_reclaim_obsolete_files_after_compaction() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("a"), Bytes::from("1")).unwrap();
    engine.flush().unwrap();
    engine.put(Bytes::from("a"), Bytes::from("2")).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();

    let checkpoint = engine.checkpoint().unwrap();
    assert_eq!(checkpoint.sequence, engine.snapshot().sequence);

    let report = engine.garbage_collect().unwrap();
    assert!(report.files_reclaimed >= 1);
    assert!(report.bytes_reclaimed > 0);
}

#[tokio::test]
async fn async_engine_wraps_sync_core() {
    let dir = tempdir().unwrap();
    let engine = AsyncPraxisEngine::open(PraxisConfig::new(dir.path()))
        .await
        .unwrap();
    engine
        .put(Bytes::from("async-key"), Bytes::from("async-value"))
        .await
        .unwrap();
    assert_eq!(
        engine.get(Bytes::from("async-key")).await.unwrap().unwrap(),
        Bytes::from("async-value")
    );
    assert_eq!(engine.flush().await.unwrap(), Some(1));
}

#[test]
fn memtable_flush_threshold_bounds_ram_growth() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.page_size = 4096;
    config.block_size = 4096;
    config.memtable_flush_threshold_bytes = 4096;
    let engine = PraxisEngine::open(config).unwrap();
    for i in 0..20 {
        engine
            .put(
                Bytes::from(format!("bounded/{i}")),
                Bytes::from(vec![b'x'; 512]),
            )
            .unwrap();
    }
    let stats = engine.stats();
    assert!(
        stats["metrics"]["automatic_flushes"].as_u64().unwrap() > 0,
        "expected automatic flushes once threshold is crossed"
    );
}

#[test]
fn l0_pressure_triggers_compaction_before_accepting_more_writes() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.l0_slowdown_segments = 1;
    config.l0_stop_segments = 2;
    let engine = PraxisEngine::open(config).unwrap();

    engine
        .put(Bytes::from("pressure/a"), Bytes::from("1"))
        .unwrap();
    engine.flush().unwrap();
    engine
        .put(Bytes::from("pressure/b"), Bytes::from("2"))
        .unwrap();

    let stats = engine.stats();
    assert_eq!(stats["metrics"]["write_stalls"].as_u64().unwrap(), 1);
    assert_eq!(
        stats["metrics"]["l0_pressure_compactions"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(engine.get("pressure/a").unwrap().unwrap(), Bytes::from("1"));
    assert_eq!(engine.get("pressure/b").unwrap().unwrap(), Bytes::from("2"));
}

#[test]
fn pinned_snapshot_survives_compaction_until_released() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("mvcc"), Bytes::from("v1")).unwrap();
    engine.flush().unwrap();
    let pinned = engine.pin_snapshot();
    engine.put(Bytes::from("mvcc"), Bytes::from("v2")).unwrap();
    engine.flush().unwrap();

    engine.compact().unwrap();
    assert_eq!(engine.get("mvcc").unwrap().unwrap(), Bytes::from("v2"));
    assert_eq!(
        engine
            .get_cf(&ColumnFamily::default(), b"mvcc", pinned.snapshot())
            .unwrap()
            .unwrap(),
        Bytes::from("v1")
    );
    assert_eq!(
        engine.stats()["snapshots"]["pinned_count"]
            .as_u64()
            .unwrap(),
        1
    );

    drop(pinned);
    assert_eq!(
        engine.stats()["snapshots"]["pinned_count"]
            .as_u64()
            .unwrap(),
        0
    );
}

#[test]
fn multiple_pinned_snapshots_survive_compaction_with_distinct_versions() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("mvcc-many"), Bytes::from("v1"))
        .unwrap();
    engine.flush().unwrap();
    let pinned_v1 = engine.pin_snapshot();

    engine
        .put(Bytes::from("mvcc-many"), Bytes::from("v2"))
        .unwrap();
    engine.flush().unwrap();
    let pinned_v2 = engine.pin_snapshot();

    engine
        .put(Bytes::from("mvcc-many"), Bytes::from("v3"))
        .unwrap();
    engine.flush().unwrap();

    engine.compact().unwrap();
    assert_eq!(engine.get("mvcc-many").unwrap().unwrap(), Bytes::from("v3"));
    assert_eq!(
        engine
            .get_cf(&ColumnFamily::default(), b"mvcc-many", pinned_v1.snapshot())
            .unwrap()
            .unwrap(),
        Bytes::from("v1")
    );
    assert_eq!(
        engine
            .get_cf(&ColumnFamily::default(), b"mvcc-many", pinned_v2.snapshot())
            .unwrap()
            .unwrap(),
        Bytes::from("v2")
    );
}

#[test]
fn segment_bloom_filter_rejects_absent_disk_key() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("present"), Bytes::from("value"))
        .unwrap();
    engine.flush().unwrap();

    assert_eq!(engine.get("absent").unwrap(), None);
    let stats = engine.stats();
    assert!(
        stats["metrics"]["bloom_negative_hits"].as_u64().unwrap() > 0,
        "expected bloom filter to reject absent key"
    );
}

#[test]
fn column_families_are_explicit_keyspaces() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut batch = WriteBatch::new();
    batch.put("missing", Bytes::from("k"), Bytes::from("v"));
    assert!(matches!(
        engine.write_batch(batch).unwrap_err(),
        PraxisError::UnknownColumnFamily(_)
    ));

    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "pages".to_string(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let mut batch = WriteBatch::new();
    batch.put("pages", Bytes::from("k"), Bytes::from("v"));
    engine.write_batch(batch).unwrap();
    assert_eq!(
        engine
            .get_cf(&ColumnFamily("pages".to_string()), b"k", engine.snapshot())
            .unwrap()
            .unwrap(),
        Bytes::from("v")
    );
    assert!(
        engine
            .list_column_families()
            .iter()
            .any(|cf| cf.name == "pages")
    );
}

#[test]
fn optimistic_transaction_detects_write_conflict() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("txn"), Bytes::from("v1")).unwrap();
    let mut txn = engine.begin_transaction();
    assert_eq!(txn.get("txn").unwrap().unwrap(), Bytes::from("v1"));
    engine.put(Bytes::from("txn"), Bytes::from("v2")).unwrap();
    txn.put(Bytes::from("txn"), Bytes::from("v3"));

    assert!(matches!(
        txn.commit().unwrap_err(),
        PraxisError::TransactionConflict { .. }
    ));
    assert_eq!(engine.get("txn").unwrap().unwrap(), Bytes::from("v2"));
}

#[test]
fn optimistic_transaction_commits_when_keys_do_not_change() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut txn = engine.begin_transaction();
    txn.put(Bytes::from("txn-ok"), Bytes::from("v1"));
    let sequence = txn.commit().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(engine.get("txn-ok").unwrap().unwrap(), Bytes::from("v1"));
}

#[test]
fn effective_config_is_persisted_and_verified_on_reopen() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.page_size = 4096;
    config.block_size = 4096;
    config.wal_segment_size = 4096;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.effective_config(), config.persisted());
    drop(engine);

    let reopened = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(reopened.effective_config(), config.persisted());
    drop(reopened);

    let mut incompatible = config;
    incompatible.block_size = 8192;
    match PraxisEngine::open(incompatible) {
        Err(PraxisError::ConfigMismatch(_)) => {}
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("expected config mismatch"),
    }
}

#[test]
fn open_from_file_loads_validated_toml_config() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("praxis.toml");
    fs::write(
        &config_path,
        format!(
            r#"
data_dir = "{}"
page_size = 4096
block_size = 4096
segment_size = 4096
wal_segment_size = 4096
wal_sync_policy = "EveryBatch"
cache_size_bytes = 4096
compression = "Lz4"
checksum = "Crc32c"
background_workers = 1
direct_io = false
accelerator = "Cpu"
large_value_threshold = 1024
memtable_flush_threshold_bytes = 4096
immutable_memtable_limit = 1
l0_slowdown_segments = 2
l0_stop_segments = 3
"#,
            data_dir.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();

    let engine = PraxisEngine::open_from_file(&config_path).unwrap();
    engine.put(Bytes::from("cfg"), Bytes::from("ok")).unwrap();
    assert_eq!(engine.get("cfg").unwrap().unwrap(), Bytes::from("ok"));
}

#[test]
fn verify_checks_live_segment_digest() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("verify"), Bytes::from("ok"))
        .unwrap();
    engine.flush().unwrap();
    let report = engine.verify().unwrap();
    assert_eq!(report.segments_checked, 1);

    let segment_path = engine.stats()["manifest"]["segments"][0]["path"]
        .as_str()
        .unwrap()
        .to_string();
    OpenOptions::new()
        .append(true)
        .open(&segment_path)
        .unwrap()
        .write_all(b"corrupt")
        .unwrap();
    assert!(matches!(
        engine.verify().unwrap_err(),
        PraxisError::Corrupt { .. }
    ));
}

#[test]
fn ttl_expiration_hides_entries_after_deadline() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.default_compaction_strategy = praxis::CompactionStrategy::Leveled;
    let engine = PraxisEngine::open(config).unwrap();
    engine
        .put_with_ttl(Bytes::from("ttl-key"), Bytes::from("ttl-value"), 1)
        .unwrap();
    assert_eq!(
        engine.get("ttl-key").unwrap().unwrap(),
        Bytes::from("ttl-value")
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(engine.get("ttl-key").unwrap(), None);
}

#[test]
fn merge_operator_sum_i64_is_applied_deterministically() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "counter".to_string(),
            options: praxis::manifest::ColumnFamilyOptions {
                merge_operator: Some("sum_i64".to_string()),
                ..praxis::manifest::ColumnFamilyOptions::default()
            },
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();

    engine
        .merge(
            ColumnFamily("counter".to_string()),
            Bytes::from("hits"),
            Bytes::from(1_i64.to_le_bytes().to_vec()),
        )
        .unwrap();
    engine
        .merge(
            ColumnFamily("counter".to_string()),
            Bytes::from("hits"),
            Bytes::from(2_i64.to_le_bytes().to_vec()),
        )
        .unwrap();
    let value = engine
        .get_cf(
            &ColumnFamily("counter".to_string()),
            b"hits",
            engine.snapshot(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(i64::from_le_bytes(value.as_ref().try_into().unwrap()), 3);
}

#[test]
fn prefix_scan_and_backup_restore_roundtrip() {
    let dir = tempdir().unwrap();
    let backup_dir = dir.path().join("backup");
    let restore_dir = dir.path().join("restore");
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
    engine.put(Bytes::from("pfx/a"), Bytes::from("1")).unwrap();
    engine.put(Bytes::from("pfx/b"), Bytes::from("2")).unwrap();
    engine
        .put(Bytes::from("other/c"), Bytes::from("3"))
        .unwrap();

    let rows = engine.scan_prefix(b"pfx/", 10).unwrap();
    assert_eq!(rows.len(), 2);
    engine.backup_to(&backup_dir).unwrap();
    PraxisEngine::restore_from_backup(&backup_dir, &restore_dir).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&restore_dir)).unwrap();
    assert_eq!(restored.get("pfx/a").unwrap().unwrap(), Bytes::from("1"));
    assert_eq!(restored.get("pfx/b").unwrap().unwrap(), Bytes::from("2"));
    assert_eq!(restored.get("other/c").unwrap().unwrap(), Bytes::from("3"));
}

#[test]
fn prefix_scan_cf_at_snapshot_preserves_visible_versions_across_compaction() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "pages".to_string(),
            options: praxis::manifest::ColumnFamilyOptions {
                prefix_extractor_len: Some(4),
                ..praxis::manifest::ColumnFamilyOptions::default()
            },
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let pages = ColumnFamily("pages".to_string());

    let mut batch = WriteBatch::new();
    batch.put(pages.clone(), Bytes::from("doc/a"), Bytes::from("v1"));
    batch.put(pages.clone(), Bytes::from("doc/b"), Bytes::from("v1"));
    batch.put(pages.clone(), Bytes::from("misc/z"), Bytes::from("v0"));
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();

    let pinned = engine.pin_snapshot();

    let mut batch = WriteBatch::new();
    batch.put(pages.clone(), Bytes::from("doc/a"), Bytes::from("v2"));
    batch.delete(pages.clone(), Bytes::from("doc/b"));
    batch.put(pages.clone(), Bytes::from("doc/c"), Bytes::from("v2"));
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();

    let current = engine.scan_prefix_cf(&pages, b"doc/", 10).unwrap();
    assert_eq!(
        current,
        vec![
            (Bytes::from("doc/a"), Bytes::from("v2")),
            (Bytes::from("doc/c"), Bytes::from("v2")),
        ]
    );

    let historical = engine
        .scan_prefix_cf_at_snapshot(&pages, b"doc/", 10, pinned.snapshot())
        .unwrap();
    assert_eq!(
        historical,
        vec![
            (Bytes::from("doc/a"), Bytes::from("v1")),
            (Bytes::from("doc/b"), Bytes::from("v1")),
        ]
    );
}

#[test]
fn maintenance_queue_runs_priority_jobs() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("m/a"), Bytes::from("1")).unwrap();
    let low = engine
        .enqueue_flush_job("low", praxis::maintenance::JobPriority::Low)
        .unwrap();
    let high = engine
        .enqueue_compaction_job(
            praxis::CompactionStrategy::Leveled,
            "high",
            praxis::maintenance::JobPriority::High,
        )
        .unwrap();
    let first = engine.run_next_maintenance_job().unwrap().unwrap();
    let second = engine.run_next_maintenance_job().unwrap().unwrap();
    assert_eq!(first, high);
    assert_eq!(second, low);
}

#[test]
fn maintenance_runtime_requires_at_least_one_worker() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let error = engine
        .start_maintenance_runtime(MaintenanceRuntimeConfig {
            flush: RuntimeLaneConfig { workers: 0 },
            compaction: RuntimeLaneConfig { workers: 0 },
            admin: RuntimeLaneConfig { workers: 0 },
            idle_sleep_ms: 5,
        })
        .unwrap_err();
    assert!(matches!(error, PraxisError::InvalidConfig(_)));
}

#[test]
fn maintenance_workers_process_queued_jobs() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put(Bytes::from("w/a"), Bytes::from("1")).unwrap();
    engine
        .enqueue_flush_job("worker-1", praxis::maintenance::JobPriority::Normal)
        .unwrap();
    engine
        .enqueue_compaction_job(
            praxis::CompactionStrategy::Leveled,
            "worker-2",
            praxis::maintenance::JobPriority::Normal,
        )
        .unwrap();
    let completed = engine.run_maintenance_workers(2, 8).unwrap();
    assert!(completed >= 2);
    assert_eq!(
        engine.stats()["maintenance"]["queue_len"].as_u64().unwrap(),
        0
    );
}

#[test]
fn cache_partition_percent_limits_cf_cache_usage() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.cache_size_bytes = 65536;
    let engine = PraxisEngine::open(config).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "tiny-cache".to_string(),
            options: praxis::manifest::ColumnFamilyOptions {
                cache_partition_percent: Some(5),
                ..praxis::manifest::ColumnFamilyOptions::default()
            },
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let mut batch = WriteBatch::new();
    batch.put(
        ColumnFamily("tiny-cache".to_string()),
        Bytes::from("large-value"),
        Bytes::from(vec![b'v'; 256]),
    );
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    let _ = engine
        .get_cf(
            &ColumnFamily("tiny-cache".to_string()),
            b"large-value",
            engine.snapshot(),
        )
        .unwrap();

    let stats = engine.stats();
    let used = stats["cache"]["bytes_by_cf"]["tiny-cache"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(used, 0);
}

#[test]
fn column_family_compression_override_is_honored_for_flush_and_compaction() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.compression = praxis::Compression::Zstd;
    let engine = PraxisEngine::open(config).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "lz4-pages".to_string(),
            options: praxis::manifest::ColumnFamilyOptions {
                compression_override: Some(praxis::Compression::Lz4),
                ..praxis::manifest::ColumnFamilyOptions::default()
            },
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let cf = ColumnFamily("lz4-pages".to_string());

    let mut batch = WriteBatch::new();
    batch.put(cf.clone(), Bytes::from("doc/a"), Bytes::from("v1"));
    batch.put(cf.clone(), Bytes::from("doc/b"), Bytes::from("v1"));
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();

    let first_segment_path = engine.stats()["manifest"]["segments"][0]["path"]
        .as_str()
        .unwrap()
        .to_string();
    let first_header = fs::read(&first_segment_path).unwrap();
    assert_eq!(first_header[8], 1, "expected LZ4 compression tag");

    let mut batch = WriteBatch::new();
    batch.put(cf.clone(), Bytes::from("doc/a"), Bytes::from("v2"));
    batch.put(cf, Bytes::from("doc/c"), Bytes::from("v2"));
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();

    let stats = engine.stats();
    let segments = stats["manifest"]["segments"].as_array().unwrap();
    assert_eq!(segments.len(), 1);
    let compacted_path = segments[0]["path"].as_str().unwrap();
    let compacted_header = fs::read(compacted_path).unwrap();
    assert_eq!(compacted_header[8], 1, "expected LZ4 compression tag");
}

#[test]
fn maintenance_runtime_processes_jobs_and_reports_status() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("runtime/a"), Bytes::from("1"))
        .unwrap();
    engine
        .enqueue_flush_job("runtime", JobPriority::Normal)
        .unwrap();
    engine
        .start_maintenance_runtime(MaintenanceRuntimeConfig {
            flush: RuntimeLaneConfig { workers: 1 },
            compaction: RuntimeLaneConfig { workers: 1 },
            admin: RuntimeLaneConfig { workers: 1 },
            idle_sleep_ms: 5,
        })
        .unwrap();

    for _ in 0..40 {
        let status = engine.maintenance_status();
        if status.queued.is_empty() && status.running.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let running_status = engine.maintenance_status();
    assert!(running_status.runtime.running);
    assert_eq!(running_status.queued.len(), 0);
    assert_eq!(running_status.running.len(), 0);

    engine.stop_maintenance_runtime().unwrap();
    engine.join_maintenance_runtime().unwrap();

    let stopped_status = engine.maintenance_status();
    assert!(!stopped_status.runtime.running);
}

#[test]
fn unfinished_compaction_jobs_are_aborted_on_reopen() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .put(Bytes::from("reconcile"), Bytes::from("v1"))
        .unwrap();
    engine.flush().unwrap();
    drop(engine);

    let manifest_path = dir.path().join("MANIFEST");
    let manifest_text = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest = toml::from_str::<Manifest>(&manifest_text).unwrap();
    manifest
        .compaction_jobs
        .push(praxis::manifest::CompactionJobState {
            id: 999,
            strategy: praxis::CompactionStrategy::Leveled,
            status: CompactionJobStatus::Running,
            source_segment_ids: vec![1],
            output_segment_id: Some(2),
            created_at_ms: 1,
            updated_at_ms: 1,
        });
    fs::write(&manifest_path, toml::to_string_pretty(&manifest).unwrap()).unwrap();

    let reopened = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let status = reopened.stats();
    assert_eq!(
        status["manifest"]["compaction_jobs"][0]["status"]
            .as_str()
            .unwrap(),
        "Aborted"
    );
    assert_eq!(status["manifest"]["segments"].as_array().unwrap().len(), 1);
}
