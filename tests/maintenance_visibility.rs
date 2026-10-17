use bytes::Bytes;
use praxis::config::CompactionStrategy;
use praxis::{ColumnFamily, PraxisConfig, PraxisEngine};
use tempfile::tempdir;

#[test]
fn sequence_reservation_does_not_publish_an_uncommitted_snapshot() {
    let manager = praxis::memory::SnapshotManager::default();
    let reserved = manager.next_sequence();
    assert_eq!(manager.snapshot().sequence, 0);
    manager.observe(reserved);
    assert_eq!(manager.snapshot().sequence, reserved);
}

#[test]
fn pinned_snapshot_keeps_overwritten_value_after_flush() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "before").unwrap();
    let pinned = engine.pin_snapshot();
    engine.put("key", "after").unwrap();
    engine.flush().unwrap();
    assert_eq!(
        engine
            .get_cf(&ColumnFamily::default(), b"key", pinned.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"before"))
    );
}

#[test]
fn flush_preserves_merge_base_and_operands_after_reopen() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("key", "a").unwrap();
    engine.merge(ColumnFamily::default(), "key", "b").unwrap();
    engine.merge(ColumnFamily::default(), "key", "c").unwrap();
    engine.flush().unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(Bytes::from_static(b"abc")));
    drop(engine);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(Bytes::from_static(b"abc")));
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(Bytes::from_static(b"abc")));
}

#[test]
fn every_compaction_strategy_keeps_merge_chains_and_pinned_versions() {
    for strategy in [
        CompactionStrategy::Leveled,
        CompactionStrategy::Tiered,
        CompactionStrategy::Universal,
    ] {
        let dir = tempdir().unwrap();
        let config = PraxisConfig::new(dir.path());
        let engine = PraxisEngine::open(config.clone()).unwrap();
        engine.put("key", "a").unwrap();
        engine.flush().unwrap();
        let pinned = engine.pin_snapshot();
        for _ in 0..6 {
            engine.merge(ColumnFamily::default(), "key", "b").unwrap();
            engine.flush().unwrap();
        }
        engine.compact_with_strategy(strategy).unwrap();
        assert_eq!(
            engine
                .get_cf(&ColumnFamily::default(), b"key", pinned.snapshot())
                .unwrap(),
            Some(Bytes::from_static(b"a")),
            "{strategy:?}"
        );
        assert_eq!(
            engine.get("key").unwrap(),
            Some(Bytes::from_static(b"abbbbbb")),
            "{strategy:?}"
        );
        drop(pinned);
        drop(engine);
        let engine = PraxisEngine::open(config).unwrap();
        assert_eq!(
            engine.get("key").unwrap(),
            Some(Bytes::from_static(b"abbbbbb")),
            "reopen {strategy:?}"
        );
    }
}

#[test]
fn flush_failure_keeps_data_visible_and_can_be_retried() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("key", "value").unwrap();
    let segment_dir = dir.path().join("segments/0");
    std::fs::remove_dir(&segment_dir).unwrap();
    std::fs::write(&segment_dir, b"force segment creation to fail").unwrap();
    assert!(engine.flush().is_err());
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"value"))
    );
    std::fs::remove_file(&segment_dir).unwrap();
    std::fs::create_dir(&segment_dir).unwrap();
    engine.flush().unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"value"))
    );
}

#[test]
fn garbage_collection_retains_rotated_unflushed_wals() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.page_size = 4096;
    config.wal_segment_size = 4096;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let value = Bytes::from(vec![42; 3000]);
    engine.put("first", value.clone()).unwrap();
    engine.put("second", value.clone()).unwrap();
    engine.put("third", value.clone()).unwrap();
    engine.garbage_collect().unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    for key in ["first", "second", "third"] {
        assert_eq!(engine.get(key).unwrap(), Some(value.clone()), "{key}");
    }
}

#[test]
fn failed_wal_rotation_does_not_publish_a_missing_active_file() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("key", "before").unwrap();
    let next_wal = dir.path().join("wal/00000000000000000002.wal");
    std::fs::create_dir(&next_wal).unwrap();
    assert!(engine.flush().is_err());
    let manifest: praxis::manifest::Manifest =
        toml::from_str(&std::fs::read_to_string(dir.path().join("MANIFEST")).unwrap()).unwrap();
    assert_eq!(manifest.active_wal_id, 1);
    std::fs::remove_dir(&next_wal).unwrap();
    engine.put("key", "after").unwrap();
    engine.flush().unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"after"))
    );
}

#[test]
fn compacted_large_values_survive_garbage_collection_and_restart() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 8;
    let value = Bytes::from(vec![7; 128]);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("key", value.clone()).unwrap();
    engine.flush().unwrap();
    drop(engine);
    // Reopening loads physical value pointers before the next compaction.
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("other", "small").unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();
    engine.garbage_collect().unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(value.clone()));
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(value));
}

#[test]
fn concurrent_writes_flush_and_gc_keep_every_acknowledged_value() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.page_size = 4096;
    config.wal_segment_size = 4096;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let gate = std::sync::Arc::new(std::sync::Barrier::new(4));
    std::thread::scope(|scope| {
        for writer in 0..3 {
            let engine = engine.clone();
            let gate = gate.clone();
            scope.spawn(move || {
                gate.wait();
                for index in 0..24 {
                    engine
                        .put(
                            Bytes::from(format!("{writer}/{index}")),
                            Bytes::from(vec![index; 512]),
                        )
                        .unwrap();
                }
            });
        }
        let engine = engine.clone();
        scope.spawn(move || {
            gate.wait();
            for _ in 0..8 {
                engine.flush().unwrap();
                engine.garbage_collect().unwrap();
            }
        });
    });
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    for writer in 0..3 {
        for index in 0..24 {
            assert_eq!(
                engine.get(format!("{writer}/{index}")).unwrap(),
                Some(Bytes::from(vec![index; 512]))
            );
        }
    }
}

#[test]
fn legacy_manifest_replays_overlapping_wal_operations_once() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("key", "a").unwrap();
    let mut batch = praxis::WriteBatch::new();
    // Identical operands in the same batch must both survive overlap repair.
    batch.merge(ColumnFamily::default(), "key", "b");
    batch.merge(ColumnFamily::default(), "key", "b");
    engine.write_batch(batch).unwrap();
    let old_wal = dir.path().join("wal/00000000000000000001.wal");
    let retained_wal = std::fs::read(&old_wal).unwrap();
    engine.flush().unwrap();
    drop(engine);
    std::fs::write(&old_wal, retained_wal).unwrap();
    let manifest_path = dir.path().join("MANIFEST");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let legacy = manifest
        .lines()
        .filter(|line| !line.starts_with("flushed_sequence") && !line.starts_with("flushed_wal_id"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&manifest_path, legacy).unwrap();
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(Bytes::from_static(b"abb")));
    engine.flush().unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.get("key").unwrap(), Some(Bytes::from_static(b"abb")));
}
