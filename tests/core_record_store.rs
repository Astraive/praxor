use praxis::store::{BatchRecord, IndexInsert};
use praxis::{
    CompactionStrategy, Compression, CoreDatabase, MappingDescriptor, PraxisConfig, PraxisEngine,
    PraxisError, RecordAuthorityOptions, RecordId, WalSyncPolicy,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

fn options() -> RecordAuthorityOptions {
    RecordAuthorityOptions {
        indexes: vec![
            MappingDescriptor {
                name: "kv".into(),
                namespace: "main".into(),
            },
            MappingDescriptor {
                name: "other".into(),
                namespace: "other".into(),
            },
        ],
    }
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".praxor.writer.lock" {
                continue;
            }
            let path = entry.path();
            let key = path.strip_prefix(root).unwrap().to_owned();
            if entry.file_type().unwrap().is_dir() {
                result.insert(key, None);
                visit(root, &path, result);
            } else {
                result.insert(key, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn public_records_preserve_raw_decisions_through_shared_lifecycle() {
    for policy in [
        WalSyncPolicy::EveryBatch,
        WalSyncPolicy::GroupCommit,
        WalSyncPolicy::Never,
    ] {
        for compression in [Compression::None, Compression::Lz4, Compression::Zstd] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = PraxisConfig::new(dir.path());
            config.wal_sync_policy = policy;
            config.compression = compression;
            config.large_value_threshold = 1;
            let db = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
            let records = db.records();
            let a = [IndexInsert::new("kv", b"k".to_vec())];
            let b = [a[0].clone(), a[0].clone()];
            let ids = records
                .put_batch(&[BatchRecord::new(b"a", &a), BatchRecord::new(b"bb", &b)])
                .unwrap();
            assert_eq!(ids, [RecordId(1), RecordId(2)]);
            assert_eq!(records.compatibility_sequence().unwrap(), 5);
            let check = |records: &praxis::CoreRecordStore| {
                for (ceiling, rid) in [
                    (0, None),
                    (1, None),
                    (2, Some(ids[0])),
                    (3, Some(ids[0])),
                    (4, Some(ids[1])),
                    (5, Some(ids[1])),
                    (u64::MAX, Some(ids[1])),
                ] {
                    assert_eq!(records.lookup_rid_at("kv", b"k", ceiling).unwrap(), rid);
                }
                assert_eq!(
                    records.fetch_by_index("kv", b"k").unwrap(),
                    Some(b"bb".to_vec())
                );
            };
            check(&records);
            records.flush().unwrap();
            for strategy in [
                CompactionStrategy::Leveled,
                CompactionStrategy::Tiered,
                CompactionStrategy::Universal,
            ] {
                db.kv()
                    .put(format!("marker-{strategy:?}"), "value")
                    .unwrap();
                records.flush().unwrap();
                assert!(db.kv().compact_with_strategy(strategy).unwrap() > 0);
                db.kv().garbage_collect().unwrap();
                check(&records);
            }
            let report = db.kv().verify().unwrap();
            assert!(report.segments_checked > 0 && report.value_logs_checked > 0);
            let backup = tempfile::tempdir().unwrap();
            db.kv().backup_to(backup.path()).unwrap();
            drop(records);
            drop(db);
            for _ in 0..2 {
                let reopened = CoreDatabase::open(config.clone()).unwrap();
                check(&reopened.records());
            }
            let restored = tempfile::tempdir().unwrap();
            PraxisEngine::restore_from_backup(backup.path(), restored.path()).unwrap();
            let restored = CoreDatabase::open(PraxisConfig {
                data_dir: restored.path().to_path_buf(),
                ..config.clone()
            })
            .unwrap();
            check(&restored.records());
            let db = CoreDatabase::open(config).unwrap();
            let records = db.records();
            records.delete_record(ids[1]).unwrap();
            assert_eq!(records.lookup_rid("kv", b"k").unwrap(), Some(ids[1]));
            assert_eq!(records.fetch_by_index("kv", b"k").unwrap(), None);
            assert_eq!(records.delete_by_index("kv", b"k").unwrap(), Some(ids[1]));
            records.delete_record(ids[1]).unwrap();
            records.put_index("kv", b"k", ids[0]).unwrap();
            records
                .delete_record_with_index_cleanup(ids[0], &a)
                .unwrap();
            let before = records.compatibility_sequence().unwrap();
            assert!(matches!(
                records.put_index("kv", b"k", ids[0]),
                Err(PraxisError::KeyNotFound)
            ));
            assert!(matches!(
                records.delete_records(&[ids[0], RecordId(999)]),
                Err(PraxisError::KeyNotFound)
            ));
            assert_eq!(records.compatibility_sequence().unwrap(), before);
            assert_eq!(
                (
                    records.live_count().unwrap(),
                    records.live_bytes().unwrap(),
                    records.dead_records().unwrap()
                ),
                (0, 0, 2)
            );
            assert_eq!(records.put(b"next", &[]).unwrap(), RecordId(3));
            assert!(!dir.path().join("primary").exists());
        }
    }
}

#[test]
fn raw_ranges_isolate_descriptors_lengths_binary_neighbors_and_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(PraxisConfig::new(dir.path()), options()).unwrap();
    let records = db.records();
    let keys: &[&[u8]] = &[
        b"",
        b"a",
        b"a\0",
        b"a\0\xff",
        b"a\xff",
        b"\0",
        b"\xff",
        b"\xff\xff",
    ];
    let mut expected = Vec::new();
    for key in keys {
        let rid = records
            .put(
                key,
                &[
                    IndexInsert::new("kv", key.to_vec()),
                    IndexInsert::new("other", key.to_vec()),
                ],
            )
            .unwrap();
        let put = records.compatibility_sequence().unwrap() - 1;
        records.delete_index("kv", key).unwrap();
        let delete = records.compatibility_sequence().unwrap();
        expected.push((*key, rid, put, delete));
    }
    records.flush().unwrap();
    for (key, rid, put, delete) in expected {
        assert_eq!(records.lookup_rid_at("kv", key, put - 1).unwrap(), None);
        assert_eq!(records.lookup_rid_at("kv", key, put).unwrap(), Some(rid));
        assert_eq!(records.lookup_rid_at("kv", key, delete).unwrap(), None);
        assert_eq!(records.lookup_rid_at("kv", key, u64::MAX).unwrap(), None);
        assert_eq!(
            records.lookup_rid_at("other", key, u64::MAX).unwrap(),
            Some(rid)
        );
    }
    assert!(matches!(
        records.lookup_rid_at("missing", b"", 0),
        Err(PraxisError::InvalidConfig(_))
    ));
}

#[test]
fn immutable_registry_resolves_first_middle_last_utf8_and_unknown_names() {
    let dir = tempfile::tempdir().unwrap();
    let names = ["a", "b", "middle", "z", "é"];
    let db = CoreDatabase::create_fresh(
        PraxisConfig::new(dir.path()),
        RecordAuthorityOptions {
            indexes: names
                .iter()
                .rev()
                .map(|name| MappingDescriptor {
                    name: (*name).into(),
                    namespace: "ordered".into(),
                })
                .collect(),
        },
    )
    .unwrap();
    let records = db.records();
    for name in names {
        let rid = records
            .put(name.as_bytes(), &[IndexInsert::new(name, b"k".to_vec())])
            .unwrap();
        assert_eq!(records.lookup_rid(name, b"k").unwrap(), Some(rid));
    }
    for unknown in ["", "aa", "zz", "ê"] {
        assert!(matches!(
            records.lookup_rid(unknown, b"k"),
            Err(PraxisError::InvalidConfig(_))
        ));
    }
}

#[test]
fn healthy_empty_requests_do_not_append_or_advance_and_auto_flush_is_shared() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.memtable_flush_threshold_bytes = config.page_size;
    config.wal_sync_policy = WalSyncPolicy::Never;
    let db = CoreDatabase::create_fresh(config, options()).unwrap();
    let records = db.records();
    let before = tree(dir.path());
    let sequence = db.kv().snapshot().sequence;
    assert!(records.put_batch(&[]).unwrap().is_empty());
    records.delete_records(&[]).unwrap();
    assert_eq!(records.compatibility_sequence().unwrap(), 0);
    assert_eq!(db.kv().snapshot().sequence, sequence);
    assert_eq!(tree(dir.path()), before);
    let payload = vec![7; 32 * 1024];
    let rid = records.put(&payload, &[]).unwrap();
    assert!(db.kv().verify().unwrap().segments_checked > 0);
    assert_eq!(records.fetch(rid).unwrap(), payload);
    db.kv().put("never", "covered").unwrap();
    let sequence = db.kv().snapshot().sequence;
    records.flush().unwrap();
    assert_eq!(db.kv().snapshot().sequence, sequence);
}

#[test]
fn record_views_keep_the_single_owner_after_database_and_kv_views_drop() {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    let records = db.records();
    let rid = records.put(b"held", &[]).unwrap();
    let kv = db.kv();
    drop(db);
    kv.close().unwrap();
    drop(kv);
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(records.fetch(rid).unwrap(), b"held");
    drop(records);
    assert_eq!(
        CoreDatabase::open(config)
            .unwrap()
            .records()
            .fetch(rid)
            .unwrap(),
        b"held"
    );
}

#[test]
fn concurrent_record_and_kv_views_share_order_and_persistent_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::GroupCommit;
    let db = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
    let mut joins = Vec::new();
    for worker in 0..4 {
        let records = db.records();
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            (0..8)
                .map(|item| {
                    let payload = format!("{worker}-{item}").into_bytes();
                    let rid = records
                        .put(&payload, &[IndexInsert::new("kv", payload.clone())])
                        .unwrap();
                    (rid, payload)
                })
                .collect::<Vec<_>>()
        }));
    }
    barrier.wait();
    for item in 0..16 {
        db.kv().put(format!("kv-{item}"), "user").unwrap();
    }
    let mut rows = joins
        .into_iter()
        .flat_map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    rows.sort_by_key(|(rid, _)| rid.0);
    assert_eq!(
        rows.iter().map(|(rid, _)| rid.0).collect::<Vec<_>>(),
        (1..=32).collect::<Vec<_>>()
    );
    assert_eq!(db.records().compatibility_sequence().unwrap(), 64);
    db.records().flush().unwrap();
    db.kv().verify().unwrap();
    drop(db);
    let db = CoreDatabase::open(config).unwrap();
    for (rid, payload) in rows {
        assert_eq!(
            db.records().fetch_by_index("kv", &payload).unwrap(),
            Some(payload.clone())
        );
        assert_eq!(db.records().fetch(rid).unwrap(), payload);
    }
}

#[test]
fn corrupt_checkpoints_refuse_v3_verify_and_legacy_copy_before_replacement() {
    for record_authority in [false, true] {
        let source = tempfile::tempdir().unwrap();
        let db = record_authority.then(|| {
            CoreDatabase::create_fresh(PraxisConfig::new(source.path()), options()).unwrap()
        });
        let engine = db
            .as_ref()
            .map(CoreDatabase::kv)
            .unwrap_or_else(|| PraxisEngine::open(PraxisConfig::new(source.path())).unwrap());
        engine.put("source", "value").unwrap();
        let checkpoint = engine.checkpoint().unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&checkpoint.path)
            .unwrap()
            .write_all(b"corrupt")
            .unwrap();
        let source_before = tree(source.path());
        if record_authority {
            assert!(matches!(engine.verify(), Err(PraxisError::Corrupt { .. })));
        }
        let target = tempfile::tempdir().unwrap();
        let old = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
        old.put("keep", "old").unwrap();
        drop(old);
        let before = tree(target.path());
        assert!(matches!(
            engine.backup_to(target.path()),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(tree(target.path()), before);
        assert_eq!(tree(source.path()), source_before);
    }
}

fn offline_corrupt_checkpoint_does_not_create_a_restore_target(record_authority: bool) {
    let source = tempfile::tempdir().unwrap();
    let db = record_authority
        .then(|| CoreDatabase::create_fresh(PraxisConfig::new(source.path()), options()).unwrap());
    let engine = db
        .as_ref()
        .map(CoreDatabase::kv)
        .unwrap_or_else(|| PraxisEngine::open(PraxisConfig::new(source.path())).unwrap());
    engine.put("source", "value").unwrap();
    let checkpoint = engine.checkpoint().unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(checkpoint.path)
        .unwrap()
        .write_all(b"corrupt")
        .unwrap();
    drop(engine);
    drop(db);
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("absent");
    assert!(!target.exists());
    let before = tree(source.path());
    assert!(matches!(
        PraxisEngine::restore_from_backup(source.path(), &target),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(
        !target.exists(),
        "offline checkpoint validation must precede destination creation"
    );
    assert_eq!(tree(source.path()), before);
}

#[test]
fn offline_legacy_checkpoint_preflight_precedes_absent_target_creation() {
    offline_corrupt_checkpoint_does_not_create_a_restore_target(false);
}

#[test]
fn offline_v3_checkpoint_preflight_precedes_absent_target_creation() {
    offline_corrupt_checkpoint_does_not_create_a_restore_target(true);
}
