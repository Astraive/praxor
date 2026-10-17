use super::*;
use crate::{CoreDatabase, MappingDescriptor, PraxisConfig, RecordAuthorityOptions};
use std::sync::mpsc;
use std::time::Duration;

fn database() -> (tempfile::TempDir, PraxisConfig, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 1;
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "tests".into(),
            }],
        },
    )
    .unwrap();
    (dir, config, db)
}

fn snapshot_disk_state(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn visit(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .is_some_and(|name| name == crate::writer_lease::LOCK_FILE_NAME)
            {
                continue;
            }
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn retained_token_clones_and_all_checked_reads_use_one_pin_without_io_or_sync() {
    let (dir, _config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"v", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    let engine = db.kv();
    let before = snapshot_disk_state(dir.path());
    let syncs = engine
        .inner
        .metrics
        .commit_sync_attempts
        .load(Ordering::Relaxed);
    let sequence = engine.snapshot().sequence;
    let token = records.pin_snapshot().unwrap();
    let clones = (0..32).map(|_| token.clone()).collect::<Vec<_>>();
    assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    assert_eq!(records.fetch_at_snapshot(rid, &token).unwrap(), b"v");
    assert_eq!(
        records.lookup_rid_at_snapshot("kv", b"k", &token).unwrap(),
        Some(rid)
    );
    assert_eq!(
        records
            .fetch_by_index_at_snapshot("kv", b"k", &token)
            .unwrap(),
        Some(b"v".to_vec())
    );
    assert!(matches!(
        records.fetch_at_snapshot(RecordId(999), &token),
        Err(PraxisError::KeyNotFound)
    ));
    assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    assert_eq!(engine.snapshot().sequence, sequence);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        syncs
    );
    assert_eq!(snapshot_disk_state(dir.path()), before);
    drop(token);
    assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    drop(clones);
    assert_eq!(engine.inner.snapshots.pinned_count(), 0);
}

#[test]
fn retained_combined_read_keeps_its_one_pin_during_clone_mutation_and_install() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"old", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    records.flush().unwrap();
    let token = records.pin_snapshot().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let reader = records.clone();
    let join = std::thread::spawn(move || {
        READ_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |phase| {
                if phase == ReadPhase::Head {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            }))
        });
        let result = reader.fetch_by_index_at_snapshot("kv", b"k", &token);
        READ_HOOK.with(|hook| *hook.borrow_mut() = None);
        result
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    records.delete_record(rid).unwrap();
    records
        .put(b"new", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    records.flush().unwrap();
    db.kv()
        .compact_with_strategy(crate::CompactionStrategy::Leveled)
        .unwrap();
    db.kv().garbage_collect().unwrap();
    resume_tx.send(()).unwrap();
    assert_eq!(join.join().unwrap().unwrap(), Some(b"old".to_vec()));
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
}

#[test]
fn checked_payload_errors_and_shared_poison_do_not_release_the_token() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"v", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    let token = records.pin_snapshot().unwrap();
    let engine = db.kv();
    for value in [None, Some(vec![])] {
        let mut batch = crate::WriteBatch::new();
        let key = Key::Payload(rid.0).encode().unwrap();
        if let Some(value) = value {
            batch.put(Role::Payload.cf(), key, value);
        } else {
            batch.delete(Role::Payload.cf(), key);
        }
        for op in batch.ops() {
            engine
                .inner
                .memtable
                .write()
                .apply(token.core_sequence(), op);
        }
        assert!(matches!(
            records.fetch_at_snapshot(rid, &token),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            records.fetch_by_index_at_snapshot("kv", b"k", &token),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    }
    let mut restored = crate::WriteBatch::new();
    restored.put(
        Role::Payload.cf(),
        Key::Payload(rid.0).encode().unwrap(),
        Row::Payload(b"v").encode().unwrap(),
    );
    for op in restored.ops() {
        engine
            .inner
            .memtable
            .write()
            .apply(token.core_sequence(), op);
    }
    assert_eq!(records.fetch_at_snapshot(rid, &token).unwrap(), b"v");
    engine
        .inner
        .group_commit
        .poison("test uncertain write".into());
    assert!(matches!(
        records.pin_snapshot(),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        records.fetch_at_snapshot(rid, &token),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        records.lookup_rid_at_snapshot("kv", b"k", &token),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        records.fetch_by_index_at_snapshot("kv", b"k", &token),
        Err(PraxisError::RecoveryRequired)
    ));
    assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    drop(token);
    assert_eq!(engine.inner.snapshots.pinned_count(), 0);
}

#[test]
fn checked_external_read_io_failure_keeps_its_pin_and_later_read_works() {
    let (_dir, config, db) = database();
    let rid = db.records().put(b"external payload", &[]).unwrap();
    db.records().flush().unwrap();
    drop(db);
    let db = CoreDatabase::open(config).unwrap();
    let records = db.records();
    let engine = db.kv();
    let token = records.pin_snapshot().unwrap();
    let path = {
        let index = engine.inner.segment_index.read();
        let versions = &index[&(
            ColumnFamily(Role::Payload.cf().into()),
            Bytes::from(Key::Payload(rid.0).encode().unwrap()),
        )];
        let crate::types::StoredValue::BlobPointer(pointer) = &versions.last().unwrap().value
        else {
            panic!("persisted external pointer required")
        };
        std::path::PathBuf::from(&pointer.path)
    };
    let held = path.with_extension("held");
    std::fs::rename(&path, &held).unwrap();
    assert!(matches!(
        records.fetch_at_snapshot(rid, &token),
        Err(PraxisError::Io(_))
    ));
    assert_eq!(engine.inner.snapshots.pinned_count(), 1);
    std::fs::rename(held, path).unwrap();
    assert_eq!(
        records.fetch_at_snapshot(rid, &token).unwrap(),
        b"external payload"
    );
}

#[test]
fn raw_range_skips_future_fact_keys_added_after_the_one_current_pin() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let old = records
        .put(b"old", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    let new = records.put(b"new", &[]).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let reader = records.clone();
    let join = std::thread::spawn(move || {
        READ_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |phase| {
                if phase == ReadPhase::RangeKeys {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            }))
        });
        let result = reader.lookup_rid_at("kv", b"k", u64::MAX);
        READ_HOOK.with(|hook| *hook.borrow_mut() = None);
        result
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    records.put_index("kv", b"k", new).unwrap();
    resume_tx.send(()).unwrap();
    assert_eq!(join.join().unwrap().unwrap(), Some(old));
    assert_eq!(
        records.lookup_rid_at("kv", b"k", u64::MAX).unwrap(),
        Some(new)
    );
}

#[test]
fn combined_reads_hold_exactly_one_pin_through_delete_and_all_compactions() {
    for strategy in [
        crate::CompactionStrategy::Leveled,
        crate::CompactionStrategy::Tiered,
        crate::CompactionStrategy::Universal,
    ] {
        let (_dir, _config, db) = database();
        let records = db.records();
        let rid = records
            .put(b"old payload", &[IndexInsert::new("kv", b"k".to_vec())])
            .unwrap();
        records.flush().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let reader = records.clone();
        let join = std::thread::spawn(move || {
            READ_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |phase| {
                    if phase == ReadPhase::Head {
                        ready_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                }))
            });
            let result = reader.fetch_by_index("kv", b"k");
            READ_HOOK.with(|hook| *hook.borrow_mut() = None);
            result
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
        records.delete_record(rid).unwrap();
        records.flush().unwrap();
        assert!(db.kv().compact_with_strategy(strategy).unwrap() > 0);
        db.kv().garbage_collect().unwrap();
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
        resume_tx.send(()).unwrap();
        assert_eq!(join.join().unwrap().unwrap(), Some(b"old payload".to_vec()));
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
        assert_eq!(records.fetch_by_index("kv", b"k").unwrap(), None);
    }
}

#[test]
fn live_missing_or_malformed_payload_is_corruption_and_never_index_absence() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"v", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    let engine = db.kv();
    for value in [None, Some(vec![])] {
        let mut batch = crate::WriteBatch::new();
        if let Some(bytes) = value {
            batch.put(
                Role::Payload.cf(),
                Key::Payload(rid.0).encode().unwrap(),
                bytes,
            );
        } else {
            batch.delete(Role::Payload.cf(), Key::Payload(rid.0).encode().unwrap());
        }
        for op in batch.ops() {
            engine
                .inner
                .memtable
                .write()
                .apply(engine.snapshot().sequence, op);
        }
        assert!(matches!(
            records.fetch(rid),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            records.fetch_by_index("kv", b"k"),
            Err(PraxisError::Corrupt { .. })
        ));
    }
    assert!(matches!(
        records.fetch(RecordId(999)),
        Err(PraxisError::KeyNotFound)
    ));
    assert_eq!(records.fetch_by_index("kv", b"missing").unwrap(), None);
}

#[test]
fn common_poison_blocks_record_reads_counters_and_even_empty_requests() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records.put(b"v", &[]).unwrap();
    db.kv()
        .inner
        .group_commit
        .poison("test ambiguous commit".into());
    macro_rules! denied {
        ($call:expr) => {
            assert!(matches!($call, Err(PraxisError::RecoveryRequired)));
        };
    }
    denied!(records.put_batch(&[]));
    denied!(records.delete_records(&[]));
    denied!(records.put(b"v", &[]));
    denied!(records.fetch(rid));
    denied!(records.fetch_by_index("kv", b"k"));
    denied!(records.lookup_rid("kv", b"k"));
    denied!(records.lookup_rid_at("kv", b"k", u64::MAX));
    denied!(records.put_index("kv", b"k", rid));
    denied!(records.delete_index("kv", b"k"));
    denied!(records.delete_by_index("kv", b"k"));
    denied!(records.delete_record_with_index_cleanup(rid, &[]));
    denied!(records.live_count());
    denied!(records.live_bytes());
    denied!(records.dead_records());
    denied!(records.compatibility_sequence());
    denied!(records.flush());
    denied!(db.kv().verify());
}

#[test]
fn semantic_verify_counts_unique_referenced_extents_without_syncing_or_whole_file_claims() {
    use std::io::Write;
    let (_dir, _config, db) = database();
    db.records()
        .put(
            b"external payload",
            &[IndexInsert::new("kv", b"k".to_vec())],
        )
        .unwrap();
    db.records().flush().unwrap();
    let engine = db.kv();
    let manifest = engine.inner.manifest.lock().clone();
    let mut expected = 0u64;
    let mut extents = BTreeSet::new();
    let mut files = BTreeSet::new();
    for metadata in &manifest.segments {
        let path = std::path::Path::new(&metadata.path);
        let bytes = std::fs::read(path).unwrap();
        expected += bytes.len() as u64;
        let raw =
            crate::segments::codec::decode_segment(&bytes, path, &crate::accel::CpuAccelerator)
                .unwrap();
        for entry in raw.blocks.iter().flatten() {
            if let crate::types::StoredValue::BlobPointer(pointer) = &entry.entry.version.value {
                files.insert(pointer.path.clone());
                if extents.insert((
                    pointer.path.clone(),
                    pointer.offset,
                    pointer.len,
                    pointer.checksum,
                )) {
                    expected += pointer.len + 12;
                }
            }
        }
    }
    if let Some(checkpoint) = manifest.latest_checkpoint {
        expected += std::fs::metadata(checkpoint.path).unwrap().len();
    }
    for file in std::fs::read_dir(engine.inner.layout.wal_root()).unwrap() {
        expected += file.unwrap().metadata().unwrap().len();
    }
    let path = files.first().unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(&[7; 64])
        .unwrap();
    let attempts = engine
        .inner
        .metrics
        .commit_sync_attempts
        .load(Ordering::Relaxed);
    let report = engine.verify().unwrap();
    assert_eq!(report.bytes_checked, expected);
    assert_eq!(report.segments_checked, manifest.segments.len() as u64);
    assert_eq!(report.value_logs_checked, files.len() as u64);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        attempts
    );
}

#[test]
fn public_record_flush_is_a_real_ordered_barrier_after_never_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::WalSyncPolicy::Never;
    config.wal_segment_size = config.page_size;
    let payload_size = config.page_size * 2;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    let engine = db.kv();
    for key in ["first", "second"] {
        engine.put(key, vec![7; payload_size]).unwrap();
    }
    assert!(engine.inner.manifest.lock().active_wal_id > 1);
    let before = engine
        .inner
        .metrics
        .commit_sync_attempts
        .load(Ordering::Relaxed);
    let sequence = engine.snapshot().sequence;
    let records = db.records();
    records.flush().unwrap();
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        before + 1
    );
    assert_eq!(engine.snapshot().sequence, sequence);
    drop(records);
    drop(engine);
    drop(db);
    let db = CoreDatabase::open(config).unwrap();
    assert_eq!(db.kv().get("first").unwrap().unwrap().len(), payload_size);
    assert_eq!(db.kv().get("second").unwrap().unwrap().len(), payload_size);
}
