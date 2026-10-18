use super::*;
use crate::core_records::{CoreRecordScanError, RecordScanLimits};
use crate::query::{QueryGateway, QueryReadError, QueryReadView, QueryResult, TypedParameters};
use crate::types::{StoredValue, VersionedValue};
use crate::{CoreDatabase, MappingDescriptor, PraxisConfig, RecordAuthorityOptions};
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
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

fn tiered_database() -> (tempfile::TempDir, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.default_compaction_strategy = crate::CompactionStrategy::Tiered;
    config.memtable_flush_threshold_bytes = usize::MAX;
    config.large_value_threshold = usize::MAX;
    let db = CoreDatabase::create_fresh(
        config,
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "tests".into(),
            }],
        },
    )
    .unwrap();
    (dir, db)
}

fn disk_versions(db: &CoreDatabase, role: Role, key: Key<'_>) -> Vec<crate::types::VersionedValue> {
    db.kv()
        .inner
        .segment_index
        .read()
        .get(&(
            ColumnFamily(role.cf().into()),
            Bytes::from(key.encode().unwrap()),
        ))
        .cloned()
        .unwrap_or_default()
}

fn inject_raw_at(
    db: &CoreDatabase,
    sequence: u64,
    role: Role,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
) {
    let mut batch = crate::WriteBatch::new();
    match value {
        Some(value) => batch.put(role.cf(), key, value),
        None => batch.delete(role.cf(), key),
    };
    for op in batch.ops() {
        db.kv().inner.memtable.write().apply(sequence, op);
    }
}

#[test]
fn tiered_owner_prunes_unpinned_protected_history_but_preserves_user_chain_and_raw_facts() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    let rid = records
        .put(b"old", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    db.kv().put("ordinary", "one").unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    records.delete_record(rid).unwrap();
    db.kv().put("ordinary", "two").unwrap();
    records.flush().unwrap();
    assert_eq!(
        db.kv()
            .compact_with_strategy(crate::CompactionStrategy::Tiered)
            .unwrap(),
        1
    );
    assert_eq!(records.fetch_at_snapshot(rid, &held).unwrap(), b"old");
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        2
    );
    drop(held);
    db.kv().put("later", "value").unwrap();
    records.flush().unwrap();
    assert_eq!(
        db.kv()
            .compact_with_strategy(crate::CompactionStrategy::Tiered)
            .unwrap(),
        1
    );
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        1,
        "Tiered must retire the unpinned old payload while retaining its delete barrier"
    );
    assert_eq!(
        db.kv().inner.segment_index.read()
            [&(ColumnFamily::default(), Bytes::from_static(b"ordinary"))]
            .len(),
        2,
        "ordinary Tiered user versions remain unchanged"
    );
    assert_eq!(
        db.kv()
            .inner
            .segment_index
            .read()
            .keys()
            .filter(|(cf, key)| {
                cf.0 == Role::Index.cf()
                    && matches!(
                        Key::decode(Role::Index, key, db.kv().inner.layout.root()).unwrap(),
                        Key::Fact { .. }
                    )
            })
            .count(),
        1,
        "raw decision facts stay queryable"
    );
    db.kv().verify().unwrap();
}

#[test]
fn one_segment_with_obsolete_payload_needs_an_explicit_rewrite() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    let rid = records.put(b"old", &[]).unwrap();
    records.delete_record(rid).unwrap();
    records.flush().unwrap();
    assert_eq!(db.kv().inner.manifest.lock().segments.len(), 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        2
    );
    // Ordinary compaction stays a no-op with one segment. Requested record
    // maintenance may still rewrite its obsolete protected versions.
    assert_eq!(
        db.kv()
            .compact_with_strategy(crate::CompactionStrategy::Tiered)
            .unwrap(),
        0
    );
    let report = records.reclaim_snapshot_history().unwrap();
    assert!(report.rewrite_performed);
    assert!(report.protected_versions_removed >= 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        1,
        "requested rewrite prunes the old payload in one installed segment"
    );
    assert_eq!(db.kv().inner.manifest.lock().segments.len(), 1);
    assert!(matches!(records.fetch(rid), Err(PraxisError::KeyNotFound)));
    db.kv().verify().unwrap();
}

#[test]
fn no_obsolete_protected_versions_must_not_reserve_an_explicit_rewrite_job() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    records.put(b"live", &[]).unwrap();
    records.flush().unwrap();
    // Retire the obsolete bootstrap allocator value first. The next request
    // then sees a protected source in which every version is still needed.
    assert!(
        records
            .reclaim_snapshot_history()
            .unwrap()
            .rewrite_performed
    );
    db.kv().put("user-a", "one").unwrap();
    records.flush().unwrap();
    let before = db.kv().inner.manifest.lock().clone();
    assert_eq!(before.segments.len(), 2);
    let report = records.reclaim_snapshot_history().unwrap();
    assert!(!report.rewrite_performed);
    assert_eq!(report.protected_versions_removed, 0);
    let after = db.kv().inner.manifest.lock().clone();
    assert_eq!(after.next_segment_id, before.next_segment_id);
    assert_eq!(after.compaction_jobs, before.compaction_jobs);
}

#[test]
fn held_old_view_makes_an_explicit_rewrite_a_true_noop_until_pin_release() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    let rid = records.put(b"old", &[]).unwrap();
    records.flush().unwrap();
    assert!(
        records
            .reclaim_snapshot_history()
            .unwrap()
            .rewrite_performed
    );
    let held = records.pin_snapshot().unwrap();
    records.delete_record(rid).unwrap();
    records.flush().unwrap();
    let before = db.kv().inner.manifest.lock().clone();

    let no_op = records.reclaim_snapshot_history().unwrap();
    assert!(!no_op.rewrite_performed);
    assert_eq!(no_op.protected_versions_removed, 0);
    let after = db.kv().inner.manifest.lock().clone();
    assert_eq!(after.next_segment_id, before.next_segment_id);
    assert_eq!(after.compaction_jobs, before.compaction_jobs);
    assert_eq!(records.fetch_at_snapshot(rid, &held).unwrap(), b"old");

    drop(held);
    let retired = records.reclaim_snapshot_history().unwrap();
    assert!(retired.rewrite_performed);
    assert!(retired.protected_versions_removed >= 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        1
    );
}

#[test]
fn ordinary_kv_pin_retains_record_history_until_its_last_release() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    let rid = records.put(b"before", &[]).unwrap();
    records.flush().unwrap();
    let kv_pin = db.kv().pin_snapshot();
    records.delete_record(rid).unwrap();
    records.flush().unwrap();

    records.reclaim_snapshot_history().unwrap();
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        2
    );
    let old_payload = db
        .kv()
        .resolve_value_at_snapshot(
            &ColumnFamily(Role::Payload.cf().into()),
            &Key::Payload(rid.0).encode().unwrap(),
            kv_pin.sequence(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        Row::decode(
            &Key::Payload(rid.0),
            &old_payload,
            db.kv().inner.layout.root(),
        )
        .unwrap(),
        Row::Payload(b"before")
    );
    drop(kv_pin);

    let report = records.reclaim_snapshot_history().unwrap();
    assert!(report.rewrite_performed);
    assert!(report.protected_versions_removed >= 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(rid.0)).len(),
        1
    );
    db.kv().verify().unwrap();
}

#[test]
fn commit_and_pin_between_latest_and_pin_capture_remain_readable_through_rewrite() {
    use crate::engine::core::engine::reclaim_hooks;

    let (_dir, db) = tiered_database();
    let records = db.records();
    let old = records.put(b"old", &[]).unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    records.delete_record(old).unwrap();
    records.flush().unwrap();

    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let worker_records = records.clone();
    let worker = std::thread::spawn(move || {
        let _hook = reclaim_hooks::install(move || {
            ready_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        worker_records.reclaim_snapshot_history()
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let late = records.put(b"late", &[]).unwrap();
    let late_pin = records.pin_snapshot().unwrap();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 2);
    resume_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();

    assert_eq!(records.fetch_at_snapshot(old, &held).unwrap(), b"old");
    assert_eq!(records.fetch_at_snapshot(late, &late_pin).unwrap(), b"late");
    assert!(matches!(
        records.fetch_at_snapshot(old, &late_pin),
        Err(PraxisError::KeyNotFound)
    ));
    drop(held);
    records.flush().unwrap();
    records.reclaim_snapshot_history().unwrap();
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(old.0)).len(),
        1
    );
    assert_eq!(records.fetch_at_snapshot(late, &late_pin).unwrap(), b"late");
    db.kv().verify().unwrap();
}

#[test]
fn new_pin_after_retained_view_capture_sees_late_commit_through_install() {
    use crate::engine::core::engine::reclaim_hooks::{self, Phase};

    let (_dir, db) = tiered_database();
    let records = db.records();
    let old = records.put(b"old", &[]).unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    records.delete_record(old).unwrap();
    records.flush().unwrap();

    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let worker_records = records.clone();
    let worker = std::thread::spawn(move || {
        let _hook = reclaim_hooks::install_rewrite(move |phase| {
            if phase == Phase::AfterPinnedViews {
                ready_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            Ok(())
        });
        worker_records.reclaim_snapshot_history()
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let late = records.put(b"late", &[]).unwrap();
    let new_pin = records.pin_snapshot().unwrap();
    resume_tx.send(()).unwrap();
    let report = worker.join().unwrap().unwrap();
    assert!(report.rewrite_performed);
    assert_eq!(records.fetch_at_snapshot(old, &held).unwrap(), b"old");
    assert_eq!(records.fetch_at_snapshot(late, &new_pin).unwrap(), b"late");
    assert!(matches!(
        records.fetch_at_snapshot(old, &new_pin),
        Err(PraxisError::KeyNotFound)
    ));
    db.kv().verify().unwrap();
}

#[test]
fn last_pin_drop_during_rewrite_may_overretain_once_then_next_reclaim_prunes() {
    use crate::engine::core::engine::reclaim_hooks::{self, Phase};

    let (_dir, db) = tiered_database();
    let records = db.records();
    let sacrificial = records.put(b"sacrificial", &[]).unwrap();
    records.delete_record(sacrificial).unwrap();
    let target = records.put(b"target", &[]).unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    records.delete_record(target).unwrap();
    records.flush().unwrap();

    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let worker_records = records.clone();
    let worker = std::thread::spawn(move || {
        let _hook = reclaim_hooks::install_rewrite(move |phase| {
            if phase == Phase::AfterReplacementValidated {
                ready_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            Ok(())
        });
        worker_records.reclaim_snapshot_history()
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(records.fetch_at_snapshot(target, &held).unwrap(), b"target");
    drop(held);
    resume_tx.send(()).unwrap();
    let first = worker.join().unwrap().unwrap();
    assert!(first.rewrite_performed);
    assert!(first.protected_versions_removed >= 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(target.0)).len(),
        2
    );
    db.kv().verify().unwrap();

    let second = records.reclaim_snapshot_history().unwrap();
    assert!(second.rewrite_performed);
    assert!(second.protected_versions_removed >= 1);
    assert_eq!(
        disk_versions(&db, Role::Payload, Key::Payload(target.0)).len(),
        1
    );
    db.kv().verify().unwrap();
}

#[test]
fn same_core_sequence_keeps_the_last_head_and_both_raw_decision_facts() {
    let (_dir, db) = tiered_database();
    let records = db.records();
    let mapping = [IndexInsert::new("kv", b"same".to_vec())];
    let ids = records
        .put_batch(&[
            BatchRecord::new(b"first", &mapping),
            BatchRecord::new(b"second", &mapping),
        ])
        .unwrap();
    records.flush().unwrap();
    let head_key = Key::Head {
        index: 1,
        incarnation: 1,
        key: b"same",
    };
    let before = disk_versions(&db, Role::Index, head_key.clone());
    assert_eq!(before.len(), 2);
    assert_eq!(before[0].sequence, before[1].sequence);
    let pinned = records.pin_snapshot().unwrap();
    let report = records.reclaim_snapshot_history().unwrap();
    assert!(report.protected_versions_removed >= 1);
    assert_eq!(disk_versions(&db, Role::Index, head_key).len(), 1);
    assert_eq!(
        records
            .lookup_rid_at_snapshot("kv", b"same", &pinned)
            .unwrap(),
        Some(ids[1])
    );
    assert_eq!(records.lookup_rid("kv", b"same").unwrap(), Some(ids[1]));
    let fact_count = db
        .kv()
        .inner
        .segment_index
        .read()
        .keys()
        .filter(|(cf, key)| {
            cf.0 == Role::Index.cf()
                && matches!(
                    Key::decode(Role::Index, key, db.kv().inner.layout.root()).unwrap(),
                    Key::Fact { key: b"same", .. }
                )
        })
        .count();
    assert_eq!(fact_count, 2);
    db.kv().verify().unwrap();
}

#[test]
fn shared_external_log_is_collected_only_after_its_last_live_pointer_retires() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    // Keep bootstrap binding/allocator/descriptor rows inline, so the first
    // value log is referenced only by the two large record payloads.
    config.large_value_threshold = 128;
    config.memtable_flush_threshold_bytes = usize::MAX;
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
    let records = db.records();
    let first_payload = vec![b'a'; 1024];
    let second_payload = vec![b'b'; 1024];
    let first = records.put(&first_payload, &[]).unwrap();
    let second = records.put(&second_payload, &[]).unwrap();
    records.flush().unwrap();
    drop(records);
    drop(db);
    // Reopen to exercise persisted external pointers rather than flush's
    // in-memory source values, which are still represented as Put entries.
    let db = CoreDatabase::open(config).unwrap();
    let records = db.records();
    let pointer_path = |rid| {
        let versions = disk_versions(&db, Role::Payload, Key::Payload(rid));
        let crate::types::StoredValue::BlobPointer(pointer) = &versions[0].value else {
            panic!("external payload pointer required");
        };
        std::path::PathBuf::from(&pointer.path)
    };
    let shared_log = pointer_path(first.0);
    assert_eq!(shared_log, pointer_path(second.0));
    assert!(shared_log.is_file());

    let held = records.pin_snapshot().unwrap();
    records.delete_record(first).unwrap();
    records.flush().unwrap();
    records.reclaim_snapshot_history().unwrap();
    assert!(
        shared_log.is_file(),
        "held payload and live neighbor both reference the log"
    );
    assert_eq!(
        records.fetch_at_snapshot(first, &held).unwrap(),
        first_payload
    );

    drop(held);
    let retired_first = records.reclaim_snapshot_history().unwrap();
    assert!(retired_first.protected_versions_removed >= 1);
    assert!(
        shared_log.is_file(),
        "second live payload still references the whole log"
    );
    assert_eq!(records.fetch(second).unwrap(), second_payload);

    records.delete_record(second).unwrap();
    records.flush().unwrap();
    let retired_second = records.reclaim_snapshot_history().unwrap();
    assert!(retired_second.protected_versions_removed >= 1);
    assert!(retired_second.gc.files_reclaimed >= 1);
    assert!(retired_second.gc.bytes_reclaimed > 0);
    assert!(!shared_log.exists());
    db.kv().verify().unwrap();
}

#[test]
fn legacy_user_family_with_a_protected_looking_name_keeps_tiered_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.default_compaction_strategy = crate::CompactionStrategy::Tiered;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config).unwrap();
    let name = Role::Payload.cf();
    engine
        .create_column_family(crate::manifest::ColumnFamilyDescriptor {
            name: name.into(),
            ..Default::default()
        })
        .unwrap();
    let mut first = crate::WriteBatch::new();
    first.put(name, "k", "old");
    engine.write_batch(first).unwrap();
    engine.flush().unwrap();
    let pinned = engine.pin_snapshot();
    let mut second = crate::WriteBatch::new();
    second.put(name, "k", "new");
    engine.write_batch(second).unwrap();
    engine.flush().unwrap();
    assert_eq!(
        engine
            .compact_with_strategy(crate::CompactionStrategy::Tiered)
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .inner
            .segment_index
            .read()
            .get(&(ColumnFamily(name.into()), Bytes::from_static(b"k")))
            .unwrap()
            .len(),
        2,
    );
    assert_eq!(
        engine
            .get_cf(&ColumnFamily(name.into()), b"k", pinned.snapshot())
            .unwrap()
            .unwrap()
            .as_ref(),
        b"old"
    );
    engine.verify().unwrap();
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
fn scan_rejects_a_visible_malformed_physical_state_key() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"v", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    let engine = db.kv();
    // A tag below the first canonical RID is physically present and visible at
    // this pin, but cannot be decoded as any State key.
    let malformed = vec![0];
    assert!(Key::decode(Role::State, &malformed, engine.inner.layout.root()).is_err());
    let mut batch = crate::WriteBatch::new();
    batch.put(
        Role::State.cf(),
        malformed.clone(),
        Row::State {
            live: false,
            payload_length: 0,
        }
        .encode()
        .unwrap(),
    );
    for op in batch.ops() {
        engine
            .inner
            .memtable
            .write()
            .apply(held.core_sequence(), op);
    }
    assert!(
        engine
            .resolve_value_at_snapshot(
                &ColumnFamily(Role::State.cf().into()),
                &malformed,
                held.core_sequence(),
            )
            .unwrap()
            .is_some(),
        "the malformed physical State key is visible at the retained pin"
    );

    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
    ));
}

#[test]
fn scan_rejects_a_missing_live_state_even_when_the_candidate_set_is_empty() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records.put(b"v", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    let allocator_key = Key::Allocator;
    let allocator_bytes = records
        .value(
            Role::Meta,
            &allocator_key,
            held.pin_for(&records.engine).unwrap(),
        )
        .unwrap()
        .unwrap();
    let Row::Allocator(allocator) = Row::decode(
        &allocator_key,
        &allocator_bytes,
        db.kv().inner.layout.root(),
    )
    .unwrap() else {
        panic!("the retained view must have an allocator row");
    };
    assert_eq!(allocator.live_count, 1);
    assert_eq!(allocator.live_payload_bytes, 1);

    // Remove the only physical State key without changing the allocator. This
    // simulates a missing physical live row rather than a logical tombstone.
    let engine = db.kv();
    let state_cf = ColumnFamily(Role::State.cf().into());
    engine.inner.memtable.write().remove_cf(&state_cf);
    assert!(
        engine
            .resolve_value_at_snapshot(
                &state_cf,
                &Key::State(rid.0).encode().unwrap(),
                held.core_sequence(),
            )
            .unwrap()
            .is_none(),
        "the live State key must really be physically absent at the retained pin"
    );

    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
    ));
}

#[test]
fn scan_returns_only_live_rows_in_rid_order_and_skips_post_pin_keys() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let empty = records.pin_snapshot().unwrap();
    assert!(
        records
            .scan_live_at_snapshot(&empty, RecordScanLimits::fixture_v1())
            .unwrap()
            .is_empty()
    );
    drop(empty);

    let first = records.put(b"first", &[]).unwrap();
    let second = records.put(b"second", &[]).unwrap();
    let old = records.pin_snapshot().unwrap();
    let old_clone = old.clone();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    records.delete_record(second).unwrap();
    let third = records.put(b"third", &[]).unwrap();
    let latest = records.pin_snapshot().unwrap();
    assert_eq!(
        records
            .scan_live_at_snapshot(&old, RecordScanLimits::fixture_v1())
            .unwrap(),
        vec![(first, b"first".to_vec()), (second, b"second".to_vec())]
    );
    assert_eq!(
        records
            .scan_live_at_snapshot(&latest, RecordScanLimits::fixture_v1())
            .unwrap(),
        vec![(first, b"first".to_vec()), (third, b"third".to_vec())]
    );
    drop(old);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 2);
    drop(old_clone);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    drop(latest);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
}

#[test]
fn scan_resolves_raw_visibility_before_decoding_a_future_malformed_key() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records.put(b"old", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    inject_raw_at(
        &db,
        held.core_sequence() + 1,
        Role::State,
        vec![0],
        Some(
            Row::State {
                live: false,
                payload_length: 0,
            }
            .encode()
            .unwrap(),
        ),
    );
    assert_eq!(
        records
            .scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1())
            .unwrap(),
        vec![(rid, b"old".to_vec())]
    );
}

#[test]
fn scan_rejects_missing_dead_state_and_extra_live_or_dead_rid() {
    {
        let (_dir, _config, db) = database();
        let records = db.records();
        records.put(b"live", &[]).unwrap();
        let dead = records.put(b"dead", &[]).unwrap();
        records.delete_record(dead).unwrap();
        records.flush().unwrap();
        let held = records.pin_snapshot().unwrap();
        let removed = db.kv().inner.segment_index.write().remove(&(
            ColumnFamily(Role::State.cf().into()),
            Bytes::from(Key::State(dead.0).encode().unwrap()),
        ));
        assert!(removed.is_some());
        assert!(matches!(
            records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
            Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
        ));
    }
    for live in [false, true] {
        let (_dir, _config, db) = database();
        let records = db.records();
        records.put(b"one", &[]).unwrap();
        let held = records.pin_snapshot().unwrap();
        inject_raw_at(
            &db,
            held.core_sequence(),
            Role::State,
            Key::State(2).encode().unwrap(),
            Some(
                Row::State {
                    live,
                    payload_length: if live { 1 } else { 0 },
                }
                .encode()
                .unwrap(),
            ),
        );
        assert!(matches!(
            records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
            Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
        ));
    }
}

#[test]
fn scan_rejects_first_middle_and_last_missing_payload_without_partial_success() {
    for failed_index in 0..3 {
        let (_dir, _config, db) = database();
        let records = db.records();
        let ids: Vec<_> = [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]
            .iter()
            .map(|payload| records.put(payload, &[]).unwrap())
            .collect();
        let held = records.pin_snapshot().unwrap();
        inject_raw_at(
            &db,
            held.core_sequence(),
            Role::Payload,
            Key::Payload(ids[failed_index].0).encode().unwrap(),
            None,
        );
        assert!(matches!(
            records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
            Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
        ));
    }
}

#[test]
fn scan_refuses_raw_key_and_allocator_limits_with_typed_errors() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"one", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_candidate_keys = 0;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, limits),
        Err(CoreRecordScanError::ResourceLimit {
            code: "state_candidates"
        })
    ));
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_live_rows = 0;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, limits),
        Err(CoreRecordScanError::ResourceLimit { code: "live_rows" })
    ));
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_payload_bytes = 2;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, limits),
        Err(CoreRecordScanError::ResourceLimit {
            code: "payload_bytes"
        })
    ));
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_candidate_key_bytes = 8;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, limits),
        Err(CoreRecordScanError::ResourceLimit {
            code: "candidate_key_bytes"
        })
    ));
    // Even a key first written after the pin must pass the raw-key admission
    // limit before it can be cloned into the candidate set.
    inject_raw_at(
        &db,
        held.core_sequence() + 1,
        Role::State,
        vec![2; 4_097],
        Some(vec![0]),
    );
    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::ResourceLimit {
            code: "raw_state_key_bytes"
        })
    ));
}

#[test]
fn scan_refuses_a_second_distinct_candidate_before_its_raw_key_clone() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"one", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    inject_raw_at(
        &db,
        held.core_sequence() + 1,
        Role::State,
        Key::State(2).encode().unwrap(),
        Some(
            Row::State {
                live: false,
                payload_length: 0,
            }
            .encode()
            .unwrap(),
        ),
    );
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_candidate_keys = 1;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, limits),
        Err(CoreRecordScanError::ResourceLimit {
            code: "state_candidates"
        })
    ));
}

#[test]
fn scan_adds_distinct_raw_key_lengths_before_the_cumulative_byte_limit() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let first = records.put(b"one", &[]).unwrap();
    let second = records.put(b"two", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    assert_eq!(Key::State(first.0).encode().unwrap().len(), 9);
    assert_eq!(Key::State(second.0).encode().unwrap().len(), 9);

    let mut admitted = RecordScanLimits::fixture_v1();
    admitted.max_candidate_key_bytes = 18;
    assert_eq!(
        records.scan_live_at_snapshot(&held, admitted).unwrap(),
        vec![(first, b"one".to_vec()), (second, b"two".to_vec())]
    );
    let mut refused = RecordScanLimits::fixture_v1();
    refused.max_candidate_key_bytes = 17;
    assert!(matches!(
        records.scan_live_at_snapshot(&held, refused),
        Err(CoreRecordScanError::ResourceLimit {
            code: "candidate_key_bytes"
        })
    ));
}

#[test]
fn scan_rejects_foreign_owner_and_poison_after_materialization() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"one", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    let (_other_dir, _other_config, other) = database();
    assert!(matches!(
        other
            .records()
            .scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(
            PraxisError::ForeignRecordSnapshot { .. }
        ))
    ));
    let engine = db.kv().clone();
    READ_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |phase| {
            if phase == ReadPhase::ScanBeforeReturn {
                engine.inner.group_commit.poison("scan final guard".into());
            }
        }))
    });
    let late = records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1());
    READ_HOOK.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(
        late,
        Err(CoreRecordScanError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
}

#[test]
fn scan_rejects_a_poisoned_owner_before_any_scan_hook_fires() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"one", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    let hook_calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let observed = hook_calls.clone();
    READ_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_| {
            observed.set(observed.get() + 1);
        }))
    });
    db.kv().inner.group_commit.poison("scan entry guard".into());
    let result = records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1());
    READ_HOOK.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(
        result,
        Err(CoreRecordScanError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(hook_calls.get(), 0);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
}

#[test]
fn scan_preserves_old_and_new_rows_through_flush_compaction_and_reclaim() {
    for strategy in [
        crate::CompactionStrategy::Leveled,
        crate::CompactionStrategy::Tiered,
        crate::CompactionStrategy::Universal,
    ] {
        let (_dir, _config, db) = database();
        let records = db.records();
        let old_rid = records.put(b"old", &[]).unwrap();
        records.flush().unwrap();
        let old = records.pin_snapshot().unwrap();
        records.delete_record(old_rid).unwrap();
        let new_rid = records.put(b"new", &[]).unwrap();
        records.flush().unwrap();
        assert!(db.kv().compact_with_strategy(strategy).unwrap() > 0);
        records.reclaim_snapshot_history().unwrap();
        db.kv().garbage_collect().unwrap();
        assert_eq!(
            records
                .scan_live_at_snapshot(&old, RecordScanLimits::fixture_v1())
                .unwrap(),
            vec![(old_rid, b"old".to_vec())]
        );
        let latest = records.pin_snapshot().unwrap();
        assert_eq!(
            records
                .scan_live_at_snapshot(&latest, RecordScanLimits::fixture_v1())
                .unwrap(),
            vec![(new_rid, b"new".to_vec())]
        );
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 2);
        drop(old);
        drop(latest);
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
    }
}

#[test]
fn scan_counts_a_key_in_segment_and_mutable_tiers_only_once() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records.put(b"old", &[]).unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    records.delete_record(rid).unwrap();
    let mut limits = RecordScanLimits::fixture_v1();
    limits.max_candidate_keys = 1;
    assert_eq!(
        records.scan_live_at_snapshot(&held, limits).unwrap(),
        vec![(rid, b"old".to_vec())]
    );
}

#[test]
fn scan_rejects_a_physically_missing_allocator_at_the_held_pin() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"one", &[]).unwrap();
    records.flush().unwrap();
    let held = records.pin_snapshot().unwrap();
    let allocator_key = Key::Allocator.encode().unwrap();
    let meta_cf = ColumnFamily(Role::Meta.cf().into());
    let removed = db
        .kv()
        .inner
        .segment_index
        .write()
        .remove(&(meta_cf.clone(), Bytes::from(allocator_key.clone())));
    assert!(removed.is_some());
    assert!(
        db.kv()
            .resolve_value_at_snapshot(&meta_cf, &allocator_key, held.core_sequence())
            .unwrap()
            .is_none()
    );
    assert!(
        db.kv()
            .resolve_value_at_snapshot(
                &meta_cf,
                &Key::Binding.encode().unwrap(),
                held.core_sequence(),
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
    ));
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
}

#[test]
fn scan_rejects_malformed_allocator_and_state_rows() {
    for role in [Role::Meta, Role::State] {
        let (_dir, _config, db) = database();
        let records = db.records();
        let rid = records.put(b"one", &[]).unwrap();
        let held = records.pin_snapshot().unwrap();
        let key = match role {
            Role::Meta => Key::Allocator,
            Role::State => Key::State(rid.0),
            _ => unreachable!(),
        };
        inject_raw_at(
            &db,
            held.core_sequence(),
            role,
            key.encode().unwrap(),
            Some(vec![0]),
        );
        assert!(matches!(
            records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
            Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
        ));
    }
}

#[test]
fn scan_preserves_external_payload_io_error_and_the_retained_pin() {
    let (_dir, config, db) = database();
    let records = db.records();
    let first = records.put(b"first", &[]).unwrap();
    let second = records.put(b"second", &[]).unwrap();
    records.flush().unwrap();
    drop(records);
    drop(db);
    let db = CoreDatabase::open(config).unwrap();
    let records = db.records();
    let held = records.pin_snapshot().unwrap();
    let engine = db.kv();
    let path = {
        let index = engine.inner.segment_index.read();
        let versions = &index[&(
            ColumnFamily(Role::Payload.cf().into()),
            Bytes::from(Key::Payload(second.0).encode().unwrap()),
        )];
        let crate::types::StoredValue::BlobPointer(pointer) = &versions.last().unwrap().value
        else {
            panic!("persisted external payload pointer required")
        };
        std::path::PathBuf::from(&pointer.path)
    };
    let held_path = path.with_extension("held");
    std::fs::rename(&path, &held_path).unwrap();
    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(PraxisError::Io(_)))
    ));
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    std::fs::rename(&held_path, &path).unwrap();
    assert_eq!(
        records
            .scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1())
            .unwrap(),
        vec![(first, b"first".to_vec()), (second, b"second".to_vec())]
    );
}

#[test]
fn scan_rejects_payload_length_mismatch_after_an_earlier_live_row() {
    let (_dir, _config, db) = database();
    let records = db.records();
    records.put(b"first", &[]).unwrap();
    let second = records.put(b"second", &[]).unwrap();
    let held = records.pin_snapshot().unwrap();
    inject_raw_at(
        &db,
        held.core_sequence(),
        Role::Payload,
        Key::Payload(second.0).encode().unwrap(),
        Some(Row::Payload(b"short").encode().unwrap()),
    );
    assert!(matches!(
        records.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1()),
        Err(CoreRecordScanError::Storage(PraxisError::Corrupt { .. }))
    ));
}

#[test]
fn scan_releases_topology_before_a_barrier_and_returns_one_retained_view() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let first = records.put(b"first", &[]).unwrap();
    records.flush().unwrap();
    let old = records.pin_snapshot().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let reader = records.clone();
    let held = old.clone();
    let join = std::thread::spawn(move || {
        READ_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |phase| {
                if phase == ReadPhase::ScanCaptured {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            }))
        });
        let result = reader.scan_live_at_snapshot(&held, RecordScanLimits::fixture_v1());
        READ_HOOK.with(|hook| *hook.borrow_mut() = None);
        result
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    let second = records.put(b"second", &[]).unwrap();
    records.flush().unwrap();
    db.kv()
        .compact_with_strategy(crate::CompactionStrategy::Leveled)
        .unwrap();
    resume_tx.send(()).unwrap();
    assert_eq!(
        join.join().unwrap().unwrap(),
        vec![(first, b"first".to_vec())]
    );
    let latest = records.pin_snapshot().unwrap();
    assert_eq!(
        records
            .scan_live_at_snapshot(&latest, RecordScanLimits::fixture_v1())
            .unwrap(),
        vec![(first, b"first".to_vec()), (second, b"second".to_vec())]
    );
    drop(old);
    drop(latest);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
}

// These frames are independently frozen PRXQDOC-NUL v1 bytes. In particular,
// neither this fixture nor its expected query rows call the sibling codec.
const GATEWAY_FRAME_ONE: &[u8] = b"PRXQDOC\0\x00\x01\x00\x00\x00\x00\x00\x29\x00\x04docs\x00\x03one\x00\x01\x00\x01n\x04\x00\x00\x00\x00\x00\x00\x00\x01";
const GATEWAY_FRAME_TWO: &[u8] = b"PRXQDOC\0\x00\x01\x00\x00\x00\x00\x00\x29\x00\x04docs\x00\x03two\x00\x01\x00\x01n\x04\x00\x00\x00\x00\x00\x00\x00\x02";
const GATEWAY_FRAME_THREE: &[u8] = b"PRXQDOC\0\x00\x01\x00\x00\x00\x00\x00\x2b\x00\x04docs\x00\x05three\x00\x01\x00\x01n\x04\x00\x00\x00\x00\x00\x00\x00\x03";

type GatewayLiteralRow = (String, String, Vec<(String, serde_json::Value)>);

fn gateway_fault_expected_rows() -> Vec<GatewayLiteralRow> {
    vec![
        (
            "docs".into(),
            "one".into(),
            vec![("n".into(), serde_json::json!(1))],
        ),
        (
            "docs".into(),
            "two".into(),
            vec![("n".into(), serde_json::json!(2))],
        ),
        (
            "docs".into(),
            "three".into(),
            vec![("n".into(), serde_json::json!(3))],
        ),
    ]
}

fn gateway_fault_rows(result: QueryResult) -> Vec<GatewayLiteralRow> {
    let QueryResult::Rows(rows) = result else {
        panic!("expected Rows")
    };
    rows.into_iter()
        .map(|row| (row.id.collection, row.id.key, row.fields))
        .collect()
}

fn gateway_fault_catalog() -> crate::Catalog {
    use crate::catalog::IntegerType;
    use crate::{AttributeSchema, AttributeType, CollectionSchema};

    let mut catalog = crate::Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("docs").with_attribute(AttributeSchema::new(
                "n",
                AttributeType::Integer(IntegerType::Uint8),
            )),
        )
        .unwrap();
    catalog
}

fn gateway_resolver_chain(
    records: &CoreRecordStore,
    role: Role,
    rid: RecordId,
) -> Vec<VersionedValue> {
    let key = match role {
        Role::State => Key::State(rid.0),
        Role::Payload => Key::Payload(rid.0),
        _ => panic!("gateway fault target must be State or Payload"),
    }
    .encode()
    .unwrap();
    let cf = ColumnFamily(role.cf().into());
    let engine = &records.engine;
    // Match the resolver's segment -> mutable -> immutable tie order while
    // topology is held, then release every lock before query or rename.
    let mut chain = {
        let _topology = engine.inner.topology.read();
        let mut chain = engine
            .inner
            .segment_index
            .read()
            .get(&(cf.clone(), Bytes::copy_from_slice(&key)))
            .cloned()
            .unwrap_or_default();
        chain.extend(engine.inner.memtable.read().versions_for_key(&cf, &key));
        for immutable in engine.inner.immutable_memtables.lock().iter() {
            chain.extend(immutable.versions_for_key(&cf, &key));
        }
        chain
    };
    chain.sort_by_key(|version| version.sequence);
    chain
}

fn gateway_pointer_path(
    records: &CoreRecordStore,
    role: Role,
    rid: RecordId,
    sequence: u64,
) -> PathBuf {
    let chain = gateway_resolver_chain(records, role, rid);
    let visible = chain
        .iter()
        .filter(|version| version.sequence <= sequence)
        .collect::<Vec<_>>();
    assert_eq!(
        visible.len(),
        1,
        "{role:?} {rid}: exactly one visible version required"
    );
    let StoredValue::BlobPointer(pointer) = &visible[0].value else {
        panic!("{role:?} {rid}: visible version is not a BlobPointer")
    };
    let path = PathBuf::from(&pointer.path);
    assert!(path.is_file(), "{role:?} {rid}: pointer file absent");
    let pointed = crate::values::ValueLog::read_pointer(pointer).unwrap();
    let key = match role {
        Role::State => Key::State(rid.0),
        Role::Payload => Key::Payload(rid.0),
        _ => unreachable!(),
    }
    .encode()
    .unwrap();
    let segment = records
        .engine
        .inner
        .segment_index
        .read()
        .get(&(ColumnFamily(role.cf().into()), Bytes::copy_from_slice(&key)))
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        segment.len(),
        1,
        "{role:?} {rid}: one segment version required"
    );
    assert_eq!(
        &segment[0], visible[0],
        "{role:?} {rid}: pointer must be the segment version"
    );
    assert_eq!(
        records
            .engine
            .resolve_value_at_snapshot(&ColumnFamily(role.cf().into()), &key, sequence)
            .unwrap(),
        Some(pointed),
        "{role:?} {rid}: held resolver must read that one pointer"
    );
    path
}

struct GatewayFaultFixture {
    _dir: tempfile::TempDir,
    db: CoreDatabase,
    records: CoreRecordStore,
    gateway: QueryGateway,
    view: QueryReadView,
    rids: [RecordId; 3],
    sequence: u64,
    state_paths: [PathBuf; 3],
    payload_paths: [PathBuf; 3],
}

impl GatewayFaultFixture {
    fn target_path(&self, role: Role, index: usize) -> &PathBuf {
        match role {
            Role::State => &self.state_paths[index],
            Role::Payload => &self.payload_paths[index],
            _ => unreachable!(),
        }
    }

    fn query(&self) -> std::result::Result<QueryResult, QueryReadError> {
        self.gateway.query(
            &self.view,
            "SELECT n FROM docs",
            &TypedParameters::default(),
        )
    }
}

fn gateway_fault_fixture() -> GatewayFaultFixture {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 1;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions::default()).unwrap();
    let records = db.records();
    let mut rids = Vec::new();
    for frame in [GATEWAY_FRAME_ONE, GATEWAY_FRAME_TWO, GATEWAY_FRAME_THREE] {
        let rid = records.put(frame, &[]).unwrap();
        records.flush().unwrap();
        rids.push(rid);
    }
    assert_eq!(rids, [RecordId(1), RecordId(2), RecordId(3)]);
    drop(records);
    drop(db);

    let db = CoreDatabase::open(config).unwrap();
    let records = db.records();
    let gateway = QueryGateway::attach_fixture_v1(&db, gateway_fault_catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let adjacent = records.pin_snapshot().unwrap();
    let sequence = adjacent.core_sequence();
    let key = Key::Allocator;
    let allocator_bytes = records
        .value(Role::Meta, &key, adjacent.pin_for(&records.engine).unwrap())
        .unwrap()
        .unwrap();
    let Row::Allocator(allocator) =
        Row::decode(&key, &allocator_bytes, records.engine.inner.layout.root()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(allocator.last_rid, 3);
    assert_eq!(allocator.live_count, 3);
    assert_eq!(allocator.dead_count, 0);
    assert_eq!(
        allocator.live_payload_bytes,
        (GATEWAY_FRAME_ONE.len() + GATEWAY_FRAME_TWO.len() + GATEWAY_FRAME_THREE.len()) as u64
    );
    let candidates = records
        .bounded_state_candidates(RecordScanLimits::fixture_v1())
        .unwrap()
        .into_iter()
        .map(|raw| {
            let Key::State(rid) =
                Key::decode(Role::State, &raw, records.engine.inner.layout.root()).unwrap()
            else {
                panic!("non-State candidate")
            };
            rid
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates, [1, 2, 3]);
    let rids: [RecordId; 3] = rids.try_into().unwrap();
    let state_paths = rids.map(|rid| gateway_pointer_path(&records, Role::State, rid, sequence));
    let payload_paths =
        rids.map(|rid| gateway_pointer_path(&records, Role::Payload, rid, sequence));
    for left in 0..3 {
        for right in left + 1..3 {
            assert_ne!(state_paths[left], state_paths[right]);
            assert_ne!(payload_paths[left], payload_paths[right]);
            assert_ne!(state_paths[left], payload_paths[right]);
            assert_ne!(payload_paths[left], state_paths[right]);
        }
        // A same-row State read may share the Payload path, but it completes
        // before that row's Payload hook renames it.
        eprintln!(
            "gateway fault preflight rid={} state_payload_path_alias={}",
            rids[left].0,
            state_paths[left] == payload_paths[left]
        );
    }
    assert_eq!(
        gateway_fault_rows(
            gateway
                .query(&view, "SELECT n FROM docs", &TypedParameters::default())
                .unwrap()
        ),
        gateway_fault_expected_rows()
    );
    drop(adjacent);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    GatewayFaultFixture {
        _dir: dir,
        db,
        records,
        gateway,
        view,
        rids,
        sequence,
        state_paths,
        payload_paths,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GatewayScanHits {
    captured: usize,
    state: usize,
    payload: usize,
    before_return: usize,
}

impl GatewayScanHits {
    fn record(&mut self, phase: ReadPhase) -> usize {
        let count = match phase {
            ReadPhase::ScanCaptured => &mut self.captured,
            ReadPhase::ScanState => &mut self.state,
            ReadPhase::ScanPayload => &mut self.payload,
            ReadPhase::ScanBeforeReturn => &mut self.before_return,
            _ => return 0,
        };
        *count += 1;
        *count
    }
}

fn gateway_expected_terminal_hits(role: Role, index: usize) -> GatewayScanHits {
    GatewayScanHits {
        captured: 1,
        state: index + 1,
        payload: index + usize::from(role == Role::Payload),
        before_return: 0,
    }
}

struct GatewayHookReset {
    installed: bool,
}

impl GatewayHookReset {
    fn clear(&mut self) -> std::result::Result<(), &'static str> {
        READ_HOOK.with(|slot| {
            let Ok(mut hook) = slot.try_borrow_mut() else {
                return Err("gateway hook still borrowed");
            };
            if hook.is_none() {
                return Err("gateway hook missing");
            }
            *hook = None;
            self.installed = false;
            Ok(())
        })
    }
}

impl Drop for GatewayHookReset {
    fn drop(&mut self) {
        if self.installed {
            READ_HOOK.with(|slot| {
                // During unwinding this must not cause a second panic.
                if let Ok(mut hook) = slot.try_borrow_mut() {
                    *hook = None;
                }
            });
        }
    }
}

struct GatewayPathRestore {
    original: PathBuf,
    displaced: PathBuf,
    armed: Rc<Cell<bool>>,
}

impl GatewayPathRestore {
    fn new(original: PathBuf) -> Self {
        let displaced = original.with_extension("stage4b-held");
        assert!(!displaced.exists(), "fault displacement already exists");
        Self {
            original,
            displaced,
            armed: Rc::new(Cell::new(false)),
        }
    }

    fn restore(&self) -> std::io::Result<()> {
        if self.armed.get() {
            std::fs::rename(&self.displaced, &self.original)?;
            self.armed.set(false);
        }
        Ok(())
    }
}

impl Drop for GatewayPathRestore {
    fn drop(&mut self) {
        // Best effort on unwind; the explicit normal-path restore is checked.
        let _ = self.restore();
    }
}

fn gateway_public_physical_io_cell(role: Role, index: usize) {
    let fixture = gateway_fault_fixture();
    let target = fixture.target_path(role, index).clone();
    let restore = GatewayPathRestore::new(target.clone());
    let displaced = restore.displaced.clone();
    let armed = Rc::clone(&restore.armed);
    let hits = Rc::new(Cell::new(GatewayScanHits::default()));
    let hook_hits = Rc::clone(&hits);
    let target_phase = if role == Role::State {
        ReadPhase::ScanState
    } else {
        ReadPhase::ScanPayload
    };
    READ_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "previous hook leaked into fault cell"
        );
        *slot.borrow_mut() = Some(Box::new(move |phase| {
            let mut current = hook_hits.get();
            let ordinal = current.record(phase);
            hook_hits.set(current);
            if phase == target_phase && ordinal == index + 1 && !armed.get() {
                std::fs::rename(&target, &displaced).unwrap();
                armed.set(true);
            }
        }));
    });
    // The reset guard is created after the restore guard, so it drops first
    // during unwind. Never clear READ_HOOK inside its borrowed callback.
    let mut reset = GatewayHookReset { installed: true };
    let result = fixture.query();
    let terminal_hits = hits.get();
    reset.clear().expect("gateway I/O hook did not clear");
    drop(reset);
    let renamed = restore.armed.get();
    restore.restore().unwrap();
    assert!(
        renamed,
        "{role:?} index {index}: target hook did not rename"
    );
    assert_eq!(
        terminal_hits,
        gateway_expected_terminal_hits(role, index),
        "{role:?} index {index}: wrong scan ordinal or retry"
    );
    assert!(
        matches!(
            &result,
            Err(QueryReadError::Storage(PraxisError::Io(error)))
                if error.kind() == std::io::ErrorKind::NotFound
        ),
        "{role:?} index {index}: expected physical Io(NotFound), got {result:?}"
    );
    assert_eq!(
        gateway_fault_rows(fixture.query().unwrap()),
        gateway_fault_expected_rows(),
        "{role:?} index {index}: same held view must survive restored I/O"
    );
}

fn gateway_public_corrupt_cell(role: Role, index: usize) {
    let fixture = gateway_fault_fixture();
    let rid = fixture.rids[index];
    let physical_key = match role {
        Role::State => Key::State(rid.0),
        Role::Payload => Key::Payload(rid.0),
        _ => unreachable!(),
    };
    let key = physical_key.encode().unwrap();
    inject_raw_at(
        &fixture.db,
        fixture.sequence,
        role,
        key.clone(),
        Some(vec![0]),
    );
    let chain = gateway_resolver_chain(&fixture.records, role, rid);
    let visible = chain
        .iter()
        .filter(|version| version.sequence <= fixture.sequence)
        .collect::<Vec<_>>();
    assert_eq!(
        visible.len(),
        2,
        "{role:?} {rid}: expected pointer then injected Put"
    );
    let segment = disk_versions(&fixture.db, role, physical_key);
    assert_eq!(segment.len(), 1);
    assert_eq!(
        visible[0], &segment[0],
        "{role:?} {rid}: original segment first"
    );
    assert!(matches!(visible[0].value, StoredValue::BlobPointer(_)));
    assert_eq!(visible[1].sequence, fixture.sequence);
    assert!(matches!(&visible[1].value, StoredValue::Put(bytes) if bytes == &[0]));
    assert_eq!(
        fixture
            .records
            .engine
            .resolve_value_at_snapshot(&ColumnFamily(role.cf().into()), &key, fixture.sequence)
            .unwrap(),
        Some(vec![0]),
        "{role:?} {rid}: held resolver must choose injected raw byte"
    );

    let hits = Rc::new(Cell::new(GatewayScanHits::default()));
    let hook_hits = Rc::clone(&hits);
    READ_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "previous hook leaked into corrupt cell"
        );
        *slot.borrow_mut() = Some(Box::new(move |phase| {
            let mut current = hook_hits.get();
            current.record(phase);
            hook_hits.set(current);
        }));
    });
    let mut reset = GatewayHookReset { installed: true };
    let result = fixture.query();
    let terminal_hits = hits.get();
    reset.clear().expect("gateway Corrupt hook did not clear");
    drop(reset);
    assert_eq!(
        terminal_hits,
        gateway_expected_terminal_hits(role, index),
        "{role:?} index {index}: wrong corrupt-scan ordinal or retry"
    );
    assert!(
        matches!(
            &result,
            Err(QueryReadError::Storage(PraxisError::Corrupt { .. }))
        ),
        "{role:?} index {index}: expected Storage(Corrupt), got {result:?}"
    );
}

macro_rules! gateway_io_case {
    ($name:ident, $role:expr, $index:expr) => {
        #[test]
        fn $name() {
            gateway_public_physical_io_cell($role, $index);
        }
    };
}

macro_rules! gateway_corrupt_case {
    ($name:ident, $role:expr, $index:expr) => {
        #[test]
        fn $name() {
            gateway_public_corrupt_cell($role, $index);
        }
    };
}

gateway_io_case!(gateway_public_io_state_first, Role::State, 0);
gateway_io_case!(gateway_public_io_state_middle, Role::State, 1);
gateway_io_case!(gateway_public_io_state_last, Role::State, 2);
gateway_io_case!(gateway_public_io_payload_first, Role::Payload, 0);
gateway_io_case!(gateway_public_io_payload_middle, Role::Payload, 1);
gateway_io_case!(gateway_public_io_payload_last, Role::Payload, 2);
gateway_corrupt_case!(gateway_public_corrupt_state_first, Role::State, 0);
gateway_corrupt_case!(gateway_public_corrupt_state_middle, Role::State, 1);
gateway_corrupt_case!(gateway_public_corrupt_state_last, Role::State, 2);
gateway_corrupt_case!(gateway_public_corrupt_payload_first, Role::Payload, 0);
gateway_corrupt_case!(gateway_public_corrupt_payload_middle, Role::Payload, 1);
gateway_corrupt_case!(gateway_public_corrupt_payload_last, Role::Payload, 2);

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
