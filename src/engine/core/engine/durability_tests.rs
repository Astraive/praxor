use super::*;
use std::time::{Duration, Instant};

fn engine(policy: crate::WalSyncPolicy) -> (tempfile::TempDir, PraxisConfig, PraxisEngine) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = policy;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    (dir, config, engine)
}
fn queue(engine: &PraxisEngine, key: &str, durability: Durability) -> Arc<CommitRequest> {
    let mut batch = WriteBatch::new();
    batch.put_default(key.to_owned(), "value");
    queue_batch(engine, batch, durability)
}
fn queue_batch(
    engine: &PraxisEngine,
    batch: WriteBatch,
    durability: Durability,
) -> Arc<CommitRequest> {
    let (batch, generations) = engine.normalize_batch_with_cf_policies(batch).unwrap();
    let len = WalRecord::checked_encoded_batch_len(&batch).unwrap();
    engine
        .inner
        .group_commit
        .admit_user(
            batch,
            generations,
            WriteCondition::Unconditional,
            durability,
            len,
            &engine.inner.metrics,
        )
        .unwrap()
}
fn write(sequence: u64) -> CommitOutcome {
    CommitOutcome::Write { sequence }
}
fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn private_durable_request_syncs_under_never_without_changing_persisted_policy() {
    for policy in [
        crate::WalSyncPolicy::EveryBatch,
        crate::WalSyncPolicy::GroupCommit,
        crate::WalSyncPolicy::Never,
    ] {
        let (_dir, config, engine) = engine(policy);
        let first = queue(&engine, "configured-before", Durability::Configured);
        let durable = queue(&engine, "durable", Durability::Durable);
        let last = queue(&engine, "configured-after", Durability::Configured);
        assert_eq!(engine.wait_for_commit(&first).unwrap(), write(1));
        assert_eq!(engine.wait_for_commit(&durable).unwrap(), write(2));
        assert_eq!(engine.wait_for_commit(&last).unwrap(), write(3));
        let syncs = if policy == crate::WalSyncPolicy::EveryBatch {
            3
        } else {
            1
        };
        assert_eq!(
            engine
                .inner
                .metrics
                .commit_sync_attempts
                .load(Ordering::Relaxed),
            syncs
        );
        assert_eq!(
            engine.inner.metrics.commit_syncs.load(Ordering::Relaxed),
            syncs
        );
        assert_eq!(engine.effective_config().wal_sync_policy, policy);
        drop(engine);
        let engine = PraxisEngine::open(config).unwrap();
        assert_eq!(engine.get("durable").unwrap().unwrap().as_ref(), b"value");
        assert_eq!(
            engine.get("configured-before").unwrap().unwrap().as_ref(),
            b"value"
        );
    }
}

#[test]
fn barrier_is_fifo_fenced_and_has_no_wal_frame_or_sequence() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::Never);
    let before = queue(&engine, "before", Durability::Configured);
    let barrier = engine
        .inner
        .group_commit
        .admit_barrier(&engine.inner.metrics)
        .unwrap();
    let after = queue(&engine, "after", Durability::Configured);
    assert_eq!(engine.wait_for_commit(&before).unwrap(), write(1));
    let length = std::fs::metadata(engine.inner.wal.lock().path())
        .unwrap()
        .len();
    assert_eq!(
        engine.wait_for_commit(&barrier).unwrap(),
        CommitOutcome::Barrier {
            through_sequence: 1
        }
    );
    assert_eq!(engine.snapshot().sequence, 1);
    assert_eq!(engine.inner.manifest.lock().last_sequence, 1);
    assert_eq!(
        std::fs::metadata(engine.inner.wal.lock().path())
            .unwrap()
            .len(),
        length
    );
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
    assert_eq!(engine.inner.metrics.wal_records.load(Ordering::Relaxed), 1);
    assert_eq!(engine.wait_for_commit(&after).unwrap(), write(2));
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
}

#[test]
fn empty_never_write_stays_a_noop_but_empty_barrier_really_syncs() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::Never);
    let before = std::fs::read(engine.inner.wal.lock().path()).unwrap();
    assert_eq!(engine.write_batch(WriteBatch::new()).unwrap(), 0);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(engine.durable_barrier().unwrap(), 0);
    assert_eq!(engine.durable_barrier().unwrap(), 0);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 2);
    assert_eq!(
        std::fs::read(engine.inner.wal.lock().path()).unwrap(),
        before
    );
}

#[test]
fn invalid_durable_request_performs_no_wal_or_sync_and_keeps_owner_healthy() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::Never);
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "retired".into(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let mut batch = WriteBatch::new();
    batch.put("retired", "key", "value");
    let invalid = queue_batch(&engine, batch, Durability::Durable);
    engine.drop_column_family("retired").unwrap();
    let before = std::fs::read(engine.inner.wal.lock().path()).unwrap();
    assert!(matches!(
        engine.wait_for_commit(&invalid),
        Err(PraxisError::WriteStalled { .. })
    ));
    assert_eq!(engine.snapshot().sequence, 0);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        std::fs::read(engine.inner.wal.lock().path()).unwrap(),
        before
    );
    assert!(engine.inner.group_commit.ensure_writable().is_ok());
}

#[test]
fn rejected_middle_request_keeps_typed_outcomes_and_contiguous_write_sequences() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::GroupCommit);
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "retired".into(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let first = queue(&engine, "first", Durability::Configured);
    let mut batch = WriteBatch::new();
    batch.put("retired", "key", "value");
    let invalid = queue_batch(&engine, batch, Durability::Durable);
    let last = queue(&engine, "last", Durability::Configured);
    engine.drop_column_family("retired").unwrap();
    assert_eq!(engine.wait_for_commit(&first).unwrap(), write(1));
    assert!(matches!(
        engine.wait_for_commit(&invalid),
        Err(PraxisError::WriteStalled { .. })
    ));
    assert_eq!(engine.wait_for_commit(&last).unwrap(), write(2));
    assert_eq!(
        engine.inner.metrics.commit_batches.load(Ordering::Relaxed),
        2
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
}

#[test]
fn durable_success_does_not_publish_or_complete_before_memtable_installation() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::Never);
    let table = engine.inner.memtable.write();
    let writer_engine = engine.clone();
    let (sent, received) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let request = queue(&writer_engine, "pending", Durability::Durable);
        sent.send(writer_engine.wait_for_commit(&request)).unwrap();
    });
    wait_until(|| engine.inner.metrics.commit_syncs.load(Ordering::Acquire) == 1);
    assert_eq!(engine.snapshot().sequence, 0);
    assert!(received.try_recv().is_err());
    drop(table);
    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap(),
        write(1)
    );
    writer.join().unwrap();
}

#[test]
fn never_barrier_covers_a_forced_rotation_and_refuses_shared_poison() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::WalSyncPolicy::Never;
    config.wal_segment_size = config.page_size;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    for index in 0..20 {
        engine
            .put(format!("key-{index}"), vec![index as u8; 1024])
            .unwrap();
    }
    assert!(engine.inner.manifest.lock().active_wal_id > 1);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        0,
        "rotation syncs are separate from commit/barrier metrics"
    );
    assert_eq!(engine.durable_barrier().unwrap(), 20);
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
    engine.inner.group_commit.poison("test poison".into());
    assert!(matches!(
        engine.durable_barrier(),
        Err(PraxisError::RecoveryRequired)
    ));
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        1
    );
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.snapshot().sequence, 20);
    for index in 0..20 {
        assert_eq!(
            engine
                .get(format!("key-{index}"))
                .unwrap()
                .unwrap()
                .as_ref(),
            vec![index as u8; 1024]
        );
    }
}

#[test]
fn waiting_barrier_holds_no_maintenance_wal_or_manifest_guard() {
    let (_dir, _config, engine) = engine(crate::WalSyncPolicy::Never);
    let writer = engine.inner.write_serialization.lock();
    let worker = engine.clone();
    let barrier = std::thread::spawn(move || worker.durable_barrier());
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 1
    });
    assert!(engine.inner.maintenance_serialization.try_lock().is_some());
    assert!(engine.inner.wal.try_lock().is_some());
    assert!(engine.inner.manifest.try_lock().is_some());
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        0
    );
    drop(writer);
    assert_eq!(barrier.join().unwrap().unwrap(), 0);
}

#[test]
fn barrier_remains_valid_after_flush_and_gc_retire_its_prior_wal() {
    let (_dir, config, engine) = engine(crate::WalSyncPolicy::Never);
    engine.put("prior", "value").unwrap();
    let barrier = engine
        .inner
        .group_commit
        .admit_barrier(&engine.inner.metrics)
        .unwrap();
    engine.flush().unwrap();
    engine.garbage_collect().unwrap();
    assert_eq!(
        engine.wait_for_commit(&barrier).unwrap(),
        CommitOutcome::Barrier {
            through_sequence: 1
        }
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
    drop(engine);
    assert_eq!(
        PraxisEngine::open(config)
            .unwrap()
            .get("prior")
            .unwrap()
            .unwrap()
            .as_ref(),
        b"value"
    );
}

#[test]
fn v3_zero_index_owner_barrier_preserves_typed_bootstrap_and_shared_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::WalSyncPolicy::Never;
    let database =
        crate::CoreDatabase::create_fresh(config.clone(), crate::RecordAuthorityOptions::default())
            .unwrap();
    let identity = database.authority().database_id;
    let kv = database.kv();
    kv.put("user", "value").unwrap();
    let before = std::fs::read(kv.inner.wal.lock().path()).unwrap();
    assert_eq!(kv.durable_barrier().unwrap(), 2);
    assert_eq!(kv.snapshot().sequence, 2);
    assert_eq!(std::fs::read(kv.inner.wal.lock().path()).unwrap(), before);
    kv.flush().unwrap();
    kv.garbage_collect().unwrap();
    assert_eq!(kv.durable_barrier().unwrap(), 2);
    assert_eq!(
        kv.inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        2
    );
    drop(kv);
    drop(database);
    let database = crate::CoreDatabase::open(config).unwrap();
    assert_eq!(database.authority().database_id, identity);
    assert_eq!(
        database.kv().get("user").unwrap().unwrap().as_ref(),
        b"value"
    );
}
