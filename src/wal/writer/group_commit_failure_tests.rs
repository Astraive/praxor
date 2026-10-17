use super::*;
use crate::config::PraxisConfig;
use crate::engine::PraxisEngine;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[test]
fn failed_core_append_wakes_group_and_poison_blocks_maintenance() {
    failed_core_io(false);
}

#[test]
fn failed_core_sync_wakes_group_and_counts_attempt_without_publication() {
    failed_core_io(true);
}

fn failed_core_io(fail_sync: bool) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::GroupCommit;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("committed", "old").unwrap();
    let previous_sync_ns = engine.inner.metrics.commit_sync_ns.load(Ordering::Relaxed);
    let writer = engine.inner.write_serialization.lock();
    {
        let mut wal = engine.inner.wal.lock();
        // Real OS files exercise the production IO path without a fault hook.
        // A null device accepts seek/write but rejects the durability sync;
        // a read-only WAL rejects append before any sync attempt.
        wal.file = if fail_sync {
            #[cfg(windows)]
            let device = "NUL";
            #[cfg(not(windows))]
            let device = "/dev/null";
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(device)
                .unwrap()
        } else {
            File::open(wal.path()).unwrap()
        };
    }
    let (sent, received) = std::sync::mpsc::channel();
    let mut writers = Vec::new();
    for index in 0..8 {
        let engine = engine.clone();
        let sent = sent.clone();
        writers.push(std::thread::spawn(move || {
            sent.send(engine.put(format!("failed-{index}"), "new"))
                .unwrap();
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while engine
        .inner
        .metrics
        .write_admissions
        .load(Ordering::Relaxed)
        != 9
    {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    drop(writer);
    for _ in 0..8 {
        assert!(matches!(
            received.recv_timeout(Duration::from_secs(10)).unwrap(),
            Err(PraxisError::RecoveryRequired)
        ));
    }
    for writer in writers {
        writer.join().unwrap();
    }
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        if fail_sync { 2 } else { 1 }
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
    if fail_sync {
        assert!(engine.inner.metrics.commit_sync_ns.load(Ordering::Relaxed) > previous_sync_ns);
    } else {
        assert_eq!(
            engine.inner.metrics.commit_sync_ns.load(Ordering::Relaxed),
            previous_sync_ns
        );
    }
    assert_eq!(engine.snapshot().sequence, 1);
    assert_eq!(engine.get("committed").unwrap().unwrap().as_ref(), b"old");
    for index in 0..8 {
        assert!(engine.get(format!("failed-{index}")).unwrap().is_none());
    }
    assert!(matches!(
        engine.put("later", "x"),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(engine.flush(), Err(PraxisError::RecoveryRequired)));
    assert!(matches!(
        engine.compact(),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        engine.garbage_collect(),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        engine.checkpoint(),
        Err(PraxisError::RecoveryRequired)
    ));
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert!(engine.put("after-recovery", "works").is_ok());
}

#[test]
fn failed_ordered_barrier_sync_poison_wakes_later_requests_without_a_wal_frame() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::Never;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("prior", "value").unwrap();
    let path = engine.inner.wal.lock().path().to_path_buf();
    let before = std::fs::read(&path).unwrap();
    let writer = engine.inner.write_serialization.lock();
    #[cfg(windows)]
    let device = "NUL";
    #[cfg(not(windows))]
    let device = "/dev/null";
    engine.inner.wal.lock().file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .unwrap();
    let barrier_engine = engine.clone();
    let barrier = std::thread::spawn(move || barrier_engine.durable_barrier());
    let deadline = Instant::now() + Duration::from_secs(10);
    while engine
        .inner
        .metrics
        .write_admissions
        .load(Ordering::Relaxed)
        != 2
    {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let later: Vec<_> = (0..2)
        .map(|index| {
            let engine = engine.clone();
            std::thread::spawn(move || engine.put(format!("later-{index}"), "no"))
        })
        .collect();
    while engine
        .inner
        .metrics
        .write_admissions
        .load(Ordering::Relaxed)
        != 4
    {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    drop(writer);
    assert!(matches!(
        barrier.join().unwrap(),
        Err(PraxisError::RecoveryRequired)
    ));
    for worker in later {
        assert!(matches!(
            worker.join().unwrap(),
            Err(PraxisError::RecoveryRequired)
        ));
    }
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 0);
    assert!(engine.inner.metrics.commit_sync_ns.load(Ordering::Relaxed) > 0);
    assert_eq!(engine.snapshot().sequence, 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(matches!(
        engine.durable_barrier(),
        Err(PraxisError::RecoveryRequired)
    ));
    assert!(matches!(engine.flush(), Err(PraxisError::RecoveryRequired)));
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        1
    );
    drop(engine);
    assert!(
        PraxisEngine::open(config)
            .unwrap()
            .put("recovered", "yes")
            .is_ok()
    );
}

#[test]
fn never_rotation_must_sync_old_wal_before_a_later_barrier_can_acknowledge() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::Never;
    config.wal_segment_size = config.page_size;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine
        .put("oversized", vec![1; config.wal_segment_size])
        .unwrap();
    #[cfg(windows)]
    let device = "NUL";
    #[cfg(not(windows))]
    let device = "/dev/null";
    engine.inner.wal.lock().file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .unwrap();
    assert!(matches!(
        engine.put("force-rotation", "no"),
        Err(PraxisError::RecoveryRequired)
    ));
    assert_eq!(engine.inner.manifest.lock().active_wal_id, 1);
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
        0,
        "failed rotation sync is not a closed commit/barrier sync"
    );
    drop(engine);
    assert_eq!(PraxisEngine::open(config).unwrap().snapshot().sequence, 1);
}

#[test]
fn mixed_record_user_failures_complete_all_waiters_and_poison_the_one_owner() {
    use crate::core_records::intent::{IntentKind, NewRecord, RecordIntent, RecordResult};
    use crate::core_records::{CoreDatabase, RecordAuthorityOptions};
    for fail_sync in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PraxisConfig::new(dir.path());
        config.wal_sync_policy = WalSyncPolicy::GroupCommit;
        let db =
            CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
                .unwrap();
        let engine = db.kv();
        let before = std::fs::read(engine.inner.wal.lock().path()).unwrap();
        let writer = engine.inner.write_serialization.lock();
        {
            let mut wal = engine.inner.wal.lock();
            wal.file = if fail_sync {
                #[cfg(windows)]
                let device = "NUL";
                #[cfg(not(windows))]
                let device = "/dev/null";
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(device)
                    .unwrap()
            } else {
                File::open(wal.path()).unwrap()
            };
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        for index in 0..8 {
            let engine = engine.clone();
            let tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                let result = if index % 2 == 0 {
                    engine
                        .commit_record(
                            RecordIntent::new(IntentKind::Create(vec![NewRecord {
                                payload: vec![index as u8],
                                mappings: vec![],
                            }]))
                            .unwrap(),
                        )
                        .map(|_| ())
                } else {
                    engine.put(format!("user-{index}"), "new").map(|_| ())
                };
                tx.send(result).unwrap();
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            != 8
        {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        drop(writer);
        for _ in 0..8 {
            assert!(matches!(
                rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                Err(PraxisError::RecoveryRequired)
            ));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(engine.snapshot().sequence, 1);
        assert_eq!(
            engine
                .inner
                .metrics
                .commit_sync_attempts
                .load(Ordering::Relaxed),
            u64::from(fail_sync)
        );
        assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 0);
        if fail_sync {
            assert!(engine.inner.metrics.commit_sync_ns.load(Ordering::Relaxed) > 0);
        }
        assert_eq!(
            std::fs::read(engine.inner.wal.lock().path()).unwrap(),
            before
        );
        assert!(matches!(
            engine.durable_barrier(),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(engine.flush(), Err(PraxisError::RecoveryRequired)));
        assert!(matches!(
            engine.compact(),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            engine.checkpoint(),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            engine.garbage_collect(),
            Err(PraxisError::RecoveryRequired)
        ));
        drop(engine);
        drop(db);
        let db = CoreDatabase::open(config).unwrap();
        assert_eq!(
            db.kv()
                .commit_record(
                    RecordIntent::new(IntentKind::Create(vec![NewRecord {
                        payload: b"reopened".to_vec(),
                        mappings: vec![]
                    }]))
                    .unwrap()
                )
                .unwrap()
                .result,
            RecordResult::Created(vec![crate::store::RecordId(1)])
        );
    }
}
