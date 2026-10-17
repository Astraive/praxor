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
