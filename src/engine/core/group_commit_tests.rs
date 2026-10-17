use super::engine::PraxisEngine;
use crate::config::{PraxisConfig, WalSyncPolicy};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline, "commit progress timed out");
        std::thread::yield_now();
    }
}

fn engine() -> (tempfile::TempDir, PraxisConfig, PraxisEngine) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::GroupCommit;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    (dir, config, engine)
}

#[test]
fn queued_concurrent_batches_share_one_commit_sync_and_recover() {
    let (_dir, config, engine) = engine();
    let writer = engine.inner.write_serialization.lock();
    let mut writers = Vec::new();
    for index in 0..8 {
        let writer_engine = engine.clone();
        writers.push(std::thread::spawn(move || {
            writer_engine
                .put(format!("key-{index}"), format!("value-{index}"))
                .unwrap()
        }));
        wait_until(|| {
            engine
                .inner
                .metrics
                .write_admissions
                .load(Ordering::Relaxed)
                == index + 1
        });
    }
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 8
    });
    assert_eq!(engine.snapshot().sequence, 0);
    drop(writer);
    let mut sequences: Vec<_> = writers
        .into_iter()
        .enumerate()
        .map(|(index, writer)| {
            let sequence = writer.join().unwrap();
            assert_eq!(sequence, index as u64 + 1, "FIFO publication sequence");
            sequence
        })
        .collect();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
    assert_eq!(
        engine.inner.metrics.commit_syncs.load(Ordering::Relaxed),
        1,
        "all requests admitted behind the writer lock must share the closed group sync"
    );
    assert_eq!(
        engine.inner.metrics.commit_batches.load(Ordering::Relaxed),
        8
    );
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    for index in 0..8 {
        assert_eq!(
            engine
                .get(format!("key-{index}"))
                .unwrap()
                .unwrap()
                .as_ref(),
            format!("value-{index}").as_bytes()
        );
    }
    assert_eq!(engine.snapshot().sequence, 8);
}

#[test]
fn synced_group_is_not_visible_or_complete_until_memtable_publication() {
    let (_dir, _config, engine) = engine();
    let memtable = engine.inner.memtable.write();
    let (sent, received) = std::sync::mpsc::channel();
    let writer = {
        let engine = engine.clone();
        std::thread::spawn(move || {
            sent.send(engine.put("pending", "value")).unwrap();
        })
    };
    wait_until(|| engine.inner.metrics.commit_syncs.load(Ordering::Acquire) == 1);
    assert_eq!(engine.snapshot().sequence, 0);
    assert!(received.try_recv().is_err());
    drop(memtable);
    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap(),
        1
    );
    writer.join().unwrap();
    assert_eq!(engine.get("pending").unwrap().unwrap().as_ref(), b"value");
}

#[test]
fn conditional_requests_validate_in_fifo_order_and_fail_individually() {
    let (_dir, _config, engine) = engine();
    let writer = engine.inner.write_serialization.lock();
    let first = {
        let engine = engine.clone();
        std::thread::spawn(move || engine.put("key", "first"))
    };
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 1
    });
    let cas = {
        let engine = engine.clone();
        std::thread::spawn(move || engine.compare_and_swap("key", Some(b"first"), "cas"))
    };
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 2
    });
    let bad_cas = {
        let engine = engine.clone();
        std::thread::spawn(move || engine.compare_and_swap("key", Some(b"first"), "bad"))
    };
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 3
    });
    let last = {
        let engine = engine.clone();
        std::thread::spawn(move || engine.put("key", "last"))
    };
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 4
    });
    drop(writer);
    assert_eq!(first.join().unwrap().unwrap(), 1);
    assert_eq!(cas.join().unwrap().unwrap(), 2);
    assert!(matches!(
        bad_cas.join().unwrap(),
        Err(crate::errors::PraxisError::CompareAndSwapFailed)
    ));
    assert_eq!(last.join().unwrap().unwrap(), 3);
    assert_eq!(engine.get("key").unwrap().unwrap().as_ref(), b"last");
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 3);
}

#[test]
fn optimistic_conflicts_and_pins_survive_queued_commit() {
    let (_dir, _config, engine) = engine();
    let mut first = engine.begin_transaction();
    let mut second = engine.begin_transaction();
    first.put("key", "first");
    second.put("key", "second");
    let writer = engine.inner.write_serialization.lock();
    let first = std::thread::spawn(move || first.commit());
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 1
    });
    let second = std::thread::spawn(move || second.commit());
    wait_until(|| {
        engine
            .inner
            .metrics
            .write_admissions
            .load(Ordering::Relaxed)
            == 2
    });
    assert_eq!(engine.inner.snapshots.pinned_count(), 2);
    drop(writer);
    assert_eq!(first.join().unwrap().unwrap(), 1);
    assert!(matches!(
        second.join().unwrap(),
        Err(crate::errors::PraxisError::TransactionConflict { .. })
    ));
    assert_eq!(engine.inner.snapshots.pinned_count(), 0);
}

#[test]
fn sync_policies_and_rotation_flush_gc_keep_acknowledged_prefix() {
    for policy in [
        WalSyncPolicy::EveryBatch,
        WalSyncPolicy::GroupCommit,
        WalSyncPolicy::Never,
    ] {
        let _dir = tempfile::tempdir().unwrap();
        let mut config = PraxisConfig::new(_dir.path());
        config.wal_sync_policy = policy;
        config.wal_segment_size = config.page_size;
        let engine = PraxisEngine::open(config.clone()).unwrap();
        for index in 0..20 {
            engine
                .put(format!("key-{index}"), vec![index as u8; 1024])
                .unwrap();
        }
        assert_eq!(
            engine.inner.metrics.commit_syncs.load(Ordering::Relaxed),
            if matches!(policy, WalSyncPolicy::Never) {
                0
            } else {
                20
            }
        );
        engine.flush().unwrap();
        engine.garbage_collect().unwrap();
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
}

#[test]
fn sequence_exhaustion_rejects_before_wal_and_does_not_poison() {
    let (_dir, _config, engine) = engine();
    engine.inner.snapshots.observe(u64::MAX - 1);
    assert_eq!(engine.put("last", "value").unwrap(), u64::MAX);
    assert!(matches!(
        engine.put("overflow", "x"),
        Err(crate::errors::PraxisError::WriteStalled { .. })
    ));
    assert!(engine.inner.group_commit.ensure_writable().is_ok());
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 1);
    assert_eq!(engine.get("last").unwrap().unwrap().as_ref(), b"value");
}

#[test]
fn oversized_core_request_commits_as_singleton_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::GroupCommit;
    config.wal_segment_size = config.page_size;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = [("oversized", config.wal_segment_size * 2), ("small", 1)]
        .into_iter()
        .map(|(key, size)| {
            let engine = engine.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                engine.put(key, vec![42; size]).unwrap();
            })
        })
        .collect();
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        engine.inner.metrics.commit_groups.load(Ordering::Relaxed),
        2
    );
    assert_eq!(engine.inner.metrics.commit_syncs.load(Ordering::Relaxed), 2);
    assert!(engine.inner.manifest.lock().active_wal_id > 1);
    drop(engine);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.snapshot().sequence, 2);
    assert_eq!(
        engine.get("oversized").unwrap().unwrap().as_ref(),
        vec![42; config.wal_segment_size * 2]
    );
    assert_eq!(engine.get("small").unwrap().unwrap().as_ref(), &[42]);
}
