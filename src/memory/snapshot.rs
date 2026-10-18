use crate::errors::{PraxisError, Result};
use crate::types::{ReadSnapshot, SequenceNumber};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct SnapshotManager {
    reserved_sequence: AtomicU64,
    latest_sequence: AtomicU64,
    next_pin_id: AtomicU64,
    pinned: Mutex<BTreeMap<u64, SequenceNumber>>,
}

#[derive(Debug)]
pub struct PinnedSnapshot {
    id: u64,
    snapshot: ReadSnapshot,
    manager: Arc<SnapshotManager>,
}

impl SnapshotManager {
    pub fn next_sequence(&self) -> SequenceNumber {
        self.reserved_sequence.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn observe(&self, sequence: SequenceNumber) {
        self.reserved_sequence.fetch_max(sequence, Ordering::SeqCst);
        let mut current = self.latest_sequence.load(Ordering::SeqCst);
        while sequence > current {
            match self.latest_sequence.compare_exchange(
                current,
                sequence,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    pub fn snapshot(&self) -> ReadSnapshot {
        ReadSnapshot {
            sequence: self.latest_sequence.load(Ordering::SeqCst),
        }
    }

    pub fn pin(self: &Arc<Self>) -> PinnedSnapshot {
        self.try_pin().expect("snapshot pin identifiers exhausted")
    }

    /// Register the current published view without wrapping or reusing a pin ID.
    pub fn try_pin(self: &Arc<Self>) -> Result<PinnedSnapshot> {
        let mut pinned = self.pinned.lock();
        let id = self
            .next_pin_id
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(PraxisError::SnapshotPinExhausted)?;
        let snapshot = self.snapshot();
        self.next_pin_id.store(id, Ordering::SeqCst);
        pinned.insert(id, snapshot.sequence);
        Ok(PinnedSnapshot {
            id,
            snapshot,
            manager: self.clone(),
        })
    }

    pub fn oldest_pinned_sequence(&self) -> Option<SequenceNumber> {
        self.pinned.lock().values().copied().min()
    }

    pub fn pinned_sequences(&self) -> Vec<SequenceNumber> {
        self.pinned.lock().values().copied().collect()
    }

    pub fn pinned_count(&self) -> usize {
        self.pinned.lock().len()
    }

    fn unpin(&self, id: u64) {
        self.pinned.lock().remove(&id);
    }
}

impl PinnedSnapshot {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn snapshot(&self) -> ReadSnapshot {
        self.snapshot
    }

    pub fn sequence(&self) -> SequenceNumber {
        self.snapshot.sequence
    }
}

impl Drop for PinnedSnapshot {
    fn drop(&mut self) {
        self.manager.unpin(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn pin_exhaustion_does_not_wrap_or_replace_live_registry() {
        let manager = Arc::new(SnapshotManager::default());
        manager.observe(7);
        let held = manager.pin();
        manager.next_pin_id.store(u64::MAX, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| manager.pin()));
        assert!(result.is_err(), "legacy wrapper must fail on exhaustion");
        assert_eq!(manager.next_pin_id.load(Ordering::SeqCst), u64::MAX);
        assert_eq!(manager.pinned_count(), 1);
        assert_eq!(manager.pinned.lock().get(&held.id()), Some(&7));
    }

    #[test]
    fn concurrent_last_id_has_one_winner_and_never_reuses_a_live_pin() {
        let manager = Arc::new(SnapshotManager::default());
        let held = manager.pin();
        manager.next_pin_id.store(u64::MAX - 1, Ordering::SeqCst);
        let start = Arc::new(std::sync::Barrier::new(5));
        let joins = (0..4)
            .map(|_| {
                let manager = manager.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    manager.try_pin()
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let results = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .all(|pin| pin.id() == u64::MAX)
        );
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| matches!(error, crate::PraxisError::SnapshotPinExhausted))
        );
        assert_eq!(manager.next_pin_id.load(Ordering::SeqCst), u64::MAX);
        assert_eq!(manager.pinned_count(), 2);
        drop(results);
        assert_eq!(manager.pinned_count(), 1);
        drop(held);
        assert_eq!(manager.pinned_count(), 0);
    }

    #[test]
    fn all_allocating_engine_routes_share_the_checked_exhaustion_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::CoreDatabase::create_fresh(
            crate::PraxisConfig::new(dir.path()),
            crate::RecordAuthorityOptions::default(),
        )
        .unwrap();
        let engine = db.kv();
        let records = db.records();
        let rid = records.put(b"v", &[]).unwrap();
        let manager = &engine.inner.snapshots;
        let held = engine.pin_snapshot();
        let sequence = held.sequence();
        manager.next_pin_id.store(u64::MAX - 1, Ordering::SeqCst);
        let last = engine.try_pin_snapshot().unwrap();
        assert_eq!(last.id(), u64::MAX);
        macro_rules! exhausted {
            ($call:expr) => {
                assert!(matches!(
                    $call,
                    Err(crate::PraxisError::SnapshotPinExhausted)
                ));
            };
        }
        exhausted!(manager.try_pin());
        exhausted!(engine.try_pin_snapshot());
        exhausted!(records.pin_snapshot());
        exhausted!(records.fetch(rid));
        exhausted!(records.lookup_rid("unknown", b"k"));
        exhausted!(records.lookup_rid_at("unknown", b"k", u64::MAX));
        exhausted!(records.fetch_by_index("unknown", b"k"));
        exhausted!(records.put_batch(&[]));
        exhausted!(records.live_count());
        exhausted!(records.live_bytes());
        exhausted!(records.dead_records());
        exhausted!(records.compatibility_sequence());
        macro_rules! legacy {
            ($call:expr) => {
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        let _ = $call;
                    }))
                    .is_err()
                );
                assert_eq!(manager.next_pin_id.load(Ordering::SeqCst), u64::MAX);
                assert_eq!(manager.pinned_count(), 2);
            };
        }
        legacy!(manager.pin());
        legacy!(engine.pin_snapshot());
        legacy!(engine.begin_transaction());
        legacy!(engine.get("k"));
        legacy!(engine.scan(None, None, 10));
        legacy!(engine.scan_prefix(b"k", 10));
        legacy!(engine.scan_cf(&crate::ColumnFamily::default(), None, None, 10));
        legacy!(engine.scan_prefix_cf(&crate::ColumnFamily::default(), b"k", 10));
        assert_eq!(engine.snapshot().sequence, sequence);
        assert_eq!(manager.pinned.lock().get(&held.id()), Some(&sequence));
        drop(last);
        drop(held);
        assert_eq!(manager.pinned_count(), 0);
    }
}
