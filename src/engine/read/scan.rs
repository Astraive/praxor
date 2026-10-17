use bytes::Bytes;
use std::collections::BTreeSet;

use crate::engine::core::engine::PraxisEngine;
use crate::errors::Result;
use crate::types::{ColumnFamily, Key, ReadSnapshot, Value};

impl PraxisEngine {
    pub fn scan(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Key, Value)>> {
        let snapshot = self.pin_snapshot();
        self.scan_cf_at_snapshot(
            &ColumnFamily::default(),
            start,
            end,
            limit,
            snapshot.snapshot(),
        )
    }

    pub fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Key, Value)>> {
        let snapshot = self.pin_snapshot();
        self.scan_prefix_cf_at_snapshot(
            &ColumnFamily::default(),
            prefix,
            limit,
            snapshot.snapshot(),
        )
    }

    /// Keep the corresponding pinned snapshot alive until this historical scan
    /// completes; a raw sequence cannot restore history already retired by compaction.
    pub fn scan_at_snapshot(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        snapshot: ReadSnapshot,
    ) -> Result<Vec<(Key, Value)>> {
        self.scan_cf_at_snapshot(&ColumnFamily::default(), start, end, limit, snapshot)
    }

    /// Keep the corresponding pinned snapshot alive for this historical scan.
    pub fn scan_prefix_at_snapshot(
        &self,
        prefix: &[u8],
        limit: usize,
        snapshot: ReadSnapshot,
    ) -> Result<Vec<(Key, Value)>> {
        self.scan_prefix_cf_at_snapshot(&ColumnFamily::default(), prefix, limit, snapshot)
    }

    pub fn scan_cf(
        &self,
        cf: &ColumnFamily,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Key, Value)>> {
        let snapshot = self.pin_snapshot();
        self.scan_cf_at_snapshot(cf, start, end, limit, snapshot.snapshot())
    }

    pub fn scan_prefix_cf(
        &self,
        cf: &ColumnFamily,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Key, Value)>> {
        let snapshot = self.pin_snapshot();
        self.scan_prefix_cf_at_snapshot(cf, prefix, limit, snapshot.snapshot())
    }

    /// Keep the corresponding pinned snapshot alive for this historical scan.
    pub fn scan_cf_at_snapshot(
        &self,
        cf: &ColumnFamily,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        snapshot: ReadSnapshot,
    ) -> Result<Vec<(Key, Value)>> {
        self.ensure_column_family(cf)?;
        if limit == 0 {
            return Ok(Vec::new());
        }

        // Enumerate keys, including tombstones, expired values, and merge operands.
        // Materializing rows per tier loses those markers and can resurrect older
        // values or miss merge chains spanning multiple tiers.
        let in_range = |key: &Key| {
            start.is_none_or(|start| key.as_ref() >= start)
                && end.is_none_or(|end| key.as_ref() < end)
        };
        let keys = {
            // Capture all tiers coherently while flush/compaction change their
            // topology. Release this guard before the point resolver takes its
            // own read guard; recursively acquiring it can deadlock with a writer.
            let _topology = self.inner.topology.read();
            let mut keys = BTreeSet::new();
            for (entry_cf, key) in self.inner.memtable.read().keys() {
                if entry_cf == cf && in_range(key) {
                    keys.insert(key.clone());
                }
            }
            for imm in self.inner.immutable_memtables.lock().iter() {
                for (entry_cf, key) in imm.keys() {
                    if entry_cf == cf && in_range(key) {
                        keys.insert(key.clone());
                    }
                }
            }
            for (entry_cf, key) in self.inner.segment_index.read().keys() {
                if entry_cf == cf && in_range(key) {
                    keys.insert(key.clone());
                }
            }
            keys
        };

        let mut rows = Vec::new();
        for key in keys {
            // Share point lookup's full version-chain resolution and snapshot
            // semantics rather than resolving each storage tier independently.
            if let Some(value) = self.resolve_value_at_snapshot(cf, &key, snapshot.sequence)? {
                rows.push((key, Bytes::from(value)));
                if rows.len() == limit {
                    break;
                }
            }
        }
        Ok(rows)
    }

    /// Keep the corresponding pinned snapshot alive for this historical scan.
    pub fn scan_prefix_cf_at_snapshot(
        &self,
        cf: &ColumnFamily,
        prefix: &[u8],
        limit: usize,
        snapshot: ReadSnapshot,
    ) -> Result<Vec<(Key, Value)>> {
        let end = prefix_upper_bound(prefix);
        self.scan_cf_at_snapshot(cf, Some(prefix), end.as_deref(), limit, snapshot)
    }

    pub fn snapshot(&self) -> ReadSnapshot {
        self.inner.snapshots.snapshot()
    }

    pub fn pin_snapshot(&self) -> crate::memory::PinnedSnapshot {
        self.try_pin_snapshot()
            .expect("snapshot pin identifiers exhausted")
    }

    /// Register the current published view, failing without reusing a live pin ID.
    pub fn try_pin_snapshot(&self) -> Result<crate::memory::PinnedSnapshot> {
        self.inner.snapshots.try_pin()
    }
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return None;
    }
    let mut upper = prefix.to_vec();
    for i in (0..upper.len()).rev() {
        if upper[i] != u8::MAX {
            upper[i] = upper[i].saturating_add(1);
            upper.truncate(i + 1);
            return Some(upper);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PraxisConfig;
    use tempfile::tempdir;

    fn freeze_memtable(engine: &PraxisEngine) {
        let frozen = std::mem::take(&mut *engine.inner.memtable.write());
        engine.inner.immutable_memtables.lock().push(frozen);
    }

    #[test]
    fn convenience_scans_pin_their_snapshot_until_resolution_finishes() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        for method in 0..4 {
            let dir = tempdir().unwrap();
            let engine = Arc::new(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
            engine.put("key", "value").unwrap();

            // Block the real scan before enumeration so its snapshot must remain
            // registered while waiting, rather than relying on timing a full scan.
            let table = engine.inner.memtable.write();
            let reader_engine = Arc::clone(&engine);
            let reader = std::thread::spawn(move || match method {
                0 => reader_engine.scan(None, None, 10),
                1 => reader_engine.scan_prefix(b"key", 10),
                2 => reader_engine.scan_cf(&ColumnFamily::default(), None, None, 10),
                _ => reader_engine.scan_prefix_cf(&ColumnFamily::default(), b"key", 10),
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while engine.inner.snapshots.pinned_count() == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            let protected = engine.inner.snapshots.pinned_count() == 1;
            drop(table);
            let rows = reader.join().unwrap().unwrap();

            assert!(
                protected,
                "scan method {method} did not protect its snapshot"
            );
            assert_eq!(rows, vec![(Bytes::from("key"), Bytes::from("value"))]);
            assert_eq!(engine.inner.snapshots.pinned_count(), 0);
        }
    }

    #[test]
    fn immutable_tombstone_hides_older_immutable_and_segment_values() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("gone", "segment").unwrap();
        engine.flush().unwrap();
        engine.put("gone", "immutable").unwrap();
        freeze_memtable(&engine);
        engine.delete("gone").unwrap();
        freeze_memtable(&engine);

        assert_eq!(engine.get("gone").unwrap(), None);
        assert_eq!(engine.scan(None, None, 10).unwrap(), vec![]);
    }

    #[test]
    fn immutable_merge_chains_resolve_at_the_requested_snapshot() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("merged", "base").unwrap();
        engine.flush().unwrap();
        engine
            .merge(ColumnFamily::default(), "merged", "+one")
            .unwrap();
        freeze_memtable(&engine);
        let snapshot = engine.pin_snapshot();
        engine
            .merge(ColumnFamily::default(), "merged", "+two")
            .unwrap();
        freeze_memtable(&engine);
        engine
            .merge(ColumnFamily::default(), "merged", "+active")
            .unwrap();

        assert_eq!(
            engine.get("merged").unwrap(),
            Some(Bytes::from("base+one+two+active"))
        );
        assert_eq!(
            engine.scan(None, None, 10).unwrap(),
            vec![(Bytes::from("merged"), Bytes::from("base+one+two+active"))]
        );
        assert_eq!(
            engine
                .scan_at_snapshot(None, None, 10, snapshot.snapshot())
                .unwrap(),
            vec![(Bytes::from("merged"), Bytes::from("base+one"))]
        );
    }
}
