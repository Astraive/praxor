use bytes::Bytes;

use crate::engine::core::engine::PraxisEngine;
use crate::errors::Result;
use crate::segments::bloom::bloom_key;
use crate::types::{ColumnFamily, ReadSnapshot, Value, ValueRef};
use std::sync::atomic::Ordering;

impl PraxisEngine {
    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Value>> {
        let snapshot = self.pin_snapshot();
        self.get_cf(&ColumnFamily::default(), key.as_ref(), snapshot.snapshot())
    }

    /// Keep a pinned snapshot alive when reading historical sequences.
    pub fn get_cf(
        &self,
        cf: &ColumnFamily,
        key: &[u8],
        snapshot: ReadSnapshot,
    ) -> Result<Option<Value>> {
        self.ensure_column_family(cf)?;
        self.inner.metrics.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(value) = self.resolve_value_at_snapshot(cf, key, snapshot.sequence)? {
            return Ok(Some(Bytes::from(value)));
        }
        let cache_key = (cf.0.clone(), snapshot.sequence, key.to_vec());
        if let Some(value) = self.inner.cache.lock().get(&cache_key) {
            self.inner
                .metrics
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Some(value));
        }
        self.inner
            .metrics
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);
        if !self.segment_filters_may_contain(cf, key) {
            self.inner
                .metrics
                .bloom_negative_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let resolved = self.resolve_value_at_snapshot(cf, key, snapshot.sequence)?;
        Ok(match resolved {
            Some(value) => {
                let value = Bytes::from(value);
                self.cache_insert_with_partition(cf, cache_key, value.clone());
                Some(value)
            }
            None => None,
        })
    }

    pub fn get_ref(&self, key: impl AsRef<[u8]>) -> Result<Option<ValueRef<'static>>> {
        Ok(self.get(key)?.map(ValueRef::Owned))
    }

    pub(crate) fn segment_filters_may_contain(&self, cf: &ColumnFamily, key: &[u8]) -> bool {
        let encoded = bloom_key(&cf.0, key);
        let prefix_len = self
            .cf_options_map()
            .get(&cf.0)
            .and_then(|options| options.prefix_extractor_len);
        self.inner.manifest.lock().segments.iter().any(|segment| {
            if !segment.min_key.is_empty()
                && (key < segment.min_key.as_slice() || key > segment.max_key.as_slice())
            {
                return false;
            }
            if let (Some(filter), Some(expected_prefix_len)) =
                (&segment.partitioned_bloom_filter, prefix_len)
                && filter.prefix_len == expected_prefix_len
            {
                return filter.may_contain(&encoded);
            }
            segment.bloom_filter.may_contain(&encoded)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PraxisConfig;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn point_read_keeps_its_snapshot_pinned_until_resolution_finishes() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "value").unwrap();
        let memtable = engine.inner.memtable.write();
        let reader = engine.clone();
        let handle = std::thread::spawn(move || reader.get("key"));
        let started = Instant::now();
        while engine.inner.snapshots.pinned_count() == 0
            && started.elapsed() < Duration::from_secs(1)
        {
            std::thread::yield_now();
        }
        let was_pinned = engine.inner.snapshots.pinned_count() > 0;
        drop(memtable);
        assert_eq!(
            handle.join().unwrap().unwrap(),
            Some(Bytes::from_static(b"value"))
        );
        assert!(
            was_pinned,
            "point reads must register their sequence before reading storage"
        );
        assert_eq!(engine.inner.snapshots.pinned_count(), 0);
    }
}
