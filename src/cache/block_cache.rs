use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug)]
pub struct BlockCache<K> {
    capacity_bytes: usize,
    current_bytes: usize,
    // Empty payloads still consume one unit so entry metadata has a bound.
    admission_bytes: usize,
    clock: u64,
    order: VecDeque<(K, u64)>,
    entries: HashMap<K, CacheEntry>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    value: Bytes,
    generation: u64,
}

impl<K> BlockCache<K>
where
    K: Clone + Eq + Hash,
{
    /// Limit admission by payload size, charging one byte for an empty value.
    /// A zero budget disables admission, including empty values.
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            current_bytes: 0,
            admission_bytes: 0,
            clock: 0,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &K) -> Option<Bytes> {
        self.prepare_clock();
        let entry = self.entries.get_mut(key)?;
        self.clock += 1;
        entry.generation = self.clock;
        let value = entry.value.clone();
        self.order.push_back((key.clone(), self.clock));
        self.compact_order_if_needed();
        Some(value)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Report payload bytes, excluding the minimum empty-entry admission charge.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub fn value_len(&self, key: &K) -> Option<usize> {
        self.entries.get(key).map(|entry| entry.value.len())
    }

    pub fn insert(&mut self, key: K, value: Bytes) {
        let _ = self.insert_with_evicted(key, value);
    }

    pub fn insert_with_evicted(&mut self, key: K, value: Bytes) -> Vec<(K, Bytes)> {
        let mut evicted = Vec::new();
        self.prepare_clock();
        self.clock += 1;
        if let Some(old) = self.entries.insert(
            key.clone(),
            CacheEntry {
                value: value.clone(),
                generation: self.clock,
            },
        ) {
            self.current_bytes = self.current_bytes.saturating_sub(old.value.len());
            self.admission_bytes = self.admission_bytes.saturating_sub(old.value.len().max(1));
        }
        self.current_bytes += value.len();
        self.admission_bytes += value.len().max(1);
        self.order.push_back((key, self.clock));
        self.evict(&mut evicted);
        self.compact_order_if_needed();
        evicted
    }

    /// Remove all entries where the predicate returns false.
    pub fn retain<F: Fn(&K) -> bool>(&mut self, predicate: F) {
        self.entries.retain(|key, entry| {
            if predicate(key) {
                return true;
            }
            self.current_bytes = self.current_bytes.saturating_sub(entry.value.len());
            self.admission_bytes = self
                .admission_bytes
                .saturating_sub(entry.value.len().max(1));
            false
        });
        self.compact_order();
    }

    fn compact_order_if_needed(&mut self) {
        let limit = self.entries.len().saturating_mul(4).max(64);
        if self.entries.is_empty()
            || self.order.len() > limit
            || self.order.capacity() > limit.saturating_mul(2)
        {
            self.compact_order();
        }
    }

    fn compact_order(&mut self) {
        let mut current = VecDeque::with_capacity(self.entries.len());
        for (key, generation) in self.order.drain(..) {
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                current.push_back((key, generation));
            }
        }
        self.order = current;
    }

    fn prepare_clock(&mut self) {
        if self.clock != u64::MAX {
            return;
        }
        // Remove stale events before reusing generation numbers, preserving
        // the live events' oldest-to-newest order during the rebase.
        self.compact_order();
        self.clock = 0;
        for (key, generation) in &mut self.order {
            self.clock += 1;
            *generation = self.clock;
            self.entries
                .get_mut(key)
                .expect("current recency entry")
                .generation = self.clock;
        }
    }

    fn evict(&mut self, evicted: &mut Vec<(K, Bytes)>) {
        while self.admission_bytes > self.capacity_bytes {
            let Some((key, generation)) = self.order.pop_front() else {
                break;
            };
            let is_current = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.generation == generation);
            if !is_current {
                continue;
            }
            if let Some(entry) = self.entries.remove(&key) {
                self.current_bytes = self.current_bytes.saturating_sub(entry.value.len());
                self.admission_bytes = self
                    .admission_bytes
                    .saturating_sub(entry.value.len().max(1));
                evicted.push((key, entry.value));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BlockCache;
    use bytes::Bytes;
    use std::sync::Arc;

    #[test]
    fn cache_does_not_evict_fresh_generation_from_stale_queue_entry() {
        let mut cache = BlockCache::new(10);
        cache.insert("a", Bytes::from_static(b"aaaa"));
        cache.insert("b", Bytes::from_static(b"bbbb"));
        assert_eq!(cache.get(&"a"), Some(Bytes::from_static(b"aaaa")));
        cache.insert("c", Bytes::from_static(b"cccc"));

        assert!(cache.contains_key(&"a"));
        assert!(!cache.contains_key(&"b"));
        assert!(cache.contains_key(&"c"));
        assert!(cache.current_bytes() <= 10);
    }

    #[test]
    fn hot_reads_keep_key_ownership_bounded_and_preserve_lru() {
        let hot: Arc<str> = Arc::from("hot");
        let cold: Arc<str> = Arc::from("cold");
        let mut cache = BlockCache::new(2);
        cache.insert(hot.clone(), Bytes::from_static(b"h"));
        cache.insert(cold.clone(), Bytes::from_static(b"c"));
        for operations in [1_000, 10_000, 100_000] {
            for _ in 0..operations {
                assert_eq!(cache.get(&hot), Some(Bytes::from_static(b"h")));
            }
            assert!(
                Arc::strong_count(&hot) <= 130,
                "hot reads retained obsolete key clones"
            );
            assert!(
                cache.order.capacity() <= 256,
                "recency allocation grew with hit count"
            );
        }
        let evicted = cache.insert_with_evicted(Arc::from("new"), Bytes::from_static(b"n"));
        assert_eq!(evicted, vec![(cold, Bytes::from_static(b"c"))]);
        assert!(cache.contains_key(&hot));
    }

    #[test]
    fn hot_overwrites_bound_recency_storage_and_keep_latest_value() {
        let hot: Arc<str> = Arc::from("hot");
        let cold: Arc<str> = Arc::from("cold");
        let mut cache = BlockCache::new(3);
        cache.insert(hot.clone(), Bytes::from_static(b"h"));
        cache.insert(cold.clone(), Bytes::from_static(b"c"));
        for _ in 0..100_000 {
            assert!(
                cache
                    .insert_with_evicted(hot.clone(), Bytes::from_static(b"x"))
                    .is_empty()
            );
            assert!(
                cache
                    .insert_with_evicted(hot.clone(), Bytes::from_static(b"yy"))
                    .is_empty()
            );
        }
        assert!(
            Arc::strong_count(&hot) <= 130,
            "overwrites retained obsolete key clones"
        );
        assert!(cache.order.capacity() <= 256);
        assert_eq!(cache.current_bytes(), 3);
        let evicted = cache.insert_with_evicted(Arc::from("new"), Bytes::from_static(b"n"));
        assert_eq!(evicted, vec![(cold, Bytes::from_static(b"c"))]);
        assert_eq!(cache.get(&hot), Some(Bytes::from_static(b"yy")));
    }

    #[test]
    fn retain_reclaims_recency_allocation_and_preserves_survivor_order() {
        let mut cache = BlockCache::new(128);
        for key in 0..128 {
            cache.insert(key, Bytes::from_static(b"v"));
        }
        for _ in 0..10_000 {
            cache.get(&127);
        }
        cache.retain(|key| *key == 0 || *key == 127);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_bytes(), 2);
        assert!(
            cache.order.capacity() <= 4,
            "retain kept allocation for removed entries"
        );
        let evicted = cache.insert_with_evicted(128, Bytes::from(vec![9; 127]));
        assert_eq!(evicted, vec![(0, Bytes::from_static(b"v"))]);
        assert!(cache.contains_key(&127));
        cache.retain(|_| false);
        assert!(cache.is_empty());
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.order.capacity(), 0);
    }

    #[test]
    fn empty_values_consume_admission_budget_and_remain_cacheable() {
        let mut cache = BlockCache::new(2);
        cache.insert("a", Bytes::new());
        cache.insert("b", Bytes::new());
        assert_eq!(cache.get(&"a"), Some(Bytes::new()));
        let evicted = cache.insert_with_evicted("c", Bytes::new());
        assert_eq!(evicted, vec![("b", Bytes::new())]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.get(&"c"), Some(Bytes::new()));
        let evicted = cache.insert_with_evicted("a", Bytes::from_static(b"xx"));
        assert_eq!(evicted, vec![("c", Bytes::new())]);
        assert_eq!(cache.current_bytes(), 2);
        assert_eq!(cache.get(&"a"), Some(Bytes::from_static(b"xx")));
    }

    #[test]
    fn zero_capacity_does_not_admit_empty_entries() {
        let mut cache = BlockCache::new(0);
        for key in 0..1_000 {
            assert_eq!(
                cache.insert_with_evicted(key, Bytes::new()),
                vec![(key, Bytes::new())]
            );
        }
        assert!(cache.is_empty());
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.order.capacity(), 0);
    }

    #[test]
    fn generation_overflow_rebases_without_changing_lru() {
        let mut cache = BlockCache::new(3);
        for key in ["a", "b", "c"] {
            cache.insert(key, Bytes::from_static(b"v"));
        }
        cache.clock = u64::MAX - 1;
        assert_eq!(cache.get(&"a"), Some(Bytes::from_static(b"v")));
        assert_eq!(cache.get(&"b"), Some(Bytes::from_static(b"v")));
        assert_eq!(
            cache.insert_with_evicted("d", Bytes::from_static(b"d")),
            vec![("c", Bytes::from_static(b"v"))]
        );
        cache.clock = u64::MAX;
        assert_eq!(cache.get(&"missing"), None);
        cache.insert("a", Bytes::from_static(b"a"));
        assert_eq!(
            cache.insert_with_evicted("e", Bytes::from_static(b"e")),
            vec![("b", Bytes::from_static(b"v"))]
        );
        assert_eq!(cache.get(&"a"), Some(Bytes::from_static(b"a")));
    }

    #[test]
    #[ignore = "manual cache metadata and workload timing measurement"]
    fn cache_metadata_workload_profile() {
        use std::hint::black_box;
        use std::time::Instant;

        for workload in ["hit", "overwrite", "mixed_eviction"] {
            for operations in [100_000, 1_000_000] {
                let mut cache = BlockCache::new(1024);
                for key in 0..256 {
                    cache.insert(key, Bytes::from_static(b"data"));
                }
                let started = Instant::now();
                let mut peak_queue_capacity = cache.order.capacity();
                for operation in 0..operations {
                    match workload {
                        "hit" => {
                            black_box(cache.get(&(operation % 256)));
                        }
                        "overwrite" => cache.insert(operation % 256, Bytes::from_static(b"data")),
                        _ if operation % 2 == 0 => {
                            black_box(cache.get(&(operation % 512)));
                        }
                        _ => cache.insert(operation % 512, Bytes::from_static(b"data")),
                    }
                    peak_queue_capacity = peak_queue_capacity.max(cache.order.capacity());
                }
                let elapsed_us = started.elapsed().as_micros() as u64;
                crate::slog::info(
                    "cache_metadata_profile",
                    crate::slog::context()
                        .with_str("workload", workload)
                        .with_u64("operations", operations as u64)
                        .with_u64("elapsed_us", elapsed_us)
                        .with_u64("live_entries", cache.len() as u64)
                        .with_u64("queue_len", cache.order.len() as u64)
                        .with_u64("retained_queue_capacity", peak_queue_capacity as u64)
                        .with_u64(
                            "retained_queue_bytes",
                            (peak_queue_capacity * std::mem::size_of::<(usize, u64)>()) as u64,
                        ),
                );
            }
        }
    }
}
