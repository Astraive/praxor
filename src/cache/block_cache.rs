use bytes::Bytes;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug)]
pub struct BlockCache<K> {
    capacity_bytes: usize,
    current_bytes: usize,
    // Empty payloads still consume one unit so entry metadata has a bound.
    admission_bytes: usize,
    entries: HashMap<K, usize>,
    // Tombstones can lower HashMap::capacity() without freeing its buckets.
    lookup_capacity: usize,
    slots: Vec<Slot<K>>,
    least_recent: Option<usize>,
    most_recent: Option<usize>,
    // Vacancies share the arena allocation and are reused before it grows.
    free: Option<usize>,
}

#[derive(Debug)]
enum Slot<K> {
    Occupied(CacheEntry<K>),
    Vacant { next: Option<usize> },
}

#[derive(Debug)]
struct CacheEntry<K> {
    key: K,
    value: Bytes,
    previous: Option<usize>,
    next: Option<usize>,
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
            entries: HashMap::new(),
            lookup_capacity: 0,
            slots: Vec::new(),
            least_recent: None,
            most_recent: None,
            free: None,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<Bytes> {
        let index = *self.entries.get(key)?;
        let value = self.entry(index).value.clone();
        self.touch(index);
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
        self.entries
            .get(key)
            .map(|&index| self.entry(index).value.len())
    }

    pub fn insert(&mut self, key: K, value: Bytes) {
        let _ = self.insert_with_evicted(key, value);
    }

    pub fn insert_with_evicted(&mut self, key: K, value: Bytes) -> Vec<(K, Bytes)> {
        let mut evicted = Vec::new();
        let value_len = value.len();
        if let Some(&index) = self.entries.get(&key) {
            let old_len = self.entry(index).value.len();
            self.current_bytes -= old_len;
            self.admission_bytes -= old_len.max(1);
            self.entry_mut(index).value = value;
            self.touch(index);
        } else {
            // Clone/hash user keys before changing the arena's free links.
            let index = self.free.unwrap_or(self.slots.len());
            self.entries.insert(key.clone(), index);
            self.lookup_capacity = self.lookup_capacity.max(self.entries.capacity());
            let index = self.allocate_slot();
            self.slots[index] = Slot::Occupied(CacheEntry {
                key,
                value,
                previous: None,
                next: None,
            });
            self.append(index);
        }
        self.current_bytes += value_len;
        self.admission_bytes += value_len.max(1);
        while self.admission_bytes > self.capacity_bytes {
            let index = self.least_recent.expect("over-budget cache has entries");
            let entry = self.remove(index);
            evicted.push((entry.key, entry.value));
        }
        self.reclaim_storage();
        evicted
    }

    /// Remove all entries where the predicate returns false.
    pub fn retain<F: Fn(&K) -> bool>(&mut self, predicate: F) {
        let mut current = self.least_recent;
        while let Some(index) = current {
            let entry = self.entry(index);
            current = entry.next;
            if !predicate(&entry.key) {
                self.remove(index);
            }
        }
        self.reclaim_storage();
    }

    fn entry(&self, index: usize) -> &CacheEntry<K> {
        match &self.slots[index] {
            Slot::Occupied(entry) => entry,
            Slot::Vacant { .. } => unreachable!("recency links point to occupied slots"),
        }
    }

    fn entry_mut(&mut self, index: usize) -> &mut CacheEntry<K> {
        match &mut self.slots[index] {
            Slot::Occupied(entry) => entry,
            Slot::Vacant { .. } => unreachable!("recency links point to occupied slots"),
        }
    }

    fn allocate_slot(&mut self) -> usize {
        if let Some(index) = self.free {
            let Slot::Vacant { next } = self.slots[index] else {
                unreachable!("free links point to vacant slots");
            };
            self.free = next;
            index
        } else {
            let index = self.slots.len();
            self.slots.push(Slot::Vacant { next: None });
            index
        }
    }

    fn unlink(&mut self, index: usize) {
        let entry = self.entry(index);
        let (previous, next) = (entry.previous, entry.next);
        if let Some(previous) = previous {
            self.entry_mut(previous).next = next;
        } else {
            self.least_recent = next;
        }
        if let Some(next) = next {
            self.entry_mut(next).previous = previous;
        } else {
            self.most_recent = previous;
        }
    }

    fn append(&mut self, index: usize) {
        let previous = self.most_recent;
        let entry = self.entry_mut(index);
        entry.previous = previous;
        entry.next = None;
        if let Some(previous) = previous {
            self.entry_mut(previous).next = Some(index);
        } else {
            self.least_recent = Some(index);
        }
        self.most_recent = Some(index);
    }

    fn touch(&mut self, index: usize) {
        if self.most_recent != Some(index) {
            self.unlink(index);
            self.append(index);
        }
    }

    fn remove(&mut self, index: usize) -> CacheEntry<K> {
        let Slot::Occupied(entry) = &self.slots[index] else {
            unreachable!("only occupied slots can be removed");
        };
        self.entries.remove(&entry.key);
        self.unlink(index);
        let Slot::Occupied(entry) =
            std::mem::replace(&mut self.slots[index], Slot::Vacant { next: self.free })
        else {
            unreachable!("only occupied slots can be removed");
        };
        self.free = Some(index);
        self.current_bytes -= entry.value.len();
        self.admission_bytes -= entry.value.len().max(1);
        entry
    }

    fn reclaim_storage(&mut self) {
        let live = self.entries.len();
        if live == 0 {
            self.slots = Vec::new();
            self.entries = HashMap::new();
            self.lookup_capacity = 0;
            self.free = None;
            return;
        }
        // Churn reuses vacancies. Only a substantial live-set contraction
        // rebuilds storage, keeping both retained capacity and rebuild work bounded.
        let limit = live.saturating_mul(4).max(64);
        if self.slots.capacity() > limit {
            let mut slots = Vec::with_capacity(live);
            let mut current = self.least_recent;
            while let Some(index) = current {
                let relocated = slots.len();
                // The old slot temporarily records its new position. Reindex
                // the map through its values without cloning or hashing keys.
                let Slot::Occupied(mut entry) = std::mem::replace(
                    &mut self.slots[index],
                    Slot::Vacant {
                        next: Some(relocated),
                    },
                ) else {
                    unreachable!("recency links point to occupied slots");
                };
                current = entry.next;
                entry.previous = relocated.checked_sub(1);
                entry.next = (relocated + 1 < live).then_some(relocated + 1);
                slots.push(Slot::Occupied(entry));
            }
            for index in self.entries.values_mut() {
                let Slot::Vacant {
                    next: Some(relocated),
                } = self.slots[*index]
                else {
                    unreachable!("resident slots have relocation indices");
                };
                *index = relocated;
            }
            self.slots = slots;
            self.least_recent = Some(0);
            self.most_recent = Some(live - 1);
            self.free = None;
        }
        if self.lookup_capacity > limit {
            self.entries.shrink_to_fit();
            self.lookup_capacity = self.entries.capacity();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockCache, Slot};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::fmt::Debug;
    use std::hash::Hash;
    use std::sync::Arc;

    fn assert_structure<K: Clone + Eq + Hash + Debug>(cache: &BlockCache<K>) {
        let mut occupied = HashSet::new();
        let mut current = cache.least_recent;
        let mut previous = None;
        let mut payload = 0;
        let mut admission = 0;
        while let Some(index) = current {
            assert!(occupied.insert(index), "recency list contains a cycle");
            let entry = cache.entry(index);
            assert_eq!(entry.previous, previous);
            assert_eq!(cache.entries.get(&entry.key), Some(&index));
            payload += entry.value.len();
            admission += entry.value.len().max(1);
            previous = current;
            current = entry.next;
        }
        assert_eq!(previous, cache.most_recent);
        assert_eq!(occupied.len(), cache.len());
        assert_eq!(payload, cache.current_bytes());
        assert_eq!(admission, cache.admission_bytes);
        let mut vacant = HashSet::new();
        current = cache.free;
        while let Some(index) = current {
            assert!(vacant.insert(index), "free list contains a cycle");
            assert!(!occupied.contains(&index));
            let Slot::Vacant { next } = cache.slots[index] else {
                panic!("free list contains an occupied slot");
            };
            current = next;
        }
        assert_eq!(occupied.len() + vacant.len(), cache.slots.len());
        let limit = cache.len().saturating_mul(4).max(64);
        assert!(cache.slots.capacity() <= limit);
        assert!(cache.entries.capacity() <= limit);
        assert!(cache.lookup_capacity <= limit);
        if cache.is_empty() {
            assert!(cache.least_recent.is_none());
            assert!(cache.most_recent.is_none());
            assert_eq!(cache.slots.capacity(), 0);
            assert_eq!(cache.entries.capacity(), 0);
            assert_eq!(cache.lookup_capacity, 0);
        }
    }

    #[test]
    fn retain_reclaims_the_lookup_map_after_a_large_contraction() {
        let mut cache = BlockCache::new(4_096);
        for key in 0..4_096 {
            cache.insert(key, Bytes::from_static(b"v"));
        }
        cache.retain(|key| *key == 0 || *key == 4_095);
        assert_eq!(cache.len(), 2);
        assert!(
            cache.entries.capacity() <= 64,
            "lookup map retained its high water allocation"
        );
        assert_eq!(cache.get(&4_095), Some(Bytes::from_static(b"v")));
        assert_structure(&cache);
    }

    #[test]
    fn a_large_overwrite_reclaims_the_lookup_map_after_mass_eviction() {
        let mut cache = BlockCache::new(4_096);
        for key in 0..4_096 {
            cache.insert(key, Bytes::from_static(b"v"));
        }
        let evicted = cache.insert_with_evicted(4_095, Bytes::from(vec![1; 4_096]));
        assert_eq!(evicted.len(), 4_095);
        assert_eq!(evicted.first().map(|entry| entry.0), Some(0));
        assert_eq!(evicted.last().map(|entry| entry.0), Some(4_094));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.current_bytes(), 4_096);
        assert!(
            cache.entries.capacity() <= 64,
            "mass eviction retained the lookup allocation"
        );
        assert_structure(&cache);
    }

    #[test]
    fn a_hit_promotes_only_its_key_before_eviction() {
        let mut cache = BlockCache::new(10);
        cache.insert("a", Bytes::from_static(b"aaaa"));
        cache.insert("b", Bytes::from_static(b"bbbb"));
        assert_eq!(cache.get(&"a"), Some(Bytes::from_static(b"aaaa")));
        cache.insert("c", Bytes::from_static(b"cccc"));

        assert!(cache.contains_key(&"a"));
        assert!(!cache.contains_key(&"b"));
        assert!(cache.contains_key(&"c"));
        assert!(cache.current_bytes() <= 10);
        assert_structure(&cache);
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
                Arc::strong_count(&hot) <= 3,
                "hot reads retained obsolete key clones"
            );
            assert!(
                cache.slots.capacity() <= 64,
                "recency allocation grew with hit count"
            );
        }
        let evicted = cache.insert_with_evicted(Arc::from("new"), Bytes::from_static(b"n"));
        assert_eq!(evicted, vec![(cold, Bytes::from_static(b"c"))]);
        assert!(cache.contains_key(&hot));
        assert_structure(&cache);
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
            Arc::strong_count(&hot) <= 3,
            "overwrites retained obsolete key clones"
        );
        assert!(cache.slots.capacity() <= 64);
        assert_eq!(cache.current_bytes(), 3);
        let evicted = cache.insert_with_evicted(Arc::from("new"), Bytes::from_static(b"n"));
        assert_eq!(evicted, vec![(cold, Bytes::from_static(b"c"))]);
        assert_eq!(cache.get(&hot), Some(Bytes::from_static(b"yy")));
        assert_structure(&cache);
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
            cache.slots.capacity() <= 4,
            "retain kept allocation for removed entries"
        );
        let evicted = cache.insert_with_evicted(128, Bytes::from(vec![9; 127]));
        assert_eq!(evicted, vec![(0, Bytes::from_static(b"v"))]);
        assert!(cache.contains_key(&127));
        cache.retain(|_| false);
        assert!(cache.is_empty());
        assert_eq!(cache.current_bytes(), 0);
        assert_structure(&cache);
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
        assert_structure(&cache);
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
        assert_structure(&cache);
    }

    #[test]
    fn long_eviction_history_reuses_vacancies_and_preserves_links() {
        let mut cache = BlockCache::new(32);
        for key in 0..100_000 {
            let evicted = cache.insert_with_evicted(key, Bytes::from_static(b"v"));
            if key >= 32 {
                assert_eq!(evicted, vec![(key - 32, Bytes::from_static(b"v"))]);
            }
            assert!(cache.slots.len() <= 33, "churn did not reuse vacant slots");
            if key % 127 == 0 {
                assert_structure(&cache);
            }
        }
        cache.retain(|key| key % 2 == 0);
        assert_structure(&cache);
        for key in 100_000..101_000 {
            cache.insert(key, Bytes::new());
            assert_structure(&cache);
        }
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
                let mut peak_slot_capacity = cache.slots.capacity();
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
                    peak_slot_capacity = peak_slot_capacity.max(cache.slots.capacity());
                }
                let elapsed_us = started.elapsed().as_micros() as u64;
                crate::slog::info(
                    "cache_metadata_profile",
                    crate::slog::context()
                        .with_str("workload", workload)
                        .with_u64("operations", operations as u64)
                        .with_u64("elapsed_us", elapsed_us)
                        .with_u64("live_entries", cache.len() as u64)
                        .with_u64("arena_len", cache.slots.len() as u64)
                        .with_u64("retained_arena_capacity", peak_slot_capacity as u64)
                        .with_u64(
                            "retained_arena_bytes",
                            (peak_slot_capacity * std::mem::size_of::<Slot<usize>>()) as u64,
                        ),
                );
            }
        }
    }
}
