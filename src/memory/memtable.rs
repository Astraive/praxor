use crate::transactions::BatchOp;
use crate::types::{ColumnFamily, Key, SequenceNumber, StoredValue, Value, VersionedValue};
use bytes::Bytes;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct MemTable {
    entries: BTreeMap<(ColumnFamily, Key), Vec<VersionedValue>>,
    approximate_bytes: usize,
}

impl MemTable {
    pub fn apply(&mut self, sequence: SequenceNumber, op: &BatchOp) {
        match op {
            BatchOp::Put { cf, key, value } => {
                self.approximate_bytes += cf.0.len() + key.len() + value.len() + 32;
                self.entries
                    .entry((cf.clone(), Bytes::from(key.clone())))
                    .or_default()
                    .push(VersionedValue {
                        sequence,
                        value: StoredValue::Put(value.clone()),
                    });
            }
            BatchOp::PutWithExpiry {
                cf,
                key,
                value,
                expires_at_ms,
            } => {
                self.approximate_bytes += cf.0.len() + key.len() + value.len() + 40;
                self.entries
                    .entry((cf.clone(), Bytes::from(key.clone())))
                    .or_default()
                    .push(VersionedValue {
                        sequence,
                        value: StoredValue::PutWithExpiry {
                            value: value.clone(),
                            expires_at_ms: *expires_at_ms,
                        },
                    });
            }
            BatchOp::Merge { cf, key, value } => {
                self.approximate_bytes += cf.0.len() + key.len() + value.len() + 32;
                self.entries
                    .entry((cf.clone(), Bytes::from(key.clone())))
                    .or_default()
                    .push(VersionedValue {
                        sequence,
                        value: StoredValue::Merge(value.clone()),
                    });
            }
            BatchOp::Delete { cf, key } => {
                self.approximate_bytes += cf.0.len() + key.len() + 24;
                self.entries
                    .entry((cf.clone(), Bytes::from(key.clone())))
                    .or_default()
                    .push(VersionedValue {
                        sequence,
                        value: StoredValue::Delete,
                    });
            }
        }
    }

    pub fn get(
        &self,
        cf: &ColumnFamily,
        key: &[u8],
        snapshot: SequenceNumber,
    ) -> Option<StoredValue> {
        self.entries
            .get(&(cf.clone(), Bytes::copy_from_slice(key)))
            .and_then(|versions| {
                versions
                    .iter()
                    .rev()
                    .find(|version| version.sequence <= snapshot)
                    .map(|version| version.value.clone())
            })
    }

    pub fn scan(
        &self,
        cf: &ColumnFamily,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        snapshot: SequenceNumber,
    ) -> Vec<(Key, Value)> {
        let mut out = Vec::new();
        for ((entry_cf, key), versions) in &self.entries {
            if entry_cf != cf {
                continue;
            }
            if start.is_some_and(|start| key.as_ref() < start) {
                continue;
            }
            if end.is_some_and(|end| key.as_ref() >= end) {
                continue;
            }
            if let Some(version) = versions
                .iter()
                .rev()
                .find(|version| version.sequence <= snapshot)
                && let StoredValue::Put(value) | StoredValue::PutWithExpiry { value, .. } =
                    &version.value
            {
                out.push((key.clone(), Bytes::from(value.clone())));
            }
        }
        out
    }

    /// Enumerate keys without materializing or cloning their stored values.
    pub fn keys(&self) -> impl Iterator<Item = (&ColumnFamily, &Key)> {
        self.entries.keys().map(|(cf, key)| (cf, key))
    }

    /// Inclusive bounds in one CF, without visiting unrelated keys or values.
    pub(crate) fn keys_in_range<'a>(
        &'a self,
        cf: &ColumnFamily,
        start: &Key,
        end: &Key,
    ) -> impl Iterator<Item = &'a Key> {
        self.entries
            .range((cf.clone(), start.clone())..=(cf.clone(), end.clone()))
            .map(|((_, key), _)| key)
    }

    pub fn drain_latest(&self) -> Vec<(ColumnFamily, Key, VersionedValue)> {
        self.entries
            .iter()
            .filter_map(|((cf, key), versions)| {
                versions
                    .last()
                    .cloned()
                    .map(|version| (cf.clone(), key.clone(), version))
            })
            .collect()
    }

    /// Flush every version; compaction alone decides when history is obsolete.
    pub fn versions(&self) -> Vec<(ColumnFamily, Key, VersionedValue)> {
        self.entries
            .iter()
            .flat_map(|((cf, key), versions)| {
                versions
                    .iter()
                    .cloned()
                    .map(|version| (cf.clone(), key.clone(), version))
            })
            .collect()
    }

    pub fn latest_sequence(&self, cf: &ColumnFamily, key: &[u8]) -> Option<SequenceNumber> {
        self.entries
            .get(&(cf.clone(), Bytes::copy_from_slice(key)))
            .and_then(|versions| versions.last())
            .map(|version| version.sequence)
    }

    pub fn versions_for_key(&self, cf: &ColumnFamily, key: &[u8]) -> Vec<VersionedValue> {
        self.entries
            .get(&(cf.clone(), Bytes::copy_from_slice(key)))
            .cloned()
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn approximate_bytes(&self) -> usize {
        self.approximate_bytes
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.approximate_bytes = 0;
    }

    /// Remove all entries belonging to the given column family.
    pub fn remove_cf(&mut self, cf: &ColumnFamily) {
        let before = self.entries.len();
        self.entries.retain(|(k_cf, _), _| k_cf != cf);
        let removed = before - self.entries.len();
        // Approximate recalculation — better than leaving stale bytes
        if removed > 0 {
            self.approximate_bytes = self.approximate_bytes.saturating_sub(removed * 64); // rough estimate
        }
    }
}
