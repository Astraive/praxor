use crate::engine::PraxisEngine;
use crate::errors::Result;
use crate::memory::PinnedSnapshot;
use crate::transactions::{BatchOp, WriteBatch};
use crate::types::{
    ColumnFamily, Key, ReadSnapshot, SequenceNumber, StoredValue, Value, VersionedValue,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct OptimisticTransaction {
    engine: PraxisEngine,
    snapshot: Arc<PinnedSnapshot>,
    batch: WriteBatch,
}

impl OptimisticTransaction {
    pub(crate) fn new(engine: PraxisEngine, snapshot: PinnedSnapshot) -> Self {
        Self {
            engine,
            snapshot: Arc::new(snapshot),
            batch: WriteBatch::new(),
        }
    }

    pub fn snapshot(&self) -> ReadSnapshot {
        self.snapshot.snapshot()
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Value>> {
        self.get_cf(&ColumnFamily::default(), key.as_ref())
    }

    fn get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Result<Option<Value>> {
        let snapshot = self.snapshot();
        let mut versions = Vec::new();
        let mut needs_base = true;
        for op in self.batch.ops() {
            let (op_cf, op_key) = match op {
                BatchOp::Put { cf, key, .. }
                | BatchOp::PutWithExpiry { cf, key, .. }
                | BatchOp::Merge { cf, key, .. }
                | BatchOp::Delete { cf, key } => (cf, key),
            };
            if op_cf != cf || op_key.as_slice() != key {
                continue;
            }
            let value = match op {
                BatchOp::Put { value, .. } => StoredValue::Put(value.clone()),
                BatchOp::PutWithExpiry {
                    value,
                    expires_at_ms,
                    ..
                } => StoredValue::PutWithExpiry {
                    value: value.clone(),
                    expires_at_ms: *expires_at_ms,
                },
                BatchOp::Merge { value, .. } => StoredValue::Merge(value.clone()),
                BatchOp::Delete { .. } => StoredValue::Delete,
            };
            if !matches!(value, StoredValue::Merge(_)) {
                // A reset masks the base and all earlier local operands. Keep
                // expired puts in the chain so they remain deletion barriers.
                versions.clear();
                needs_base = false;
            }
            versions.push(VersionedValue {
                sequence: snapshot.sequence,
                value,
            });
        }
        if versions.is_empty() {
            return self.engine.get_cf(cf, key, snapshot);
        }
        self.engine.ensure_column_family(cf)?;
        if needs_base && let Some(base) = self.engine.get_cf(cf, key, snapshot)? {
            versions.insert(
                0,
                VersionedValue {
                    sequence: snapshot.sequence,
                    value: StoredValue::Put(base.to_vec()),
                },
            );
        }
        // Local versions share a synthetic sequence but stay in batch order;
        // canonical resolution supplies the same merge and expiry semantics.
        self.engine
            .resolve_versions_chain(cf, &versions, snapshot.sequence)
            .map(|value| value.map(Value::from))
    }

    pub fn put(&mut self, key: impl Into<Key>, value: impl Into<Value>) -> &mut Self {
        self.batch.put_default(key, value);
        self
    }

    pub fn delete(&mut self, key: impl Into<Key>) -> &mut Self {
        self.batch.delete_default(key);
        self
    }

    pub fn commit(self) -> Result<SequenceNumber> {
        self.engine
            .commit_optimistic_transaction(self.snapshot.snapshot(), self.batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PraxisConfig;
    use bytes::Bytes;
    use tempfile::tempdir;

    #[test]
    fn staged_merge_operands_use_the_pinned_base_in_batch_order() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "base").unwrap();
        let mut transaction = engine.begin_transaction();
        engine.put("key", "external").unwrap();
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "+one");
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "+two");

        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"base+one+two"))
        );
    }

    #[test]
    fn staged_merge_after_delete_starts_with_an_empty_base() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "old").unwrap();
        let mut transaction = engine.begin_transaction();
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "discarded");
        transaction.delete("key");
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "new");

        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"new"))
        );
    }

    #[test]
    fn expired_staged_put_is_a_barrier_to_older_values_and_merges() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "old").unwrap();
        let mut transaction = engine.begin_transaction();
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "discarded");
        transaction
            .batch
            .put_with_expiry(ColumnFamily::default(), "key", "expired", 0);

        assert_eq!(transaction.get("key").unwrap(), None);
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "new");
        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"new"))
        );
    }

    #[test]
    fn unexpired_staged_put_replaces_the_base_before_merging() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "old").unwrap();
        let mut transaction = engine.begin_transaction();
        transaction
            .batch
            .put_with_expiry(ColumnFamily::default(), "key", "live", u64::MAX);
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "+delta");

        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"live+delta"))
        );
    }

    #[test]
    fn local_reads_use_the_column_family_merge_operator() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        // Configure the actual default family; transactions currently expose
        // only default-family writes, so no public API is added for this fixture.
        engine.inner.manifest.lock().column_families[0]
            .options
            .merge_operator = Some("sum_i64".into());
        engine
            .put("counter", Bytes::from(2_i64.to_le_bytes().to_vec()))
            .unwrap();
        let mut transaction = engine.begin_transaction();
        transaction.batch.merge(
            ColumnFamily::default(),
            "counter",
            Bytes::from(3_i64.to_le_bytes().to_vec()),
        );
        transaction.batch.merge(
            ColumnFamily::default(),
            "counter",
            Bytes::from(4_i64.to_le_bytes().to_vec()),
        );

        assert_eq!(
            transaction.get("counter").unwrap(),
            Some(Bytes::from(9_i64.to_le_bytes().to_vec()))
        );
    }

    #[test]
    fn automatic_column_family_expiry_is_applied_at_commit() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.inner.manifest.lock().column_families[0]
            .options
            .ttl_seconds = Some(0);
        let mut transaction = engine.begin_transaction();
        transaction.put("key", "local");

        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"local"))
        );
        transaction.commit().unwrap();
        assert_eq!(engine.get("key").unwrap(), None);
    }

    #[test]
    fn staged_operations_for_another_family_or_key_are_ignored() {
        let dir = tempdir().unwrap();
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
        engine.put("key", "base").unwrap();
        let mut transaction = engine.begin_transaction();
        transaction.batch.put("other", "key", "wrong family");
        transaction.batch.delete("other", "key");
        transaction.batch.merge("other", "key", "wrong merge");
        transaction
            .batch
            .put_with_expiry("other", "key", "expired", 0);
        transaction.put("other-key", "wrong key");
        transaction
            .batch
            .merge(ColumnFamily::default(), "key", "+right");

        assert_eq!(
            transaction.get("key").unwrap(),
            Some(Bytes::from_static(b"base+right"))
        );
    }
}
