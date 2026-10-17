use crate::engine::PraxisEngine;
use crate::errors::Result;
use crate::memory::PinnedSnapshot;
use crate::transactions::WriteBatch;
use crate::types::{ColumnFamily, Key, ReadSnapshot, SequenceNumber, Value};
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
        self.engine
            .get_cf(&ColumnFamily::default(), key.as_ref(), self.snapshot())
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
