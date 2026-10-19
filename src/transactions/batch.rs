use crate::types::{ColumnFamily, Key, Value};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::TryReserveError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BatchOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    PutWithExpiry {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
        expires_at_ms: u64,
    },
    Merge {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(
        &mut self,
        cf: impl Into<ColumnFamily>,
        key: impl Into<Key>,
        value: impl Into<Value>,
    ) -> &mut Self {
        self.ops.push(BatchOp::Put {
            cf: cf.into(),
            key: key.into().to_vec(),
            value: value.into().to_vec(),
        });
        self
    }

    pub fn put_default(&mut self, key: impl Into<Bytes>, value: impl Into<Bytes>) -> &mut Self {
        self.put(ColumnFamily::default(), key, value)
    }

    pub fn put_with_expiry(
        &mut self,
        cf: impl Into<ColumnFamily>,
        key: impl Into<Key>,
        value: impl Into<Value>,
        expires_at_ms: u64,
    ) -> &mut Self {
        self.ops.push(BatchOp::PutWithExpiry {
            cf: cf.into(),
            key: key.into().to_vec(),
            value: value.into().to_vec(),
            expires_at_ms,
        });
        self
    }

    pub fn merge(
        &mut self,
        cf: impl Into<ColumnFamily>,
        key: impl Into<Key>,
        value: impl Into<Value>,
    ) -> &mut Self {
        self.ops.push(BatchOp::Merge {
            cf: cf.into(),
            key: key.into().to_vec(),
            value: value.into().to_vec(),
        });
        self
    }

    pub fn delete(&mut self, cf: impl Into<ColumnFamily>, key: impl Into<Key>) -> &mut Self {
        self.ops.push(BatchOp::Delete {
            cf: cf.into(),
            key: key.into().to_vec(),
        });
        self
    }

    pub fn delete_default(&mut self, key: impl Into<Bytes>) -> &mut Self {
        self.delete(ColumnFamily::default(), key)
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn ops(&self) -> &[BatchOp] {
        &self.ops
    }

    /// Truncate the batch to the given length.
    /// Used by savepoints to roll back operations.
    pub fn truncate(&mut self, len: usize) {
        self.ops.truncate(len);
    }

    /// Push a single operation into the batch.
    /// Used by nested transactions to merge child batches.
    pub fn push_op(&mut self, op: BatchOp) {
        self.ops.push(op);
    }

    pub(crate) fn try_reserve_ops(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.ops.try_reserve_exact(additional)
    }

    /// A v4 decoded batch calls this only after reserving all declared ops.
    /// A mismatched count returns false without another allocation.
    pub(crate) fn try_push_reserved_op(&mut self, op: BatchOp) -> bool {
        if self.ops.len() == self.ops.capacity() {
            return false;
        }
        self.ops.push(op);
        true
    }
}

impl From<&str> for ColumnFamily {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
