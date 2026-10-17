//! Index plugins for praxis's no-duplication storage engine.
//!
//! Every index plugin stores only `key → RecordId` mappings.  The actual
//! value bytes live in the primary [`RecordStore`][crate::store::RecordStore]
//! and are never copied into an index.  To read a value, the caller:
//!
//! 1. Queries an index plugin for the [`RecordId`] associated with a key.
//! 2. Calls `RecordStore::get(rid)` to fetch the raw bytes.
//!
//! This guarantees that each value is stored on disk exactly once,
//! regardless of how many index plugins reference it simultaneously.

pub mod adjacency;
pub mod bitmap;
pub mod bm25;
pub mod btree;
pub mod graph;
pub(crate) mod history;
pub mod hnsw;
pub mod hybrid;
pub mod inverted;
pub mod ivf;
pub mod rtree;
pub mod scalar;
pub mod specialized;
pub mod time_series;
pub mod vector_query;

pub use adjacency::AdjacencyIndex;
pub use bitmap::BitmapIndex;
pub use bm25::Bm25Index;
pub use btree::BTreeIndex;
pub use graph::GraphIndex;
pub use hnsw::HnswIndex;
pub use hybrid::{HybridHit, HybridWeights, RecordScoringOverride, RetrievalEngine};
pub use inverted::InvertedIndex;
pub use ivf::IvfFlatIndex;
pub use rtree::{BoundingBox, PackedRTreeIndex};
pub use scalar::ScalarIndex;
pub use specialized::{SpecializedEngineContract, SpecializedEngineRegistry};
pub use time_series::TimePartition;
pub use vector_query::{DistanceMetric, VectorIndex, VectorStrategy};

use crate::errors::Result;
use crate::store::RecordId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexStats {
    pub live_keys: u64,
    pub versions: u64,
}

/// Snapshot contract declared by an index plugin. Opting in requires preserving
/// every raw ceiling through compaction, not merely implementing a read method.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IndexSnapshotCapability {
    #[default]
    Unsupported,
    RawSequenceCeilings,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexStorageLayout {
    pub stores_full_values: bool,
    pub stores_record_ids: bool,
    pub stores_lossy_summaries: bool,
}

impl IndexStorageLayout {
    pub const POINTER_ONLY: Self = Self {
        stores_full_values: false,
        stores_record_ids: true,
        stores_lossy_summaries: false,
    };

    pub const POINTER_WITH_LOSSY_SUMMARIES: Self = Self {
        stores_full_values: false,
        stores_record_ids: true,
        stores_lossy_summaries: true,
    };

    pub fn validate_default_kernel_policy(self, index_name: &str) -> Result<()> {
        if self.stores_full_values {
            return Err(crate::errors::PraxisError::InvalidConfig(format!(
                "index {index_name} violates pointer-only kernel policy"
            )));
        }
        if !self.stores_record_ids {
            return Err(crate::errors::PraxisError::InvalidConfig(format!(
                "index {index_name} must store RecordId pointers"
            )));
        }
        Ok(())
    }
}

/// The interface every index plugin must implement.
///
/// An index plugin stores `key → RecordId` mappings only.  It never holds
/// a copy of the actual value bytes.
pub trait IndexPlugin: Send + Sync {
    /// Human-readable name used to derive on-disk file names.
    fn name(&self) -> &str;

    /// Associate `key` with `rid`.
    fn put(&mut self, key: &[u8], rid: RecordId) -> Result<()>;

    /// Associate `key` with `rid` at a caller-assigned sequence number.
    ///
    /// Default behavior ignores the supplied sequence and delegates to [`Self::put`].
    fn put_with_sequence(&mut self, key: &[u8], rid: RecordId, _sequence: u64) -> Result<()> {
        self.put(key, rid)
    }

    /// Look up the [`RecordId`] for `key`, or `None` if absent.
    fn get(&self, key: &[u8]) -> Option<RecordId>;

    /// Snapshot read: return the value visible at `sequence`.
    ///
    /// The legacy default fails closed. Use [`Self::get_at_checked`] to
    /// distinguish an unsupported plugin from an absent mapping.
    fn get_at(&self, _key: &[u8], _sequence: u64) -> Option<RecordId> {
        None
    }

    fn snapshot_read_capability(&self) -> IndexSnapshotCapability {
        IndexSnapshotCapability::Unsupported
    }

    /// Read an index mapping at a raw sequence ceiling. Custom plugins must
    /// explicitly opt in and implement sequence-aware mutation/retention.
    fn get_at_checked(&self, key: &[u8], sequence: u64) -> Result<Option<RecordId>> {
        match self.snapshot_read_capability() {
            IndexSnapshotCapability::RawSequenceCeilings => Ok(self.get_at(key, sequence)),
            IndexSnapshotCapability::Unsupported => {
                Err(crate::errors::PraxisError::UnsupportedIndexSnapshotRead {
                    index: self.name().to_string(),
                })
            }
        }
    }

    /// Remove the mapping for `key` (insert a tombstone).
    fn delete(&mut self, key: &[u8]) -> Result<()>;

    /// Remove the mapping for `key` at a caller-assigned sequence number.
    ///
    /// Default behavior delegates to [`Self::delete`].
    fn delete_with_sequence(&mut self, key: &[u8], _sequence: u64) -> Result<()> {
        self.delete(key)
    }

    /// Persist in-memory state to disk.
    fn flush(&mut self) -> Result<()>;

    /// Optional plugin-local compaction hook.
    fn compact(&mut self) -> Result<()> {
        Ok(())
    }

    /// Return plugin-level key/version counters.
    fn stats(&self) -> IndexStats {
        IndexStats::default()
    }

    /// Versions the next compaction may discard without breaking this plugin's
    /// snapshot contract. Required historical versions are not reclaimable.
    fn reclaimable_version_count(&self) -> u64 {
        0
    }

    /// Durable storage layout declaration used to enforce praxis's
    /// single-copy value contract.
    fn storage_layout(&self) -> IndexStorageLayout {
        IndexStorageLayout::POINTER_ONLY
    }
}
