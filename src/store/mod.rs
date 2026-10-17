//! Primary data store — every value is stored here exactly once.
//!
//! The caller writes raw bytes and receives a stable [`RecordId`].  All index
//! plugins store only `key → RecordId` mappings and never duplicate the actual
//! value bytes.  The [`IndirectionTable`] maps each logical `RecordId` to a
//! physical `(segment_id, record_offset, length)`, so compaction can rewrite
//! segment files and update only the indirection table; all outstanding
//! `RecordId` values remain valid.

mod engine;
mod indirection;
mod manifest;
mod record_id;
mod runtime;
mod segment;
mod wal;

pub use engine::{
    BatchRecord, CacheBlockKey, CacheEntryType, DirectorySyncPolicy, IndexCompactionReport,
    IndexInsert, MaintenanceCycleOptions, MaintenanceCycleReport, StorageEngine,
    StorageEngineOptions, StorageEngineStats, SuggestedMaintenanceJob, UnifiedBlockCache,
};
pub use indirection::{IndirectionTable, PhysicalLocation};
pub use manifest::{
    ManifestEdit, PendingCompactionAbort, PendingCompactionCleanup, StorageManifest,
    StorageManifestStore,
};
pub use record_id::RecordId;
pub use runtime::{
    SharedStorageEngine, StorageMaintenanceRuntimeConfig, StorageMaintenanceRuntimeController,
    StorageMaintenanceRuntimeStatus,
};
pub use segment::RecordSegment;
pub use wal::{StorageWal, StorageWalEntry, StorageWalOperation, StorageWalOptions};

use crate::errors::Result;
use crate::io::create_dir_all_durable;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical record directory used by the storage kernel.
///
/// Every index points to `RecordId`, and only this directory resolves that
/// logical id to physical bytes in the primary value store.
pub type RecordDirectory = IndirectionTable;

/// Statistics returned by [`RecordStore::compact`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactionStats {
    /// Number of live records copied to the new segment.
    pub records_retained: u64,
    /// Number of dead (tombstoned) records dropped.
    pub records_dropped: u64,
    /// Total bytes of live record data written to the new segment.
    pub bytes_written: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedCompaction {
    pub stats: CompactionStats,
    pub old_segment_ids: Vec<u32>,
    pub new_segment_id: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalStorageStats {
    pub live_records: u64,
    pub dead_records: u64,
    pub total_records: u64,
    pub canonical_live_bytes: u64,
}

/// The single primary data store for praxis's no-duplication storage engine.
///
/// Raw value bytes are appended to the active segment file exactly once.
/// The returned [`RecordId`] is the canonical stable address used by all
/// index plugins; they store only `key → RecordId`, never `key → value`.
///
/// # No-duplication guarantee
///
/// If the same logical entity (a graph node, a SQL row, a vector embedding)
/// is indexed by multiple index plugins simultaneously, the value bytes
/// appear **once** on disk inside a segment file.  Each index plugin holds
/// only a 64-bit [`RecordId`] pointer.
///
/// # Compaction
///
/// Calling [`RecordStore::compact`] rewrites all live records into a fresh
/// segment, eliminates dead (tombstoned) entries, and updates the
/// [`IndirectionTable`] in-place.  All outstanding [`RecordId`] values
/// remain valid; index plugins require no changes.
pub struct RecordStore {
    dir: PathBuf,
    active_segment: RecordSegment,
    indirection: IndirectionTable,
}

pub(crate) struct PreparedPrimaryPut {
    pub rid: RecordId,
    pub location: PhysicalLocation,
}

impl RecordStore {
    const SEGMENT_SUBDIR: &'static str = "records";
    const INDIRECTION_FILE: &'static str = "indirection.tind";

    /// Open or create a record store rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        create_dir_all_durable(&dir.join(Self::SEGMENT_SUBDIR))?;

        let ind_path = dir.join(Self::INDIRECTION_FILE);
        let indirection = if ind_path.exists() {
            IndirectionTable::load(&ind_path)?
        } else {
            IndirectionTable::default()
        };

        let seg_id = indirection.active_segment_id();
        let seg_path = Self::seg_path(&dir, seg_id);
        let active_segment = RecordSegment::open(seg_path, seg_id)?;

        Ok(Self {
            dir,
            active_segment,
            indirection,
        })
    }

    fn seg_path(dir: &Path, id: u32) -> PathBuf {
        dir.join(Self::SEGMENT_SUBDIR)
            .join(format!("{id:08x}.trec"))
    }

    /// Write `bytes` to the primary store and return a stable [`RecordId`].
    ///
    /// The bytes are appended to the active segment file exactly once,
    /// regardless of how many index plugins will subsequently reference
    /// this record.
    pub fn put(&mut self, bytes: &[u8]) -> Result<RecordId> {
        let rid = self.put_unsynced(bytes)?;
        self.active_segment.sync()?;
        Ok(rid)
    }

    pub(crate) fn put_unsynced(&mut self, bytes: &[u8]) -> Result<RecordId> {
        let prepared = self.prepare_put(bytes)?;
        let rid = prepared.rid;
        self.publish_puts(&[prepared]);
        Ok(rid)
    }

    pub(crate) fn prepare_put(&mut self, bytes: &[u8]) -> Result<PreparedPrimaryPut> {
        u32::try_from(bytes.len()).map_err(|_| {
            crate::errors::PraxisError::InvalidConfig("primary record exceeds u32 length".into())
        })?;
        let rid = self.indirection.reserve_rid()?;
        let (record_offset, length) = self.active_segment.append(bytes)?;
        let loc = PhysicalLocation {
            segment_id: self.active_segment.segment_id(),
            record_offset,
            length,
        };
        Ok(PreparedPrimaryPut { rid, location: loc })
    }

    pub(crate) fn publish_puts(&mut self, puts: &[PreparedPrimaryPut]) {
        for put in puts {
            self.indirection.upsert_live(put.rid, put.location);
        }
    }

    pub(crate) fn sync_active_segment(&self) -> Result<()> {
        self.active_segment.sync()
    }

    pub fn location(&self, rid: RecordId) -> Result<PhysicalLocation> {
        self.indirection.locate(rid)
    }

    pub fn contains(&self, rid: RecordId) -> bool {
        self.indirection.contains_live(rid)
    }

    /// Delete preflight distinguishes unknown IDs from known tombstones so
    /// idempotent deletes and cleanup of stale secondary pointers stay valid.
    pub(crate) fn contains_record(&self, rid: RecordId) -> bool {
        self.indirection.contains_record(rid)
    }

    pub fn replay_primary_put(&mut self, rid: RecordId, location: PhysicalLocation) -> Result<()> {
        self.indirection.upsert_live(rid, location);
        Ok(())
    }

    pub fn replay_primary_delete(&mut self, rid: RecordId) -> Result<()> {
        self.indirection.tombstone_if_present(rid);
        Ok(())
    }

    /// Retrieve the bytes associated with `rid`.
    pub fn get(&self, rid: RecordId) -> Result<Vec<u8>> {
        let loc = self.indirection.locate(rid)?;
        let path = Self::seg_path(&self.dir, loc.segment_id);
        RecordSegment::read_at(&path, loc.record_offset, loc.length)
    }

    /// Mark `rid` as deleted.  Space is reclaimed on the next [`Self::compact`].
    pub fn delete(&mut self, rid: RecordId) -> Result<()> {
        self.indirection.tombstone(rid)
    }

    /// Persist the indirection table to disk.
    ///
    /// Must be called before the store is dropped to ensure that all written
    /// records survive a restart.
    pub fn flush(&mut self) -> Result<()> {
        self.indirection
            .save(&self.dir.join(Self::INDIRECTION_FILE))
    }

    /// Garbage-collect dead records.
    ///
    /// All live records are rewritten to a fresh segment; dead ones are
    /// dropped.  The [`IndirectionTable`] is updated in-place so every
    /// outstanding [`RecordId`] remains valid.  Index plugins are
    /// **not** touched because they hold logical ids, not physical offsets.
    pub fn compact_prepare(&mut self) -> Result<PreparedCompaction> {
        let live: Vec<RecordId> = self.indirection.live_rids().collect();
        let mut stats = CompactionStats {
            records_dropped: self.indirection.dead_count(),
            ..Default::default()
        };

        // Collect the set of old segment ids that will be superseded.
        let old_segment_ids: HashSet<u32> = live
            .iter()
            .filter_map(|rid| self.indirection.locate(*rid).ok().map(|l| l.segment_id))
            .collect();

        let new_id = self.indirection.alloc_segment_id();
        let new_path = Self::seg_path(&self.dir, new_id);
        let mut new_seg = RecordSegment::open(&new_path, new_id)?;

        for rid in &live {
            let loc = self.indirection.locate(*rid)?;
            let old_path = Self::seg_path(&self.dir, loc.segment_id);
            let bytes = RecordSegment::read_at(&old_path, loc.record_offset, loc.length)?;
            let (record_offset, length) = new_seg.append(&bytes)?;
            let new_loc = PhysicalLocation {
                segment_id: new_id,
                record_offset,
                length,
            };
            self.indirection.relocate(*rid, new_loc);
            stats.records_retained += 1;
            stats.bytes_written += length as u64;
        }
        new_seg.sync()?;

        // Swap in the new active segment.
        self.active_segment = new_seg;

        // Install the repaired directory before any old segment is removed.
        self.flush()?;

        let mut old_segment_ids: Vec<u32> = old_segment_ids.into_iter().collect();
        old_segment_ids.sort_unstable();

        Ok(PreparedCompaction {
            stats,
            old_segment_ids,
            new_segment_id: new_id,
        })
    }

    pub fn complete_compaction_cleanup(
        &mut self,
        old_segment_ids: &[u32],
        retained_segment_id: u32,
    ) -> Result<Vec<u32>> {
        let mut cleaned = Vec::new();
        for old_id in old_segment_ids {
            if *old_id == retained_segment_id {
                continue;
            }
            let old_path = Self::seg_path(&self.dir, *old_id);
            if old_path.exists() {
                fs::remove_file(old_path)?;
                cleaned.push(*old_id);
            }
        }
        cleaned.sort_unstable();
        Ok(cleaned)
    }

    pub fn compact(&mut self) -> Result<CompactionStats> {
        let plan = self.compact_prepare()?;
        self.complete_compaction_cleanup(&plan.old_segment_ids, plan.new_segment_id)?;
        Ok(plan.stats)
    }

    /// Number of live (non-deleted) records.
    pub fn live_count(&self) -> u64 {
        self.indirection.live_count()
    }

    /// Total bytes occupied by live records on disk (data bytes only).
    pub fn live_bytes(&self) -> u64 {
        self.indirection.live_bytes()
    }

    pub fn dead_count(&self) -> u64 {
        self.indirection.dead_count()
    }

    pub fn total_count(&self) -> u64 {
        self.indirection.total_count()
    }

    pub fn live_segment_ids(&self) -> Result<Vec<u32>> {
        let mut segments = HashSet::new();
        for rid in self.indirection.live_rids() {
            segments.insert(self.indirection.locate(rid)?.segment_id);
        }
        let mut segments: Vec<u32> = segments.into_iter().collect();
        segments.sort_unstable();
        Ok(segments)
    }

    pub fn canonical_stats(&self) -> CanonicalStorageStats {
        CanonicalStorageStats {
            live_records: self.live_count(),
            dead_records: self.dead_count(),
            total_records: self.total_count(),
            canonical_live_bytes: self.live_bytes(),
        }
    }
}
