use super::record_id::RecordId;
use crate::errors::{PraxisError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;

/// Physical location of a record within a segment file.
///
/// `record_offset` is the byte position of the record's **length** field
/// (i.e. the very start of the `[length:4][checksum:4][data:length]`
/// on-disk layout).  `length` is the number of data bytes, not including
/// the 8-byte per-record header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhysicalLocation {
    pub segment_id: u32,
    /// Byte position of the record header (`length` field) inside the segment.
    pub record_offset: u64,
    /// Length of the raw data in bytes (excluding the 8-byte record header).
    pub length: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    location: PhysicalLocation,
    alive: bool,
}

/// Maps stable logical [`RecordId`] values to physical segment locations.
///
/// Compaction rewrites segment files and calls [`IndirectionTable::relocate`]
/// to update physical pointers without invalidating any outstanding
/// `RecordId` held by callers or index plugins.  Index plugins therefore
/// need no changes during compaction.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IndirectionTable {
    /// Monotonically-increasing counter; `0` is reserved (= `RecordId::NULL`).
    next_rid: u64,
    /// Monotonically-increasing segment counter.
    next_segment_id: u32,
    entries: HashMap<u64, Entry>,
}

impl IndirectionTable {
    pub(crate) fn reserve_rid(&mut self) -> Result<RecordId> {
        self.next_rid = self
            .next_rid
            .checked_add(1)
            .ok_or_else(|| PraxisError::InvalidConfig("record id exhausted".into()))?;
        Ok(RecordId(self.next_rid))
    }
    /// Allocate a new logical [`RecordId`] pointing to `location`.
    pub fn allocate(&mut self, location: PhysicalLocation) -> RecordId {
        self.next_rid += 1;
        self.entries.insert(
            self.next_rid,
            Entry {
                location,
                alive: true,
            },
        );
        RecordId(self.next_rid)
    }

    /// Resolve a [`RecordId`] to its current physical location.
    pub fn locate(&self, rid: RecordId) -> Result<PhysicalLocation> {
        self.entries
            .get(&rid.0)
            .filter(|e| e.alive)
            .map(|e| e.location)
            .ok_or(PraxisError::KeyNotFound)
    }

    /// Mark `rid` as deleted; its space will be reclaimed during compaction.
    pub fn tombstone(&mut self, rid: RecordId) -> Result<()> {
        let entry = self
            .entries
            .get_mut(&rid.0)
            .ok_or(PraxisError::KeyNotFound)?;
        entry.alive = false;
        Ok(())
    }

    pub fn tombstone_if_present(&mut self, rid: RecordId) {
        if let Some(entry) = self.entries.get_mut(&rid.0) {
            entry.alive = false;
        }
    }

    /// Install or repair a logical record mapping during WAL replay.
    pub fn upsert_live(&mut self, rid: RecordId, location: PhysicalLocation) {
        self.entries.insert(
            rid.0,
            Entry {
                location,
                alive: true,
            },
        );
        self.next_rid = self.next_rid.max(rid.0);
        self.next_segment_id = self.next_segment_id.max(location.segment_id);
    }

    /// Update the physical location of `rid` (called during compaction).
    pub fn relocate(&mut self, rid: RecordId, new_location: PhysicalLocation) {
        if let Some(entry) = self.entries.get_mut(&rid.0) {
            entry.location = new_location;
        }
    }

    /// Return an iterator over all live (non-deleted) record ids.
    pub fn live_rids(&self) -> impl Iterator<Item = RecordId> + '_ {
        self.entries
            .iter()
            .filter(|(_, e)| e.alive)
            .map(|(id, _)| RecordId(*id))
    }

    /// Number of live records.
    pub fn live_count(&self) -> u64 {
        self.entries.values().filter(|e| e.alive).count() as u64
    }

    /// Number of dead (tombstoned) records.
    pub fn dead_count(&self) -> u64 {
        self.entries.values().filter(|e| !e.alive).count() as u64
    }

    /// Total bytes of all live records (data bytes only, no record headers).
    pub fn live_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| e.alive)
            .map(|e| e.location.length as u64)
            .sum()
    }

    /// Total number of records tracked by this directory, live plus tombstoned.
    pub fn total_count(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn contains_live(&self, rid: RecordId) -> bool {
        self.entries.get(&rid.0).is_some_and(|entry| entry.alive)
    }

    pub(crate) fn contains_record(&self, rid: RecordId) -> bool {
        self.entries.contains_key(&rid.0)
    }

    /// The ID of the currently active segment (new records appended here).
    pub fn active_segment_id(&self) -> u32 {
        self.next_segment_id
    }

    /// Allocate a fresh segment ID for compaction output.
    ///
    /// Increments the internal counter and returns the **new** segment id.
    pub fn alloc_segment_id(&mut self) -> u32 {
        self.next_segment_id += 1;
        self.next_segment_id
    }

    /// Persist the table to `path` as JSON through temp-write + atomic rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, json)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path)?
            .sync_all()?;
        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&tmp_path, path)?;
        sync_parent_dir(path)?;
        Ok(())
    }

    /// Load the table from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read(path)?;
        Ok(serde_json::from_slice(&json)?)
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}
