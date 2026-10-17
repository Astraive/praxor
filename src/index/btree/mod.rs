//! B-tree-style index: `column_value → RecordId` with sequence-aware snapshots.

pub mod binary;
pub mod manager;
pub mod page;

use super::history::{reclaimable_versions, retain_snapshot_versions};
use super::{IndexPlugin, IndexSnapshotCapability, IndexStats};
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::store::RecordId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct VersionedRid {
    sequence: u64,
    rid: Option<RecordId>,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    next_sequence: u64,
    entries: Vec<(Vec<u8>, Vec<VersionedRid>)>,
    #[serde(default = "default_page_size")]
    page_size: usize,
    #[serde(default)]
    pages: Vec<BTreePageMetadata>,
}

const BTREE_SNAPSHOT_MAGIC: u32 = 0x4254_5232;
const BTREE_SNAPSHOT_VERSION: u8 = 1;

fn default_page_size() -> usize {
    128
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BTreePageMetadata {
    pub page_id: u64,
    pub key_count: usize,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
}

/// B-tree key-to-RID index with ordered range scan support.
pub struct BTreeIndex {
    name: String,
    dir: PathBuf,
    entries: BTreeMap<Vec<u8>, Vec<VersionedRid>>,
    next_sequence: u64,
    page_size: usize,
    pages: Vec<BTreePageMetadata>,
}

impl BTreeIndex {
    /// Open or create a B-tree index named `name` inside `dir`.
    pub fn open(name: impl Into<String>, dir: impl Into<PathBuf>) -> Result<Self> {
        let name = name.into();
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;

        let mut entries = BTreeMap::new();
        let mut next_sequence = 0;
        let mut page_size = default_page_size();
        let mut pages = Vec::new();
        let path = Self::snapshot_path(&dir, &name);
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            let on_disk: OnDisk = if looks_like_binary_snapshot(&bytes) {
                decode_binary_snapshot(&bytes, &path)?
            } else {
                serde_json::from_slice(&bytes)?
            };
            next_sequence = on_disk.next_sequence;
            entries.extend(on_disk.entries);
            page_size = on_disk.page_size;
            pages = on_disk.pages;
        }

        let mut index = Self {
            name,
            dir,
            entries,
            next_sequence,
            page_size,
            pages,
        };
        index.refresh_pages();
        Ok(index)
    }

    fn snapshot_path(dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("{name}.btidx"))
    }

    /// Forward range scan returning live `(key, rid)` pairs in `[lower, upper)`.
    pub fn range(&self, lower: Option<&[u8]>, upper: Option<&[u8]>) -> Vec<(Vec<u8>, RecordId)> {
        let lo = lower
            .map(|b| Bound::Included(b.to_vec()))
            .unwrap_or(Bound::Unbounded);
        let hi = upper
            .map(|b| Bound::Excluded(b.to_vec()))
            .unwrap_or(Bound::Unbounded);
        self.entries
            .range((lo, hi))
            .filter_map(|(key, versions)| {
                latest_visible(versions, u64::MAX).map(|rid| (key.clone(), rid))
            })
            .collect()
    }

    fn next_seq(&mut self) -> u64 {
        self.next_sequence += 1;
        self.next_sequence
    }

    /// Deterministic page metadata generated from sorted live keys.
    pub fn page_metadata(&self) -> &[BTreePageMetadata] {
        &self.pages
    }

    fn refresh_pages(&mut self) {
        self.pages.clear();
        let live_keys: Vec<Vec<u8>> = self
            .entries
            .iter()
            .filter_map(|(key, versions)| {
                latest_visible(versions, u64::MAX)
                    .is_some()
                    .then_some(key.clone())
            })
            .collect();
        for (idx, chunk) in live_keys.chunks(self.page_size).enumerate() {
            let min_key = chunk.first().cloned().unwrap_or_default();
            let max_key = chunk.last().cloned().unwrap_or_default();
            self.pages.push(BTreePageMetadata {
                page_id: idx as u64,
                key_count: chunk.len(),
                min_key,
                max_key,
            });
        }
    }
}

impl IndexPlugin for BTreeIndex {
    fn name(&self) -> &str {
        &self.name
    }

    fn put(&mut self, key: &[u8], rid: RecordId) -> Result<()> {
        let sequence = self.next_seq();
        self.put_with_sequence(key, rid, sequence)
    }

    fn put_with_sequence(&mut self, key: &[u8], rid: RecordId, sequence: u64) -> Result<()> {
        self.next_sequence = self.next_sequence.max(sequence);
        self.entries
            .entry(key.to_vec())
            .or_default()
            .push(VersionedRid {
                sequence,
                rid: Some(rid),
            });
        self.refresh_pages();
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<RecordId> {
        self.get_at(key, u64::MAX)
    }

    fn get_at(&self, key: &[u8], sequence: u64) -> Option<RecordId> {
        self.entries
            .get(key)
            .and_then(|versions| latest_visible(versions, sequence))
    }

    fn snapshot_read_capability(&self) -> IndexSnapshotCapability {
        IndexSnapshotCapability::RawSequenceCeilings
    }

    fn delete(&mut self, key: &[u8]) -> Result<()> {
        let sequence = self.next_seq();
        self.delete_with_sequence(key, sequence)
    }

    fn delete_with_sequence(&mut self, key: &[u8], sequence: u64) -> Result<()> {
        self.next_sequence = self.next_sequence.max(sequence);
        self.entries
            .entry(key.to_vec())
            .or_default()
            .push(VersionedRid {
                sequence,
                rid: None,
            });
        self.refresh_pages();
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        let on_disk = OnDisk {
            next_sequence: self.next_sequence,
            entries: self
                .entries
                .iter()
                .map(|(key, versions)| (key.clone(), versions.clone()))
                .collect(),
            page_size: self.page_size,
            pages: self.pages.clone(),
        };
        let bytes = encode_binary_snapshot(&on_disk);
        std::fs::write(Self::snapshot_path(&self.dir, &self.name), bytes)?;
        Ok(())
    }

    fn compact(&mut self) -> Result<()> {
        for versions in self.entries.values_mut() {
            retain_snapshot_versions(versions, |version| version.sequence);
        }
        self.entries.retain(|_, versions| !versions.is_empty());
        self.refresh_pages();
        Ok(())
    }

    fn stats(&self) -> IndexStats {
        let live_keys = self
            .entries
            .values()
            .filter(|versions| latest_visible(versions, u64::MAX).is_some())
            .count() as u64;
        let versions = self.entries.values().map(|v| v.len() as u64).sum();
        IndexStats {
            live_keys,
            versions,
        }
    }

    fn reclaimable_version_count(&self) -> u64 {
        self.entries
            .values()
            .map(|versions| reclaimable_versions(versions, |version| version.sequence))
            .sum()
    }
}

fn latest_visible(versions: &[VersionedRid], sequence: u64) -> Option<RecordId> {
    versions
        .iter()
        .rev()
        .find(|version| version.sequence <= sequence)
        .and_then(|version| version.rid)
}

fn looks_like_binary_snapshot(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == BTREE_SNAPSHOT_MAGIC
}

fn encode_binary_snapshot(on_disk: &OnDisk) -> Vec<u8> {
    let mut payload = BinaryWriter::new();
    payload.write_u64(on_disk.next_sequence);
    payload.write_u64(on_disk.page_size as u64);
    payload.write_u32(on_disk.entries.len() as u32);
    for (key, versions) in &on_disk.entries {
        payload.write_len_bytes(key);
        payload.write_u32(versions.len() as u32);
        for version in versions {
            payload.write_u64(version.sequence);
            match version.rid {
                Some(rid) => {
                    payload.write_u8(1);
                    payload.write_u64(rid.0);
                }
                None => payload.write_u8(0),
            }
        }
    }
    payload.write_u32(on_disk.pages.len() as u32);
    for page in &on_disk.pages {
        payload.write_u64(page.page_id);
        payload.write_u64(page.key_count as u64);
        payload.write_len_bytes(&page.min_key);
        payload.write_len_bytes(&page.max_key);
    }
    let payload = payload.into_inner();
    let mut out = BinaryWriter::new();
    out.write_u32(BTREE_SNAPSHOT_MAGIC);
    out.write_u8(BTREE_SNAPSHOT_VERSION);
    out.write_u32(payload.len() as u32);
    out.write_u32(crc32c(&payload));
    out.write_bytes(&payload);
    out.into_inner()
}

fn decode_binary_snapshot(bytes: &[u8], source: &Path) -> Result<OnDisk> {
    if bytes.len() < 13 {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "truncated B-tree snapshot header".to_string(),
        });
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != BTREE_SNAPSHOT_MAGIC {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "bad B-tree snapshot magic".to_string(),
        });
    }
    if bytes[4] != BTREE_SNAPSHOT_VERSION {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: format!("unsupported B-tree snapshot version {}", bytes[4]),
        });
    }
    let payload_len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    let expected_crc = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    if bytes.len() < 13 + payload_len {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "truncated B-tree snapshot payload".to_string(),
        });
    }
    let payload = &bytes[13..13 + payload_len];
    let actual_crc = crc32c(payload);
    if actual_crc != expected_crc {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: format!(
                "B-tree snapshot checksum mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"
            ),
        });
    }
    let mut reader = BinaryReader::new(payload, source.to_path_buf());
    let next_sequence = reader.read_u64()?;
    let page_size = reader.read_u64()? as usize;
    let entry_count = reader.read_u32()? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let key = reader.read_len_bytes()?;
        let version_count = reader.read_u32()? as usize;
        let mut versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            let sequence = reader.read_u64()?;
            let has_rid = reader.read_u8()?;
            let rid = if has_rid == 1 {
                Some(RecordId(reader.read_u64()?))
            } else {
                None
            };
            versions.push(VersionedRid { sequence, rid });
        }
        entries.push((key, versions));
    }
    let page_count = reader.read_u32()? as usize;
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        pages.push(BTreePageMetadata {
            page_id: reader.read_u64()?,
            key_count: reader.read_u64()? as usize,
            min_key: reader.read_len_bytes()?,
            max_key: reader.read_len_bytes()?,
        });
    }
    Ok(OnDisk {
        next_sequence,
        entries,
        page_size,
        pages,
    })
}
