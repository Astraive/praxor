//! LSM-style index: `encoded_key → RecordId`.
//!
//! This implementation stores versioned key histories in memory and on disk:
//! each key has an ordered sequence of updates (`put` or tombstone delete).
//! Snapshot reads resolve the newest update whose sequence is `<= snapshot`.

pub mod binary;
pub mod pipeline;
pub mod sstable;

pub use pipeline::{
    ImmutableMemtable, LsmFlushPipeline, LsmFlushReport, MemtableEntry, MemtableEntryKind,
    MutableMemtable,
};

use crate::errors::{PraxisError, Result};
use crate::index::{IndexPlugin, IndexStats};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::store::RecordId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    #[serde(default)]
    bloom_bits: Vec<u8>,
    #[serde(default)]
    bloom_bit_len: usize,
    #[serde(default)]
    bloom_hashes: u8,
    // Legacy field (exact-set scaffold snapshot format).
    #[serde(default)]
    bloom_keys: Vec<Vec<u8>>,
    #[serde(default)]
    fence_min: Option<Vec<u8>>,
    #[serde(default)]
    fence_max: Option<Vec<u8>>,
}

const LSM_SNAPSHOT_MAGIC: u32 = 0x4c53_4d32;
const LSM_SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct BloomMetadata {
    bits: Vec<u8>,
    bit_len: usize,
    hashes: u8,
}

impl BloomMetadata {
    fn with_capacity(capacity: usize, false_positive_rate: f64) -> Self {
        if capacity == 0 {
            return Self::default();
        }
        let n = capacity as f64;
        let p = false_positive_rate.clamp(1e-9, 0.5);
        let ln2 = std::f64::consts::LN_2;
        let bit_len = ((-n * p.ln()) / (ln2 * ln2)).ceil().max(1024.0) as usize;
        let hashes = ((bit_len as f64 / n) * ln2).round().clamp(1.0, 16.0) as u8;
        Self {
            bits: vec![0u8; bit_len.div_ceil(8)],
            bit_len,
            hashes,
        }
    }

    fn maybe_contains(&self, key: &[u8]) -> bool {
        if self.bit_len == 0 || self.hashes == 0 {
            return false;
        }
        for idx in hash_indexes(key, self.hashes, self.bit_len) {
            if !bit_is_set(&self.bits, idx) {
                return false;
            }
        }
        true
    }

    fn insert(&mut self, key: &[u8]) {
        if self.bit_len == 0 || self.hashes == 0 {
            return;
        }
        for idx in hash_indexes(key, self.hashes, self.bit_len) {
            set_bit(&mut self.bits, idx);
        }
    }
}

/// LSM-style key-to-RID index with sequence-aware snapshot lookups.
pub struct LsmIndex {
    name: String,
    dir: PathBuf,
    history: BTreeMap<Vec<u8>, Vec<VersionedRid>>,
    next_sequence: u64,
    // Current membership is separate from historical versions. One key copy per
    // live key provides exact bounds without scanning tombstoned history.
    live_keys: BTreeSet<Vec<u8>>,
    version_count: u64,
    bloom: BloomMetadata,
    bloom_capacity: usize,
    bloom_insertions: usize,
}

impl LsmIndex {
    /// Open or create an LSM index named `name` inside `dir`.
    pub fn open(name: impl Into<String>, dir: impl Into<PathBuf>) -> Result<Self> {
        let name = name.into();
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;

        let mut history: BTreeMap<Vec<u8>, Vec<VersionedRid>> = BTreeMap::new();
        let mut next_sequence = 0;
        let snapshot = Self::snapshot_path(&dir, &name);
        if snapshot.exists() {
            let bytes = std::fs::read(&snapshot)?;
            let on_disk: OnDisk = if looks_like_binary_snapshot(&bytes) {
                decode_binary_snapshot(&bytes, &snapshot)?
            } else {
                serde_json::from_slice(&bytes)?
            };
            next_sequence = on_disk.next_sequence;
            history.extend(on_disk.entries);
        }

        let mut index = Self {
            name,
            dir,
            history,
            next_sequence,
            live_keys: BTreeSet::new(),
            version_count: 0,
            bloom: BloomMetadata::default(),
            bloom_capacity: 0,
            bloom_insertions: 0,
        };
        // Both legacy JSON and binary snapshots carry derived metadata. Rebuild
        // it once from authoritative histories, including the insertion budget.
        index.rebuild_metadata();
        Ok(index)
    }

    fn snapshot_path(dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("{name}.lsm"))
    }

    /// Forward range scan: returns all live `(key, rid)` pairs in `[start, end)`.
    pub fn scan(&self, start: Option<&[u8]>, end: Option<&[u8]>) -> Vec<(Vec<u8>, RecordId)> {
        self.history
            .iter()
            .filter(|(key, _)| {
                start.is_none_or(|s| key.as_slice() >= s) && end.is_none_or(|e| key.as_slice() < e)
            })
            .filter_map(|(key, versions)| {
                latest_visible(versions, u64::MAX).map(|rid| (key.clone(), rid))
            })
            .collect()
    }

    fn next_seq(&mut self) -> u64 {
        self.next_sequence += 1;
        self.next_sequence
    }

    /// Probabilistic bloom membership check for current live keys.
    ///
    /// Deleted keys may remain false positives until a rebuild. This filter must
    /// not gate historical snapshot reads, whose keys may now be tombstoned.
    pub fn may_contain_key(&self, key: &[u8]) -> bool {
        self.bloom.maybe_contains(key)
    }

    /// Fence pointer bounds `(min_key, max_key)` for live keys.
    pub fn fence_bounds(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (
            self.live_keys.first().cloned(),
            self.live_keys.last().cloned(),
        )
    }

    fn rebuild_metadata(&mut self) {
        self.live_keys.clear();
        self.version_count = 0;
        for (key, versions) in &self.history {
            self.version_count += versions.len() as u64;
            if latest_visible(versions, u64::MAX).is_some() {
                self.live_keys.insert(key.clone());
            }
        }
        self.rebuild_bloom();
    }

    fn rebuild_bloom(&mut self) {
        if self.live_keys.is_empty() {
            self.bloom = BloomMetadata::default();
            self.bloom_capacity = 0;
            self.bloom_insertions = 0;
            return;
        }
        // Geometric headroom amortizes rebuilds over live-key transitions.
        // The budget counts reinsertions too, so churn cannot saturate the
        // filter while its live cardinality stays small.
        let desired = self
            .live_keys
            .len()
            .saturating_mul(2)
            .max(MIN_BLOOM_CAPACITY);
        self.bloom_capacity = desired.checked_next_power_of_two().unwrap_or(desired);
        self.bloom = BloomMetadata::with_capacity(self.bloom_capacity, DEFAULT_BLOOM_FPR);
        for key in &self.live_keys {
            self.bloom.insert(key);
        }
        self.bloom_insertions = self.live_keys.len();
    }

    fn append_version(&mut self, key: &[u8], rid: Option<RecordId>, sequence: u64) {
        self.next_sequence = self.next_sequence.max(sequence);
        let versions = self.history.entry(key.to_vec()).or_default();
        let was_live = versions.last().is_some_and(|version| version.rid.is_some());
        // Preserve append order, including equal/decreasing caller sequences.
        // Historical visibility continues to use latest_visible unchanged.
        versions.push(VersionedRid { sequence, rid });
        self.version_count += 1;

        if rid.is_some() && !was_live {
            self.live_keys.insert(key.to_vec());
            if self.bloom_insertions >= self.bloom_capacity {
                self.rebuild_bloom();
            } else {
                self.bloom.insert(key);
                self.bloom_insertions += 1;
            }
        } else if rid.is_none() && was_live {
            self.live_keys.remove(key);
            // Clearing shared bits could reject other live keys. Shrink only
            // after crossing a geometric threshold; otherwise keep stale bits.
            if self.live_keys.is_empty()
                || (self.bloom_capacity > MIN_BLOOM_CAPACITY
                    && self.live_keys.len() < self.bloom_capacity / 4)
            {
                self.rebuild_bloom();
            }
        }
    }
}

impl IndexPlugin for LsmIndex {
    fn name(&self) -> &str {
        &self.name
    }

    fn put(&mut self, key: &[u8], rid: RecordId) -> Result<()> {
        let sequence = self.next_seq();
        self.put_with_sequence(key, rid, sequence)
    }

    fn put_with_sequence(&mut self, key: &[u8], rid: RecordId, sequence: u64) -> Result<()> {
        self.append_version(key, Some(rid), sequence);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<RecordId> {
        self.get_at(key, u64::MAX)
    }

    fn get_at(&self, key: &[u8], sequence: u64) -> Option<RecordId> {
        self.history
            .get(key)
            .and_then(|versions| latest_visible(versions, sequence))
    }

    fn delete(&mut self, key: &[u8]) -> Result<()> {
        let sequence = self.next_seq();
        self.delete_with_sequence(key, sequence)
    }

    fn delete_with_sequence(&mut self, key: &[u8], sequence: u64) -> Result<()> {
        self.append_version(key, None, sequence);
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        let (fence_min, fence_max) = self.fence_bounds();
        let on_disk = OnDisk {
            next_sequence: self.next_sequence,
            entries: self
                .history
                .iter()
                .map(|(key, versions)| (key.clone(), versions.clone()))
                .collect(),
            bloom_bits: self.bloom.bits.clone(),
            bloom_bit_len: self.bloom.bit_len,
            bloom_hashes: self.bloom.hashes,
            bloom_keys: Vec::new(),
            fence_min,
            fence_max,
        };
        let bytes = encode_binary_snapshot(&on_disk);
        std::fs::write(Self::snapshot_path(&self.dir, &self.name), bytes)?;
        Ok(())
    }

    fn compact(&mut self) -> Result<()> {
        for versions in self.history.values_mut() {
            if let Some(last) = versions.last().copied() {
                versions.clear();
                versions.push(last);
            }
        }
        self.history.retain(|_, versions| versions[0].rid.is_some());
        self.rebuild_metadata();
        Ok(())
    }

    fn stats(&self) -> IndexStats {
        IndexStats {
            live_keys: self.live_keys.len() as u64,
            versions: self.version_count,
        }
    }
}

fn latest_visible(versions: &[VersionedRid], sequence: u64) -> Option<RecordId> {
    versions
        .iter()
        .rev()
        .find(|version| version.sequence <= sequence)
        .and_then(|version| version.rid)
}

const DEFAULT_BLOOM_FPR: f64 = 0.01;
const MIN_BLOOM_CAPACITY: usize = 128;

fn hash_indexes(key: &[u8], hashes: u8, bit_len: usize) -> impl Iterator<Item = usize> + '_ {
    let digest = blake3::hash(key);
    let bytes = digest.as_bytes();
    let h1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0u8; 8]));
    let mut h2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0u8; 8]));
    if h2 == 0 {
        h2 = 0x9e37_79b9_7f4a_7c15;
    }
    (0..hashes).map(move |i| {
        let mixed = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (mixed % bit_len as u64) as usize
    })
}

fn bit_is_set(bits: &[u8], idx: usize) -> bool {
    let byte_idx = idx / 8;
    let bit_idx = idx % 8;
    bits.get(byte_idx)
        .is_some_and(|byte| (byte & (1u8 << bit_idx)) != 0)
}

fn set_bit(bits: &mut [u8], idx: usize) {
    let byte_idx = idx / 8;
    let bit_idx = idx % 8;
    if let Some(byte) = bits.get_mut(byte_idx) {
        *byte |= 1u8 << bit_idx;
    }
}

fn looks_like_binary_snapshot(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == LSM_SNAPSHOT_MAGIC
}

fn encode_binary_snapshot(on_disk: &OnDisk) -> Vec<u8> {
    let mut payload = BinaryWriter::new();
    payload.write_u64(on_disk.next_sequence);
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
    payload.write_len_bytes(&on_disk.bloom_bits);
    payload.write_u64(on_disk.bloom_bit_len as u64);
    payload.write_u8(on_disk.bloom_hashes);
    write_optional_bytes(&mut payload, on_disk.fence_min.as_ref());
    write_optional_bytes(&mut payload, on_disk.fence_max.as_ref());

    let payload = payload.into_inner();
    let mut out = BinaryWriter::new();
    out.write_u32(LSM_SNAPSHOT_MAGIC);
    out.write_u8(LSM_SNAPSHOT_VERSION);
    out.write_u32(payload.len() as u32);
    out.write_u32(crc32c(&payload));
    out.write_bytes(&payload);
    out.into_inner()
}

fn decode_binary_snapshot(bytes: &[u8], source: &Path) -> Result<OnDisk> {
    if bytes.len() < 13 {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "truncated LSM snapshot header".to_string(),
        });
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != LSM_SNAPSHOT_MAGIC {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "bad LSM snapshot magic".to_string(),
        });
    }
    if bytes[4] != LSM_SNAPSHOT_VERSION {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: format!("unsupported LSM snapshot version {}", bytes[4]),
        });
    }
    let payload_len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    let expected_crc = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    if bytes.len() < 13 + payload_len {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "truncated LSM snapshot payload".to_string(),
        });
    }
    let payload = &bytes[13..13 + payload_len];
    let actual_crc = crc32c(payload);
    if actual_crc != expected_crc {
        return Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: format!(
                "LSM snapshot checksum mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"
            ),
        });
    }

    let mut reader = BinaryReader::new(payload, source.to_path_buf());
    let next_sequence = reader.read_u64()?;
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
    let bloom_bits = reader.read_len_bytes()?;
    let bloom_bit_len = reader.read_u64()? as usize;
    let bloom_hashes = reader.read_u8()?;
    let fence_min = read_optional_bytes(&mut reader)?;
    let fence_max = read_optional_bytes(&mut reader)?;

    Ok(OnDisk {
        next_sequence,
        entries,
        bloom_bits,
        bloom_bit_len,
        bloom_hashes,
        bloom_keys: Vec::new(),
        fence_min,
        fence_max,
    })
}

fn write_optional_bytes(writer: &mut BinaryWriter, value: Option<&Vec<u8>>) {
    match value {
        Some(bytes) => {
            writer.write_u8(1);
            writer.write_len_bytes(bytes);
        }
        None => writer.write_u8(0),
    }
}

fn read_optional_bytes(reader: &mut BinaryReader<'_>) -> Result<Option<Vec<u8>>> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(reader.read_len_bytes()?)),
        _ => Err(PraxisError::Corrupt {
            path: PathBuf::from("lsm-snapshot"),
            reason: format!("invalid optional-bytes tag {tag}"),
        }),
    }
}
