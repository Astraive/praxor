use super::RecordId;
use crate::errors::{PraxisError, Result};
use crate::io::sync_parent_dir;
use crc32fast::Hasher as Crc32Hasher;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const STORAGE_WAL_MAGIC: u32 = 0x5453_574c;
const STORAGE_WAL_VERSION: u8 = 1;
const STORAGE_WAL_PAYLOAD_MAGIC: u32 = 0x5453_5742;
const STORAGE_WAL_PAYLOAD_VERSION: u8 = 1;
const STORAGE_WAL_GROUP_VERSION: u8 = 2;
const STORAGE_WAL_GROUP_HEADER_LEN: usize = 13;
// The payload cap includes group and nested-entry metadata. The outer frame
// contributes another eight bytes; the segment size remains a rotation target.
pub(crate) const MAX_STORAGE_WAL_GROUP_BYTES: usize = 64 * 1024 * 1024;
const MIN_ENTRY_PAYLOAD_LEN: usize = 29;
const STORAGE_WAL_HEADER_LEN: usize = 5;
const STORAGE_WAL_RECORD_HEADER_LEN: usize = 8;
const DEFAULT_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StorageWalOperation {
    Put,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageWalEntry {
    pub sequence: u64,
    pub index_type: String,
    pub key: Vec<u8>,
    pub rid: Option<RecordId>,
    pub operation: StorageWalOperation,
}

pub struct StorageWal {
    path: PathBuf,
    dir: PathBuf,
    stem: String,
    active_segment_id: u64,
    active_segment_path: PathBuf,
    file: File,
    active_size: u64,
    max_segment_bytes: u64,
    recovery_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageWalOptions {
    pub max_segment_bytes: u64,
}

impl Default for StorageWalOptions {
    fn default() -> Self {
        Self {
            max_segment_bytes: DEFAULT_SEGMENT_BYTES,
        }
    }
}

impl StorageWal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_options(path, StorageWalOptions::default())
    }

    pub fn open_with_options(path: impl Into<PathBuf>, options: StorageWalOptions) -> Result<Self> {
        let path = path.into();
        let dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        crate::io::create_dir_all_durable(&dir)?;
        let stem = wal_stem(&path);

        // Older databases may still have an unsegmented WAL at `path`.
        // Validate it before creating a successor; replay retains it as the
        // immutable prefix when new segmented groups are appended.
        replay_file(&path)?;

        let mut segment_ids = list_segment_ids(&dir, &stem)?;
        segment_ids.sort_unstable();
        let active_segment_id = segment_ids.last().copied().unwrap_or(1);
        // Validate immutable segments before repairing the active one. New
        // appends must not succeed when replay would fail on an older segment.
        for &segment_id in segment_ids.iter().take(segment_ids.len().saturating_sub(1)) {
            replay_file(&segment_path(&dir, &stem, segment_id))?;
        }
        let active_segment_path = segment_path(&dir, &stem, active_segment_id);
        let (file, active_size) = open_segment_file(&active_segment_path)?;

        Ok(Self {
            path,
            dir,
            stem,
            active_segment_id,
            active_segment_path,
            file,
            active_size,
            max_segment_bytes: options.max_segment_bytes.max(1024),
            recovery_required: false,
        })
    }

    pub fn append(&mut self, entry: &StorageWalEntry) -> Result<()> {
        self.append_batch(std::slice::from_ref(entry))
    }

    /// Durably append all entries as one ordered, checksummed v2 group.
    /// Readers retain v1 binary/JSON support; v2 requires an upgraded reader.
    /// After an I/O error the handle must be closed and reopened before reuse.
    pub fn append_batch(&mut self, entries: &[StorageWalEntry]) -> Result<()> {
        if self.recovery_required {
            return Err(PraxisError::RecoveryRequired);
        }
        if entries.is_empty() {
            return Ok(());
        }

        // Encode and validate before any filesystem mutation. A group has one
        // checksum and one recovery boundary, even when larger than a segment.
        let encoded = encode_group_record(entries)?;
        let batch_bytes = encoded.len() as u64;
        let result = (|| {
            if self.active_size > STORAGE_WAL_HEADER_LEN as u64
                && self.active_size.saturating_add(batch_bytes) > self.max_segment_bytes
            {
                self.rotate_segment()?;
            }
            self.file.seek(SeekFrom::End(0))?;
            self.file.write_all(&encoded)?;
            self.file.sync_data()?;
            self.active_size += batch_bytes;
            Ok(())
        })();
        if result.is_err() {
            // A failed write or sync has an ambiguous durable outcome. Reopen
            // must validate/repair it before another group can be appended.
            self.recovery_required = true;
        }
        result
    }

    pub(crate) fn requires_recovery(&self) -> bool {
        self.recovery_required
    }

    pub(crate) fn validate_batch(entries: &[StorageWalEntry]) -> Result<()> {
        group_payload_len(entries).map(|_| ())
    }

    pub fn replay(path: &Path) -> Result<Vec<StorageWalEntry>> {
        let dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let stem = wal_stem(path);
        let mut segment_ids = list_segment_ids(&dir, &stem)?;
        segment_ids.sort_unstable();
        let mut out = replay_file(path)?;
        for segment_id in segment_ids {
            let segment = segment_path(&dir, &stem, segment_id);
            out.extend(replay_file(&segment)?);
        }
        Ok(out)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate_segment(&mut self) -> Result<()> {
        self.file.sync_data()?;
        let next_id = self
            .active_segment_id
            .checked_add(1)
            .ok_or_else(|| PraxisError::InvalidConfig("storage WAL segment id exhausted".into()))?;
        let next_path = segment_path(&self.dir, &self.stem, next_id);
        let (file, active_size) = open_segment_file(&next_path)?;
        self.active_segment_id = next_id;
        self.active_segment_path = next_path;
        self.file = file;
        self.active_size = active_size;
        Ok(())
    }
}

fn wal_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("storage")
        .to_string()
}

fn segment_path(dir: &Path, stem: &str, segment_id: u64) -> PathBuf {
    dir.join(format!("{stem}.{segment_id:020}.swal"))
}

fn list_segment_ids(dir: &Path, stem: &str) -> Result<Vec<u64>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let prefix = format!("{stem}.");
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("swal") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let middle = name
            .strip_prefix(&prefix)
            .and_then(|suffix| suffix.strip_suffix(".swal"));
        if let Some(raw_id) = middle
            && let Ok(segment_id) = raw_id.parse::<u64>()
        {
            ids.push(segment_id);
        }
    }
    Ok(ids)
}

fn open_segment_file(path: &Path) -> Result<(File, u64)> {
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (_, valid_len) = replay_records(&bytes, path)?;
    if bytes.len() < STORAGE_WAL_HEADER_LEN {
        // A crash can interrupt creation of the segment header itself. The
        // scanner accepts only a matching prefix, so completing it is safe.
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&STORAGE_WAL_MAGIC.to_le_bytes())?;
        file.write_all(&[STORAGE_WAL_VERSION])?;
        file.sync_data()?;
        sync_parent_dir(path)?;
    } else if valid_len < bytes.len() {
        // New records must start at the recovered boundary, not behind a
        // torn append that would hide them from subsequent replay.
        file.set_len(valid_len as u64)?;
        file.sync_data()?;
    }
    let size = file.metadata()?.len();
    Ok((file, size))
}

fn replay_file(path: &Path) -> Result<Vec<StorageWalEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    replay_records(&bytes, path).map(|(records, _)| records)
}

/// A short terminal record header or a payload extending past EOF is a torn
/// append. Complete records must pass checksum and payload validation; errors
/// are corruption, even when the affected record is the final one in a file.
fn replay_records(bytes: &[u8], path: &Path) -> Result<(Vec<StorageWalEntry>, usize)> {
    if bytes.len() < STORAGE_WAL_HEADER_LEN {
        let mut header = STORAGE_WAL_MAGIC.to_le_bytes().to_vec();
        header.push(STORAGE_WAL_VERSION);
        return if header.starts_with(bytes) {
            Ok((Vec::new(), 0))
        } else {
            Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "bad partial storage WAL header".to_string(),
            })
        };
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != STORAGE_WAL_MAGIC {
        return Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "bad storage WAL magic".to_string(),
        });
    }
    if bytes[4] != STORAGE_WAL_VERSION {
        return Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unsupported storage WAL version {}", bytes[4]),
        });
    }

    let mut out = Vec::new();
    let mut cursor = STORAGE_WAL_HEADER_LEN;
    while bytes.len() - cursor >= STORAGE_WAL_RECORD_HEADER_LEN {
        let len = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        let expected = u32::from_le_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]);
        let start = cursor + STORAGE_WAL_RECORD_HEADER_LEN;
        // The mirrored length belongs to the checksummed v2 payload. Inspect
        // it before treating an oversized outer length as an interrupted write.
        let available = &bytes[start..];
        if available.len() >= 5
            && available[..4] == STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes()
            && ![STORAGE_WAL_PAYLOAD_VERSION, STORAGE_WAL_GROUP_VERSION].contains(&available[4])
        {
            return Err(payload_corrupt(format!(
                "unsupported storage WAL payload version {}",
                available[4]
            )));
        }
        if available.len() >= 5
            && available[..4] == STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes()
            && available[4] == STORAGE_WAL_GROUP_VERSION
        {
            if !(STORAGE_WAL_GROUP_HEADER_LEN..=MAX_STORAGE_WAL_GROUP_BYTES).contains(&len) {
                return Err(payload_corrupt("invalid storage WAL group size"));
            }
            if available.len() >= 9 {
                let mirror = u32::from_le_bytes(available[5..9].try_into().unwrap()) as usize;
                if mirror != len {
                    return Err(payload_corrupt("storage WAL group length mismatch"));
                }
            }
        }
        if len > bytes.len() - start {
            break;
        }
        let end = start + len;
        let payload = &bytes[start..end];
        if crc32(payload) != expected {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("storage WAL checksum mismatch at offset {cursor}"),
            });
        }
        out.extend(decode_record_payload(payload)?);
        cursor = end;
    }
    Ok((out, cursor))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

// V2 payload: [magic:u32][version:u8][payload_len:u32][count:u32], followed
// by [entry_len:u32][v1_binary_entry] for each ordered entry. The existing
// outer [length:u32][payload_crc:u32] frame checksums the complete envelope.
fn encode_group_record(entries: &[StorageWalEntry]) -> Result<Vec<u8>> {
    let len = group_payload_len(entries)?;
    let mut payload = Vec::with_capacity(len);
    payload.extend_from_slice(&STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes());
    payload.push(STORAGE_WAL_GROUP_VERSION);
    payload.extend_from_slice(&(len as u32).to_le_bytes());
    payload.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        let inner = encode_payload(entry)?;
        payload.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        payload.extend_from_slice(&inner);
    }
    let checksum = crc32(&payload);
    let mut out = Vec::with_capacity(STORAGE_WAL_RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn group_payload_len(entries: &[StorageWalEntry]) -> Result<usize> {
    u32::try_from(entries.len())
        .map_err(|_| PraxisError::InvalidConfig("too many storage WAL group entries".into()))?;
    let mut len = STORAGE_WAL_GROUP_HEADER_LEN;
    for entry in entries {
        if entry.index_type.len() > u16::MAX as usize || entry.key.len() > u32::MAX as usize {
            return Err(PraxisError::InvalidConfig(
                "storage WAL entry exceeds binary payload limit".into(),
            ));
        }
        len = len
            .checked_add(4)
            .and_then(|n| n.checked_add(MIN_ENTRY_PAYLOAD_LEN))
            .and_then(|n| n.checked_add(entry.index_type.len()))
            .and_then(|n| n.checked_add(entry.key.len()))
            .ok_or_else(|| PraxisError::InvalidConfig("storage WAL group size overflow".into()))?;
        if len > MAX_STORAGE_WAL_GROUP_BYTES {
            return Err(PraxisError::InvalidConfig(
                "storage WAL group exceeds 64 MiB limit".into(),
            ));
        }
    }
    Ok(len)
}

fn decode_record_payload(payload: &[u8]) -> Result<Vec<StorageWalEntry>> {
    if payload.len() < 5
        || payload[..4] != STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes()
        || payload[4] != STORAGE_WAL_GROUP_VERSION
    {
        return decode_payload(payload).map(|entry| vec![entry]);
    }
    if payload.len() > MAX_STORAGE_WAL_GROUP_BYTES {
        return Err(payload_corrupt("storage WAL group exceeds 64 MiB limit"));
    }
    let mut cursor = 5;
    if read_u32(payload, &mut cursor)? as usize != payload.len() {
        return Err(payload_corrupt("storage WAL group length mismatch"));
    }
    let count = read_u32(payload, &mut cursor)? as usize;
    if count == 0 || count > (payload.len() - cursor) / (4 + MIN_ENTRY_PAYLOAD_LEN) {
        return Err(payload_corrupt("invalid storage WAL group entry count"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(payload, &mut cursor)? as usize;
        let end = cursor
            .checked_add(len)
            .ok_or_else(|| payload_corrupt("entry length overflow"))?;
        let inner = payload
            .get(cursor..end)
            .ok_or_else(|| payload_corrupt("truncated group entry"))?;
        if inner.len() < MIN_ENTRY_PAYLOAD_LEN
            || inner[..4] != STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes()
            || inner[4] != STORAGE_WAL_PAYLOAD_VERSION
        {
            return Err(payload_corrupt("invalid nested storage WAL entry"));
        }
        entries.push(decode_payload(inner)?);
        cursor = end;
    }
    if cursor != payload.len() {
        return Err(payload_corrupt("trailing storage WAL group bytes"));
    }
    Ok(entries)
}

fn encode_payload(entry: &StorageWalEntry) -> Result<Vec<u8>> {
    if entry.index_type.len() > u16::MAX as usize {
        return Err(PraxisError::InvalidConfig(
            "storage WAL index type exceeds binary payload limit".to_string(),
        ));
    }
    if entry.key.len() > u32::MAX as usize {
        return Err(PraxisError::InvalidConfig(
            "storage WAL key exceeds binary payload limit".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(31 + entry.index_type.len() + entry.key.len());
    out.extend_from_slice(&STORAGE_WAL_PAYLOAD_MAGIC.to_le_bytes());
    out.push(STORAGE_WAL_PAYLOAD_VERSION);
    out.extend_from_slice(&entry.sequence.to_le_bytes());
    out.push(match entry.operation {
        StorageWalOperation::Put => 1,
        StorageWalOperation::Delete => 2,
    });
    out.extend_from_slice(&(entry.index_type.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entry.key.len() as u32).to_le_bytes());
    match entry.rid {
        Some(rid) => {
            out.push(1);
            out.extend_from_slice(&rid.0.to_le_bytes());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&0_u64.to_le_bytes());
        }
    }
    out.extend_from_slice(entry.index_type.as_bytes());
    out.extend_from_slice(&entry.key);
    Ok(out)
}

fn decode_payload(payload: &[u8]) -> Result<StorageWalEntry> {
    if payload.len() < 5 {
        return Ok(serde_json::from_slice(payload)?);
    }
    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if magic != STORAGE_WAL_PAYLOAD_MAGIC {
        return Ok(serde_json::from_slice(payload)?);
    }
    if payload[4] != STORAGE_WAL_PAYLOAD_VERSION {
        return Err(PraxisError::Corrupt {
            path: PathBuf::from("<storage-wal-payload>"),
            reason: format!("unsupported storage WAL payload version {}", payload[4]),
        });
    }

    let mut cursor = 5;
    let sequence = read_u64(payload, &mut cursor)?;
    let operation = match read_u8(payload, &mut cursor)? {
        1 => StorageWalOperation::Put,
        2 => StorageWalOperation::Delete,
        code => {
            return Err(PraxisError::Corrupt {
                path: PathBuf::from("<storage-wal-payload>"),
                reason: format!("unknown storage WAL operation code {code}"),
            });
        }
    };
    let index_len = read_u16(payload, &mut cursor)? as usize;
    let key_len = read_u32(payload, &mut cursor)? as usize;
    let rid_present = read_u8(payload, &mut cursor)?;
    let raw_rid = read_u64(payload, &mut cursor)?;

    let index_end = cursor
        .checked_add(index_len)
        .ok_or_else(|| payload_corrupt("index length overflow"))?;
    let key_end = index_end
        .checked_add(key_len)
        .ok_or_else(|| payload_corrupt("key length overflow"))?;
    if key_end != payload.len() {
        return Err(payload_corrupt(
            "payload length does not match encoded fields",
        ));
    }

    let index_type = std::str::from_utf8(&payload[cursor..index_end])
        .map_err(|err| payload_corrupt(format!("index type is not utf-8: {err}")))?
        .to_string();
    let key = payload[index_end..key_end].to_vec();
    let rid = match rid_present {
        0 => None,
        1 => Some(RecordId(raw_rid)),
        code => {
            return Err(payload_corrupt(format!(
                "invalid storage WAL rid-present flag {code}"
            )));
        }
    };

    Ok(StorageWalEntry {
        sequence,
        index_type,
        key,
        rid,
        operation,
    })
}

fn read_u8(payload: &[u8], cursor: &mut usize) -> Result<u8> {
    let Some(value) = payload.get(*cursor).copied() else {
        return Err(payload_corrupt("unexpected end of payload"));
    };
    *cursor += 1;
    Ok(value)
}

fn read_u16(payload: &[u8], cursor: &mut usize) -> Result<u16> {
    let end = cursor
        .checked_add(2)
        .ok_or_else(|| payload_corrupt("cursor overflow"))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| payload_corrupt("unexpected end of payload"))?;
    *cursor = end;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("slice length checked"),
    ))
}

fn read_u32(payload: &[u8], cursor: &mut usize) -> Result<u32> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| payload_corrupt("cursor overflow"))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| payload_corrupt("unexpected end of payload"))?;
    *cursor = end;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("slice length checked"),
    ))
}

fn read_u64(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let end = cursor
        .checked_add(8)
        .ok_or_else(|| payload_corrupt("cursor overflow"))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| payload_corrupt("unexpected end of payload"))?;
    *cursor = end;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("slice length checked"),
    ))
}

fn payload_corrupt(reason: impl Into<String>) -> PraxisError {
    PraxisError::Corrupt {
        path: PathBuf::from("<storage-wal-payload>"),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_wal_binary_payload_roundtrips() {
        let entry = StorageWalEntry {
            sequence: 42,
            index_type: "kv".to_string(),
            key: b"hello".to_vec(),
            rid: Some(RecordId(7)),
            operation: StorageWalOperation::Put,
        };

        let payload = encode_payload(&entry).unwrap();

        assert_ne!(payload.first(), Some(&b'{'));
        assert_eq!(decode_payload(&payload).unwrap(), entry);
    }

    #[test]
    fn storage_wal_replay_accepts_legacy_json_payloads() {
        let entry = StorageWalEntry {
            sequence: 43,
            index_type: "legacy".to_string(),
            key: b"json".to_vec(),
            rid: None,
            operation: StorageWalOperation::Delete,
        };
        let payload = serde_json::to_vec(&entry).unwrap();

        assert_eq!(decode_payload(&payload).unwrap(), entry);
    }
}
