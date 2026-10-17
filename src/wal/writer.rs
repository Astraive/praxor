use crate::config::WalSyncPolicy;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryWriter, sync_parent_dir};
use crate::wal::record::{RecordPrefix, WAL_MAGIC, WAL_V2_MAGIC, WalRecord, parse_record_prefix};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const WAL_FILE_MAGIC: u32 = 0x5457_4146;
const WAL_FILE_VERSION: u32 = 1;
const WAL_FILE_HEADER_LEN: usize = 16;

#[cfg(test)]
mod group_commit_failure_tests;

#[derive(Debug)]
pub struct Wal {
    path: PathBuf,
    segment_id: u64,
    file: File,
    sync_policy: WalSyncPolicy,
    bytes_written: u64,
}

impl Wal {
    pub fn open(
        path: impl Into<PathBuf>,
        segment_id: u64,
        sync_policy: WalSyncPolicy,
    ) -> Result<Self> {
        let path = path.into();
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(&path)?;
        let mut bytes_written = file.metadata()?.len();
        if bytes_written == 0 {
            let header = file_header(segment_id);
            file.write_all(&header)?;
            file.sync_data()?;
            sync_parent_dir(&path)?;
            bytes_written = header.len() as u64;
        } else {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let (_, valid_len) = replay_records(&bytes, &path)?;
            if is_partial_file_header(&bytes) {
                let header = file_header(segment_id);
                if !header.starts_with(&bytes) {
                    return Err(PraxisError::Corrupt {
                        path: path.clone(),
                        reason: "WAL file header prefix does not match segment id".to_string(),
                    });
                }
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&header)?;
                file.sync_data()?;
                sync_parent_dir(&path)?;
                bytes_written = header.len() as u64;
            } else if valid_len < bytes.len() {
                // Remove the incomplete append before any new records can be
                // written behind it and become unreachable during replay.
                file.set_len(valid_len as u64)?;
                file.sync_data()?;
                bytes_written = valid_len as u64;
            }
        }
        Ok(Self {
            path,
            segment_id,
            file,
            sync_policy,
            bytes_written,
        })
    }

    pub fn should_rotate(&self, next_record_len: usize, max_segment_bytes: usize) -> bool {
        self.bytes_written > WAL_FILE_HEADER_LEN as u64
            && self.bytes_written.saturating_add(next_record_len as u64) > max_segment_bytes as u64
    }

    pub fn append(&mut self, record: &WalRecord) -> Result<()> {
        self.append_unsynced(record)?;
        if matches!(self.sync_policy, WalSyncPolicy::EveryBatch) {
            self.file.sync_data()?;
        }
        Ok(())
    }

    /// The core coordinator explicitly syncs its closed group. Public callers
    /// of append retain the configured EveryBatch behavior above.
    pub(crate) fn append_unsynced(&mut self, record: &WalRecord) -> Result<()> {
        let encoded = record.try_encode()?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&encoded)?;
        self.bytes_written += encoded.len() as u64;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    pub fn replay_dir(root: &Path) -> Result<Vec<WalRecord>> {
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("wal") {
                paths.push(path);
            }
        }
        paths.sort();
        let mut records = Vec::new();
        for path in paths {
            records.extend(Self::replay(&path)?);
        }
        records.sort_by_key(|record| record.sequence);
        Ok(records)
    }

    pub fn replay(path: &Path) -> Result<Vec<WalRecord>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut file = File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        replay_records(&bytes, path).map(|(records, _)| records)
    }

    pub fn truncate(&mut self) -> Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub(crate) fn validate_backup_prefix(
        bytes: &[u8],
        path: &Path,
        id: u64,
        sequence: u64,
    ) -> Result<Vec<u64>> {
        if bytes.starts_with(&WAL_FILE_MAGIC.to_le_bytes())
            && (bytes.len() < WAL_FILE_HEADER_LEN
                || u64::from_le_bytes(bytes[8..16].try_into().expect("complete header")) != id)
        {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "backup WAL role/header ID mismatch".to_string(),
            });
        }
        let (records, end) = replay_records(bytes, path)?;
        if end != bytes.len() || records.iter().any(|record| record.sequence > sequence) {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "backup WAL prefix is incomplete or exceeds capture".to_string(),
            });
        }
        Ok(records.into_iter().map(|record| record.sequence).collect())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Return the decoded records and the end of the last complete record.
/// Framing, checksum and legacy length-probe decisions live in the same parser
/// used by direct decoding. Only a torn suffix may be repaired; Corrupt never
/// returns a boundary that Wal::open could silently truncate.
fn replay_records(bytes: &[u8], path: &Path) -> Result<(Vec<WalRecord>, usize)> {
    let mut offset = file_payload_offset(bytes, path)?;
    let mut records = Vec::new();
    while offset < bytes.len() {
        match parse_record_prefix(&bytes[offset..], path)? {
            RecordPrefix::Complete {
                record,
                encoded_len,
            } => {
                records.push(record);
                offset += encoded_len;
            }
            RecordPrefix::Torn => break,
        }
    }
    Ok((records, offset))
}

fn file_header(segment_id: u64) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(WAL_FILE_MAGIC);
    writer.write_u32(WAL_FILE_VERSION);
    writer.write_u64(segment_id);
    writer.into_inner()
}

fn file_payload_offset(bytes: &[u8], path: &Path) -> Result<usize> {
    if is_partial_file_header(bytes) {
        // An interrupted new segment has no complete records to replay.
        // Wal::open will complete the header before reusing the segment.
        return Ok(bytes.len());
    }
    if bytes.len() < 4
        && [WAL_MAGIC, WAL_V2_MAGIC]
            .iter()
            .any(|magic| magic.to_le_bytes().starts_with(bytes))
    {
        return Ok(0);
    }
    if bytes.len() < 4 {
        return Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "bad WAL file header prefix".to_string(),
        });
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if matches!(magic, WAL_MAGIC | WAL_V2_MAGIC) {
        return Ok(0); // Headerless legacy, current or mixed record stream.
    }
    if magic != WAL_FILE_MAGIC || bytes.len() < WAL_FILE_HEADER_LEN {
        return Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "invalid WAL file header".to_string(),
        });
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != WAL_FILE_VERSION {
        return Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unsupported WAL file version {version}"),
        });
    }
    Ok(WAL_FILE_HEADER_LEN)
}

fn is_partial_file_header(bytes: &[u8]) -> bool {
    // Replay need not know the segment id, but every available byte of the
    // magic and version must match. Open also checks the supplied segment id.
    let known_len = bytes.len().min(8);
    bytes.len() < WAL_FILE_HEADER_LEN && file_header(0)[..known_len] == bytes[..known_len]
}
