use crate::config::WalSyncPolicy;
use crate::core_records::codec::Envelope;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryWriter, sync_parent_dir};
use crate::wal::record::{
    CoreRecordPrefix, CoreWalRecord, MAX_CATALOG_WAL_FRAME_BYTES, RecordPrefix, WAL_MAGIC,
    WAL_RECORD_HEADER_LEN, WAL_V2_MAGIC, WalRecord, parse_core_record_prefix, parse_record_prefix,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const WAL_FILE_MAGIC: u32 = 0x5457_4146;
const WAL_FILE_VERSION: u32 = 1;
const WAL_FILE_HEADER_LEN: usize = 16;
const MAX_BUFFERED_LEGACY_FRAME: u64 = 8 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static LEGACY_SECOND_PASS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

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
        Self::open_impl(path.into(), segment_id, sync_policy, false)
    }

    pub(crate) fn open_core(
        path: impl Into<PathBuf>,
        segment_id: u64,
        sync_policy: WalSyncPolicy,
    ) -> Result<Self> {
        Self::open_impl(path.into(), segment_id, sync_policy, true)
    }

    fn open_impl(
        path: PathBuf,
        segment_id: u64,
        sync_policy: WalSyncPolicy,
        typed_core: bool,
    ) -> Result<Self> {
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
            let valid_len = if typed_core {
                replay_core_records(&bytes, &path)?.1
            } else {
                replay_records(&bytes, &path)?.1
            };
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
        self.append_encoded(&encoded)
    }

    pub(crate) fn append_user_batch_unsynced(
        &mut self,
        sequence: u64,
        batch: &crate::transactions::WriteBatch,
    ) -> Result<()> {
        let encoded = crate::wal::record::encode_record(sequence, batch, None)?;
        self.append_encoded(&encoded)
    }

    fn append_encoded(&mut self, encoded: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(encoded)?;
        self.bytes_written += encoded.len() as u64;
        Ok(())
    }

    pub(crate) fn append_core_unsynced(&mut self, record: &CoreWalRecord) -> Result<()> {
        let encoded = record.try_encode()?;
        self.append_encoded(&encoded)
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
    ) -> Result<Vec<CoreWalRecord>> {
        Self::validate_backup_prefix_for_owner(bytes, path, id, sequence, true, true)
    }

    /// Classify complete records before checking a capture's sequence bound.
    /// A retired generic WAL is inspected with its existing torn-tail policy;
    /// copied and protected prefixes must be complete at the captured length.
    pub(crate) fn validate_backup_prefix_for_owner(
        bytes: &[u8],
        path: &Path,
        id: u64,
        sequence: u64,
        record_authority: bool,
        strict: bool,
    ) -> Result<Vec<CoreWalRecord>> {
        if bytes.starts_with(&WAL_FILE_MAGIC.to_le_bytes())
            && (bytes.len() < WAL_FILE_HEADER_LEN
                || u64::from_le_bytes(bytes[8..16].try_into().expect("complete header")) != id)
        {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "backup WAL role/header ID mismatch".to_string(),
            });
        }
        let (records, end) = replay_core_records(bytes, path)?;
        for record in &records {
            classify_backup_record(record, path, record_authority)?;
        }
        if strict
            && (end != bytes.len() || records.iter().any(|record| record.sequence() > sequence))
        {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "backup WAL prefix is incomplete or exceeds capture".to_string(),
            });
        }
        Ok(records)
    }

    /// Inspect an exact captured WAL without buffering the whole file or
    /// accumulating decoded records. V2 frames have their wire-format 64 MiB
    /// ceiling; large v1 frames and length probes use fixed-size chunks. The
    /// digest binds later staged bytes to this scan.
    pub(crate) fn inspect_backup_file_for_owner(
        path: &Path,
        id: u64,
        captured_len: u64,
        sequence: u64,
        record_authority: bool,
        strict: bool,
        mut visit_sequence: impl FnMut(u64) -> Result<()>,
    ) -> Result<blake3::Hash> {
        let mut file = File::open(path)?;
        if file.metadata()?.len() != captured_len {
            return backup_file_changed(path);
        }
        let mut lead = [0u8; WAL_FILE_HEADER_LEN];
        let lead_len = captured_len.min(WAL_FILE_HEADER_LEN as u64) as usize;
        file.read_exact(&mut lead[..lead_len])?;
        if lead[..lead_len].starts_with(&WAL_FILE_MAGIC.to_le_bytes()) {
            if lead_len < WAL_FILE_HEADER_LEN {
                if strict || !file_header(id).starts_with(&lead[..lead_len]) {
                    return Err(PraxisError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "backup WAL role/header ID mismatch".to_string(),
                    });
                }
                let mut digest = blake3::Hasher::new();
                digest.update(&lead[..lead_len]);
                if file.metadata()?.len() != captured_len {
                    return backup_file_changed(path);
                }
                return Ok(digest.finalize());
            }
            if u64::from_le_bytes(lead[8..16].try_into().expect("complete header")) != id {
                return Err(PraxisError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "backup WAL role/header ID mismatch".to_string(),
                });
            }
        }
        let payload_offset = file_payload_offset(&lead[..lead_len], path)?;
        let mut digest = blake3::Hasher::new();
        if payload_offset == lead_len {
            digest.update(&lead[..lead_len]);
        }
        let mut offset = payload_offset as u64;
        file.seek(SeekFrom::Start(offset))?;
        while offset < captured_len {
            let remaining = captured_len - offset;
            let mut header = [0u8; WAL_FILE_HEADER_LEN];
            let first = remaining.min(12) as usize;
            file.read_exact(&mut header[..first])?;
            digest.update(&header[..first]);
            if first < 12 {
                // The shared parser treats a short terminal record header as
                // a torn suffix regardless of its partial magic bytes.
                if strict {
                    return backup_prefix_incomplete(path);
                }
                break;
            }
            let magic = u32::from_le_bytes(header[..4].try_into().expect("magic"));
            let header_len = match magic {
                WAL_MAGIC => 12,
                WAL_V2_MAGIC => WAL_RECORD_HEADER_LEN,
                _ => {
                    parse_core_record_prefix(&header[..first], path)?;
                    unreachable!("invalid magic must be rejected by shared parser")
                }
            };
            if header_len > first {
                let extra = (remaining - first as u64).min((header_len - first) as u64) as usize;
                file.read_exact(&mut header[first..first + extra])?;
                digest.update(&header[first..first + extra]);
                if first + extra < header_len {
                    if strict {
                        return backup_prefix_incomplete(path);
                    }
                    break;
                }
            }
            // Authenticate v2 header CRC and length before reserving payload.
            let _ = parse_core_record_prefix(&header[..header_len], path)?;
            let payload_len = u32::from_le_bytes(header[4..8].try_into().expect("length")) as u64;
            let encoded_len = header_len as u64 + payload_len;
            if magic == WAL_MAGIC && encoded_len.min(remaining) > MAX_BUFFERED_LEGACY_FRAME {
                let payload_start = offset + header_len as u64;
                let available_payload = (remaining - header_len as u64).min(payload_len);
                let second_pass_digest = digest.clone();
                let crc = hash_captured_suffix(&mut file, &mut digest, available_payload)?;
                let captured_digest = digest.finalize();
                let complete = encoded_len <= remaining;
                if complete && crc != u32::from_le_bytes(header[8..12].try_into().expect("CRC")) {
                    return wal_corrupt(path, "WAL checksum mismatch");
                }
                #[cfg(test)]
                LEGACY_SECOND_PASS_HOOK.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().take() {
                        hook();
                    }
                });
                file.seek(SeekFrom::Start(payload_start))?;
                let scan = walk_legacy_payload_file(
                    &mut file,
                    available_payload,
                    path,
                    second_pass_digest,
                )?;
                if scan.full_crc != crc || scan.full_digest != captured_digest {
                    return backup_file_changed(path);
                }
                let walked = scan.record;
                if !complete {
                    if let Some((_, _, consumed_crc, _)) = walked
                        && consumed_crc
                            == u32::from_le_bytes(header[8..12].try_into().expect("CRC"))
                    {
                        return wal_corrupt(
                            path,
                            "legacy WAL length disagrees with intact payload",
                        );
                    }
                    if strict {
                        return backup_prefix_incomplete(path);
                    }
                    break;
                }
                let Some((record_sequence, consumed, _, protected)) = walked else {
                    return wal_corrupt(path, "truncated WAL payload");
                };
                if consumed != payload_len {
                    return wal_corrupt(path, "trailing WAL payload bytes");
                }
                if protected {
                    return wal_corrupt(path, "record authority requires v2 WAL framing");
                }
                if strict && record_sequence > sequence {
                    return backup_prefix_incomplete(path);
                }
                visit_sequence(record_sequence)?;
                offset += encoded_len;
                file.seek(SeekFrom::Start(offset))?;
                continue;
            }
            if magic == WAL_V2_MAGIC && encoded_len > remaining {
                hash_captured_suffix(&mut file, &mut digest, remaining - header_len as u64)?;
                if strict {
                    return backup_prefix_incomplete(path);
                }
                break;
            }
            // Read the authenticated v2 control prefix only once. A catalog
            // frame above the v4 bound is checksummed in fixed-size chunks;
            // the same bytes feed the captured digest, and no second read can
            // classify a different hard-linked version of this frame.
            let mut v2_prefix = [0u8; 13];
            let v2_prefix_len = if magic == WAL_V2_MAGIC {
                (payload_len as usize).min(v2_prefix.len())
            } else {
                0
            };
            if v2_prefix_len != 0 {
                file.read_exact(&mut v2_prefix[..v2_prefix_len])?;
                digest.update(&v2_prefix[..v2_prefix_len]);
            }
            let catalog_v2 = v2_prefix_len == v2_prefix.len()
                && u32::from_le_bytes(v2_prefix[8..12].try_into().expect("op count")) != 0
                && matches!(v2_prefix[12], 6 | 7);
            if catalog_v2 && encoded_len > MAX_CATALOG_WAL_FRAME_BYTES as u64 {
                let mut crc = crc32fast::Hasher::new();
                crc.update(&v2_prefix);
                hash_captured_suffix_with_crc(
                    &mut file,
                    &mut digest,
                    payload_len - v2_prefix_len as u64,
                    &mut crc,
                )?;
                if crc.finalize() != u32::from_le_bytes(header[8..12].try_into().expect("CRC")) {
                    return wal_corrupt(path, "WAL checksum mismatch");
                }
                return wal_corrupt(path, "catalog WAL frame exceeds 1 MiB limit");
            }
            let available = encoded_len.min(remaining);
            let reserve = usize::try_from(available).map_err(|_| PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "captured WAL frame exceeds address space".to_string(),
            })?;
            let mut frame = Vec::new();
            frame
                .try_reserve_exact(reserve)
                .map_err(|_| PraxisError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "cannot reserve captured WAL frame".to_string(),
                })?;
            frame.extend_from_slice(&header[..header_len]);
            frame.extend_from_slice(&v2_prefix[..v2_prefix_len]);
            frame.resize(reserve, 0);
            file.read_exact(&mut frame[header_len + v2_prefix_len..])?;
            digest.update(&frame[header_len + v2_prefix_len..]);
            match parse_core_record_prefix(&frame, path)? {
                CoreRecordPrefix::Complete {
                    record,
                    encoded_len: decoded_len,
                } if decoded_len == reserve && available == encoded_len => {
                    classify_backup_record(&record, path, record_authority)?;
                    if strict && record.sequence() > sequence {
                        return backup_prefix_incomplete(path);
                    }
                    visit_sequence(record.sequence())?;
                }
                CoreRecordPrefix::Torn if !strict => break,
                CoreRecordPrefix::Torn => return backup_prefix_incomplete(path),
                CoreRecordPrefix::Complete { .. } => return backup_prefix_incomplete(path),
            }
            offset += available;
        }
        if file.metadata()?.len() != captured_len {
            return backup_file_changed(path);
        }
        Ok(digest.finalize())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn classify_backup_record(
    record: &CoreWalRecord,
    path: &Path,
    record_authority: bool,
) -> Result<()> {
    match record {
        CoreWalRecord::User(_) => {}
        CoreWalRecord::Record { .. } if record_authority => {}
        CoreWalRecord::Record { .. } => {
            return Err(PraxisError::RecordAuthorityWalRequired {
                path: path.to_path_buf(),
            });
        }
        CoreWalRecord::Catalog { .. } => {
            return Err(PraxisError::CatalogAuthorityWalRequired {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn backup_prefix_incomplete<T>(path: &Path) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: "backup WAL prefix is incomplete or exceeds capture".to_string(),
    })
}

fn backup_file_changed<T>(path: &Path) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: "captured WAL changed during validation".to_string(),
    })
}

fn hash_captured_suffix(file: &mut File, digest: &mut blake3::Hasher, len: u64) -> Result<u32> {
    let mut crc = crc32fast::Hasher::new();
    hash_captured_suffix_with_crc(file, digest, len, &mut crc)?;
    Ok(crc.finalize())
}

fn hash_captured_suffix_with_crc(
    file: &mut File,
    digest: &mut blake3::Hasher,
    mut len: u64,
    crc: &mut crc32fast::Hasher,
) -> Result<()> {
    let mut buffer = [0u8; 64 * 1024];
    while len != 0 {
        let next = len.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..next])?;
        digest.update(&buffer[..next]);
        crc.update(&buffer[..next]);
        len -= next as u64;
    }
    Ok(())
}

fn wal_corrupt<T>(path: &Path, reason: impl Into<String>) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    })
}

/// The legacy v1 wire length is unauthenticated and can advertise nearly
/// 4 GiB. Walk its fields with fixed-size buffers instead of reserving that
/// length. This mirrors walk_payload's structural/torn decisions and returns
/// a CRC of the consumed self-delimiting body for its length-only probe.
struct LegacyPayloadScan {
    record: Option<(u64, u64, u32, bool)>,
    full_crc: u32,
    full_digest: blake3::Hash,
}

fn walk_legacy_payload_file(
    file: &mut File,
    available: u64,
    path: &Path,
    digest: blake3::Hasher,
) -> Result<LegacyPayloadScan> {
    let mut reader = LegacyPayloadFileReader {
        file,
        remaining: available,
        consumed: 0,
        crc: crc32fast::Hasher::new(),
        digest,
    };
    let walked = walk_legacy_payload(&mut reader, path)?;
    // A self-delimiting body can stop before the captured suffix ends. Drain
    // those bytes through this same second-pass witness before a torn break.
    reader.skip_bytes(reader.remaining)?;
    Ok(LegacyPayloadScan {
        record: walked,
        full_crc: reader.crc.finalize(),
        full_digest: reader.digest.finalize(),
    })
}

fn walk_legacy_payload(
    reader: &mut LegacyPayloadFileReader<'_>,
    path: &Path,
) -> Result<Option<(u64, u64, u32, bool)>> {
    let Some(sequence) = reader.fixed::<8>()? else {
        return Ok(None);
    };
    let sequence = u64::from_le_bytes(sequence);
    let Some(count) = reader.fixed::<4>()? else {
        return Ok(None);
    };
    let count = u32::from_le_bytes(count) as u64;
    if count > reader.remaining / 9 {
        return Ok(None);
    }
    let mut protected = false;
    for index in 0..count {
        let Some([tag]) = reader.fixed::<1>()? else {
            return Ok(None);
        };
        if tag == 5 {
            if index != 0 {
                return wal_corrupt(path, "record authority control must occur once and first");
            }
            let Some(length) = reader.fixed::<4>()? else {
                return Ok(None);
            };
            let length = u32::from_le_bytes(length) as u64;
            if length > reader.remaining {
                return Ok(None);
            }
            if length != Envelope::LEN as u64 {
                return wal_corrupt(path, "invalid record envelope length");
            }
            let envelope = reader
                .fixed::<{ Envelope::LEN }>()?
                .expect("length checked");
            Envelope::decode(&envelope, sequence, path)?;
            protected = true;
            continue;
        }
        if !matches!(tag, 1..=4) {
            return wal_corrupt(path, format!("unknown WAL op tag {tag}"));
        }
        if reader.field(true, path)?.is_none() || reader.field(false, path)?.is_none() {
            return Ok(None);
        }
        if tag != 2 {
            if reader.field(false, path)?.is_none() {
                return Ok(None);
            }
            if tag == 3 && reader.fixed::<8>()?.is_none() {
                return Ok(None);
            }
        }
    }
    Ok(Some((
        sequence,
        reader.consumed,
        reader.crc.clone().finalize(),
        protected,
    )))
}

struct LegacyPayloadFileReader<'a> {
    file: &'a mut File,
    remaining: u64,
    consumed: u64,
    crc: crc32fast::Hasher,
    digest: blake3::Hasher,
}

impl LegacyPayloadFileReader<'_> {
    fn read_into(&mut self, buffer: &mut [u8]) -> Result<()> {
        self.file.read_exact(buffer)?;
        self.crc.update(buffer);
        self.digest.update(buffer);
        self.remaining -= buffer.len() as u64;
        self.consumed += buffer.len() as u64;
        Ok(())
    }

    fn fixed<const N: usize>(&mut self) -> Result<Option<[u8; N]>> {
        if self.remaining < N as u64 {
            return Ok(None);
        }
        let mut bytes = [0u8; N];
        self.read_into(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn field(&mut self, utf8: bool, path: &Path) -> Result<Option<()>> {
        let Some(length) = self.fixed::<4>()? else {
            return Ok(None);
        };
        let length = u32::from_le_bytes(length) as u64;
        if length > self.remaining {
            return Ok(None);
        }
        if utf8 {
            self.utf8_bytes(length, path)?;
        } else {
            self.skip_bytes(length)?;
        }
        Ok(Some(()))
    }

    fn skip_bytes(&mut self, mut len: u64) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        while len != 0 {
            let next = len.min(buffer.len() as u64) as usize;
            self.read_into(&mut buffer[..next])?;
            len -= next as u64;
        }
        Ok(())
    }

    fn utf8_bytes(&mut self, mut len: u64, path: &Path) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024 + 4];
        let mut pending = [0u8; 4];
        let mut pending_len = 0;
        while len != 0 {
            buffer[..pending_len].copy_from_slice(&pending[..pending_len]);
            let next = len.min((buffer.len() - 4) as u64) as usize;
            self.read_into(&mut buffer[pending_len..pending_len + next])?;
            let combined = &buffer[..pending_len + next];
            match std::str::from_utf8(combined) {
                Ok(_) => pending_len = 0,
                Err(error) if error.error_len().is_none() => {
                    let suffix = &combined[error.valid_up_to()..];
                    pending_len = suffix.len();
                    if pending_len > 3 {
                        return wal_corrupt(path, "invalid WAL column family UTF-8");
                    }
                    pending[..pending_len].copy_from_slice(suffix);
                }
                Err(_) => return wal_corrupt(path, "invalid WAL column family UTF-8"),
            }
            len -= next as u64;
        }
        if pending_len != 0 {
            return wal_corrupt(path, "invalid WAL column family UTF-8");
        }
        Ok(())
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

pub(crate) fn replay_core_records(
    bytes: &[u8],
    path: &Path,
) -> Result<(Vec<CoreWalRecord>, usize)> {
    let mut offset = file_payload_offset(bytes, path)?;
    let mut records = Vec::new();
    while offset < bytes.len() {
        match parse_core_record_prefix(&bytes[offset..], path)? {
            CoreRecordPrefix::Complete {
                record,
                encoded_len,
            } => {
                records.push(record);
                offset += encoded_len;
            }
            CoreRecordPrefix::Torn => break,
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

#[cfg(test)]
mod legacy_second_pass_tests {
    use super::*;

    fn put(payload: &mut Vec<u8>, value_len: usize) {
        payload.push(1);
        payload.extend(1u32.to_le_bytes());
        payload.push(b'x');
        payload.extend(1u32.to_le_bytes());
        payload.push(b'k');
        payload.extend((value_len as u32).to_le_bytes());
        payload.resize(payload.len() + value_len, b'v');
    }

    fn legacy_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = WAL_MAGIC.to_le_bytes().to_vec();
        frame.extend((payload.len() as u32).to_le_bytes());
        frame.extend(crc32fast::hash(payload).to_le_bytes());
        frame.extend(payload);
        frame
    }

    #[test]
    fn large_v1_second_pass_cannot_authorize_a_transient_user_rewrite() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("00000000000000000001.wal");
        let alias = temp.path().join("external-hardlink.wal");
        let target_payload_len = 9 * 1024 * 1024;
        let protected = include_bytes!("../../tests/fixtures/tag5_bootstrap_s1.bin");
        let mut protected_payload = 1u64.to_le_bytes().to_vec();
        protected_payload.extend(2u32.to_le_bytes());
        protected_payload.extend(&protected[28..]);
        let protected_value_len = target_payload_len - protected_payload.len() - 15;
        put(&mut protected_payload, protected_value_len);
        let mut ordinary_payload = 1u64.to_le_bytes().to_vec();
        ordinary_payload.extend(1u32.to_le_bytes());
        let ordinary_value_len = target_payload_len - ordinary_payload.len() - 15;
        put(&mut ordinary_payload, ordinary_value_len);
        assert_eq!(protected_payload.len(), target_payload_len);
        assert_eq!(ordinary_payload.len(), target_payload_len);
        let mut original = file_header(1);
        original.extend(legacy_frame(&protected_payload));
        let mut transient = file_header(1);
        transient.extend(legacy_frame(&ordinary_payload));
        assert_eq!(original.len(), transient.len());
        let transient_on_disk = transient.clone();
        std::fs::write(&path, &original).unwrap();
        let untouched = Wal::inspect_backup_file_for_owner(
            &path,
            1,
            original.len() as u64,
            1,
            false,
            true,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            untouched
                .to_string()
                .contains("record authority requires v2 WAL framing"),
            "{untouched:?}"
        );
        std::fs::hard_link(&path, &alias).unwrap();
        LEGACY_SECOND_PASS_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let mut handle = OpenOptions::new().write(true).open(alias).unwrap();
                handle.write_all(&transient).unwrap();
                handle.flush().unwrap();
            }));
        });
        let result = Wal::inspect_backup_file_for_owner(
            &path,
            1,
            original.len() as u64,
            1,
            false,
            true,
            |_| Ok(()),
        );
        // A staged read after the transient write could see the original
        // again; preflight must bind classification to its captured bytes.
        assert_eq!(std::fs::read(&path).unwrap(), transient_on_disk);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { reason, .. }) if reason == "captured WAL changed during validation"),
            "two-pass scan admitted a transient ordinary frame: {result:?}"
        );
        std::fs::write(&path, &original).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn torn_large_v1_second_pass_must_bind_all_available_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("00000000000000000001.wal");
        let alias = temp.path().join("external-hardlink.wal");
        let mut payload = 1u64.to_le_bytes().to_vec();
        payload.extend(0u32.to_le_bytes());
        payload.resize(9 * 1024 * 1024, 0);
        let mut original = file_header(1);
        original.extend(WAL_MAGIC.to_le_bytes());
        original.extend(u32::MAX.to_le_bytes());
        original.extend((crc32fast::hash(&payload[..12]) ^ 1).to_le_bytes());
        original.extend(payload);
        let mut transient = original.clone();
        transient[36..40].copy_from_slice(&1u32.to_le_bytes()); // op count
        transient[40] = 1; // Put
        transient[41..45].copy_from_slice(&u32::MAX.to_le_bytes()); // incomplete CF
        let transient_on_disk = transient.clone();
        std::fs::write(&path, &original).unwrap();
        Wal::inspect_backup_file_for_owner(
            &path,
            1,
            original.len() as u64,
            1,
            false,
            false,
            |_| Ok(()),
        )
        .expect("unchanged retired torn suffix is tolerated");
        std::fs::hard_link(&path, &alias).unwrap();
        LEGACY_SECOND_PASS_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let mut handle = OpenOptions::new().write(true).open(alias).unwrap();
                handle.write_all(&transient).unwrap();
                handle.flush().unwrap();
            }));
        });
        let result = Wal::inspect_backup_file_for_owner(
            &path,
            1,
            original.len() as u64,
            1,
            false,
            false,
            |_| Ok(()),
        );
        assert_eq!(std::fs::read(&path).unwrap(), transient_on_disk);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { reason, .. }) if reason == "captured WAL changed during validation"),
            "torn second pass admitted changed available bytes: {result:?}"
        );
        std::fs::write(&path, &original).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}
