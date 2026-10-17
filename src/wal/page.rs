use crate::config::WalSyncPolicy;
use crate::errors::{PraxisError, Result};
use crate::identity::{Aid, Cid, Did, Eid, FieldId, Rid};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::record::PageDatabase;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const PAGE_WAL_FILE_MAGIC: u32 = 0x5450_5746;
const PAGE_WAL_FILE_VERSION: u32 = 1;
const PAGE_WAL_FILE_HEADER_LEN: usize = 16;
const PAGE_WAL_RECORD_MAGIC: u32 = 0x5450_5752;
const PAGE_WAL_RECORD_VERSION: u8 = 1;
const PAGE_WAL_RECORD_HEADER_LEN: usize = 13;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageWalMutation {
    Put {
        cid: Cid,
        eid: Eid,
        rid: Rid,
        fields: Vec<(FieldId, Vec<u8>)>,
    },
    Delete {
        cid: Cid,
        eid: Eid,
        rid: Rid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageWalRecord {
    pub sequence: u64,
    pub mutation: PageWalMutation,
}

#[derive(Debug)]
pub struct PageWal {
    pub(crate) database: PageDatabase,
    path: PathBuf,
}

pub(crate) struct PageWalWriter {
    file: File,
    sync_policy: WalSyncPolicy,
    next_sequence: u64,
    bytes_written: u64,
    #[cfg(test)]
    failure: Option<PageWalFailure>,
}

/// Per-writer, one-shot IO faults; absent from non-test builds.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum PageWalFailure {
    AppendAfterPrefix(usize),
    Sync,
}

pub(crate) struct PreparedPageWalRecord {
    record: PageWalRecord,
    encoded: Vec<u8>,
    next_bytes: u64,
}

impl PageWalRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = BinaryWriter::new();
        payload.write_u64(self.sequence);
        match &self.mutation {
            PageWalMutation::Put {
                cid,
                eid,
                rid,
                fields,
            } => {
                payload.write_u8(1);
                payload.write_u32(cid.0);
                payload.write_u32(eid.0);
                payload.write_u64(rid.0);
                payload.write_u32(fields.len() as u32);
                for (field, bytes) in fields {
                    write_field(&mut payload, *field);
                    payload.write_len_bytes(bytes);
                }
            }
            PageWalMutation::Delete { cid, eid, rid } => {
                payload.write_u8(2);
                payload.write_u32(cid.0);
                payload.write_u32(eid.0);
                payload.write_u64(rid.0);
            }
        }
        let payload = payload.into_inner();
        let mut out = BinaryWriter::new();
        out.write_u32(PAGE_WAL_RECORD_MAGIC);
        out.write_u8(PAGE_WAL_RECORD_VERSION);
        out.write_u32(payload.len() as u32);
        out.write_u32(crc32c(&payload));
        out.write_bytes(&payload);
        out.into_inner()
    }

    pub fn decode(bytes: &[u8], source: impl Into<PathBuf>) -> Result<Self> {
        let source = source.into();
        if bytes.len() < PAGE_WAL_RECORD_HEADER_LEN {
            return corrupt(&source, "truncated page WAL record header");
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PAGE_WAL_RECORD_MAGIC {
            return corrupt(&source, "bad page WAL record magic");
        }
        if bytes[4] != PAGE_WAL_RECORD_VERSION {
            return corrupt(
                &source,
                &format!("unsupported page WAL record version {}", bytes[4]),
            );
        }
        let len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        let expected = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        if bytes.len() < PAGE_WAL_RECORD_HEADER_LEN + len {
            return corrupt(&source, "torn page WAL record");
        }
        let payload = &bytes[PAGE_WAL_RECORD_HEADER_LEN..PAGE_WAL_RECORD_HEADER_LEN + len];
        let actual = crc32c(payload);
        if actual != expected {
            return corrupt(
                &source,
                &format!(
                    "page WAL checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                ),
            );
        }
        let mut reader = BinaryReader::new(payload, source.clone());
        let sequence = reader.read_u64()?;
        let tag = reader.read_u8()?;
        let mutation = match tag {
            1 => {
                let cid = Cid(reader.read_u32()?);
                let eid = Eid(reader.read_u32()?);
                let rid = Rid(reader.read_u64()?);
                let count = reader.read_u32()? as usize;
                if count > reader.remaining() / 9 {
                    return corrupt(&source, "page WAL field count exceeds its actual payload");
                }
                let mut fields = Vec::with_capacity(count);
                for _ in 0..count {
                    let field = read_field(&mut reader, &source)?;
                    let bytes = reader.read_len_bytes()?;
                    fields.push((field, bytes));
                }
                PageWalMutation::Put {
                    cid,
                    eid,
                    rid,
                    fields,
                }
            }
            2 => PageWalMutation::Delete {
                cid: Cid(reader.read_u32()?),
                eid: Eid(reader.read_u32()?),
                rid: Rid(reader.read_u64()?),
            },
            _ => return corrupt(&source, &format!("unknown page WAL mutation tag {tag}")),
        };
        if reader.remaining() != 0 {
            return corrupt(&source, "trailing bytes in page WAL mutation");
        }
        Ok(Self { sequence, mutation })
    }
}

impl PageWal {
    pub(crate) fn from_owner(database: PageDatabase, path: PathBuf) -> Self {
        Self { database, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes_written(&self) -> Result<u64> {
        self.database.page_wal_bytes()
    }

    pub fn sync(&mut self) -> Result<()> {
        self.database.sync_page_wal()
    }

    /// Forensic prefix replay only. A successful prefix is not complete recovery.
    pub fn replay(path: &Path) -> Result<Vec<PageWalRecord>> {
        replay_prefix(path)
    }
}

impl PageWalWriter {
    pub(crate) fn open(path: impl Into<PathBuf>, sync_policy: WalSyncPolicy) -> Result<Self> {
        let path = path.into();
        let records = read_records_strict(&path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        let mut bytes_written = file.metadata()?.len();
        if bytes_written == 0 {
            let header = file_header();
            file.write_all(&header)?;
            file.sync_data()?;
            bytes_written = header.len() as u64;
        }
        let next_sequence = records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(Self {
            file,
            sync_policy,
            next_sequence,
            bytes_written,
            #[cfg(test)]
            failure: None,
        })
    }

    pub(crate) fn prepare_put(
        &self,
        cid: Cid,
        eid: Eid,
        rid: Rid,
        fields: &[(FieldId, &[u8])],
    ) -> Result<PreparedPageWalRecord> {
        u32::try_from(fields.len()).map_err(|_| {
            PraxisError::InvalidConfig("page WAL field count exceeds v1 range".to_string())
        })?;
        for (_, bytes) in fields {
            u32::try_from(bytes.len()).map_err(|_| {
                PraxisError::InvalidConfig("page WAL field length exceeds v1 range".to_string())
            })?;
        }
        let record = PageWalRecord {
            sequence: self.claim_sequence()?,
            mutation: PageWalMutation::Put {
                cid,
                eid,
                rid,
                fields: fields
                    .iter()
                    .map(|(field, bytes)| (*field, (*bytes).to_vec()))
                    .collect(),
            },
        };
        self.prepare(record)
    }

    pub(crate) fn prepare_delete(
        &self,
        cid: Cid,
        eid: Eid,
        rid: Rid,
    ) -> Result<PreparedPageWalRecord> {
        let record = PageWalRecord {
            sequence: self.claim_sequence()?,
            mutation: PageWalMutation::Delete { cid, eid, rid },
        };
        self.prepare(record)
    }

    fn prepare(&self, record: PageWalRecord) -> Result<PreparedPageWalRecord> {
        validate_identity(&record, Path::new("page-wal-input"))?;
        let encoded = record.encode();
        u32::try_from(encoded.len().saturating_sub(PAGE_WAL_RECORD_HEADER_LEN)).map_err(|_| {
            PraxisError::InvalidConfig("page WAL record exceeds v1 range".to_string())
        })?;
        let next_bytes = self
            .bytes_written
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| PraxisError::WriteStalled {
                reason: "page WAL byte counter exhausted".to_string(),
            })?;
        Ok(PreparedPageWalRecord {
            record,
            encoded,
            next_bytes,
        })
    }

    pub(crate) fn append_prepared(
        &mut self,
        prepared: PreparedPageWalRecord,
    ) -> Result<PageWalRecord> {
        self.file.seek(SeekFrom::End(0))?;
        #[cfg(test)]
        if let Some(PageWalFailure::AppendAfterPrefix(len)) = self.failure {
            self.failure = None;
            self.file
                .write_all(&prepared.encoded[..len.min(prepared.encoded.len())])?;
            return Err(std::io::Error::other("injected partial page WAL append").into());
        }
        self.file.write_all(&prepared.encoded)?;
        if matches!(
            self.sync_policy,
            WalSyncPolicy::EveryBatch | WalSyncPolicy::GroupCommit
        ) {
            self.sync()?;
        }
        self.bytes_written = prepared.next_bytes;
        self.next_sequence = prepared.record.sequence.saturating_add(1);
        Ok(prepared.record)
    }

    pub(crate) fn sync(&mut self) -> Result<()> {
        #[cfg(test)]
        if matches!(self.failure, Some(PageWalFailure::Sync)) {
            self.failure = None;
            return Err(std::io::Error::other("injected page WAL sync failure").into());
        }
        self.file.sync_data()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next(&mut self, failure: PageWalFailure) {
        self.failure = Some(failure);
    }

    pub(crate) fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub(crate) fn policy(&self) -> WalSyncPolicy {
        self.sync_policy
    }

    fn claim_sequence(&self) -> Result<u64> {
        if self.next_sequence == 0 || self.next_sequence == u64::MAX {
            return Err(PraxisError::WriteStalled {
                reason: "page WAL sequence space is exhausted".to_string(),
            });
        }
        Ok(self.next_sequence)
    }
}

fn replay_prefix(path: &Path) -> Result<Vec<PageWalRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut offset = file_payload_offset(&bytes, path)?;
    let mut records = Vec::new();
    while offset + PAGE_WAL_RECORD_HEADER_LEN <= bytes.len() {
        let len = u32::from_le_bytes([
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
        ]) as usize;
        if offset + PAGE_WAL_RECORD_HEADER_LEN + len > bytes.len() {
            break;
        }
        let record_bytes = &bytes[offset..offset + PAGE_WAL_RECORD_HEADER_LEN + len];
        match PageWalRecord::decode(record_bytes, path) {
            Ok(record) => records.push(record),
            Err(_) => break,
        }
        offset += PAGE_WAL_RECORD_HEADER_LEN + len;
    }
    Ok(records)
}

pub(crate) fn read_records_strict(path: &Path) -> Result<Vec<PageWalRecord>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut offset = file_payload_offset(&bytes, path)?;
    let mut records = Vec::new();
    let mut previous = 0;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(PAGE_WAL_RECORD_HEADER_LEN)
            .ok_or_else(|| PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "page WAL header length overflow".to_string(),
            })?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "incomplete page WAL suffix".to_string(),
            })?;
        let len =
            u32::from_le_bytes(header[5..9].try_into().expect("four-byte header length")) as usize;
        let end = header_end
            .checked_add(len)
            .ok_or_else(|| PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "page WAL payload length overflow".to_string(),
            })?;
        let encoded = bytes.get(offset..end).ok_or_else(|| PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "incomplete page WAL suffix".to_string(),
        })?;
        let record = PageWalRecord::decode(encoded, path)?;
        validate_identity(&record, path)?;
        if record.sequence <= previous {
            return corrupt(path, "page WAL sequences must strictly increase");
        }
        previous = record.sequence;
        records.push(record);
        offset = end;
    }
    Ok(records)
}

pub(crate) fn validate_identity(record: &PageWalRecord, path: &Path) -> Result<()> {
    let (cid, eid, rid) = match &record.mutation {
        PageWalMutation::Put { cid, eid, rid, .. } | PageWalMutation::Delete { cid, eid, rid } => {
            (*cid, *eid, *rid)
        }
    };
    if record.sequence == 0 || cid.is_null() || eid.is_null() || rid.is_null() {
        return corrupt(path, "reserved zero identity in page WAL record");
    }
    Ok(())
}

fn write_field(writer: &mut BinaryWriter, field: FieldId) {
    match field {
        FieldId::Fixed(aid) => {
            writer.write_u8(1);
            writer.write_u32(aid.0 as u32);
        }
        FieldId::Dynamic(did) => {
            writer.write_u8(2);
            writer.write_u32(did.0 as u32);
        }
    }
}

fn read_field(reader: &mut BinaryReader<'_>, source: &Path) -> Result<FieldId> {
    let tag = reader.read_u8()?;
    let raw = u16::try_from(reader.read_u32()?).map_err(|_| PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: "page WAL field ID exceeds its v1 range".to_string(),
    })?;
    match tag {
        1 => Ok(FieldId::Fixed(Aid(raw))),
        2 => Ok(FieldId::Dynamic(Did(raw))),
        _ => corrupt(source, &format!("unknown page WAL field tag {tag}")),
    }
}

fn file_header() -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(PAGE_WAL_FILE_MAGIC);
    writer.write_u32(PAGE_WAL_FILE_VERSION);
    writer.write_u64(0);
    writer.into_inner()
}

fn file_payload_offset(bytes: &[u8], path: &Path) -> Result<usize> {
    if bytes.len() < 4 {
        return Ok(0);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != PAGE_WAL_FILE_MAGIC {
        return Ok(0);
    }
    if bytes.len() < PAGE_WAL_FILE_HEADER_LEN {
        return corrupt(path, "torn page WAL file header");
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != PAGE_WAL_FILE_VERSION {
        return corrupt(
            path,
            &format!("unsupported page WAL file version {version}"),
        );
    }
    Ok(PAGE_WAL_FILE_HEADER_LEN)
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
