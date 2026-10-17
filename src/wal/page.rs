use crate::config::WalSyncPolicy;
use crate::errors::{PraxisError, Result};
use crate::identity::{Cid, Eid, FieldId, Rid};
use crate::record::PageDatabase;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod framing;
pub(crate) mod owned;
pub use framing::{
    MAX_PAGE_WAL_PAYLOAD_BYTES, PageWalFileFormat, PageWalIncompleteKind, PageWalReplayReport,
    PageWalScanStop,
};

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
    Seek,
    Write,
    AppendAfterPrefix(usize),
    Sync,
}

pub(crate) struct PreparedPageWalRecord {
    record: PageWalRecord,
    encoded: Vec<u8>,
    next_bytes: u64,
    next_sequence: u64,
}

impl PageWalRecord {
    /// Encode a new v2 frame. Panics for invalid input; managed writes use fallible APIs.
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().expect("invalid page WAL record")
    }
    /// Check the complete v2 frame size and fields before allocating output.
    pub fn checked_encoded_len(&self) -> Result<usize> {
        framing::checked_len(self)
    }
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        framing::encode(self)
    }
    /// Decode exactly one complete legacy or v2 frame, rejecting trailing bytes.
    pub fn decode(bytes: &[u8], source: impl Into<PathBuf>) -> Result<Self> {
        framing::exact(bytes, &source.into())
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

    /// Read a complete valid log without repair. Missing paths retain the empty convenience.
    pub fn replay(path: &Path) -> Result<Vec<PageWalRecord>> {
        read_report(path)?.into_strict(path)
    }
    /// Inspect exact prefix/stop evidence, never completeness or permission to recover/append.
    pub fn replay_prefix(path: &Path) -> Result<PageWalReplayReport> {
        read_report(path)
    }
}

impl PageWalWriter {
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        sync_policy: WalSyncPolicy,
        lifecycle: &mut owned::WalLifecycle,
    ) -> Result<Self> {
        let path = path.into();
        let (file, report) = owned::writable_file(&path, lifecycle)?;
        let next_sequence = report
            .records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(Self {
            file,
            sync_policy,
            next_sequence,
            bytes_written: report.physical_len,
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
        framing::checked_put_len(fields.len(), fields.iter().map(|(_, bytes)| bytes.len()))?;
        let sequence = self.claim_sequence()?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(fields.len()).map_err(|_| {
            PraxisError::InvalidConfig("cannot reserve checked page WAL fields".into())
        })?;
        for (field, bytes) in fields {
            let mut copied = Vec::new();
            copied.try_reserve_exact(bytes.len()).map_err(|_| {
                PraxisError::InvalidConfig("cannot reserve checked page WAL field bytes".into())
            })?;
            copied.extend_from_slice(bytes);
            owned.push((*field, copied));
        }
        let record = PageWalRecord {
            sequence,
            mutation: PageWalMutation::Put {
                cid,
                eid,
                rid,
                fields: owned,
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
        let encoded = record.try_encode()?;
        let next_bytes = self
            .bytes_written
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| PraxisError::WriteStalled {
                reason: "page WAL byte counter exhausted".to_string(),
            })?;
        let next_sequence =
            record
                .sequence
                .checked_add(1)
                .ok_or_else(|| PraxisError::WriteStalled {
                    reason: "page WAL next sequence is unrepresentable".into(),
                })?;
        Ok(PreparedPageWalRecord {
            record,
            encoded,
            next_bytes,
            next_sequence,
        })
    }

    pub(crate) fn append_prepared(
        &mut self,
        prepared: PreparedPageWalRecord,
    ) -> Result<PageWalRecord> {
        if prepared.record.sequence != self.claim_sequence()? {
            return Err(PraxisError::InvalidConfig(
                "prepared page WAL sequence is stale".into(),
            ));
        }
        #[cfg(test)]
        if matches!(self.failure, Some(PageWalFailure::Seek)) {
            self.failure = None;
            return Err(std::io::Error::other("injected page WAL seek failure").into());
        }
        self.file.seek(SeekFrom::End(0))?;
        #[cfg(test)]
        if matches!(self.failure, Some(PageWalFailure::Write)) {
            self.failure = None;
            return Err(std::io::Error::other("injected page WAL write failure").into());
        }
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
        self.next_sequence = prepared.next_sequence;
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

fn read_report(path: &Path) -> Result<PageWalReplayReport> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(framing::scan(&bytes, path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PageWalReplayReport {
            records: Vec::new(),
            valid_len: 0,
            physical_len: 0,
            file_format: PageWalFileFormat::Missing,
            stop: PageWalScanStop::Clean,
        }),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn read_records_strict(path: &Path) -> Result<Vec<PageWalRecord>> {
    read_report(path)?.into_strict(path)
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

/// Pure wire recognition for the storage inspector's exact empty scaffold.
pub(crate) fn is_empty_header(bytes: &[u8]) -> bool {
    let mut legacy = [0; 16];
    legacy[..4].copy_from_slice(&framing::FILE_MAGIC.to_le_bytes());
    legacy[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes == legacy || bytes == framing::file_header_v2()
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
