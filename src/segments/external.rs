use crate::datatype::SegmentFamily;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryWriter, crc32c};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const BLOB_MAGIC: u32 = 0x5442_4c4f;
const BLOB_VERSION: u8 = 1;
const HEADER_LEN: u64 = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobLocation {
    pub family: Option<SegmentFamily>,
    pub file_id: u64,
    pub offset: u64,
    pub len: u32,
    pub checksum: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStore {
    path: PathBuf,
    family: Option<SegmentFamily>,
    file_id: u64,
}

impl BlobStore {
    /// A read view of the fixed page-owned role. Construction performs no IO.
    pub(crate) fn existing_overflow(path: PathBuf) -> Self {
        Self {
            path,
            family: None,
            file_id: 1,
        }
    }

    pub(crate) fn existing_segment(path: PathBuf, family: SegmentFamily, file_id: u64) -> Self {
        Self {
            path,
            family: Some(family),
            file_id,
        }
    }

    pub fn open_overflow(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open(path, None, 1)
    }

    pub fn open_segment(
        path: impl Into<PathBuf>,
        family: SegmentFamily,
        file_id: u64,
    ) -> Result<Self> {
        Self::open(path, Some(family), file_id)
    }

    fn open(path: impl Into<PathBuf>, family: Option<SegmentFamily>, file_id: u64) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            file.write_all(&BLOB_MAGIC.to_le_bytes())?;
            file.write_all(&[BLOB_VERSION])?;
            file.sync_all()?;
        }
        Ok(Self {
            path,
            family,
            file_id,
        })
    }

    pub fn append(&self, bytes: &[u8]) -> Result<BlobLocation> {
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&self.path)?;
        let offset = file.seek(SeekFrom::End(0))?;
        let checksum = crc32c(bytes);
        let mut writer = BinaryWriter::new();
        writer.write_u32(bytes.len() as u32);
        writer.write_u32(checksum);
        writer.write_bytes(bytes);
        file.write_all(&writer.into_inner())?;
        file.sync_data()?;
        Ok(BlobLocation {
            family: self.family,
            file_id: self.file_id,
            offset,
            len: bytes.len() as u32,
            checksum,
        })
    }

    pub fn read(&self, location: &BlobLocation) -> Result<Vec<u8>> {
        if location.family != self.family || location.file_id != self.file_id {
            return Err(PraxisError::InvalidConfig(
                "blob location does not belong to this store".to_string(),
            ));
        }
        let shape = std::fs::symlink_metadata(&self.path)?;
        if !shape.is_file() || is_alias(&shape) {
            return corrupt(&self.path, "blob store must be a regular nonalias file");
        }
        let mut file = File::open(&self.path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_LEN {
            return corrupt(&self.path, "truncated blob store header");
        }
        let mut header = [0_u8; HEADER_LEN as usize];
        file.read_exact(&mut header)?;
        if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) != BLOB_MAGIC {
            return corrupt(&self.path, "bad blob store magic");
        }
        if header[4] != BLOB_VERSION {
            return corrupt(
                &self.path,
                &format!("unsupported blob version {}", header[4]),
            );
        }
        let end = location
            .offset
            .checked_add(8)
            .and_then(|end| end.checked_add(u64::from(location.len)));
        if location.offset < HEADER_LEN || end.is_none_or(|end| end > file_len) {
            return corrupt(&self.path, "blob location outside file bounds");
        }
        file.seek(SeekFrom::Start(location.offset))?;
        let mut record_header = [0_u8; 8];
        file.read_exact(&mut record_header)?;
        let len = u32::from_le_bytes(record_header[..4].try_into().unwrap());
        let expected = u32::from_le_bytes(record_header[4..].try_into().unwrap());
        if len != location.len || (location.checksum != 0 && expected != location.checksum) {
            return corrupt(&self.path, "blob location metadata mismatch");
        }
        let len = usize::try_from(len).map_err(|_| PraxisError::Corrupt {
            path: self.path.clone(),
            reason: "blob length exceeds this platform".to_string(),
        })?;
        let mut data = Vec::new();
        data.try_reserve_exact(len)
            .map_err(|_| PraxisError::Corrupt {
                path: self.path.clone(),
                reason: "cannot reserve validated blob length".to_string(),
            })?;
        data.resize(len, 0);
        file.read_exact(&mut data)?;
        let actual = crc32c(&data);
        if actual != expected {
            return corrupt(
                &self.path,
                &format!("blob checksum mismatch: expected {expected:#010x}, got {actual:#010x}"),
            );
        }
        Ok(data)
    }
}

fn is_alias(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
