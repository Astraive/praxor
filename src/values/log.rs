use crate::errors::{PraxisError, Result};
use crate::io::{crc32c, sync_parent_dir};
use crate::types::ValuePointer;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ValueLog {
    path: PathBuf,
    file: File,
}

impl ValueLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        // Persist the log's inode and directory entry before a flush can
        // checkpoint WAL records whose values will reference this file.
        file.sync_all()?;
        sync_parent_dir(&path)?;
        Ok(Self { path, file })
    }

    pub fn append(&mut self, bytes: &[u8]) -> Result<ValuePointer> {
        let offset = self.file.seek(SeekFrom::End(0))?;
        let checksum = crc32c(bytes);
        self.file.write_all(&(bytes.len() as u64).to_le_bytes())?;
        self.file.write_all(&checksum.to_le_bytes())?;
        self.file.write_all(bytes)?;
        self.file.sync_data()?;
        Ok(ValuePointer {
            path: self.path.to_string_lossy().to_string(),
            offset,
            len: bytes.len() as u64,
            checksum,
        })
    }

    pub fn read_pointer(pointer: &ValuePointer) -> Result<Vec<u8>> {
        let path = Path::new(&pointer.path);
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(pointer.offset))?;
        let mut len_buf = [0_u8; 8];
        file.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf);
        let mut checksum_buf = [0_u8; 4];
        file.read_exact(&mut checksum_buf)?;
        let checksum = u32::from_le_bytes(checksum_buf);
        if len != pointer.len || checksum != pointer.checksum {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "value pointer header mismatch".to_string(),
            });
        }
        let mut bytes = vec![0; len as usize];
        file.read_exact(&mut bytes)?;
        if crc32c(&bytes) != checksum {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "value log checksum mismatch".to_string(),
            });
        }
        Ok(bytes)
    }
}
