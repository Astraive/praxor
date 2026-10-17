use crate::errors::{PraxisError, Result};
use crate::io::sync_parent_dir;
use crc32fast::Hasher as Crc32Hasher;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Magic bytes at the start of every segment file: `TREC`.
const SEGMENT_MAGIC: u32 = 0x54524543;
const SEGMENT_VERSION: u8 = 1;
/// Size of the per-record header: length(4) + checksum(4).
const RECORD_HEADER_SIZE: u64 = 8;

/// An append-only segment file for the primary data store.
///
/// File layout:
/// ```text
/// [magic: u32][version: u8][segment_id: u32]
/// ([length: u32][checksum: u32][data: <length> bytes]) ...
/// ```
///
/// All reads are done by seeking to an absolute byte offset; the segment
/// never needs to be scanned because the [`IndirectionTable`](super::IndirectionTable) records the
/// exact offset and length of every record.
pub struct RecordSegment {
    segment_id: u32,
    file: File,
    /// Current end-of-file offset (next write position).
    write_offset: u64,
}

impl RecordSegment {
    /// Open or create the segment file at `path` with `segment_id`.
    ///
    /// If the file does not exist it is created and a 9-byte header is
    /// written.  If it already exists the write cursor is positioned at the
    /// end of the file so new records are appended after existing ones.
    pub fn open(path: impl AsRef<Path>, segment_id: u32) -> Result<Self> {
        let path = path.as_ref();
        let is_new = !path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;

        if is_new {
            file.write_all(&SEGMENT_MAGIC.to_le_bytes())?;
            file.write_all(&[SEGMENT_VERSION])?;
            file.write_all(&segment_id.to_le_bytes())?;
            // Relocation WAL may outlive the source segments after compaction.
            // Persist the new segment's header and directory entry first.
            file.sync_all()?;
            sync_parent_dir(path)?;
        }

        let write_offset = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            segment_id,
            file,
            write_offset,
        })
    }

    pub fn segment_id(&self) -> u32 {
        self.segment_id
    }

    /// Append `data` to the segment.
    ///
    /// Returns `(record_offset, data_length)` where `record_offset` is the
    /// absolute byte position of the record's **length** field within the
    /// segment file.  This value is stored in the
    /// [`PhysicalLocation`][super::PhysicalLocation] for the record.
    pub fn append(&mut self, data: &[u8]) -> Result<(u64, u32)> {
        let length = data.len() as u32;
        let checksum = crc32(data);
        let record_offset = self.write_offset;

        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&checksum.to_le_bytes())?;
        self.file.write_all(data)?;
        self.file.flush()?;

        self.write_offset += RECORD_HEADER_SIZE + length as u64;
        Ok((record_offset, length))
    }

    pub fn sync(&self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Read `length` bytes from `path` starting at `record_offset`.
    ///
    /// The layout at `record_offset` is:
    /// `[length: u32][checksum: u32][data: length bytes]`
    ///
    /// The checksum is verified before the data is returned.
    pub fn read_at(path: &Path, record_offset: u64, length: u32) -> Result<Vec<u8>> {
        let mut file = File::open(path)?;
        // Skip the length field (4 bytes) to reach the checksum.
        file.seek(SeekFrom::Start(record_offset + 4))?;
        let mut checksum_buf = [0u8; 4];
        file.read_exact(&mut checksum_buf)?;
        let expected_checksum = u32::from_le_bytes(checksum_buf);

        let mut data = vec![0u8; length as usize];
        file.read_exact(&mut data)?;

        let actual = crc32(&data);
        if actual != expected_checksum {
            return Err(PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: format!(
                    "record checksum mismatch at offset {record_offset}: \
                     expected {expected_checksum:#010x}, got {actual:#010x}"
                ),
            });
        }
        Ok(data)
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(data);
    h.finalize()
}
