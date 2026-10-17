use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::transactions::{BatchOp, WriteBatch};
use crate::types::ColumnFamily;
use std::path::PathBuf;

pub(crate) const WAL_MAGIC: u32 = 0x5457_414c;
pub const WAL_RECORD_HEADER_LEN: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalRecord {
    pub sequence: u64,
    pub batch: WriteBatch,
}

impl WalRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = BinaryWriter::new();
        payload.write_u64(self.sequence);
        payload.write_u32(self.batch.len() as u32);
        for op in self.batch.ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    payload.write_u8(1);
                    payload.write_len_bytes(cf.0.as_bytes());
                    payload.write_len_bytes(key);
                    payload.write_len_bytes(value);
                }
                BatchOp::PutWithExpiry {
                    cf,
                    key,
                    value,
                    expires_at_ms,
                } => {
                    payload.write_u8(3);
                    payload.write_len_bytes(cf.0.as_bytes());
                    payload.write_len_bytes(key);
                    payload.write_len_bytes(value);
                    payload.write_u64(*expires_at_ms);
                }
                BatchOp::Merge { cf, key, value } => {
                    payload.write_u8(4);
                    payload.write_len_bytes(cf.0.as_bytes());
                    payload.write_len_bytes(key);
                    payload.write_len_bytes(value);
                }
                BatchOp::Delete { cf, key } => {
                    payload.write_u8(2);
                    payload.write_len_bytes(cf.0.as_bytes());
                    payload.write_len_bytes(key);
                }
            }
        }
        let payload = payload.into_inner();
        let mut out = BinaryWriter::new();
        out.write_u32(WAL_MAGIC);
        out.write_u32(payload.len() as u32);
        out.write_u32(crc32c(&payload));
        out.write_bytes(&payload);
        out.into_inner()
    }

    pub fn encoded_len(&self) -> usize {
        Self::encoded_batch_len(&self.batch)
    }

    pub(crate) fn encoded_batch_len(batch: &WriteBatch) -> usize {
        let operations = batch
            .ops()
            .iter()
            .map(|op| match op {
                BatchOp::Put { cf, key, value } | BatchOp::Merge { cf, key, value } => {
                    1 + 3 * 4 + cf.0.len() + key.len() + value.len()
                }
                BatchOp::PutWithExpiry { cf, key, value, .. } => {
                    1 + 3 * 4 + cf.0.len() + key.len() + value.len() + 8
                }
                BatchOp::Delete { cf, key } => 1 + 2 * 4 + cf.0.len() + key.len(),
            })
            .sum::<usize>();
        WAL_RECORD_HEADER_LEN + 8 + 4 + operations
    }

    pub fn decode(bytes: &[u8], source: impl Into<PathBuf>) -> Result<Self> {
        let source = source.into();
        let mut reader = BinaryReader::new(bytes, source.clone());
        let magic = reader.read_u32()?;
        if magic != WAL_MAGIC {
            return Err(PraxisError::Corrupt {
                path: source,
                reason: "bad WAL magic".to_string(),
            });
        }
        let len = reader.read_u32()? as usize;
        let expected = reader.read_u32()?;
        if bytes.len() < WAL_RECORD_HEADER_LEN + len {
            return Err(PraxisError::Corrupt {
                path: source,
                reason: "torn WAL record".to_string(),
            });
        }
        let payload = &bytes[WAL_RECORD_HEADER_LEN..WAL_RECORD_HEADER_LEN + len];
        if crc32c(payload) != expected {
            return Err(PraxisError::Corrupt {
                path: source,
                reason: "WAL checksum mismatch".to_string(),
            });
        }
        let mut payload_reader = BinaryReader::new(payload, "wal-payload");
        let sequence = payload_reader.read_u64()?;
        let ops = payload_reader.read_u32()?;
        let mut batch = WriteBatch::new();
        for _ in 0..ops {
            let tag = payload_reader.read_u8()?;
            let cf = ColumnFamily(
                String::from_utf8_lossy(&payload_reader.read_len_bytes()?).to_string(),
            );
            let key = payload_reader.read_len_bytes()?;
            match tag {
                1 => {
                    let value = payload_reader.read_len_bytes()?;
                    batch.put(cf, bytes::Bytes::from(key), bytes::Bytes::from(value));
                }
                2 => {
                    batch.delete(cf, bytes::Bytes::from(key));
                }
                3 => {
                    let value = payload_reader.read_len_bytes()?;
                    let expires_at_ms = payload_reader.read_u64()?;
                    batch.put_with_expiry(
                        cf,
                        bytes::Bytes::from(key),
                        bytes::Bytes::from(value),
                        expires_at_ms,
                    );
                }
                4 => {
                    let value = payload_reader.read_len_bytes()?;
                    batch.merge(cf, bytes::Bytes::from(key), bytes::Bytes::from(value));
                }
                _ => {
                    return Err(PraxisError::Corrupt {
                        path: PathBuf::from("wal-payload"),
                        reason: format!("unknown WAL op tag {tag}"),
                    });
                }
            }
        }
        Ok(Self { sequence, batch })
    }
}
