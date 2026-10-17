use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::transactions::{BatchOp, WriteBatch};
use crate::types::ColumnFamily;
use std::path::{Path, PathBuf};

pub(crate) const WAL_MAGIC: u32 = 0x5457_414c;
pub(crate) const WAL_V2_MAGIC: u32 = 0x5457_4132;
const LEGACY_RECORD_HEADER_LEN: usize = 12;
/// Header length emitted by the current v2 encoder. Legacy headers are 12 bytes.
pub const WAL_RECORD_HEADER_LEN: usize = 16;
/// New record payload limit, excluding the 16-byte framing header.
/// Canonical legacy records retain their existing u32 wire-length read limit.
pub const MAX_WAL_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const PAYLOAD_HEADER_LEN: usize = 12;
const MIN_OP_LEN: usize = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalRecord {
    pub sequence: u64,
    pub batch: WriteBatch,
}

pub(crate) enum RecordPrefix {
    Complete {
        record: WalRecord,
        encoded_len: usize,
    },
    Torn,
}

impl WalRecord {
    /// Encode one v2 record. New records require an upgraded reader.
    ///
    /// # Panics
    /// Panics if a field/count is not representable or the payload exceeds
    /// 64 MiB. Storage writers use [`Self::try_encode`] to return these errors
    /// before touching the WAL instead.
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode()
            .expect("invalid WAL record encoding limits")
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        let encoded_len = self.try_encoded_len()?;
        let mut payload = BinaryWriter::new();
        payload.write_u64(self.sequence);
        payload.write_u32(checked_u32(self.batch.len(), "operation count")?);
        // The nonallocating preflight above checks every field length before
        // BinaryWriter's existing u32 length-prefix writer is used.
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
        let mut out = Vec::with_capacity(encoded_len);
        out.extend_from_slice(&WAL_V2_MAGIC.to_le_bytes());
        out.extend_from_slice(&checked_u32(payload.len(), "payload length")?.to_le_bytes());
        out.extend_from_slice(&crc32c(&payload).to_le_bytes());
        out.extend_from_slice(&crc32c(&out).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Measure v2 encoding without allocating.
    ///
    /// # Panics
    /// Panics for the same invalid inputs as [`Self::encode`]. Use
    /// [`Self::try_encoded_len`] for fallible admission validation.
    pub fn encoded_len(&self) -> usize {
        self.try_encoded_len()
            .expect("invalid WAL record encoding limits")
    }

    pub fn try_encoded_len(&self) -> Result<usize> {
        Self::checked_encoded_batch_len(&self.batch)
    }

    pub(crate) fn checked_encoded_batch_len(batch: &WriteBatch) -> Result<usize> {
        checked_u32(batch.len(), "operation count")?;
        let mut len = PAYLOAD_HEADER_LEN;
        for op in batch.ops() {
            let (cf, key, value, expiry) = match op {
                BatchOp::Put { cf, key, value } | BatchOp::Merge { cf, key, value } => {
                    (cf, key, Some(value), false)
                }
                BatchOp::PutWithExpiry { cf, key, value, .. } => (cf, key, Some(value), true),
                BatchOp::Delete { cf, key } => (cf, key, None, false),
            };
            len = checked_payload_add(len, 1)?;
            for field_len in [Some(cf.0.len()), Some(key.len()), value.map(Vec::len)]
                .into_iter()
                .flatten()
            {
                checked_u32(field_len, "field length")?;
                len = checked_payload_add(len, 4)?;
                len = checked_payload_add(len, field_len)?;
            }
            if expiry {
                len = checked_payload_add(len, 8)?;
            }
        }
        len.checked_add(WAL_RECORD_HEADER_LEN)
            .ok_or_else(|| invalid("encoded record length overflow"))
    }

    /// Decode exactly one complete v1 or v2 record; reject any trailing bytes.
    pub fn decode(bytes: &[u8], source: impl Into<PathBuf>) -> Result<Self> {
        let source = source.into();
        match parse_record_prefix(bytes, &source)? {
            RecordPrefix::Complete {
                record,
                encoded_len,
            } if encoded_len == bytes.len() => Ok(record),
            RecordPrefix::Complete { .. } => Err(corrupt(&source, "trailing WAL record bytes")),
            RecordPrefix::Torn => Err(corrupt(&source, "torn WAL record")),
        }
    }
}

fn checked_u32(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid(format!("WAL {what} exceeds u32 limit")))
}

fn checked_payload_add(current: usize, additional: usize) -> Result<usize> {
    let len = current
        .checked_add(additional)
        .ok_or_else(|| invalid("WAL payload length overflow"))?;
    if len > MAX_WAL_PAYLOAD_BYTES {
        return Err(invalid("WAL payload exceeds 64 MiB limit"));
    }
    Ok(len)
}

fn invalid(reason: impl Into<String>) -> PraxisError {
    PraxisError::InvalidConfig(reason.into())
}

fn corrupt(source: &Path, reason: impl Into<String>) -> PraxisError {
    PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: reason.into(),
    }
}

/// Shared framing authority for exact decoding and sequential recovery.
/// Short terminal headers retain the existing torn-suffix policy. A complete
/// v2 header must authenticate its length before EOF can classify it as torn.
pub(crate) fn parse_record_prefix(bytes: &[u8], source: &Path) -> Result<RecordPrefix> {
    if bytes.len() < LEGACY_RECORD_HEADER_LEN {
        return Ok(RecordPrefix::Torn);
    }
    let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let header_len = match magic {
        WAL_MAGIC => LEGACY_RECORD_HEADER_LEN,
        WAL_V2_MAGIC => WAL_RECORD_HEADER_LEN,
        _ => return Err(corrupt(source, "bad WAL record magic")),
    };
    if bytes.len() < header_len {
        return Ok(RecordPrefix::Torn);
    }
    if magic == WAL_V2_MAGIC {
        let expected_header = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        if crc32c(&bytes[..12]) != expected_header {
            return Err(corrupt(source, "WAL header checksum mismatch"));
        }
    }
    let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let expected = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if magic == WAL_V2_MAGIC && !(PAYLOAD_HEADER_LEN..=MAX_WAL_PAYLOAD_BYTES).contains(&len) {
        return Err(corrupt(source, "invalid v2 WAL payload length"));
    }
    let available = &bytes[header_len..];
    if len > available.len() {
        if magic == WAL_MAGIC {
            // V1 does not authenticate the outer length. A complete,
            // self-delimiting body with its original CRC proves a length-only
            // corruption, even when a later record follows it. Probe without
            // allocating fields or constructing a batch. Truly incomplete
            // legacy bodies retain their historical torn-tail policy.
            if let Some((_, consumed)) = walk_payload(available, source, |_| {})?
                && crc32c(&available[..consumed]) == expected
            {
                return Err(corrupt(
                    source,
                    "legacy WAL length disagrees with intact payload",
                ));
            }
        }
        return Ok(RecordPrefix::Torn);
    }
    let payload = &available[..len];
    if crc32c(payload) != expected {
        return Err(corrupt(source, "WAL checksum mismatch"));
    }
    let Some((sequence, consumed)) = walk_payload(payload, source, |_| {})? else {
        return Err(corrupt(source, "truncated WAL payload"));
    };
    if consumed != payload.len() {
        return Err(corrupt(source, "trailing WAL payload bytes"));
    }
    let mut batch = WriteBatch::new();
    walk_payload(payload, source, |op| batch.push_op(op.into_owned()))?;
    Ok(RecordPrefix::Complete {
        record: WalRecord { sequence, batch },
        encoded_len: header_len + len,
    })
}

enum BorrowedOp<'a> {
    Put {
        cf: &'a str,
        key: &'a [u8],
        value: &'a [u8],
    },
    PutWithExpiry {
        cf: &'a str,
        key: &'a [u8],
        value: &'a [u8],
        expires_at_ms: u64,
    },
    Merge {
        cf: &'a str,
        key: &'a [u8],
        value: &'a [u8],
    },
    Delete {
        cf: &'a str,
        key: &'a [u8],
    },
}

impl BorrowedOp<'_> {
    fn into_owned(self) -> BatchOp {
        match self {
            Self::Put { cf, key, value } => BatchOp::Put {
                cf: ColumnFamily(cf.into()),
                key: key.to_vec(),
                value: value.to_vec(),
            },
            Self::PutWithExpiry {
                cf,
                key,
                value,
                expires_at_ms,
            } => BatchOp::PutWithExpiry {
                cf: ColumnFamily(cf.into()),
                key: key.to_vec(),
                value: value.to_vec(),
                expires_at_ms,
            },
            Self::Merge { cf, key, value } => BatchOp::Merge {
                cf: ColumnFamily(cf.into()),
                key: key.to_vec(),
                value: value.to_vec(),
            },
            Self::Delete { cf, key } => BatchOp::Delete {
                cf: ColumnFamily(cf.into()),
                key: key.to_vec(),
            },
        }
    }
}

fn partial_field<'a>(reader: &mut BinaryReader<'a>) -> Result<Option<&'a [u8]>> {
    if reader.remaining() < 4 {
        return Ok(None);
    }
    let len = reader.read_u32()? as usize;
    if len > reader.remaining() {
        return Ok(None);
    }
    reader.read_slice(len).map(Some)
}

// Visits only borrowed fields. None denotes an incomplete body; invalid tags
// and fully available invalid UTF-8 are corruption. Exact frame decoding turns
// an incomplete body into Corrupt; only the legacy EOF probe treats it as torn.
fn walk_payload<'a>(
    payload: &'a [u8],
    source: &Path,
    mut visit: impl FnMut(BorrowedOp<'a>),
) -> Result<Option<(u64, usize)>> {
    if payload.len() < PAYLOAD_HEADER_LEN {
        return Ok(None);
    }
    // Remaining-byte guards handle incomplete input before each read. Keep the
    // reader's unused error context empty so a successful legacy probe does
    // not allocate even a source-path copy; format errors use source below.
    let mut reader = BinaryReader::new(payload, PathBuf::new());
    let sequence = reader.read_u64()?;
    let ops = reader.read_u32()? as usize;
    if ops > reader.remaining() / MIN_OP_LEN {
        return Ok(None);
    }
    for _ in 0..ops {
        if reader.remaining() == 0 {
            return Ok(None);
        }
        let tag = reader.read_u8()?;
        if !matches!(tag, 1..=4) {
            return Err(corrupt(source, format!("unknown WAL op tag {tag}")));
        }
        let Some(cf) = partial_field(&mut reader)? else {
            return Ok(None);
        };
        let cf = std::str::from_utf8(cf)
            .map_err(|_| corrupt(source, "invalid WAL column family UTF-8"))?;
        let Some(key) = partial_field(&mut reader)? else {
            return Ok(None);
        };
        let op = match tag {
            2 => BorrowedOp::Delete { cf, key },
            _ => {
                let Some(value) = partial_field(&mut reader)? else {
                    return Ok(None);
                };
                match tag {
                    1 => BorrowedOp::Put { cf, key, value },
                    4 => BorrowedOp::Merge { cf, key, value },
                    _ => {
                        if reader.remaining() < 8 {
                            return Ok(None);
                        }
                        BorrowedOp::PutWithExpiry {
                            cf,
                            key,
                            value,
                            expires_at_ms: reader.read_u64()?,
                        }
                    }
                }
            }
        };
        visit(op);
    }
    Ok(Some((sequence, reader.position())))
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn payload_limit_and_arithmetic_are_checked_without_large_allocations() {
        assert_eq!(
            checked_payload_add(MAX_WAL_PAYLOAD_BYTES - 1, 1).unwrap(),
            MAX_WAL_PAYLOAD_BYTES
        );
        assert!(checked_payload_add(MAX_WAL_PAYLOAD_BYTES, 1).is_err());
        assert!(checked_payload_add(usize::MAX, 1).is_err());
        assert_eq!(checked_u32(u32::MAX as usize, "field").unwrap(), u32::MAX);
        #[cfg(target_pointer_width = "64")]
        {
            assert!(checked_u32(u32::MAX as usize + 1, "field").is_err());
            assert!(checked_u32(u32::MAX as usize + 1, "operation count").is_err());
        }
    }
}
