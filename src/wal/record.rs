use crate::core_catalog::CatalogControl;
use crate::core_records::codec::Envelope;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, crc32c};
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
pub(crate) const MAX_CATALOG_WAL_FRAME_BYTES: usize = 1_048_576;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoreWalRecord {
    User(WalRecord),
    Record {
        sequence: u64,
        envelope: Envelope,
        batch: WriteBatch,
    },
    Catalog {
        sequence: u64,
        control: CatalogControl,
        batch: WriteBatch,
    },
}

impl CoreWalRecord {
    pub(crate) fn sequence(&self) -> u64 {
        match self {
            Self::User(record) => record.sequence,
            Self::Record { sequence, .. } => *sequence,
            Self::Catalog { sequence, .. } => *sequence,
        }
    }
    pub(crate) fn batch(&self) -> &WriteBatch {
        match self {
            Self::User(record) => &record.batch,
            Self::Record { batch, .. } => batch,
            Self::Catalog { batch, .. } => batch,
        }
    }
    pub(crate) fn into_user(self, source: &Path) -> Result<WalRecord> {
        match self {
            Self::User(record) => Ok(record),
            Self::Record { .. } => Err(PraxisError::RecordAuthorityWalRequired {
                path: source.to_path_buf(),
            }),
            Self::Catalog { .. } => Err(PraxisError::CatalogAuthorityWalRequired {
                path: source.to_path_buf(),
            }),
        }
    }
    pub(crate) fn try_encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::User(record) => record.try_encode(),
            Self::Record {
                sequence,
                envelope,
                batch,
            } => encode_record(*sequence, batch, Some(envelope)),
            Self::Catalog {
                sequence,
                control,
                batch,
            } => encode_catalog_record(*sequence, control, batch),
        }
    }
}

pub(crate) enum CoreRecordPrefix {
    Complete {
        record: CoreWalRecord,
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
        encode_record(self.sequence, &self.batch, None)
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

/// One borrowed operation encoder for both wire variants. Complete size and
/// count preflight precedes allocation; neither batch nor payload is cloned.
pub(crate) fn encode_record(
    sequence: u64,
    batch: &WriteBatch,
    envelope: Option<&Envelope>,
) -> Result<Vec<u8>> {
    let encoded_len = match envelope {
        Some(value) => checked_core_encoded_len(sequence, batch, value)?,
        None => WalRecord::checked_encoded_batch_len(batch)?,
    };
    let mut count = checked_u32(batch.len(), "operation count")?;
    if envelope.is_some() {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("WAL operation count overflow"))?;
    }
    let mut out = Vec::with_capacity(encoded_len);
    out.extend([0; WAL_RECORD_HEADER_LEN]);
    out.extend(sequence.to_le_bytes());
    out.extend(count.to_le_bytes());
    if let Some(envelope) = envelope {
        out.push(5);
        out.extend((Envelope::LEN as u32).to_le_bytes());
        envelope.encode_into(sequence, &mut out)?;
    }
    append_ops(&mut out, batch);
    debug_assert_eq!(out.len(), encoded_len);
    finish_v2_frame(&mut out)?;
    Ok(out)
}

fn encode_catalog_record(
    sequence: u64,
    control: &CatalogControl,
    batch: &WriteBatch,
) -> Result<Vec<u8>> {
    let count = checked_u32(batch.len(), "operation count")?
        .checked_add(1)
        .ok_or_else(|| invalid("WAL operation count overflow"))?;
    let encoded_len = WalRecord::checked_encoded_batch_len(batch)?
        .checked_add(5 + control.encoded_len())
        .ok_or_else(|| invalid("catalog WAL frame length overflow"))?;
    if encoded_len > MAX_CATALOG_WAL_FRAME_BYTES {
        return Err(invalid("catalog WAL frame exceeds 1 MiB limit"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(encoded_len)
        .map_err(|_| invalid("cannot reserve catalog WAL frame"))?;
    out.extend([0; WAL_RECORD_HEADER_LEN]);
    out.extend(sequence.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.push(control.tag());
    out.extend((control.encoded_len() as u32).to_le_bytes());
    control.encode_into(sequence, &mut out)?;
    append_ops(&mut out, batch);
    if out.len() != encoded_len {
        return Err(invalid("catalog WAL encoded length mismatch"));
    }
    finish_v2_frame(&mut out)?;
    Ok(out)
}

fn append_ops(out: &mut Vec<u8>, batch: &WriteBatch) {
    for op in batch.ops() {
        let (tag, cf, key, value, expiry) = match op {
            BatchOp::Put { cf, key, value } => (1, cf, key, Some(value), None),
            BatchOp::Delete { cf, key } => (2, cf, key, None, None),
            BatchOp::PutWithExpiry {
                cf,
                key,
                value,
                expires_at_ms,
            } => (3, cf, key, Some(value), Some(*expires_at_ms)),
            BatchOp::Merge { cf, key, value } => (4, cf, key, Some(value), None),
        };
        out.push(tag);
        for field in [
            Some(cf.0.as_bytes()),
            Some(key.as_slice()),
            value.map(Vec::as_slice),
        ]
        .into_iter()
        .flatten()
        {
            // Every narrowing was checked against this immutable batch above.
            out.extend((field.len() as u32).to_le_bytes());
            out.extend(field);
        }
        if let Some(expiry) = expiry {
            out.extend(expiry.to_le_bytes());
        }
    }
}

fn finish_v2_frame(out: &mut [u8]) -> Result<()> {
    let payload_len = u32::try_from(out.len() - WAL_RECORD_HEADER_LEN)
        .map_err(|_| invalid("WAL payload length exceeds u32"))?;
    let payload_crc = crc32c(&out[WAL_RECORD_HEADER_LEN..]);
    out[..4].copy_from_slice(&WAL_V2_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&payload_len.to_le_bytes());
    out[8..12].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32c(&out[..12]);
    out[12..16].copy_from_slice(&header_crc.to_le_bytes());
    Ok(())
}

pub(crate) fn checked_core_encoded_len(
    sequence: u64,
    batch: &WriteBatch,
    envelope: &Envelope,
) -> Result<usize> {
    envelope.validate(sequence, Path::new("record-envelope"))?;
    checked_u32(batch.len(), "operation count")?
        .checked_add(1)
        .ok_or_else(|| invalid("WAL operation count overflow"))?;
    let len = WalRecord::checked_encoded_batch_len(batch)?;
    Ok(
        checked_payload_add(len - WAL_RECORD_HEADER_LEN, 5 + Envelope::LEN)?
            + WAL_RECORD_HEADER_LEN,
    )
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
    match parse_core_record_prefix(bytes, source)? {
        CoreRecordPrefix::Complete {
            record,
            encoded_len,
        } => Ok(RecordPrefix::Complete {
            record: record.into_user(source)?,
            encoded_len,
        }),
        CoreRecordPrefix::Torn => Ok(RecordPrefix::Torn),
    }
}

pub(crate) fn parse_core_record_prefix(bytes: &[u8], source: &Path) -> Result<CoreRecordPrefix> {
    if bytes.len() < LEGACY_RECORD_HEADER_LEN {
        return Ok(CoreRecordPrefix::Torn);
    }
    let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let header_len = match magic {
        WAL_MAGIC => LEGACY_RECORD_HEADER_LEN,
        WAL_V2_MAGIC => WAL_RECORD_HEADER_LEN,
        _ => return Err(corrupt(source, "bad WAL record magic")),
    };
    if bytes.len() < header_len {
        return Ok(CoreRecordPrefix::Torn);
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
            if let Some((_, _, consumed)) =
                walk_payload(available, source, false, true, |_| Ok(()))?
                && crc32c(&available[..consumed]) == expected
            {
                return Err(corrupt(
                    source,
                    "legacy WAL length disagrees with intact payload",
                ));
            }
        }
        return Ok(CoreRecordPrefix::Torn);
    }
    let payload = &available[..len];
    if crc32c(payload) != expected {
        return Err(corrupt(source, "WAL checksum mismatch"));
    }
    // The complete v2 payload is authenticated before any catalog control or
    // size diagnosis. This also gives a bad CRC precedence over the v4 cap.
    if magic == WAL_V2_MAGIC
        && payload.len() >= 13
        && u32::from_le_bytes(payload[8..12].try_into().unwrap()) != 0
        && matches!(payload[12], 6 | 7)
        && header_len + len > MAX_CATALOG_WAL_FRAME_BYTES
    {
        return Err(corrupt(source, "catalog WAL frame exceeds 1 MiB limit"));
    }
    let Some((sequence, control, consumed)) =
        walk_payload(payload, source, magic == WAL_V2_MAGIC, false, |_| Ok(()))?
    else {
        return Err(corrupt(source, "truncated WAL payload"));
    };
    if consumed != payload.len() {
        return Err(corrupt(source, "trailing WAL payload bytes"));
    }
    if magic == WAL_MAGIC && !matches!(control, ParsedControl::None) {
        return Err(corrupt(source, "record authority requires v2 WAL framing"));
    }
    if let ParsedControl::Unknown(tag) = &control {
        return Err(PraxisError::UnsupportedWalControl {
            path: source.to_path_buf(),
            tag: *tag,
        });
    }
    let mut batch = WriteBatch::new();
    if matches!(control, ParsedControl::Catalog(_)) {
        let count = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
        let ordinary_count = count
            .checked_sub(1)
            .ok_or_else(|| corrupt(source, "catalog WAL control has no operation slot"))?;
        batch
            .try_reserve_ops(ordinary_count)
            .map_err(|_| corrupt(source, "cannot reserve catalog WAL operations"))?;
        walk_payload(payload, source, true, false, |op| {
            let owned = op.try_into_owned(source)?;
            if !batch.try_push_reserved_op(owned) {
                return Err(corrupt(source, "catalog WAL operation reserve mismatch"));
            }
            Ok(())
        })?;
        if batch.len() != ordinary_count {
            return Err(corrupt(source, "catalog WAL operation count mismatch"));
        }
    } else {
        walk_payload(payload, source, magic == WAL_V2_MAGIC, false, |op| {
            batch.push_op(op.into_owned());
            Ok(())
        })?;
    }
    Ok(CoreRecordPrefix::Complete {
        record: match control {
            ParsedControl::Record(envelope) => CoreWalRecord::Record {
                sequence,
                envelope,
                batch,
            },
            ParsedControl::Catalog(control) => CoreWalRecord::Catalog {
                sequence,
                control,
                batch,
            },
            ParsedControl::None => CoreWalRecord::User(WalRecord { sequence, batch }),
            ParsedControl::Unknown(_) => unreachable!("rejected after complete walk"),
        },
        encoded_len: header_len + len,
    })
}

enum ParsedControl {
    None,
    Record(Envelope),
    Catalog(CatalogControl),
    Unknown(u8),
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

    fn try_into_owned(self, source: &Path) -> Result<BatchOp> {
        match self {
            Self::Put { cf, key, value } => Ok(BatchOp::Put {
                cf: ColumnFamily(try_catalog_string(cf, source)?),
                key: try_catalog_vec(key, source)?,
                value: try_catalog_vec(value, source)?,
            }),
            Self::PutWithExpiry {
                cf,
                key,
                value,
                expires_at_ms,
            } => Ok(BatchOp::PutWithExpiry {
                cf: ColumnFamily(try_catalog_string(cf, source)?),
                key: try_catalog_vec(key, source)?,
                value: try_catalog_vec(value, source)?,
                expires_at_ms,
            }),
            Self::Merge { cf, key, value } => Ok(BatchOp::Merge {
                cf: ColumnFamily(try_catalog_string(cf, source)?),
                key: try_catalog_vec(key, source)?,
                value: try_catalog_vec(value, source)?,
            }),
            Self::Delete { cf, key } => Ok(BatchOp::Delete {
                cf: ColumnFamily(try_catalog_string(cf, source)?),
                key: try_catalog_vec(key, source)?,
            }),
        }
    }
}

fn try_catalog_vec(bytes: &[u8], source: &Path) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| corrupt(source, "cannot reserve catalog WAL field"))?;
    out.extend_from_slice(bytes);
    Ok(out)
}

fn try_catalog_string(value: &str, source: &Path) -> Result<String> {
    let mut out = String::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| corrupt(source, "cannot reserve catalog WAL column family"))?;
    out.push_str(value);
    Ok(out)
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
    v2: bool,
    legacy_probe: bool,
    mut visit: impl FnMut(BorrowedOp<'a>) -> Result<()>,
) -> Result<Option<(u64, ParsedControl, usize)>> {
    if payload.len() < PAYLOAD_HEADER_LEN {
        return Ok(None);
    }
    // Remaining-byte guards handle incomplete input before each read. Keep the
    // reader's unused error context empty so a successful legacy probe does
    // not allocate even a source-path copy; format errors use source below.
    let mut reader = BinaryReader::new(payload, PathBuf::new());
    let sequence = reader.read_u64()?;
    let ops = reader.read_u32()? as usize;
    if ops != 0 {
        let first_minimum = if legacy_probe { MIN_OP_LEN } else { 5 };
        let minimum = (ops - 1)
            .checked_mul(MIN_OP_LEN)
            .and_then(|len| len.checked_add(first_minimum))
            .ok_or_else(|| corrupt(source, "WAL operation count overflow"))?;
        if minimum > reader.remaining() {
            return Ok(None);
        }
    }
    let mut control = ParsedControl::None;
    for index in 0..ops {
        if reader.remaining() == 0 {
            return Ok(None);
        }
        let tag = reader.read_u8()?;
        if matches!(tag, 5..=7) || (index == 0 && !matches!(tag, 1..=4)) {
            if index != 0 {
                return Err(corrupt(
                    source,
                    "typed WAL control must occur once and first",
                ));
            }
            let Some(bytes) = partial_field(&mut reader)? else {
                return Ok(None);
            };
            control = match tag {
                5 => ParsedControl::Record(Envelope::decode(bytes, sequence, source)?),
                6 | 7 if v2 => {
                    ParsedControl::Catalog(CatalogControl::decode(tag, bytes, sequence, source)?)
                }
                6 | 7 => {
                    return Err(corrupt(source, "catalog authority requires v2 WAL framing"));
                }
                _ if v2 => ParsedControl::Unknown(tag),
                _ => return Err(corrupt(source, format!("unknown WAL op tag {tag}"))),
            };
            continue;
        }
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
        visit(op)?;
    }
    Ok(Some((sequence, control, reader.position())))
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::core_records::codec::Kind;

    const CATALOG_BOOTSTRAP: &[u8; 563] =
        include_bytes!("../../tests/fixtures/catalog_tag6_bootstrap_s1.bin");
    const CATALOG_CREATE: &[u8; 424] =
        include_bytes!("../../tests/fixtures/catalog_tag7_create_s2.bin");

    fn assert_frozen_catalog_frame(bytes: &[u8], sequence: u64, tag: u8, control_len: u32) {
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            sequence
        );
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 5);
        assert_eq!(bytes[28], tag);
        assert_eq!(
            u32::from_le_bytes(bytes[29..33].try_into().unwrap()),
            control_len
        );
        match parse_core_record_prefix(bytes, Path::new("frozen-catalog-frame")).unwrap() {
            CoreRecordPrefix::Complete {
                record,
                encoded_len,
            } => {
                assert_eq!(encoded_len, bytes.len());
                assert_eq!(record.sequence(), sequence);
                assert_eq!(record.try_encode().unwrap(), bytes);
            }
            CoreRecordPrefix::Torn => panic!("complete frozen tag {tag} was torn"),
        }
    }

    #[test]
    fn frozen_tag6_catalog_frame_parses_and_reencodes_exactly() {
        assert_frozen_catalog_frame(CATALOG_BOOTSTRAP, 1, 6, 120);
    }

    #[test]
    fn frozen_tag7_catalog_frame_parses_and_reencodes_exactly() {
        assert_frozen_catalog_frame(CATALOG_CREATE, 2, 7, 64);
    }

    fn assert_public_catalog_refusal(bytes: &[u8]) {
        let error = WalRecord::decode(bytes, Path::new("frozen-catalog-frame")).unwrap_err();
        assert!(
            error.to_string().contains("catalog-authority WAL requires"),
            "{error}"
        );
    }

    #[test]
    fn ordinary_wal_decoder_reports_catalog_authority_for_tag6() {
        assert_public_catalog_refusal(CATALOG_BOOTSTRAP);
    }

    #[test]
    fn ordinary_wal_decoder_reports_catalog_authority_for_tag7() {
        assert_public_catalog_refusal(CATALOG_CREATE);
    }

    fn bootstrap() -> CoreWalRecord {
        CoreWalRecord::Record {
            sequence: 1,
            batch: WriteBatch::new(),
            envelope: Envelope {
                kind: Kind::Bootstrap,
                database_id: [0x11; 16],
                prior_rid: 0,
                new_rid: 0,
                prior_compatibility_sequence: 0,
                new_compatibility_sequence: 0,
                prior_append_ordinal: 0,
                new_append_ordinal: 0,
                record_count: 0,
                logical_entry_count: 0,
            },
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = WAL_V2_MAGIC.to_le_bytes().to_vec();
        bytes.extend((payload.len() as u32).to_le_bytes());
        bytes.extend(crc32c(payload).to_le_bytes());
        bytes.extend(crc32c(&bytes).to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    fn legacy_frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = WAL_MAGIC.to_le_bytes().to_vec();
        bytes.extend((payload.len() as u32).to_le_bytes());
        bytes.extend(crc32c(payload).to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    fn parse_error(bytes: &[u8], path: &Path) -> PraxisError {
        match parse_core_record_prefix(bytes, path) {
            Err(error) => error,
            Ok(_) => panic!("expected typed WAL parser refusal"),
        }
    }

    fn control_payload(tag: u8, control: &[u8], operation_count: u32) -> Vec<u8> {
        let mut payload = 1u64.to_le_bytes().to_vec();
        payload.extend(operation_count.to_le_bytes());
        payload.push(tag);
        payload.extend((control.len() as u32).to_le_bytes());
        payload.extend(control);
        payload
    }

    fn size_boundary_frame(total_len: usize) -> Vec<u8> {
        // Header 16 + payload prefix 12 + PCB1 control 125 + one Put's
        // field framing 15 leaves exactly this many value bytes.
        let value_len = total_len - 168;
        let mut payload = control_payload(6, &CATALOG_BOOTSTRAP[33..153], 2);
        payload.push(1);
        payload.extend(1u32.to_le_bytes());
        payload.push(b'x');
        payload.extend(1u32.to_le_bytes());
        payload.push(b'k');
        payload.extend((value_len as u32).to_le_bytes());
        payload.resize(payload.len() + value_len, b'v');
        let bytes = frame(&payload);
        assert_eq!(bytes.len(), total_len);
        bytes
    }

    #[test]
    fn unknown_first_control_requires_complete_structure_before_unsupported() {
        for control in [&[][..], &[0x11, 0x22][..]] {
            let bytes = frame(&control_payload(8, control, 1));
            let error = parse_error(&bytes, Path::new("unknown-first"));
            assert!(
                error.to_string().contains("unsupported WAL control"),
                "{error}"
            );
        }
        let mut ordinary = WriteBatch::new();
        ordinary.delete_default("x");
        let ordinary = WalRecord {
            sequence: 1,
            batch: ordinary,
        }
        .encode();
        let mut payload = control_payload(8, &[], 2);
        payload.extend(&ordinary[28..]);
        let error = parse_error(&frame(&payload), Path::new("unknown-first"));
        assert!(
            error.to_string().contains("unsupported WAL control"),
            "{error}"
        );
    }

    #[test]
    fn malformed_trailing_and_late_controls_remain_corruption() {
        let path = Path::new("malformed-control");
        let mut payload = control_payload(8, &[], 2);
        payload.extend([1, 2, 0, 0]); // truncated Put CF length
        assert!(matches!(
            parse_core_record_prefix(&frame(&payload), path),
            Err(PraxisError::Corrupt { .. })
        ));
        let mut ordinary = WriteBatch::new();
        ordinary.delete_default("x");
        let ordinary = WalRecord {
            sequence: 1,
            batch: ordinary,
        }
        .encode();
        for tag in [6, 8] {
            let mut payload = 1u64.to_le_bytes().to_vec();
            payload.extend(2u32.to_le_bytes());
            payload.extend(&ordinary[28..]);
            payload.push(tag);
            let control = if tag == 6 {
                &CATALOG_BOOTSTRAP[33..153]
            } else {
                &[]
            };
            payload.extend((control.len() as u32).to_le_bytes());
            payload.extend(control);
            assert!(matches!(
                parse_core_record_prefix(&frame(&payload), path),
                Err(PraxisError::Corrupt { .. })
            ));
        }
    }

    #[test]
    fn catalog_frame_limit_is_inclusive_and_checksum_precedes_limit() {
        let path = Path::new("catalog-frame-limit");
        let maximum = size_boundary_frame(1_048_576);
        assert_eq!(
            u32::from_le_bytes(maximum[8..12].try_into().unwrap()),
            0xef4d_77c6
        );
        assert!(matches!(
            parse_core_record_prefix(&maximum, path),
            Ok(CoreRecordPrefix::Complete {
                encoded_len: 1_048_576,
                ..
            })
        ));
        let oversized = size_boundary_frame(1_048_577);
        let error = parse_error(&oversized, path);
        assert!(
            error
                .to_string()
                .contains("catalog WAL frame exceeds 1 MiB limit"),
            "{error}"
        );
        let mut bad_crc = oversized;
        bad_crc[40] ^= 1;
        let error = parse_error(&bad_crc, path);
        assert!(error.to_string().contains("checksum mismatch"), "{error}");
    }

    #[test]
    fn zero_operation_user_frame_remains_valid() {
        let mut payload = 3u64.to_le_bytes().to_vec();
        payload.extend(0u32.to_le_bytes());
        let bytes = frame(&payload);
        match parse_core_record_prefix(&bytes, Path::new("empty-user")).unwrap() {
            CoreRecordPrefix::Complete {
                record: CoreWalRecord::User(record),
                encoded_len,
            } => {
                assert_eq!(encoded_len, bytes.len());
                assert_eq!(record.sequence, 3);
                assert!(record.batch.is_empty());
            }
            _ => panic!("empty ordinary frame was not User"),
        }
        let legacy = legacy_frame(&payload);
        assert!(matches!(
            parse_core_record_prefix(&legacy, Path::new("empty-v1-user")),
            Ok(CoreRecordPrefix::Complete {
                record: CoreWalRecord::User(_),
                ..
            })
        ));
    }

    #[test]
    fn v1_catalog_and_unknown_first_controls_remain_corruption() {
        let path = Path::new("legacy-control");
        for bytes in [CATALOG_BOOTSTRAP.as_slice(), CATALOG_CREATE.as_slice()] {
            let error = parse_error(&legacy_frame(&bytes[16..]), path);
            assert!(
                error
                    .to_string()
                    .contains("catalog authority requires v2 WAL framing"),
                "{error}"
            );
        }
        let unknown = control_payload(8, &[], 1);
        assert!(matches!(
            parse_core_record_prefix(&legacy_frame(&unknown), path),
            Err(PraxisError::Corrupt { .. })
        ));
    }

    #[test]
    fn catalog_control_bytes_and_declared_operation_count_are_strict() {
        let path = Path::new("catalog-control-fields");
        for literal in [CATALOG_BOOTSTRAP.as_slice(), CATALOG_CREATE.as_slice()] {
            for offset in [33, 37, 39, 57]
                .into_iter()
                .chain((literal == CATALOG_BOOTSTRAP.as_slice()).then_some(41))
            {
                let mut payload = literal[16..].to_vec();
                payload[offset - 16] ^= 1;
                assert!(matches!(
                    parse_core_record_prefix(&frame(&payload), path),
                    Err(PraxisError::Corrupt { .. })
                ));
            }
            let mut payload = literal[16..].to_vec();
            payload[29 - 16] -= 1; // Control advertises one byte less.
            assert!(matches!(
                parse_core_record_prefix(&frame(&payload), path),
                Err(PraxisError::Corrupt { .. })
            ));
            let mut payload = literal[16..].to_vec();
            payload[8..12].copy_from_slice(&4u32.to_le_bytes());
            let error = parse_error(&frame(&payload), path);
            assert!(
                error.to_string().contains("trailing WAL payload bytes"),
                "{error}"
            );
        }
    }

    #[test]
    fn typed_control_retains_envelope_and_torn_boundaries_without_legacy_downgrade() {
        let value = bootstrap();
        let bytes = value.try_encode().unwrap();
        let path = Path::new("typed");
        match parse_core_record_prefix(&bytes, path).unwrap() {
            CoreRecordPrefix::Complete {
                record,
                encoded_len,
            } => {
                assert_eq!(record, value);
                assert_eq!(encoded_len, bytes.len());
            }
            _ => panic!("complete typed record lost"),
        }
        assert!(matches!(
            WalRecord::decode(&bytes, path),
            Err(PraxisError::RecordAuthorityWalRequired { .. })
        ));
        for cut in 0..bytes.len() {
            assert!(
                matches!(
                    parse_core_record_prefix(&bytes[..cut], path).unwrap(),
                    CoreRecordPrefix::Torn
                ),
                "cut{cut}"
            );
        }
        assert_eq!(bytes.len(), 16 + 12 + 5 + 88);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 0); // high half of sequence
        assert_eq!(&bytes[24..33], &[1, 0, 0, 0, 5, 88, 0, 0, 0]);
    }

    #[test]
    fn typed_control_cannot_follow_an_operation_or_repeat_or_use_legacy_frame() {
        let path = Path::new("typed");
        let bytes = bootstrap().try_encode().unwrap();
        let control = &bytes[28..];
        let mut batch = WriteBatch::new();
        batch.delete_default("x");
        let ordinary = WalRecord { sequence: 1, batch }.try_encode().unwrap();
        for body in [
            [control, control].concat(),
            [&ordinary[28..], control].concat(),
        ] {
            let mut payload = 1u64.to_le_bytes().to_vec();
            payload.extend(2u32.to_le_bytes());
            payload.extend(body);
            assert!(parse_core_record_prefix(&frame(&payload), path).is_err());
        }
        let mut legacy = WAL_MAGIC.to_le_bytes().to_vec();
        legacy.extend(((bytes.len() - 16) as u32).to_le_bytes());
        legacy.extend(crc32c(&bytes[16..]).to_le_bytes());
        legacy.extend(&bytes[16..]);
        assert!(parse_core_record_prefix(&legacy, path).is_err());
        let mut payload = bytes[16..].to_vec();
        payload[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_core_record_prefix(&frame(&payload), path).is_err());
    }

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
