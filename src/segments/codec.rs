//! Lossless segment framing shared by ordinary readers and backup relocation.
use crate::accel::Accelerator;
use crate::config::Compression;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::segments::block::SegmentEntry;
use crate::segments::format::{SEGMENT_FOOTER_MAGIC, SEGMENT_MAGIC, SEGMENT_VERSION};
use crate::types::{ColumnFamily, StoredValue, ValuePointer, VersionedValue};
use bytes::Bytes;
use std::io::Read;
use std::path::Path;

const HEADER_LEN: usize = 21;
const TRAILER_LEN: usize = 12;

pub(crate) struct RawEntry {
    pub entry: SegmentEntry,
    // Tag 4 must remain a pointer until the caller has resolved its authority.
    pub blob_expiry: Option<u64>,
}

pub(crate) struct RawSegment {
    pub id: u64,
    pub level: u32,
    pub compression: Compression,
    pub blocks: Vec<Vec<RawEntry>>,
}

pub(crate) fn decode_segment(
    bytes: &[u8],
    path: &Path,
    _accelerator: &dyn Accelerator,
) -> Result<RawSegment> {
    if bytes.len() < HEADER_LEN + TRAILER_LEN {
        return corrupt(path, "segment too small");
    }
    let mut header = BinaryReader::new(bytes, path);
    if header.read_u32()? != SEGMENT_MAGIC || header.read_u32()? != SEGMENT_VERSION {
        return corrupt(path, "bad segment magic or version");
    }
    let compression = match header.read_u8()? {
        0 => Compression::None,
        1 => Compression::Lz4,
        2 => Compression::Zstd,
        _ => return corrupt(path, "unknown segment compression tag"),
    };
    let level = header.read_u32()?;
    let id = header.read_u64()?;
    let trailer_start = bytes.len() - TRAILER_LEN;
    let mut trailer = BinaryReader::new(&bytes[trailer_start..], path);
    let footer_len = trailer.read_u32()? as usize;
    let footer_checksum = trailer.read_u32()?;
    if trailer.read_u32()? != SEGMENT_FOOTER_MAGIC {
        return corrupt(path, "bad segment footer magic");
    }
    let footer_start = trailer_start
        .checked_sub(footer_len)
        .filter(|start| *start >= HEADER_LEN)
        .ok_or_else(|| error(path, "segment footer out of bounds"))?;
    let footer_bytes = &bytes[footer_start..trailer_start];
    if crc32c(footer_bytes) != footer_checksum {
        return corrupt(path, "segment footer checksum mismatch");
    }
    let mut footer = BinaryReader::new(footer_bytes, path);
    let count = footer.read_u32()? as usize;
    if count > footer.remaining() / 24 {
        return corrupt(path, "segment block count exceeds footer");
    }
    let mut blocks = Vec::with_capacity(count);
    let mut previous_end = HEADER_LEN;
    for _ in 0..count {
        let first_key = footer.read_len_slice()?;
        let last_key = footer.read_len_slice()?;
        let offset = usize::try_from(footer.read_u64()?)
            .map_err(|_| error(path, "segment block offset exceeds platform range"))?;
        let len = usize::try_from(footer.read_u64()?)
            .map_err(|_| error(path, "segment block length exceeds platform range"))?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| error(path, "block overflow"))?;
        if offset != previous_end || end > footer_start || len < 12 {
            return corrupt(path, "segment block offset out of bounds or overlapping");
        }
        let mut block = BinaryReader::new(&bytes[offset..end], path);
        let compressed_len = block.read_u32()? as usize;
        let uncompressed_len = block.read_u32()? as usize;
        let expected = block.read_u32()?;
        let compressed = block.read_slice(compressed_len)?;
        if block.remaining() != 0 || crc32c(compressed) != expected {
            return corrupt(path, "segment block length or checksum mismatch");
        }
        let payload = decode_block(compression, compressed, uncompressed_len, path)?;
        let entries = decode_entries(&payload, path)?;
        if entries
            .first()
            .is_none_or(|entry| entry.entry.key.as_ref() != first_key)
            || entries
                .last()
                .is_none_or(|entry| entry.entry.key.as_ref() != last_key)
        {
            return corrupt(path, "segment block key range disagrees with entries");
        }
        blocks.push(entries);
        previous_end = end;
    }
    if footer.remaining() != 0 || previous_end != footer_start {
        return corrupt(path, "unconsumed segment framing bytes");
    }
    Ok(RawSegment {
        id,
        level,
        compression,
        blocks,
    })
}

/// The wire length is untrusted. Do not pass it (or an inner frame's size)
/// directly to a decoder that reserves that much output before validation.
fn decode_block(codec: Compression, bytes: &[u8], expected: usize, path: &Path) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    match codec {
        Compression::None => {
            if bytes.len() != expected {
                return corrupt(path, "segment decoded block length mismatch");
            }
            reserve(&mut output, expected, path)?;
            output.extend_from_slice(bytes);
        }
        Compression::Lz4 => {
            let prefix = bytes
                .get(..4)
                .ok_or_else(|| error(path, "missing LZ4 size prefix"))?;
            if u32::from_le_bytes(prefix.try_into().expect("size prefix")) as usize != expected {
                return corrupt(path, "LZ4 inner and segment lengths disagree");
            }
            validate_lz4_length(&bytes[4..], expected, path)?;
            reserve(&mut output, expected, path)?;
            output.resize(expected, 0);
            let written = lz4_flex::block::decompress_into(&bytes[4..], &mut output)
                .map_err(|_| error(path, "invalid LZ4 block"))?;
            if written != expected {
                return corrupt(path, "segment decoded block length mismatch");
            }
        }
        Compression::Zstd => {
            let content = zstd::zstd_safe::get_frame_content_size(bytes)
                .map_err(|_| error(path, "invalid Zstd frame header"))?;
            if content.is_some_and(|size| size != expected as u64) {
                return corrupt(path, "Zstd frame and segment lengths disagree");
            }
            // with_buffer uses the borrowed slice without an input allocation.
            // Unknown-size frames reserve only bytes actually decoded. Reading
            // at most one byte beyond the outer length also bounds bad streams.
            let mut decoder = zstd::stream::read::Decoder::with_buffer(bytes)
                .map_err(|_| error(path, "invalid Zstd block"))?;
            let mut chunk = [0_u8; 8192];
            loop {
                let limit = expected
                    .saturating_sub(output.len())
                    .saturating_add(1)
                    .min(chunk.len());
                let count = decoder
                    .read(&mut chunk[..limit])
                    .map_err(|_| error(path, "invalid Zstd block"))?;
                if count == 0 {
                    break;
                }
                if count > expected - output.len() {
                    return corrupt(path, "Zstd output exceeds segment length");
                }
                if output.capacity() - output.len() < count {
                    let capacity = output
                        .capacity()
                        .max(chunk.len())
                        .saturating_mul(2)
                        .min(expected);
                    let additional = capacity - output.len();
                    reserve(&mut output, additional, path)?;
                }
                output.extend_from_slice(&chunk[..count]);
            }
            if output.len() != expected {
                return corrupt(path, "segment decoded block length mismatch");
            }
        }
    }
    Ok(output)
}

fn reserve(output: &mut Vec<u8>, additional: usize, path: &Path) -> Result<()> {
    output
        .try_reserve_exact(additional)
        .map_err(|_| error(path, "segment output allocation failed"))
}

// Validate the raw LZ4 token lengths and offsets without allocating output.
// The library remains responsible for decoding and final validity checks.
fn validate_lz4_length(bytes: &[u8], expected: usize, path: &Path) -> Result<()> {
    fn length(bytes: &[u8], cursor: &mut usize, base: usize, path: &Path) -> Result<usize> {
        let mut len = base;
        if base == 15 {
            loop {
                let next = *bytes
                    .get(*cursor)
                    .ok_or_else(|| error(path, "truncated LZ4 length"))?;
                *cursor += 1;
                len = len
                    .checked_add(next as usize)
                    .ok_or_else(|| error(path, "LZ4 length overflow"))?;
                if next != 255 {
                    break;
                }
            }
        }
        Ok(len)
    }
    let mut cursor = 0;
    let mut produced = 0_usize;
    while cursor < bytes.len() {
        let token = bytes[cursor];
        cursor += 1;
        let literals = length(bytes, &mut cursor, (token >> 4) as usize, path)?;
        cursor = cursor
            .checked_add(literals)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| error(path, "truncated LZ4 literals"))?;
        produced = produced
            .checked_add(literals)
            .filter(|size| *size <= expected)
            .ok_or_else(|| error(path, "LZ4 output exceeds segment length"))?;
        if cursor == bytes.len() {
            break;
        }
        let offset = bytes
            .get(cursor..cursor.saturating_add(2))
            .ok_or_else(|| error(path, "missing LZ4 offset"))?;
        let offset = u16::from_le_bytes(offset.try_into().expect("offset")) as usize;
        if offset == 0 || offset > produced {
            return corrupt(path, "invalid LZ4 offset");
        }
        cursor += 2;
        let matched = length(bytes, &mut cursor, (token & 15) as usize, path)?;
        produced = produced
            .checked_add(matched)
            .and_then(|size| size.checked_add(4))
            .filter(|size| *size <= expected)
            .ok_or_else(|| error(path, "LZ4 output exceeds segment length"))?;
    }
    if produced != expected {
        return corrupt(path, "LZ4 output length disagrees with segment");
    }
    Ok(())
}

impl RawSegment {
    pub(crate) fn encode(&self, accelerator: &dyn Accelerator) -> Result<Vec<u8>> {
        let mut out = BinaryWriter::new();
        out.write_u32(SEGMENT_MAGIC);
        out.write_u32(SEGMENT_VERSION);
        out.write_u8(match self.compression {
            Compression::None => 0,
            Compression::Lz4 => 1,
            Compression::Zstd => 2,
        });
        out.write_u32(self.level);
        out.write_u64(self.id);
        let mut footer = BinaryWriter::new();
        footer.write_u32(checked_len(self.blocks.len())?);
        for entries in &self.blocks {
            let payload = encode_entries(entries)?;
            let compressed = accelerator.encode_block(self.compression, &payload)?;
            let offset = out.len();
            out.write_u32(checked_len(compressed.len())?);
            out.write_u32(checked_len(payload.len())?);
            out.write_u32(crc32c(&compressed));
            out.write_bytes(&compressed);
            let first = entries
                .first()
                .ok_or_else(|| error(Path::new("segment"), "empty block"))?;
            let last = entries.last().expect("checked nonempty block");
            write_len(&mut footer, &first.entry.key)?;
            write_len(&mut footer, &last.entry.key)?;
            footer.write_u64(offset as u64);
            footer.write_u64((out.len() - offset) as u64);
        }
        let footer = footer.into_inner();
        out.write_bytes(&footer);
        out.write_u32(checked_len(footer.len())?);
        out.write_u32(crc32c(&footer));
        out.write_u32(SEGMENT_FOOTER_MAGIC);
        Ok(out.into_inner())
    }
}

pub(crate) fn decode_entries(payload: &[u8], path: &Path) -> Result<Vec<RawEntry>> {
    let mut reader = BinaryReader::new(payload, path);
    let count = reader.read_u32()? as usize;
    if count > reader.remaining() / 17 {
        return corrupt(path, "segment entry count exceeds payload");
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let cf = ColumnFamily(
            String::from_utf8(reader.read_len_bytes()?)
                .map_err(|_| error(path, "invalid segment family UTF-8"))?,
        );
        let key = Bytes::from(reader.read_len_bytes()?);
        let sequence = reader.read_u64()?;
        let mut blob_expiry = None;
        let value = match reader.read_u8()? {
            1 => StoredValue::Put(reader.read_len_bytes()?),
            2 => StoredValue::Delete,
            tag @ (3 | 4) => {
                if tag == 4 {
                    blob_expiry = Some(reader.read_u64()?);
                }
                let label = String::from_utf8(reader.read_len_bytes()?)
                    .map_err(|_| error(path, "invalid value path UTF-8"))?;
                StoredValue::BlobPointer(ValuePointer {
                    path: label,
                    offset: reader.read_u64()?,
                    len: reader.read_u64()?,
                    checksum: reader.read_u32()?,
                })
            }
            5 => {
                let expires_at_ms = reader.read_u64()?;
                StoredValue::PutWithExpiry {
                    value: reader.read_len_bytes()?,
                    expires_at_ms,
                }
            }
            6 => StoredValue::Merge(reader.read_len_bytes()?),
            _ => return corrupt(path, "unknown segment value tag"),
        };
        entries.push(RawEntry {
            entry: SegmentEntry {
                cf,
                key,
                version: VersionedValue { sequence, value },
            },
            blob_expiry,
        });
    }
    if reader.remaining() != 0 {
        return corrupt(path, "unconsumed segment entry bytes");
    }
    Ok(entries)
}

pub(crate) fn encode_entries(entries: &[RawEntry]) -> Result<Vec<u8>> {
    let mut out = BinaryWriter::new();
    out.write_u32(checked_len(entries.len())?);
    for raw in entries {
        let entry = &raw.entry;
        write_len(&mut out, entry.cf.0.as_bytes())?;
        write_len(&mut out, &entry.key)?;
        out.write_u64(entry.version.sequence);
        match &entry.version.value {
            StoredValue::Put(value) => {
                out.write_u8(1);
                write_len(&mut out, value)?;
            }
            StoredValue::Delete => out.write_u8(2),
            StoredValue::BlobPointer(pointer) => {
                out.write_u8(if raw.blob_expiry.is_some() { 4 } else { 3 });
                if let Some(expiry) = raw.blob_expiry {
                    out.write_u64(expiry);
                }
                write_len(&mut out, pointer.path.as_bytes())?;
                out.write_u64(pointer.offset);
                out.write_u64(pointer.len);
                out.write_u32(pointer.checksum);
            }
            StoredValue::PutWithExpiry {
                value,
                expires_at_ms,
            } => {
                out.write_u8(5);
                out.write_u64(*expires_at_ms);
                write_len(&mut out, value)?;
            }
            StoredValue::Merge(value) => {
                out.write_u8(6);
                write_len(&mut out, value)?;
            }
        }
    }
    Ok(out.into_inner())
}

fn checked_len(len: usize) -> Result<u32> {
    u32::try_from(len)
        .map_err(|_| PraxisError::InvalidConfig("segment field exceeds u32 encoding".to_string()))
}
fn write_len(out: &mut BinaryWriter, value: &[u8]) -> Result<()> {
    out.write_u32(checked_len(value.len())?);
    out.write_bytes(value);
    Ok(())
}
fn error(path: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}
fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(error(path, reason))
}
