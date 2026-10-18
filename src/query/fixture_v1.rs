//! Private PRXQDOC-NUL v1 test-root fixture codec; not a product document format.

use crate::document::{Record, RecordId};
use serde_json::{Number, Value};
use std::collections::BTreeMap;

pub(super) const MAX_FRAME_BYTES: usize = 1_048_576;
const MAGIC: &[u8; 8] = b"PRXQDOC\0";
const MIN_FRAME_BYTES: usize = 23;
const MAX_COLLECTION_BYTES: usize = 255;
const MAX_KEY_BYTES: usize = 1_024;
const MAX_ATTRIBUTE_COUNT: usize = 256;
const MAX_ATTRIBUTE_NAME_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixtureDecodeReason {
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    FrameLength,
    FrameTooLarge,
    Truncated,
    InvalidUtf8,
    InvalidCollectionLength,
    InvalidKeyLength,
    InvalidAttributeCount,
    InvalidAttributeNameLength,
    DuplicateAttribute,
    NonCanonicalAttributeOrder,
    UnknownValueTag,
    NonCanonicalInteger,
    TextTooLong,
    TrailingBytes,
}

impl FixtureDecodeReason {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::InvalidMagic => "invalid_magic",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::FrameLength => "frame_length",
            Self::FrameTooLarge => "frame_too_large",
            Self::Truncated => "truncated",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InvalidCollectionLength => "invalid_collection_length",
            Self::InvalidKeyLength => "invalid_key_length",
            Self::InvalidAttributeCount => "invalid_attribute_count",
            Self::InvalidAttributeNameLength => "invalid_attribute_name_length",
            Self::DuplicateAttribute => "duplicate_attribute",
            Self::NonCanonicalAttributeOrder => "noncanonical_attribute_order",
            Self::UnknownValueTag => "unknown_value_tag",
            Self::NonCanonicalInteger => "noncanonical_integer",
            Self::TextTooLong => "text_too_long",
            Self::TrailingBytes => "trailing_bytes",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum FixtureEncodeError {
    UnsupportedFixtureValue,
    Limit { code: &'static str },
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum FixtureBudgetDecodeError {
    Document(FixtureDecodeReason),
    AttributeBudget,
}

impl From<FixtureDecodeReason> for FixtureBudgetDecodeError {
    fn from(reason: FixtureDecodeReason) -> Self {
        Self::Document(reason)
    }
}

/// Decode with a caller-owned cumulative allowance. The parsed count is
/// checked before any attribute entry or value is allocated.
pub(super) fn decode_document_with_attribute_budget(
    bytes: &[u8],
    remaining_attributes: usize,
) -> Result<(Record, usize), FixtureBudgetDecodeError> {
    decode_document_inner(bytes, remaining_attributes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], FixtureDecodeReason> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(FixtureDecodeReason::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FixtureDecodeReason::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, FixtureDecodeReason> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, FixtureDecodeReason> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, FixtureDecodeReason> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, FixtureDecodeReason> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, FixtureDecodeReason> {
    std::str::from_utf8(bytes).map_err(|_| FixtureDecodeReason::InvalidUtf8)
}

/// Decode one complete, bounded fixture frame. No delimiter splitting or
/// extension skipping is permitted, even for attributes a query will not read.
pub(super) fn decode_document(bytes: &[u8]) -> Result<Record, FixtureDecodeReason> {
    match decode_document_inner(bytes, usize::MAX) {
        Ok((record, _)) => Ok(record),
        Err(FixtureBudgetDecodeError::Document(reason)) => Err(reason),
        Err(FixtureBudgetDecodeError::AttributeBudget) => {
            unreachable!("a v1 attribute count cannot exceed usize::MAX")
        }
    }
}

fn decode_document_inner(
    bytes: &[u8],
    remaining_attributes: usize,
) -> Result<(Record, usize), FixtureBudgetDecodeError> {
    use FixtureDecodeReason as Reason;

    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Reason::FrameTooLarge.into());
    }
    if bytes.len() < 16 {
        return Err(Reason::Truncated.into());
    }
    let declared = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if declared > MAX_FRAME_BYTES {
        return Err(Reason::FrameTooLarge.into());
    }
    if declared != bytes.len() || declared < MIN_FRAME_BYTES {
        return Err(Reason::FrameLength.into());
    }
    if &bytes[..8] != MAGIC {
        return Err(Reason::InvalidMagic.into());
    }
    if bytes[8..10] != [0, 1] {
        return Err(Reason::UnsupportedVersion.into());
    }
    if bytes[10..12] != [0, 0] {
        return Err(Reason::UnsupportedFlags.into());
    }

    let mut cursor = Cursor { bytes, offset: 16 };
    let collection_len = usize::from(cursor.u16()?);
    if !(1..=MAX_COLLECTION_BYTES).contains(&collection_len) {
        return Err(Reason::InvalidCollectionLength.into());
    }
    let collection = utf8(cursor.take(collection_len)?)?.to_owned();

    let key_len = usize::from(cursor.u16()?);
    if key_len > MAX_KEY_BYTES {
        return Err(Reason::InvalidKeyLength.into());
    }
    let key = utf8(cursor.take(key_len)?)?.to_owned();

    let attribute_count = usize::from(cursor.u16()?);
    if attribute_count > MAX_ATTRIBUTE_COUNT {
        return Err(Reason::InvalidAttributeCount.into());
    }
    if attribute_count > remaining_attributes {
        return Err(FixtureBudgetDecodeError::AttributeBudget);
    }
    let mut attributes = BTreeMap::new();
    let mut previous_name: Option<&[u8]> = None;
    for _ in 0..attribute_count {
        let name_len = usize::from(cursor.u16()?);
        if !(1..=MAX_ATTRIBUTE_NAME_BYTES).contains(&name_len) {
            return Err(Reason::InvalidAttributeNameLength.into());
        }
        let name_bytes = cursor.take(name_len)?;
        let name = utf8(name_bytes)?;
        if let Some(previous) = previous_name {
            match previous.cmp(name_bytes) {
                std::cmp::Ordering::Equal => return Err(Reason::DuplicateAttribute.into()),
                std::cmp::Ordering::Greater => {
                    return Err(Reason::NonCanonicalAttributeOrder.into());
                }
                std::cmp::Ordering::Less => {}
            }
        }
        previous_name = Some(name_bytes);

        let value = match cursor.u8()? {
            0 => Value::Null,
            1 => Value::Bool(false),
            2 => Value::Bool(true),
            3 => {
                let signed = i64::from_be_bytes(cursor.u64()?.to_be_bytes());
                if signed >= 0 {
                    return Err(Reason::NonCanonicalInteger.into());
                }
                Value::Number(Number::from(signed))
            }
            4 => Value::Number(Number::from(cursor.u64()?)),
            5 => {
                let text_len = cursor.u32()? as usize;
                if text_len > MAX_TEXT_BYTES {
                    return Err(Reason::TextTooLong.into());
                }
                Value::String(utf8(cursor.take(text_len)?)?.to_owned())
            }
            _ => return Err(Reason::UnknownValueTag.into()),
        };
        attributes.insert(name.to_owned(), value);
    }
    if cursor.offset != bytes.len() {
        return Err(Reason::TrailingBytes.into());
    }

    Ok((
        Record {
            id: RecordId::new(collection, key),
            attributes,
            labels: Vec::new(),
            vectors: BTreeMap::new(),
            edges: Vec::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
        },
        attribute_count,
    ))
}

enum Scalar<'a> {
    Null,
    False,
    True,
    Negative(i64),
    Unsigned(u64),
    Text(&'a str),
}

impl Scalar<'_> {
    fn payload_len(&self) -> usize {
        match self {
            Self::Null | Self::False | Self::True => 0,
            Self::Negative(_) | Self::Unsigned(_) => 8,
            Self::Text(text) => 4 + text.len(),
        }
    }

    fn append(self, output: &mut Vec<u8>) {
        match self {
            Self::Null => output.push(0),
            Self::False => output.push(1),
            Self::True => output.push(2),
            Self::Negative(number) => {
                output.push(3);
                output.extend_from_slice(&number.to_be_bytes());
            }
            Self::Unsigned(number) => {
                output.push(4);
                output.extend_from_slice(&number.to_be_bytes());
            }
            Self::Text(text) => {
                output.push(5);
                output.extend_from_slice(&(text.len() as u32).to_be_bytes());
                output.extend_from_slice(text.as_bytes());
            }
        }
    }
}

fn scalar(value: &Value) -> Result<Scalar<'_>, FixtureEncodeError> {
    match value {
        Value::Null => Ok(Scalar::Null),
        Value::Bool(false) => Ok(Scalar::False),
        Value::Bool(true) => Ok(Scalar::True),
        Value::String(text) if text.len() <= MAX_TEXT_BYTES => Ok(Scalar::Text(text)),
        Value::String(_) => Err(FixtureEncodeError::Limit { code: "text_bytes" }),
        Value::Number(number) => {
            if let Some(signed) = number.as_i64().filter(|signed| *signed < 0) {
                Ok(Scalar::Negative(signed))
            } else if let Some(unsigned) = number.as_u64() {
                Ok(Scalar::Unsigned(unsigned))
            } else {
                Err(FixtureEncodeError::UnsupportedFixtureValue)
            }
        }
        Value::Array(_) | Value::Object(_) => Err(FixtureEncodeError::UnsupportedFixtureValue),
    }
}

fn add_frame_bytes(total: usize, count: usize) -> Result<usize, FixtureEncodeError> {
    let total = total.checked_add(count).ok_or(FixtureEncodeError::Limit {
        code: "frame_bytes",
    })?;
    if total > MAX_FRAME_BYTES {
        Err(FixtureEncodeError::Limit {
            code: "frame_bytes",
        })
    } else {
        Ok(total)
    }
}

/// Encode only the three fixture fields after validating every value and the
/// complete output length. A full Record would silently drop unsupported extras.
pub(super) fn encode_document(
    collection: &str,
    key: &str,
    attributes: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, FixtureEncodeError> {
    if !(1..=MAX_COLLECTION_BYTES).contains(&collection.len()) {
        return Err(FixtureEncodeError::Limit {
            code: "collection_bytes",
        });
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(FixtureEncodeError::Limit { code: "key_bytes" });
    }
    if attributes.len() > MAX_ATTRIBUTE_COUNT {
        return Err(FixtureEncodeError::Limit {
            code: "attribute_count",
        });
    }

    let mut total = 16;
    total = add_frame_bytes(total, 2 + collection.len())?;
    total = add_frame_bytes(total, 2 + key.len())?;
    total = add_frame_bytes(total, 2)?;
    for (name, value) in attributes {
        if !(1..=MAX_ATTRIBUTE_NAME_BYTES).contains(&name.len()) {
            return Err(FixtureEncodeError::Limit {
                code: "attribute_name_bytes",
            });
        }
        let scalar = scalar(value)?;
        total = add_frame_bytes(total, 2 + name.len() + 1 + scalar.payload_len())?;
    }

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&(total as u32).to_be_bytes());
    output.extend_from_slice(&(collection.len() as u16).to_be_bytes());
    output.extend_from_slice(collection.as_bytes());
    output.extend_from_slice(&(key.len() as u16).to_be_bytes());
    output.extend_from_slice(key.as_bytes());
    output.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    for (name, value) in attributes {
        output.extend_from_slice(&(name.len() as u16).to_be_bytes());
        output.extend_from_slice(name.as_bytes());
        scalar(value)?.append(&mut output);
    }
    debug_assert_eq!(output.len(), total);
    Ok(output)
}

#[cfg(test)]
#[path = "fixture_v1_tests.rs"]
mod tests;
