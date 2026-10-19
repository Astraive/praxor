//! Exact, private v4 catalog keys and rows. These routines parse bytes only;
//! they neither open a root nor grant a catalog writer capability.
use crate::errors::{PraxisError, Result};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;
use std::path::Path;

const CODEC: u16 = 1;
const EPOCH: u64 = 1;
const MAX_NAME_BYTES: usize = 255;
const MAX_FIELDS: usize = 128;
const ANCHOR_DOMAIN: &[u8; 33] = b"praxor.catalog.bootstrap.head.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct CollectionId(NonZeroU64);

impl CollectionId {
    pub(crate) fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NamespaceId(NonZeroU64);

impl NamespaceId {
    pub(crate) fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatalogKey<'a> {
    Head,
    Name(&'a str),
    Schema(CollectionId),
    Namespace(NamespaceId),
    Anchor,
}

impl<'a> CatalogKey<'a> {
    pub(crate) fn decode(bytes: &'a [u8], source: &Path) -> Result<Self> {
        let mut input = Input::new(bytes, source);
        let key = match input.u8()? {
            0 => Self::Head,
            1 => {
                let len = input.u16_be()? as usize;
                if len == 0 || len > MAX_NAME_BYTES {
                    return Err(input.error("invalid catalog name length"));
                }
                let name = input.name(len)?;
                Self::Name(name)
            }
            2 => Self::Schema(
                CollectionId::new(input.u64_be()?)
                    .ok_or_else(|| input.error("zero catalog collection ID"))?,
            ),
            3 => Self::Namespace(
                NamespaceId::new(input.u64_be()?)
                    .ok_or_else(|| input.error("zero catalog namespace ID"))?,
            ),
            4 => Self::Anchor,
            _ => return Err(input.error("unknown catalog key tag")),
        };
        input.end()?;
        Ok(key)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let size = match self {
            Self::Head | Self::Anchor => 1,
            Self::Name(name) => {
                validate_name(name)?;
                3usize.checked_add(name.len()).ok_or_else(oversize)?
            }
            Self::Schema(_) | Self::Namespace(_) => 9,
        };
        let mut out = fallible_vec(size)?;
        match self {
            Self::Head => out.push(0),
            Self::Name(name) => {
                out.push(1);
                out.extend(
                    u16::try_from(name.len())
                        .map_err(|_| oversize())?
                        .to_be_bytes(),
                );
                out.extend(name.as_bytes());
            }
            Self::Schema(id) => {
                out.push(2);
                out.extend(id.get().to_be_bytes());
            }
            Self::Namespace(id) => {
                out.push(3);
                out.extend(id.get().to_be_bytes());
            }
            Self::Anchor => out.push(4),
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Head {
    pub database_id: [u8; 16],
    pub revision: u64,
    pub collection_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Anchor {
    pub database_id: [u8; 16],
    pub head_at_1_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ScalarType {
    Int2 = 1,
    Int4 = 2,
    Int8 = 3,
    Uint8 = 4,
    Boolean = 5,
    Text = 6,
}

impl ScalarType {
    fn decode(code: u8, source: &Path) -> Result<Self> {
        match code {
            1 => Ok(Self::Int2),
            2 => Ok(Self::Int4),
            3 => Ok(Self::Int8),
            4 => Ok(Self::Uint8),
            5 => Ok(Self::Boolean),
            6 => Ok(Self::Text),
            _ => Err(corrupt(source, "unknown catalog scalar code")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Field<'a> {
    pub id: u16,
    pub name: &'a str,
    pub scalar: ScalarType,
    pub nullable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Schema<'a> {
    pub collection_id: CollectionId,
    pub namespace_id: NamespaceId,
    pub name: &'a str,
    pub fields: Vec<Field<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatalogValue<'a> {
    Head(Head),
    Name(CollectionId),
    Schema(Schema<'a>),
    Namespace(CollectionId),
    Anchor(Anchor),
}

impl<'a> CatalogValue<'a> {
    pub(crate) fn decode(key: &CatalogKey<'_>, bytes: &'a [u8], source: &Path) -> Result<Self> {
        let mut input = Input::new(bytes, source);
        let magic = input.take(4)?;
        let value = match (key, magic) {
            (CatalogKey::Head, b"PCH1") => {
                input.header()?;
                let database_id = input.database_id()?;
                input.epoch()?;
                let revision = input.u64()?;
                if revision == 0 {
                    return Err(input.error("zero catalog head revision"));
                }
                Self::Head(Head {
                    database_id,
                    revision,
                    collection_count: input.u64()?,
                })
            }
            (CatalogKey::Anchor, b"PCA1") => {
                input.header()?;
                let database_id = input.database_id()?;
                input.epoch()?;
                if input.u64()? != 1 {
                    return Err(input.error("invalid catalog bootstrap sequence"));
                }
                let head_at_1_digest: [u8; 32] = input.take(32)?.try_into().unwrap();
                if head_at_1_digest != anchor_digest(database_id)? {
                    return Err(input.error("catalog Anchor digest does not match Head@1"));
                }
                Self::Anchor(Anchor {
                    database_id,
                    head_at_1_digest,
                })
            }
            (CatalogKey::Name(_), b"PCN1") => Self::Name(
                CollectionId::new(input.u64()?)
                    .ok_or_else(|| input.error("zero catalog collection ID"))?,
            ),
            (CatalogKey::Schema(key_id), b"PCS1") => {
                input.header()?;
                let collection_id = CollectionId::new(input.u64()?)
                    .ok_or_else(|| input.error("zero catalog collection ID"))?;
                let namespace_id = NamespaceId::new(input.u64()?)
                    .ok_or_else(|| input.error("zero catalog namespace ID"))?;
                if collection_id != *key_id || collection_id.get() != namespace_id.get() {
                    return Err(input.error("catalog schema key/namespace ID mismatch"));
                }
                let name_len = input.u16()? as usize;
                if name_len == 0 || name_len > MAX_NAME_BYTES {
                    return Err(input.error("invalid catalog collection name length"));
                }
                let name = input.name(name_len)?;
                let count = input.u16()? as usize;
                if !(1..=MAX_FIELDS).contains(&count)
                    || count
                        .checked_mul(9)
                        .is_none_or(|minimum| minimum > input.remaining())
                {
                    return Err(input.error("invalid catalog schema field count/length"));
                }
                let mut fields = Vec::new();
                fields
                    .try_reserve_exact(count)
                    .map_err(|_| input.error("cannot allocate catalog fields"))?;
                let mut prior_name: Option<&str> = None;
                for ordinal in 1..=count {
                    let id = input.u16()?;
                    let field_len = input.u16()? as usize;
                    if field_len == 0 || field_len > MAX_NAME_BYTES || id as usize != ordinal {
                        return Err(input.error("noncanonical catalog field ID/name length"));
                    }
                    let field_name = input.name(field_len)?;
                    if prior_name.is_some_and(|prior| prior.as_bytes() >= field_name.as_bytes()) {
                        return Err(input.error("catalog field names are not strictly sorted"));
                    }
                    let scalar = ScalarType::decode(input.u8()?, source)?;
                    let nullable = match input.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(input.error("invalid catalog nullability byte")),
                    };
                    if input.u16()? != 0 {
                        return Err(input.error("nonzero catalog field reserved bytes"));
                    }
                    fields.push(Field {
                        id,
                        name: field_name,
                        scalar,
                        nullable,
                    });
                    prior_name = Some(field_name);
                }
                Self::Schema(Schema {
                    collection_id,
                    namespace_id,
                    name,
                    fields,
                })
            }
            (CatalogKey::Namespace(key_id), b"PCX1") => {
                input.header()?;
                let collection_id = CollectionId::new(input.u64()?)
                    .ok_or_else(|| input.error("zero catalog collection ID"))?;
                if collection_id.get() != key_id.get() {
                    return Err(input.error("catalog namespace key/collection ID mismatch"));
                }
                Self::Namespace(collection_id)
            }
            _ => return Err(input.error("catalog row magic does not match key")),
        };
        input.end()?;
        Ok(value)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let size = match self {
            Self::Head(head) => {
                validate_database_id(head.database_id)?;
                if head.revision == 0 {
                    return Err(invalid("zero catalog head revision"));
                }
                48
            }
            Self::Anchor(anchor) => {
                if anchor.head_at_1_digest != anchor_digest(anchor.database_id)? {
                    return Err(invalid("catalog Anchor digest does not match Head@1"));
                }
                72
            }
            Self::Name(_) => 12,
            Self::Namespace(_) => 16,
            Self::Schema(schema) => {
                validate_schema(schema)?;
                let mut size = 4usize + 2 + 2 + 8 + 8 + 2 + schema.name.len() + 2;
                for field in &schema.fields {
                    size = size
                        .checked_add(2 + 2 + field.name.len() + 1 + 1 + 2)
                        .ok_or_else(oversize)?;
                }
                size
            }
        };
        let mut out = fallible_vec(size)?;
        match self {
            Self::Head(head) => {
                out.extend(b"PCH1");
                header(&mut out);
                out.extend(head.database_id);
                out.extend(EPOCH.to_le_bytes());
                out.extend(head.revision.to_le_bytes());
                out.extend(head.collection_count.to_le_bytes());
            }
            Self::Anchor(anchor) => {
                out.extend(b"PCA1");
                header(&mut out);
                out.extend(anchor.database_id);
                out.extend(EPOCH.to_le_bytes());
                out.extend(1u64.to_le_bytes());
                out.extend(anchor.head_at_1_digest);
            }
            Self::Name(id) => {
                out.extend(b"PCN1");
                out.extend(id.get().to_le_bytes());
            }
            Self::Schema(schema) => {
                out.extend(b"PCS1");
                header(&mut out);
                out.extend(schema.collection_id.get().to_le_bytes());
                out.extend(schema.namespace_id.get().to_le_bytes());
                out.extend(
                    u16::try_from(schema.name.len())
                        .map_err(|_| oversize())?
                        .to_le_bytes(),
                );
                out.extend(schema.name.as_bytes());
                out.extend(
                    u16::try_from(schema.fields.len())
                        .map_err(|_| oversize())?
                        .to_le_bytes(),
                );
                for field in &schema.fields {
                    out.extend(field.id.to_le_bytes());
                    out.extend(
                        u16::try_from(field.name.len())
                            .map_err(|_| oversize())?
                            .to_le_bytes(),
                    );
                    out.extend(field.name.as_bytes());
                    out.push(field.scalar as u8);
                    out.push(u8::from(field.nullable));
                    out.extend(0u16.to_le_bytes());
                }
            }
            Self::Namespace(id) => {
                out.extend(b"PCX1");
                header(&mut out);
                out.extend(id.get().to_le_bytes());
            }
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }
}

pub(crate) fn canonical_head_at_1(database_id: [u8; 16]) -> Result<[u8; 48]> {
    validate_database_id(database_id)?;
    let mut head = [0u8; 48];
    head[..4].copy_from_slice(b"PCH1");
    head[4..6].copy_from_slice(&CODEC.to_le_bytes());
    head[8..24].copy_from_slice(&database_id);
    head[24..32].copy_from_slice(&EPOCH.to_le_bytes());
    head[32..40].copy_from_slice(&1u64.to_le_bytes());
    Ok(head)
}

pub(crate) fn anchor_digest(database_id: [u8; 16]) -> Result<[u8; 32]> {
    let head = canonical_head_at_1(database_id)?;
    let mut preimage = [0u8; 85];
    preimage[..33].copy_from_slice(ANCHOR_DOMAIN);
    preimage[33..37].copy_from_slice(&48u32.to_le_bytes());
    preimage[37..].copy_from_slice(&head);
    Ok(Sha256::digest(preimage).into())
}

fn validate_schema(schema: &Schema<'_>) -> Result<()> {
    if schema.collection_id.get() != schema.namespace_id.get() {
        return Err(invalid("catalog schema collection/namespace ID mismatch"));
    }
    validate_name(schema.name)?;
    if !(1..=MAX_FIELDS).contains(&schema.fields.len()) {
        return Err(invalid("invalid catalog schema field count"));
    }
    let mut prior: Option<&str> = None;
    for (index, field) in schema.fields.iter().enumerate() {
        validate_name(field.name)?;
        if field.id as usize != index + 1
            || prior.is_some_and(|name| name.as_bytes() >= field.name.as_bytes())
        {
            return Err(invalid("noncanonical catalog field order/ID"));
        }
        prior = Some(field.name);
    }
    Ok(())
}

fn validate_database_id(database_id: [u8; 16]) -> Result<()> {
    if database_id == [0; 16] {
        Err(invalid("zero catalog database ID"))
    } else {
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name
            .as_bytes()
            .iter()
            .any(|byte| *byte == 0 || *byte < 0x20 || *byte == 0x7f)
    {
        Err(invalid("invalid catalog name"))
    } else {
        Ok(())
    }
}

fn header(out: &mut Vec<u8>) {
    out.extend(CODEC.to_le_bytes());
    out.extend(0u16.to_le_bytes());
}

fn fallible_vec(size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(size)
        .map_err(|_| invalid("cannot allocate catalog row"))?;
    Ok(out)
}

fn oversize() -> PraxisError {
    invalid("catalog row length overflow")
}

fn invalid(reason: &str) -> PraxisError {
    PraxisError::InvalidConfig(reason.into())
}

fn corrupt(source: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: reason.into(),
    }
}

struct Input<'a, 's> {
    bytes: &'a [u8],
    source: &'s Path,
}

impl<'a, 's> Input<'a, 's> {
    fn new(bytes: &'a [u8], source: &'s Path) -> Self {
        Self { bytes, source }
    }

    fn error(&self, reason: &str) -> PraxisError {
        corrupt(self.source, reason)
    }

    fn remaining(&self) -> usize {
        self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.bytes.len() {
            return Err(self.error("truncated catalog field"));
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn name(&mut self, len: usize) -> Result<&'a str> {
        let name = std::str::from_utf8(self.take(len)?)
            .map_err(|_| self.error("invalid catalog name UTF-8"))?;
        validate_name(name).map_err(|_| self.error("invalid catalog name"))?;
        Ok(name)
    }

    fn database_id(&mut self) -> Result<[u8; 16]> {
        let id: [u8; 16] = self.take(16)?.try_into().unwrap();
        validate_database_id(id).map_err(|_| self.error("zero catalog database ID"))?;
        Ok(id)
    }

    fn header(&mut self) -> Result<()> {
        if self.u16()? != CODEC || self.u16()? != 0 {
            return Err(self.error("unsupported catalog codec/flags"));
        }
        Ok(())
    }

    fn epoch(&mut self) -> Result<()> {
        if self.u64()? != EPOCH {
            return Err(self.error("unsupported catalog epoch"));
        }
        Ok(())
    }

    fn end(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(self.error("trailing catalog bytes"))
        }
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
