//! Exact F0 codecs. All untrusted lengths are checked against enclosing bytes
//! before copying; these routines do not resolve files or mutate an owner.
use super::schema::corrupt;
use crate::errors::{PraxisError, Result};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub(crate) enum Role {
    Meta = 1,
    Payload = 2,
    State = 3,
    Index = 4,
}

impl Role {
    pub(crate) fn from_cf(cf: &str) -> Option<Self> {
        super::schema::ROLES
            .iter()
            .position(|(_, name)| *name == cf)
            .map(|index| [Self::Meta, Self::Payload, Self::State, Self::Index][index])
    }
    pub(crate) fn cf(self) -> &'static str {
        super::schema::ROLES[self as usize - 1].1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Key<'a> {
    Binding,
    Allocator,
    Descriptor(u32),
    Payload(u64),
    State(u64),
    Fact {
        index: u32,
        incarnation: u64,
        key: &'a [u8],
        raw_sequence: u64,
    },
    Head {
        index: u32,
        incarnation: u64,
        key: &'a [u8],
    },
}

impl<'a> Key<'a> {
    pub(crate) fn decode(role: Role, bytes: &'a [u8], source: &Path) -> Result<Self> {
        let mut input = Input::new(bytes, source);
        let tag = input.u8()?;
        let key = match (role, tag) {
            (Role::Meta, 0) => Self::Binding,
            (Role::Meta, 1) => Self::Allocator,
            (Role::Meta, 2) => Self::Descriptor(input.nonzero_u32_be()?),
            (Role::Payload, 1) => Self::Payload(input.nonzero_u64_be()?),
            (Role::State, 1) => Self::State(input.nonzero_u64_be()?),
            (Role::Index, tag @ (1 | 2)) => {
                let index = input.nonzero_u32_be()?;
                let incarnation = input.nonzero_u64_be()?;
                if incarnation != 1 {
                    return Err(input.error("unsupported record index incarnation"));
                }
                let key = input.field()?;
                if tag == 1 {
                    Self::Fact {
                        index,
                        incarnation,
                        key,
                        raw_sequence: input.u64_be()?,
                    }
                } else {
                    Self::Head {
                        index,
                        incarnation,
                        key,
                    }
                }
            }
            _ => return Err(input.error("unknown protected key tag")),
        };
        input.end()?;
        Ok(key)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Binding => out.push(0),
            Self::Allocator => out.push(1),
            Self::Descriptor(id) => {
                positive(*id as u64)?;
                out.push(2);
                out.extend(id.to_be_bytes());
            }
            Self::Payload(rid) | Self::State(rid) => {
                positive(*rid)?;
                out.push(1);
                out.extend(rid.to_be_bytes());
            }
            Self::Fact {
                index,
                incarnation,
                key,
                ..
            }
            | Self::Head {
                index,
                incarnation,
                key,
            } => {
                positive(*index as u64)?;
                if *incarnation != 1 {
                    return Err(invalid("unsupported record index incarnation"));
                }
                out.push(if matches!(self, Self::Fact { .. }) {
                    1
                } else {
                    2
                });
                out.extend(index.to_be_bytes());
                out.extend(incarnation.to_be_bytes());
                field(&mut out, key)?;
                if let Self::Fact { raw_sequence, .. } = self {
                    out.extend(raw_sequence.to_be_bytes());
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Allocator {
    pub last_rid: u64,
    pub compatibility_sequence: u64,
    pub append_ordinal: u64,
    pub live_count: u64,
    pub dead_count: u64,
    pub live_payload_bytes: u64,
}

impl Allocator {
    pub(crate) fn validate(self) -> bool {
        self.live_count.checked_add(self.dead_count) == Some(self.last_rid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    Put(u64),
    Delete,
}

impl Decision {
    fn decode(input: &mut Input<'_, '_>) -> Result<Self> {
        let tag = input.u8()?;
        if input.take(7)? != [0; 7] {
            return Err(input.error("nonzero record decision reserved bytes"));
        }
        let rid = input.u64()?;
        match (tag, rid) {
            (1, 1..) => Ok(Self::Put(rid)),
            (2, 0) => Ok(Self::Delete),
            _ => Err(input.error("invalid record decision/RID")),
        }
    }
    fn encode(self, out: &mut Vec<u8>) -> Result<()> {
        let (tag, rid) = match self {
            Self::Put(rid) => {
                positive(rid)?;
                (1, rid)
            }
            Self::Delete => (2, 0),
        };
        out.push(tag);
        out.extend([0; 7]);
        out.extend(rid.to_le_bytes());
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Row<'a> {
    Binding {
        database_id: [u8; 16],
        descriptor_count: u32,
    },
    Allocator(Allocator),
    Descriptor {
        name: &'a str,
        namespace: &'a str,
    },
    Payload(&'a [u8]),
    State {
        live: bool,
        payload_length: u64,
    },
    Fact {
        append_ordinal: u64,
        decision: Decision,
    },
    Head {
        raw_sequence: u64,
        append_ordinal: u64,
        decision: Decision,
    },
}

impl<'a> Row<'a> {
    pub(crate) fn decode(key: &Key<'_>, bytes: &'a [u8], source: &Path) -> Result<Self> {
        let mut input = Input::new(bytes, source);
        let magic = input.take(4)?;
        if input.u16()? != 1 || input.u16()? != 0 {
            return Err(input.error("unknown record row schema/flags"));
        }
        let row = match (key, magic) {
            (Key::Binding, b"PRM1") => {
                let database_id = input.take(16)?.try_into().unwrap();
                if database_id == [0; 16] || input.u64()? != 1 || input.u32()? != 1 {
                    return Err(input.error("invalid record binding identity/epoch/schema"));
                }
                let descriptor_count = input.u32()?;
                if input.u32()? != 4 {
                    return Err(input.error("record binding role count is not four"));
                }
                for role in 1..=4 {
                    if input.u8()? != role || input.u64()? != role as u64 {
                        return Err(input.error("record binding role order/generation mismatch"));
                    }
                }
                Self::Binding {
                    database_id,
                    descriptor_count,
                }
            }
            (Key::Allocator, b"PRA1") => {
                let counters = Allocator {
                    last_rid: input.u64()?,
                    compatibility_sequence: input.u64()?,
                    append_ordinal: input.u64()?,
                    live_count: input.u64()?,
                    dead_count: input.u64()?,
                    live_payload_bytes: input.u64()?,
                };
                if !counters.validate() {
                    return Err(input.error("record allocator counts do not cover allocated RIDs"));
                }
                Self::Allocator(counters)
            }
            (Key::Descriptor(_), b"PRD1") => {
                if input.take(4)? != [1, 1, 1, 0] || input.u64()? != 1 {
                    return Err(input.error("unsupported mapping descriptor"));
                }
                let name = input.text()?;
                let namespace = input.text()?;
                if name.is_empty() || input.u32()? != 0 {
                    return Err(input.error("invalid mapping name/configuration"));
                }
                Self::Descriptor { name, namespace }
            }
            (Key::Payload(_), b"PRP1") => Self::Payload(input.field()?),
            (Key::State(_), b"PRS1") => {
                let status = input.u8()?;
                if !matches!(status, 1 | 2) || input.take(7)? != [0; 7] {
                    return Err(input.error("invalid record state status/reserved bytes"));
                }
                let payload_length = input.u64()?;
                if status == 2 && payload_length != 0 {
                    return Err(input.error("dead record has a payload length"));
                }
                Self::State {
                    live: status == 1,
                    payload_length,
                }
            }
            (Key::Fact { .. }, b"PRF1") => Self::Fact {
                append_ordinal: input.u64()?,
                decision: Decision::decode(&mut input)?,
            },
            (Key::Head { .. }, b"PRH1") => Self::Head {
                raw_sequence: input.u64()?,
                append_ordinal: input.u64()?,
                decision: Decision::decode(&mut input)?,
            },
            _ => return Err(input.error("record row magic does not match role/key")),
        };
        input.end()?;
        Ok(row)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let magic = match self {
            Self::Binding { .. } => b"PRM1",
            Self::Allocator(_) => b"PRA1",
            Self::Descriptor { .. } => b"PRD1",
            Self::Payload(_) => b"PRP1",
            Self::State { .. } => b"PRS1",
            Self::Fact { .. } => b"PRF1",
            Self::Head { .. } => b"PRH1",
        };
        let mut out = magic.to_vec();
        out.extend([1, 0, 0, 0]);
        match self {
            Self::Binding {
                database_id,
                descriptor_count,
            } => {
                if *database_id == [0; 16] {
                    return Err(invalid("zero record database ID"));
                }
                out.extend(database_id);
                out.extend(1u64.to_le_bytes());
                out.extend(1u32.to_le_bytes());
                out.extend(descriptor_count.to_le_bytes());
                out.extend(4u32.to_le_bytes());
                for role in 1u8..=4 {
                    out.push(role);
                    out.extend((role as u64).to_le_bytes());
                }
            }
            Self::Allocator(value) => {
                if !value.validate() {
                    return Err(invalid("invalid record allocator counts"));
                }
                for field in [
                    value.last_rid,
                    value.compatibility_sequence,
                    value.append_ordinal,
                    value.live_count,
                    value.dead_count,
                    value.live_payload_bytes,
                ] {
                    out.extend(field.to_le_bytes());
                }
            }
            Self::Descriptor { name, namespace } => {
                if name.is_empty() {
                    return Err(invalid("empty record mapping name"));
                }
                out.extend([1, 1, 1, 0]);
                out.extend(1u64.to_le_bytes());
                field(&mut out, name.as_bytes())?;
                field(&mut out, namespace.as_bytes())?;
                out.extend(0u32.to_le_bytes());
            }
            Self::Payload(value) => field(&mut out, value)?,
            Self::State {
                live,
                payload_length,
            } => {
                if !live && *payload_length != 0 {
                    return Err(invalid("dead record has payload length"));
                }
                out.push(if *live { 1 } else { 2 });
                out.extend([0; 7]);
                out.extend(payload_length.to_le_bytes());
            }
            Self::Fact {
                append_ordinal,
                decision,
            } => {
                out.extend(append_ordinal.to_le_bytes());
                decision.encode(&mut out)?;
            }
            Self::Head {
                raw_sequence,
                append_ordinal,
                decision,
            } => {
                out.extend(raw_sequence.to_le_bytes());
                out.extend(append_ordinal.to_le_bytes());
                decision.encode(&mut out)?;
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Kind {
    Bootstrap = 1,
    Create = 2,
    DeleteRecords = 3,
    IndexPut = 4,
    IndexDelete = 5,
    DeleteWithIndexCleanup = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Envelope {
    pub kind: Kind,
    pub database_id: [u8; 16],
    pub prior_rid: u64,
    pub new_rid: u64,
    pub prior_compatibility_sequence: u64,
    pub new_compatibility_sequence: u64,
    pub prior_append_ordinal: u64,
    pub new_append_ordinal: u64,
    pub record_count: u32,
    pub logical_entry_count: u32,
}

impl Envelope {
    pub(crate) const LEN: usize = 88;
    pub(crate) fn validate(&self, sequence: u64, source: &Path) -> Result<()> {
        let bad = || corrupt(source, "invalid record envelope counter/count arithmetic");
        if self.database_id == [0; 16] {
            return Err(bad());
        }
        if self.kind == Kind::Bootstrap {
            if sequence != 1
                || [
                    self.prior_rid,
                    self.new_rid,
                    self.prior_compatibility_sequence,
                    self.new_compatibility_sequence,
                    self.prior_append_ordinal,
                    self.new_append_ordinal,
                ]
                .iter()
                .any(|counter| *counter != 0)
                || self.record_count != 0
                || self.logical_entry_count != 0
            {
                return Err(bad());
            }
            return Ok(());
        }
        if sequence <= 1
            || self.logical_entry_count == 0
            || self
                .prior_compatibility_sequence
                .checked_add(self.logical_entry_count as u64)
                != Some(self.new_compatibility_sequence)
            || self
                .prior_append_ordinal
                .checked_add(self.logical_entry_count as u64)
                != Some(self.new_append_ordinal)
        {
            return Err(bad());
        }
        match self.kind {
            Kind::Create
                if self.record_count > 0
                    && self.logical_entry_count >= self.record_count
                    && self.prior_rid.checked_add(self.record_count as u64)
                        == Some(self.new_rid) =>
            {
                Ok(())
            }
            Kind::DeleteRecords
                if self.record_count > 0
                    && self.logical_entry_count == self.record_count
                    && self.prior_rid == self.new_rid =>
            {
                Ok(())
            }
            Kind::IndexPut | Kind::IndexDelete
                if self.record_count == 0
                    && self.logical_entry_count == 1
                    && self.prior_rid == self.new_rid =>
            {
                Ok(())
            }
            Kind::DeleteWithIndexCleanup
                if self.record_count == 1
                    && self.logical_entry_count >= 2
                    && self.prior_rid == self.new_rid =>
            {
                Ok(())
            }
            _ => Err(bad()),
        }
    }
    pub(crate) fn decode(bytes: &[u8], sequence: u64, source: &Path) -> Result<Self> {
        let mut input = Input::new(bytes, source);
        if input.take(4)? != b"PRR1" || input.u16()? != 1 {
            return Err(input.error("unknown record envelope magic/schema"));
        }
        let kind = match input.u8()? {
            1 => Kind::Bootstrap,
            2 => Kind::Create,
            3 => Kind::DeleteRecords,
            4 => Kind::IndexPut,
            5 => Kind::IndexDelete,
            6 => Kind::DeleteWithIndexCleanup,
            _ => return Err(input.error("unknown record envelope kind")),
        };
        if input.u8()? != 0 {
            return Err(input.error("unknown record envelope flags"));
        }
        let database_id = input.take(16)?.try_into().unwrap();
        if input.u64()? != 1 {
            return Err(input.error("unsupported record authority epoch"));
        }
        let value = Self {
            kind,
            database_id,
            prior_rid: input.u64()?,
            new_rid: input.u64()?,
            prior_compatibility_sequence: input.u64()?,
            new_compatibility_sequence: input.u64()?,
            prior_append_ordinal: input.u64()?,
            new_append_ordinal: input.u64()?,
            record_count: input.u32()?,
            logical_entry_count: input.u32()?,
        };
        input.end()?;
        value.validate(sequence, source)?;
        Ok(value)
    }
    #[cfg(test)]
    pub(crate) fn encode(&self, sequence: u64) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::LEN);
        self.encode_into(sequence, &mut out)?;
        Ok(out)
    }

    pub(crate) fn encode_into(&self, sequence: u64, out: &mut Vec<u8>) -> Result<()> {
        self.validate(sequence, Path::new("record-envelope"))?;
        out.extend(b"PRR1");
        out.extend(1u16.to_le_bytes());
        out.push(self.kind as u8);
        out.push(0);
        out.extend(self.database_id);
        out.extend(1u64.to_le_bytes());
        for counter in [
            self.prior_rid,
            self.new_rid,
            self.prior_compatibility_sequence,
            self.new_compatibility_sequence,
            self.prior_append_ordinal,
            self.new_append_ordinal,
        ] {
            out.extend(counter.to_le_bytes());
        }
        out.extend(self.record_count.to_le_bytes());
        out.extend(self.logical_entry_count.to_le_bytes());
        Ok(())
    }
}

fn invalid(reason: impl Into<String>) -> PraxisError {
    PraxisError::InvalidConfig(reason.into())
}
fn positive(value: u64) -> Result<()> {
    if value == 0 {
        Err(invalid("zero record/index ID"))
    } else {
        Ok(())
    }
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid("record field exceeds u32 length"))?;
    out.extend(len.to_le_bytes());
    out.extend(bytes);
    Ok(())
}

struct Input<'a, 's> {
    bytes: &'a [u8],
    source: &'s Path,
}
impl<'a, 's> Input<'a, 's> {
    fn new(bytes: &'a [u8], source: &'s Path) -> Self {
        Self { bytes, source }
    }
    fn error(&self, message: &str) -> PraxisError {
        corrupt(self.source, message)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.bytes.len() {
            return Err(self.error("truncated record field"));
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn nonzero_u32_be(&mut self) -> Result<u32> {
        let value = u32::from_be_bytes(self.take(4)?.try_into().unwrap());
        if value == 0 {
            Err(self.error("zero record index ID"))
        } else {
            Ok(value)
        }
    }
    fn nonzero_u64_be(&mut self) -> Result<u64> {
        let value = self.u64_be()?;
        if value == 0 {
            Err(self.error("zero record RID/incarnation"))
        } else {
            Ok(value)
        }
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn text(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.field()?).map_err(|_| self.error("invalid record label UTF-8"))
    }
    fn end(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(self.error("trailing record bytes"))
        }
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
