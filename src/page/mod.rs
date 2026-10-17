use crate::errors::{PraxisError, Result};
use crate::identity::Sid;
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PAGE_MAGIC: u32 = 0x5450_4147;
const PAGE_VERSION: u8 = 1;
pub const DEFAULT_PAGE_SIZE: u32 = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PageKind {
    Record,
    Overflow,
    Vector,
    Edge,
    FullText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PageHeader {
    pub page_size: u32,
    pub page_lsn: u64,
    pub kind: PageKind,
    pub slot_count: u16,
    pub free_space_start: u32,
    pub free_space_end: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlotDirectoryEntry {
    pub sid: Sid,
    pub offset: u32,
    pub len: u32,
    pub tombstone: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordPage {
    pub header: PageHeader,
    slots: Vec<SlotDirectoryEntry>,
    payload: Vec<u8>,
}

impl RecordPage {
    pub fn new(page_lsn: u64) -> Self {
        Self {
            header: PageHeader {
                page_size: DEFAULT_PAGE_SIZE,
                page_lsn,
                kind: PageKind::Record,
                slot_count: 0,
                free_space_start: 0,
                free_space_end: DEFAULT_PAGE_SIZE,
            },
            slots: Vec::new(),
            payload: Vec::new(),
        }
    }

    pub fn slots(&self) -> &[SlotDirectoryEntry] {
        &self.slots
    }

    pub fn insert(&mut self, sid: Sid, bytes: &[u8]) -> Result<()> {
        if sid.is_null() {
            return Err(PraxisError::InvalidConfig(
                "SID 0000 is reserved and cannot store a record slot".to_string(),
            ));
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.sid == sid && !slot.tombstone)
        {
            return Err(PraxisError::InvalidConfig(format!(
                "duplicate live slot {sid}"
            )));
        }
        let projected_payload = self.payload.len().saturating_add(bytes.len());
        let projected_slots = self.slots.len().saturating_add(1);
        let required = projected_payload.saturating_add(projected_slots.saturating_mul(16));
        if required > self.header.page_size as usize {
            return Err(PraxisError::WriteStalled {
                reason: "record page has insufficient free space".to_string(),
            });
        }

        let offset = self.payload.len() as u32;
        self.payload.extend_from_slice(bytes);
        self.slots.push(SlotDirectoryEntry {
            sid,
            offset,
            len: bytes.len() as u32,
            tombstone: false,
        });
        self.refresh_header();
        Ok(())
    }

    pub fn get(&self, sid: Sid) -> Result<Option<&[u8]>> {
        let Some(slot) = self
            .slots
            .iter()
            .find(|slot| slot.sid == sid && !slot.tombstone)
        else {
            return Ok(None);
        };
        let start = slot.offset as usize;
        let end = start.saturating_add(slot.len as usize);
        if end > self.payload.len() {
            return Err(PraxisError::Corrupt {
                path: PathBuf::from("record-page"),
                reason: "slot points outside page payload".to_string(),
            });
        }
        Ok(Some(&self.payload[start..end]))
    }

    pub fn delete(&mut self, sid: Sid) -> Result<()> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.sid == sid && !slot.tombstone)
            .ok_or(PraxisError::KeyNotFound)?;
        slot.tombstone = true;
        self.refresh_header();
        Ok(())
    }

    pub fn defragment(&mut self) {
        let mut new_payload = Vec::with_capacity(self.payload.len());
        for slot in self.slots.iter_mut().filter(|slot| !slot.tombstone) {
            let start = slot.offset as usize;
            let end = start.saturating_add(slot.len as usize);
            let new_offset = new_payload.len() as u32;
            if end <= self.payload.len() {
                new_payload.extend_from_slice(&self.payload[start..end]);
                slot.offset = new_offset;
            }
        }
        self.payload = new_payload;
        self.slots.retain(|slot| !slot.tombstone);
        self.refresh_header();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = BinaryWriter::new();
        payload.write_u32(self.header.page_size);
        payload.write_u64(self.header.page_lsn);
        payload.write_u8(kind_to_tag(self.header.kind));
        payload.write_u32(self.slots.len() as u32);
        payload.write_u32(self.payload.len() as u32);
        for slot in &self.slots {
            payload.write_u32(slot.sid.0 as u32);
            payload.write_u32(slot.offset);
            payload.write_u32(slot.len);
            payload.write_u8(u8::from(slot.tombstone));
        }
        payload.write_bytes(&self.payload);
        let payload = payload.into_inner();

        let mut out = BinaryWriter::new();
        out.write_u32(PAGE_MAGIC);
        out.write_u8(PAGE_VERSION);
        out.write_u32(payload.len() as u32);
        out.write_u32(crc32c(&payload));
        out.write_bytes(&payload);
        out.into_inner()
    }

    pub fn from_bytes(bytes: &[u8], source: impl Into<PathBuf>) -> Result<Self> {
        let source = source.into();
        if bytes.len() < 13 {
            return corrupt(&source, "truncated page header");
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PAGE_MAGIC {
            return corrupt(&source, "bad page magic");
        }
        if bytes[4] != PAGE_VERSION {
            return corrupt(&source, &format!("unsupported page version {}", bytes[4]));
        }
        let payload_len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        let expected_crc = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        if bytes.len() < 13 + payload_len {
            return corrupt(&source, "truncated page payload");
        }
        let payload = &bytes[13..13 + payload_len];
        let actual_crc = crc32c(payload);
        if actual_crc != expected_crc {
            return corrupt(
                &source,
                &format!(
                    "page checksum mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"
                ),
            );
        }

        let mut reader = BinaryReader::new(payload, source.clone());
        let page_size = reader.read_u32()?;
        let page_lsn = reader.read_u64()?;
        let kind = tag_to_kind(reader.read_u8()?, &source)?;
        let slot_count = reader.read_u32()? as usize;
        let payload_len = reader.read_u32()? as usize;
        let required_bytes = slot_count
            .checked_mul(13)
            .and_then(|slots| slots.checked_add(payload_len));
        if required_bytes.is_none_or(|required| required > reader.remaining())
            || slot_count > payload.len().saturating_sub(21) / 13
            || payload_len
                .checked_add(slot_count.saturating_mul(16))
                .is_none_or(|required| required > page_size as usize)
        {
            return corrupt(&source, "page slot count or payload exceeds page bounds");
        }
        let mut slots = Vec::with_capacity(slot_count);
        let mut identities = std::collections::BTreeSet::new();
        for _ in 0..slot_count {
            let sid = match u16::try_from(reader.read_u32()?) {
                Ok(raw) if raw != 0 => Sid(raw),
                _ => {
                    return corrupt(
                        &source,
                        "physical slot ID exceeds its nonzero identifier range",
                    );
                }
            };
            let offset = reader.read_u32()?;
            let len = reader.read_u32()?;
            let tombstone = reader.read_u8()?;
            if !identities.insert(sid)
                || tombstone > 1
                || (offset as usize)
                    .checked_add(len as usize)
                    .is_none_or(|end| end > payload_len)
            {
                return corrupt(
                    &source,
                    "duplicate slot identity or invalid physical slot bounds",
                );
            }
            slots.push(SlotDirectoryEntry {
                sid,
                offset,
                len,
                tombstone: tombstone != 0,
            });
        }
        let stored_payload = reader.read_slice(payload_len)?.to_vec();
        let mut page = Self {
            header: PageHeader {
                page_size,
                page_lsn,
                kind,
                slot_count: slots.len() as u16,
                free_space_start: 0,
                free_space_end: page_size,
            },
            slots,
            payload: stored_payload,
        };
        page.refresh_header();
        Ok(page)
    }

    fn refresh_header(&mut self) {
        self.header.slot_count = self.slots.len() as u16;
        self.header.free_space_start = self.payload.len() as u32;
        let slot_bytes = (self.slots.len() as u32).saturating_mul(16);
        self.header.free_space_end = self.header.page_size.saturating_sub(slot_bytes);
    }
}

fn kind_to_tag(kind: PageKind) -> u8 {
    match kind {
        PageKind::Record => 1,
        PageKind::Overflow => 2,
        PageKind::Vector => 3,
        PageKind::Edge => 4,
        PageKind::FullText => 5,
    }
}

fn tag_to_kind(tag: u8, source: &Path) -> Result<PageKind> {
    match tag {
        1 => Ok(PageKind::Record),
        2 => Ok(PageKind::Overflow),
        3 => Ok(PageKind::Vector),
        4 => Ok(PageKind::Edge),
        5 => Ok(PageKind::FullText),
        _ => corrupt(source, &format!("invalid page kind tag {tag}")),
    }
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
