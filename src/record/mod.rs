use crate::datatype::{
    DataTypeRegistry, ExternalPointer, PraxisValue, SegmentFamily, StorageClass, TypeCode,
};
use crate::errors::{PraxisError, Result};
use crate::identity::{Aid, Cid, Did, Eid, Fid, FieldId, Pid, Rid, Sid, SlotAddress, Vid};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::layout::PraxisLayout;
use crate::manifest::PageManifestStore;
use crate::page::{RecordPage, SlotDirectoryEntry};
use crate::segments::{BlobLocation, BlobStore};
use crate::wal::{
    PageWal, PageWalMutation, PageWalRecord, PageWalWriter, validate_page_wal_identity,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

const RID_DIRECTORY_MAGIC: u32 = 0x5452_4944;
const RID_DIRECTORY_VERSION: u8 = 1;
const TYPED_RECORD_MAGIC: u32 = 0x5456_4944;
const TYPED_RECORD_VERSION: u8 = 1;

mod database;
mod recovery;
use database::CollectionState;
pub use database::PageDatabase;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldOffset {
    pub field: FieldId,
    pub offset: u32,
    pub len: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordSlot {
    pub sid: Sid,
    pub body: Vec<u8>,
    pub fields: Vec<FieldOffset>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RidDirectory {
    mappings: BTreeMap<Rid, SlotAddress>,
}

#[derive(Clone, Debug)]
pub struct PageRecordStore {
    database: PageDatabase,
    cid: Cid,
    eid: Eid,
    fid: Fid,
}

struct PageOperation<'a> {
    layout: &'a PraxisLayout,
    cid: Cid,
    eid: Eid,
    fid: Fid,
    current_pid: Pid,
    next_rid: u64,
    next_sid: u32,
    directory: Cow<'a, RidDirectory>,
    deleted: Cow<'a, BTreeSet<Rid>>,
    side_effects: Cell<bool>,
}

impl RecordSlot {
    pub fn from_fields(sid: Sid, fields: &[(FieldId, &[u8])]) -> Self {
        let mut body = Vec::new();
        let mut offsets = Vec::with_capacity(fields.len());
        for (field, bytes) in fields {
            let offset = body.len() as u32;
            body.extend_from_slice(bytes);
            offsets.push(FieldOffset {
                field: *field,
                offset,
                len: bytes.len() as u32,
            });
        }
        Self {
            sid,
            body,
            fields: offsets,
        }
    }

    pub fn fixed(sid: Sid, aid: Aid, value: &[u8]) -> Self {
        Self::from_fields(sid, &[(FieldId::Fixed(aid), value)])
    }

    pub fn dynamic(sid: Sid, did: Did, value: &[u8]) -> Self {
        Self::from_fields(sid, &[(FieldId::Dynamic(did), value)])
    }

    pub fn field_bytes(&self, field: FieldId) -> Result<Option<&[u8]>> {
        let Some(offset) = self.fields.iter().find(|offset| offset.field == field) else {
            return Ok(None);
        };
        let start = offset.offset as usize;
        let end = start.saturating_add(offset.len as usize);
        if end > self.body.len() {
            return Err(PraxisError::Corrupt {
                path: "record-slot".into(),
                reason: "field offset points outside record slot body".to_string(),
            });
        }
        Ok(Some(&self.body[start..end]))
    }

    pub fn install_into_page(&self, page: &mut RecordPage) -> Result<()> {
        page.insert(self.sid, &self.body)
    }
}

impl RidDirectory {
    pub fn insert(&mut self, rid: Rid, address: SlotAddress) {
        self.mappings.insert(rid, address);
    }

    pub fn resolve(&self, rid: Rid) -> Result<SlotAddress> {
        self.mappings
            .get(&rid)
            .copied()
            .ok_or(PraxisError::KeyNotFound)
    }

    pub fn relocate(&mut self, rid: Rid, address: SlotAddress) -> Result<()> {
        if !self.mappings.contains_key(&rid) {
            return Err(PraxisError::KeyNotFound);
        }
        self.mappings.insert(rid, address);
        Ok(())
    }

    pub fn vid_for(&self, rid: Rid, field: FieldId) -> Result<Vid> {
        let address = self.resolve(rid)?;
        Ok(Vid {
            eid: address.eid,
            fid: address.fid,
            pid: address.pid,
            sid: address.sid,
            field,
        })
    }

    pub fn save_binary(
        &self,
        path: &Path,
        next_rid: u64,
        next_sid: u16,
        current_pid: Pid,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut payload = BinaryWriter::new();
        payload.write_u64(next_rid);
        payload.write_u32(next_sid as u32);
        payload.write_u32(current_pid.0);
        payload.write_u32(self.mappings.len() as u32);
        for (rid, address) in &self.mappings {
            payload.write_u64(rid.0);
            payload.write_u32(address.cid.0);
            payload.write_u32(address.eid.0);
            payload.write_u32(address.fid.0);
            payload.write_u32(address.pid.0);
            payload.write_u32(address.sid.0 as u32);
        }
        let payload = payload.into_inner();
        let mut out = BinaryWriter::new();
        out.write_u32(RID_DIRECTORY_MAGIC);
        out.write_u8(RID_DIRECTORY_VERSION);
        out.write_u32(payload.len() as u32);
        out.write_u32(crc32c(&payload));
        out.write_bytes(&payload);
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, out.into_inner())?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path)?
            .sync_all()?;
        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn load_binary(path: &Path) -> Result<(Self, u64, u16, Pid)> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 13 {
            return corrupt(path, "truncated RID directory");
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != RID_DIRECTORY_MAGIC {
            return corrupt(path, "bad RID directory magic");
        }
        if bytes[4] != RID_DIRECTORY_VERSION {
            return corrupt(
                path,
                &format!("unsupported RID directory version {}", bytes[4]),
            );
        }
        let payload_len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        let expected = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        if bytes.len() < 13 + payload_len {
            return corrupt(path, "truncated RID directory payload");
        }
        let payload = &bytes[13..13 + payload_len];
        let actual = crc32c(payload);
        if actual != expected {
            return corrupt(
                path,
                &format!(
                    "RID directory checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                ),
            );
        }
        let mut reader = BinaryReader::new(payload, path.to_path_buf());
        let next_rid = reader.read_u64()?;
        let next_sid = u16::try_from(reader.read_u32()?)
            .ok()
            .filter(|sid| *sid != 0)
            .ok_or_else(|| PraxisError::Corrupt {
                path: path.to_path_buf(),
                reason: "invalid next SID in RID directory".to_string(),
            })?;
        let current_pid = Pid(reader.read_u32()?);
        let count = reader.read_u32()? as usize;
        if next_rid == 0 || current_pid.is_null() || count > payload.len().saturating_sub(20) / 28 {
            return corrupt(path, "invalid RID directory counters or entry count");
        }
        let mut directory = Self::default();
        for _ in 0..count {
            let rid = Rid(reader.read_u64()?);
            let address = SlotAddress {
                cid: Cid(reader.read_u32()?),
                eid: Eid(reader.read_u32()?),
                fid: Fid(reader.read_u32()?),
                pid: Pid(reader.read_u32()?),
                sid: Sid(
                    u16::try_from(reader.read_u32()?).map_err(|_| PraxisError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "RID directory SID exceeds its identifier range".to_string(),
                    })?,
                ),
            };
            if rid.is_null()
                || address.cid.is_null()
                || address.eid.is_null()
                || address.fid.is_null()
                || address.pid.is_null()
                || address.sid.is_null()
                || directory.mappings.insert(rid, address).is_some()
            {
                return corrupt(path, "invalid or duplicate RID directory identity");
            }
        }
        Ok((directory, next_rid, next_sid, current_pid))
    }
}

impl PageRecordStore {
    pub fn open(base: impl Into<PathBuf>, cid: Cid, eid: Eid) -> Result<Self> {
        PageDatabase::open(base)?.entity(cid, eid)
    }

    pub fn put(&mut self, fields: &[(FieldId, &[u8])]) -> Result<Rid> {
        self.with_mutation(|operation| operation.put(fields))
    }

    pub fn put_durable(&mut self, wal: &mut PageWal, fields: &[(FieldId, &[u8])]) -> Result<Rid> {
        self.with_wal_mutation(wal, |operation, writer| {
            operation.put_durable(writer, fields)
        })
    }

    pub fn delete_durable(&mut self, wal: &mut PageWal, rid: Rid) -> Result<()> {
        self.with_wal_mutation(wal, |operation, writer| {
            operation.delete_durable(writer, rid)
        })
    }

    pub fn put_typed(&mut self, fields: &[(FieldId, PraxisValue)]) -> Result<Rid> {
        self.with_mutation(|operation| operation.put_typed(fields))
    }

    pub fn get(&self, rid: Rid) -> Result<Vec<u8>> {
        self.with_read(|operation| operation.get(rid))
    }

    pub fn get_typed_field_bytes(&self, rid: Rid, field: FieldId) -> Result<Vec<u8>> {
        self.with_read(|operation| operation.get_typed_field_bytes(rid, field))
    }

    pub fn delete(&mut self, rid: Rid) -> Result<()> {
        self.with_mutation(|operation| operation.delete(rid))
    }

    pub fn directory(&self) -> Result<RidDirectory> {
        self.with_read(|operation| Ok(operation.directory.as_ref().clone()))
    }

    pub fn layout(&self) -> &PraxisLayout {
        &self.database.inner.layout
    }

    pub fn replay_page_wal(&mut self, records: &[PageWalRecord]) -> Result<()> {
        self.with_mutation(|operation| operation.replay_page_wal(records))
    }

    pub fn apply_page_wal_record(&mut self, record: &PageWalRecord) -> Result<()> {
        self.with_mutation(|operation| operation.apply_page_wal_record(record))
    }
}

impl<'a> PageOperation<'a> {
    fn borrowed(
        layout: &'a PraxisLayout,
        cid: Cid,
        eid: Eid,
        fid: Fid,
        collection: &'a CollectionState,
    ) -> Self {
        let cursor = collection
            .cursors
            .get(&(eid, fid))
            .copied()
            .unwrap_or_default();
        Self {
            layout,
            cid,
            eid,
            fid,
            current_pid: cursor.current_pid,
            next_rid: collection.next_rid,
            next_sid: cursor.next_sid,
            directory: Cow::Borrowed(&collection.directory),
            deleted: Cow::Borrowed(&collection.deleted),
            side_effects: Cell::new(false),
        }
    }

    fn candidate(
        layout: &'a PraxisLayout,
        cid: Cid,
        eid: Eid,
        fid: Fid,
        collection: &CollectionState,
    ) -> Self {
        let cursor = collection
            .cursors
            .get(&(eid, fid))
            .copied()
            .unwrap_or_default();
        Self {
            layout,
            cid,
            eid,
            fid,
            current_pid: cursor.current_pid,
            next_rid: collection.next_rid,
            next_sid: cursor.next_sid,
            directory: Cow::Owned(collection.directory.clone()),
            deleted: Cow::Owned(collection.deleted.clone()),
            side_effects: Cell::new(false),
        }
    }

    fn next_rid(&self) -> Result<Rid> {
        if self.next_rid == 0 || self.next_rid == u64::MAX {
            return Err(PraxisError::WriteStalled {
                reason: "page collection RID space is exhausted".to_string(),
            });
        }
        Ok(Rid(self.next_rid))
    }

    fn validate_record_size(fields: &[(FieldId, &[u8])]) -> Result<()> {
        let size = fields
            .iter()
            .try_fold(16_usize, |size, (_, bytes)| size.checked_add(bytes.len()));
        if size.is_none_or(|size| size > crate::page::DEFAULT_PAGE_SIZE as usize) {
            return Err(PraxisError::WriteStalled {
                reason: "record cannot fit in a fresh page".to_string(),
            });
        }
        Ok(())
    }

    fn scope_address(&self, rid: Rid) -> Result<SlotAddress> {
        let address = self.directory.resolve(rid)?;
        if address.cid != self.cid || address.eid != self.eid {
            return Err(PraxisError::KeyNotFound);
        }
        Ok(address)
    }

    fn page_path(&self, fid: Fid, pid: Pid) -> PathBuf {
        self.layout.page_path(self.cid, self.eid, fid, pid).path
    }

    fn load_page_at(&self, fid: Fid, pid: Pid) -> Result<RecordPage> {
        let path = self.page_path(fid, pid);
        RecordPage::from_bytes(&std::fs::read(&path)?, path)
    }

    fn write_page_at(&self, fid: Fid, pid: Pid, page: &RecordPage) -> Result<()> {
        self.side_effects.set(true);
        self.layout.ensure_frame_tree(self.cid, self.eid, fid)?;
        let path = self.page_path(fid, pid);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("tmp");
        let bytes = page.to_bytes();
        std::fs::write(&tmp_path, &bytes)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path)?
            .sync_all()?;
        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        std::fs::rename(&tmp_path, &path)?;
        self.manifest_store()
            .track_bytes(&path, "record-page", 1, &bytes)
    }

    fn with_frame<T>(&mut self, fid: Fid, action: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let original = self.fid;
        self.fid = fid;
        let result = action(self);
        self.fid = original;
        result
    }

    fn rollover_pid(&self) -> Result<Pid> {
        self.current_pid
            .0
            .checked_add(1)
            .map(Pid)
            .ok_or_else(|| PraxisError::WriteStalled {
                reason: "page PID space is exhausted".to_string(),
            })
    }

    fn put(&mut self, fields: &[(FieldId, &[u8])]) -> Result<Rid> {
        let rid = self.next_rid()?;
        Self::validate_record_size(fields)?;
        self.apply_put(rid, fields)?;
        Ok(rid)
    }

    fn put_durable(&mut self, wal: &mut PageWalWriter, fields: &[(FieldId, &[u8])]) -> Result<Rid> {
        let rid = self.next_rid()?;
        Self::validate_record_size(fields)?;
        self.prepare_slot(&RecordSlot::from_fields(
            Sid(u16::try_from(self.next_sid).unwrap_or(1)),
            fields,
        ))?;
        let prepared = wal.prepare_put(self.cid, self.eid, rid, fields)?;
        self.side_effects.set(true);
        wal.append_prepared(prepared)?;
        self.apply_put(rid, fields)?;
        Ok(rid)
    }

    fn delete_durable(&mut self, wal: &mut PageWalWriter, rid: Rid) -> Result<()> {
        self.get(rid)?;
        let prepared = wal.prepare_delete(self.cid, self.eid, rid)?;
        self.side_effects.set(true);
        wal.append_prepared(prepared)?;
        self.delete(rid)
    }

    fn put_typed(&mut self, fields: &[(FieldId, PraxisValue)]) -> Result<Rid> {
        self.next_rid()?;
        let encoded = self.encode_typed_record(fields)?;
        self.put(&[(FieldId::Dynamic(Did(0xffff)), encoded.as_slice())])
    }

    /* Existing typed record codec and physical persistence helpers operate only on
     * one borrowed read view or an unpublished operation-local candidate below. */

    pub fn get_typed_field_bytes(&self, rid: Rid, field: FieldId) -> Result<Vec<u8>> {
        let body = self.get(rid)?;
        let cells = decode_typed_record(&body, Path::new("typed-record"))?;
        let cell = cells
            .into_iter()
            .find(|cell| cell.field == field)
            .ok_or(PraxisError::KeyNotFound)?;
        match cell.storage_class {
            StorageClass::Inline => Ok(cell.inline_bytes),
            StorageClass::External => {
                let ExternalPointer::Overflow {
                    page_id,
                    offset,
                    len,
                    checksum,
                } = cell.pointer.ok_or_else(|| PraxisError::Corrupt {
                    path: PathBuf::from("typed-record"),
                    reason: "external typed cell is missing overflow pointer".to_string(),
                })?
                else {
                    return Err(PraxisError::Corrupt {
                        path: PathBuf::from("typed-record"),
                        reason: "external typed cell has non-overflow pointer".to_string(),
                    });
                };
                let path = self.layout.overflow_blob_path(self.cid, self.eid).path;
                if !path.is_file() {
                    return corrupt(&path, "typed record overflow file is missing");
                }
                BlobStore::existing_overflow(path).read(&BlobLocation {
                    family: None,
                    file_id: page_id,
                    offset: offset as u64,
                    len,
                    checksum,
                })
            }
            StorageClass::Segment => {
                let ExternalPointer::Segment {
                    family,
                    segment_id,
                    offset,
                    len,
                } = cell.pointer.ok_or_else(|| PraxisError::Corrupt {
                    path: PathBuf::from("typed-record"),
                    reason: "segment typed cell is missing segment pointer".to_string(),
                })?
                else {
                    return Err(PraxisError::Corrupt {
                        path: PathBuf::from("typed-record"),
                        reason: "segment typed cell has non-segment pointer".to_string(),
                    });
                };
                let path = self
                    .layout
                    .segment_blob_path(self.cid, self.eid, family)
                    .path;
                if !path.is_file() {
                    return corrupt(&path, "typed record segment file is missing");
                }
                BlobStore::existing_segment(path, family, 1).read(&BlobLocation {
                    family: Some(family),
                    file_id: segment_id,
                    offset,
                    len,
                    checksum: 0,
                })
            }
            StorageClass::Catalog => Err(PraxisError::InvalidConfig(
                "catalog-backed values are resolved through catalog stores".to_string(),
            )),
        }
    }

    pub fn replay_page_wal(&mut self, records: &[PageWalRecord]) -> Result<()> {
        self.validate_replay(records)?;
        for record in records {
            self.apply_page_wal_record(record)?;
        }
        Ok(())
    }

    pub fn apply_page_wal_record(&mut self, record: &PageWalRecord) -> Result<()> {
        self.validate_replay(std::slice::from_ref(record))?;
        match &record.mutation {
            PageWalMutation::Put {
                cid,
                eid,
                rid,
                fields,
            } if *cid == self.cid && *eid == self.eid => {
                if self.directory.resolve(*rid).is_ok() {
                    return Ok(());
                }
                let borrowed: Vec<(FieldId, &[u8])> = fields
                    .iter()
                    .map(|(field, bytes)| (*field, bytes.as_slice()))
                    .collect();
                self.apply_put(*rid, &borrowed)
            }
            PageWalMutation::Delete { cid, eid, rid } if *cid == self.cid && *eid == self.eid => {
                if self.directory.resolve(*rid).is_err() || self.deleted.contains(rid) {
                    return Ok(());
                }
                self.delete(*rid)
            }
            _ => Ok(()),
        }
    }

    fn validate_replay<'record>(
        &self,
        records: impl IntoIterator<Item = &'record PageWalRecord>,
    ) -> Result<()> {
        let path = self.layout.logs_root().join("page.wal");
        let mut previous = 0;
        enum ReplayIdentity<'a> {
            Put(&'a [(FieldId, Vec<u8>)]),
            Deleted,
        }
        // A delete is terminal, including a delete of an as-yet unknown RID.
        // Borrow complete tuples so equal flattened bodies cannot hide changed
        // field identities, boundaries, or ordering within the log.
        let mut seen = BTreeMap::new();
        for record in records {
            validate_page_wal_identity(record, &path)?;
            if record.sequence <= previous {
                return corrupt(&path, "replay sequence must strictly increase");
            }
            previous = record.sequence;
            let (cid, eid, rid) = match &record.mutation {
                PageWalMutation::Put { cid, eid, rid, .. }
                | PageWalMutation::Delete { cid, eid, rid } => (*cid, *eid, *rid),
            };
            if cid != self.cid || eid != self.eid {
                continue;
            }
            if let Ok(address) = self.directory.resolve(rid)
                && (address.cid != cid || address.eid != eid)
            {
                return corrupt(&path, "replay RID is bound to a different entity");
            }
            match &record.mutation {
                PageWalMutation::Put { fields, .. } => {
                    let borrowed: Vec<_> = fields
                        .iter()
                        .map(|(field, bytes)| (*field, bytes.as_slice()))
                        .collect();
                    Self::validate_record_size(&borrowed)?;
                    let body: Vec<u8> = fields
                        .iter()
                        .flat_map(|(_, bytes)| bytes.iter().copied())
                        .collect();
                    match seen.get(&rid) {
                        Some(ReplayIdentity::Deleted) => {
                            return corrupt(&path, "replay Put follows a terminal delete");
                        }
                        Some(ReplayIdentity::Put(earlier)) if *earlier != fields.as_slice() => {
                            return corrupt(&path, "conflicting repeated replay Put");
                        }
                        _ => {}
                    }
                    if self.directory.resolve(rid).is_ok()
                        && !self.deleted.contains(&rid)
                        && self.get(rid)? != body
                    {
                        return corrupt(&path, "replay Put conflicts with existing bytes");
                    }
                    seen.insert(rid, ReplayIdentity::Put(fields));
                }
                PageWalMutation::Delete { .. } => {
                    seen.insert(rid, ReplayIdentity::Deleted);
                }
            }
        }
        Ok(())
    }

    fn apply_put(&mut self, rid: Rid, fields: &[(FieldId, &[u8])]) -> Result<()> {
        Self::validate_record_size(fields)?;
        if rid.is_null() || rid.0 == u64::MAX {
            return Err(PraxisError::WriteStalled {
                reason: "page RID is outside the allocatable range".to_string(),
            });
        }
        let sid = Sid(u16::try_from(self.next_sid).unwrap_or(1));
        let slot = RecordSlot::from_fields(sid, fields);
        let address = self.write_slot(&slot)?;
        self.directory.to_mut().insert(rid, address);
        self.deleted.to_mut().remove(&rid);
        self.next_rid =
            self.next_rid.max(
                rid.0
                    .checked_add(1)
                    .ok_or_else(|| PraxisError::WriteStalled {
                        reason: "page RID space is exhausted".to_string(),
                    })?,
            );
        self.next_sid = u32::from(address.sid.0) + 1;
        self.flush_directory()?;
        Ok(())
    }

    pub fn get(&self, rid: Rid) -> Result<Vec<u8>> {
        let address = self.scope_address(rid)?;
        let page = self.load_page_at(address.fid, address.pid)?;
        page.get(address.sid)?
            .map(|bytes| bytes.to_vec())
            .ok_or(PraxisError::KeyNotFound)
    }

    pub fn delete(&mut self, rid: Rid) -> Result<()> {
        let address = self.scope_address(rid)?;
        let mut page = self.load_page_at(address.fid, address.pid)?;
        page.delete(address.sid)?;
        self.write_page_at(address.fid, address.pid, &page)?;
        self.with_frame(address.fid, |operation| {
            operation.write_slot_metadata(address.pid, page.slots())
        })?;
        self.deleted.to_mut().insert(rid);
        self.flush_directory()?;
        Ok(())
    }

    fn prepare_slot(&self, slot: &RecordSlot) -> Result<(Pid, Sid, RecordPage)> {
        let mut pid = self.current_pid;
        let mut sid = slot.sid;
        let mut page = if self.next_sid > u32::from(u16::MAX) {
            pid = self.rollover_pid()?;
            sid = Sid(1);
            RecordPage::new(self.next_rid)
        } else {
            self.load_or_create_page(pid)?
        };
        let mut prepared = slot.clone();
        prepared.sid = sid;
        match prepared.install_into_page(&mut page) {
            Ok(()) => {}
            Err(PraxisError::WriteStalled { .. }) => {
                pid = self.rollover_pid()?;
                sid = Sid(1);
                prepared.sid = sid;
                page = RecordPage::new(self.next_rid);
                prepared.install_into_page(&mut page)?;
            }
            Err(error) => return Err(error),
        }
        Ok((pid, sid, page))
    }

    fn write_slot(&mut self, slot: &RecordSlot) -> Result<SlotAddress> {
        let (pid, sid, page) = self.prepare_slot(slot)?;
        self.current_pid = pid;
        self.write_page(self.current_pid, &page)?;
        self.write_slot_metadata(self.current_pid, page.slots())?;
        Ok(SlotAddress {
            cid: self.cid,
            eid: self.eid,
            fid: self.fid,
            pid: self.current_pid,
            sid,
        })
    }

    fn load_or_create_page(&self, pid: Pid) -> Result<RecordPage> {
        let path = self
            .layout
            .page_path(self.cid, self.eid, self.fid, pid)
            .path;
        if path.exists() {
            RecordPage::from_bytes(&std::fs::read(&path)?, path)
        } else {
            Ok(RecordPage::new(self.next_rid))
        }
    }

    fn load_page(&self, pid: Pid) -> Result<RecordPage> {
        self.load_page_at(self.fid, pid)
    }

    fn write_page(&self, pid: Pid, page: &RecordPage) -> Result<()> {
        self.write_page_at(self.fid, pid, page)
    }

    fn write_slot_metadata(&self, pid: Pid, slots: &[SlotDirectoryEntry]) -> Result<()> {
        self.side_effects.set(true);
        let root = self
            .layout
            .slot_directory_root(self.cid, self.eid, self.fid, pid);
        std::fs::create_dir_all(&root)?;
        let mut directory = BinaryWriter::new();
        directory.write_u32(slots.len() as u32);
        for slot in slots {
            directory.write_u32(slot.sid.0 as u32);
            directory.write_u32(slot.offset);
            directory.write_u32(slot.len);
            directory.write_u8(u8::from(slot.tombstone));
        }
        let slot_directory = directory.into_inner();
        let slot_directory_path = root.join("slot.directory");
        std::fs::write(&slot_directory_path, &slot_directory)?;
        self.manifest_store().track_bytes(
            &slot_directory_path,
            "slot-directory",
            1,
            &slot_directory,
        )?;
        let page_header = self.load_page(pid)?.header;
        let mut header = BinaryWriter::new();
        header.write_u32(page_header.page_size);
        header.write_u64(page_header.page_lsn);
        header.write_u32(page_header.slot_count as u32);
        header.write_u32(page_header.free_space_start);
        header.write_u32(page_header.free_space_end);
        std::fs::write(root.join("page.header"), header.into_inner())?;
        std::fs::write(root.join("fixed.map"), [])?;
        std::fs::write(root.join("dynamic.map"), [])?;
        std::fs::write(root.join("free.slots"), [])?;
        std::fs::write(root.join("null.bitmap"), [])?;
        std::fs::write(root.join("varlen.map"), [])?;
        std::fs::write(root.join("overflow.map"), [])?;
        Ok(())
    }

    fn flush_directory(&self) -> Result<()> {
        self.side_effects.set(true);
        let path = self.layout.critical_map_path(self.cid, "rid_to_slot").path;
        self.directory.save_binary(
            &path,
            self.next_rid,
            u16::try_from(self.next_sid).unwrap_or(u16::MAX),
            self.current_pid,
        )?;
        self.manifest_store().track_bytes(
            &path,
            "rid-directory",
            RID_DIRECTORY_VERSION as u16,
            &std::fs::read(&path)?,
        )?;
        self.flush_critical_sidecar_maps()
    }

    fn encode_typed_record(&self, fields: &[(FieldId, PraxisValue)]) -> Result<Vec<u8>> {
        let mut cells = Vec::with_capacity(fields.len());
        let mut payloads = Vec::with_capacity(fields.len());
        for (field, value) in fields {
            let encoded = DataTypeRegistry::encode(value)?;
            let payload = value.payload_bytes()?;
            let payload_len = u32::try_from(payload.len()).map_err(|_| {
                PraxisError::InvalidConfig("typed payload exceeds its v1 length field".to_string())
            })?;
            let cell = match encoded.storage_class {
                StorageClass::Inline => TypedFieldCell {
                    field: *field,
                    type_code: encoded.type_code,
                    storage_class: StorageClass::Inline,
                    inline_bytes: encoded.inline_bytes,
                    pointer: None,
                },
                StorageClass::External => TypedFieldCell {
                    field: *field,
                    type_code: encoded.type_code,
                    storage_class: StorageClass::External,
                    inline_bytes: Vec::new(),
                    pointer: Some(ExternalPointer::Overflow {
                        page_id: 1,
                        offset: 0,
                        len: payload_len,
                        checksum: crc32c(&payload),
                    }),
                },
                StorageClass::Segment => {
                    let family = pointer_family(encoded.pointer)?;
                    TypedFieldCell {
                        field: *field,
                        type_code: encoded.type_code,
                        storage_class: StorageClass::Segment,
                        inline_bytes: Vec::new(),
                        pointer: Some(ExternalPointer::Segment {
                            family,
                            segment_id: 1,
                            offset: 0,
                            len: payload_len,
                        }),
                    }
                }
                StorageClass::Catalog => TypedFieldCell {
                    field: *field,
                    type_code: encoded.type_code,
                    storage_class: StorageClass::Catalog,
                    inline_bytes: Vec::new(),
                    pointer: encoded.pointer,
                },
            };
            payloads.push(
                if matches!(
                    cell.storage_class,
                    StorageClass::External | StorageClass::Segment
                ) {
                    Some(payload)
                } else {
                    None
                },
            );
            cells.push(cell);
        }
        // Fixed-width placeholders have exactly the final pointer shape. Validate
        // every type, encoded length and destination page before any blob append.
        let preflight_body = encode_typed_cells(&cells)?;
        Self::validate_record_size(&[(FieldId::Dynamic(Did(0xffff)), &preflight_body)])?;
        let sid = Sid(u16::try_from(self.next_sid).unwrap_or(1));
        self.prepare_slot(&RecordSlot::from_fields(
            sid,
            &[(FieldId::Dynamic(Did(0xffff)), &preflight_body)],
        ))?;
        let mut offsets = BTreeMap::new();
        let mut blobs = Vec::new();
        for (index, payload) in payloads.into_iter().enumerate() {
            let Some(payload) = payload else {
                continue;
            };
            let family = match cells[index].pointer.clone() {
                Some(ExternalPointer::Segment { family, .. }) => Some(family),
                _ => None,
            };
            let path = match family {
                Some(family) => {
                    self.layout
                        .segment_blob_path(self.cid, self.eid, family)
                        .path
                }
                None => self.layout.overflow_blob_path(self.cid, self.eid).path,
            };
            let offset = match offsets.get(&path) {
                Some(offset) => *offset,
                None => match std::fs::metadata(&path) {
                    Ok(metadata) if metadata.is_file() && metadata.len() >= 5 => metadata.len(),
                    Ok(_) => return corrupt(&path, "typed blob is not a valid appendable file"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => 5,
                    Err(error) => return Err(error.into()),
                },
            };
            let len = u32::try_from(payload.len()).map_err(|_| {
                PraxisError::InvalidConfig("typed payload exceeds its v1 length field".to_string())
            })?;
            let next = offset
                .checked_add(8)
                .and_then(|value| value.checked_add(u64::from(len)))
                .ok_or_else(|| PraxisError::WriteStalled {
                    reason: "typed blob offset space is exhausted".to_string(),
                })?;
            offsets.insert(path.clone(), next);
            let location = BlobLocation {
                family,
                file_id: 1,
                offset,
                len,
                checksum: crc32c(&payload),
            };
            cells[index].pointer = Some(match family {
                Some(family) => ExternalPointer::Segment {
                    family,
                    segment_id: 1,
                    offset,
                    len,
                },
                None => ExternalPointer::Overflow {
                    page_id: 1,
                    offset: u32::try_from(offset).map_err(|_| PraxisError::WriteStalled {
                        reason: "v1 typed overflow offset space is exhausted".to_string(),
                    })?,
                    len,
                    checksum: location.checksum,
                },
            });
            blobs.push((payload, location, path));
        }
        for (payload, expected, path) in blobs {
            self.side_effects.set(true);
            let actual = match expected.family {
                Some(family) => self.segment_store(family)?.append(&payload)?,
                None => self.overflow_store()?.append(&payload)?,
            };
            if actual != expected {
                return corrupt(&path, "typed blob append moved after preflight");
            }
        }
        encode_typed_cells(&cells)
    }

    fn overflow_store(&self) -> Result<BlobStore> {
        BlobStore::open_overflow(self.layout.overflow_blob_path(self.cid, self.eid).path)
    }

    fn segment_store(&self, family: SegmentFamily) -> Result<BlobStore> {
        BlobStore::open_segment(
            self.layout
                .segment_blob_path(self.cid, self.eid, family)
                .path,
            family,
            1,
        )
    }

    fn manifest_store(&self) -> PageManifestStore {
        PageManifestStore::open(self.layout.page_manifest_path().path)
    }

    fn flush_critical_sidecar_maps(&self) -> Result<()> {
        let page_path = self.layout.critical_map_path(self.cid, "rid_to_page").path;
        let entity_path = self
            .layout
            .critical_map_path(self.cid, "rid_to_entity")
            .path;
        let commit_path = self.layout.critical_map_path(self.cid, "commit_state").path;
        let sequence_path = self.layout.critical_map_path(self.cid, "sequence").path;

        let mut rid_to_page = BinaryWriter::new();
        let mut rid_to_entity = BinaryWriter::new();
        let mut commit_state = BinaryWriter::new();
        rid_to_page.write_u32(self.directory.mappings.len() as u32);
        rid_to_entity.write_u32(self.directory.mappings.len() as u32);
        commit_state.write_u32(self.directory.mappings.len() as u32);
        for (rid, address) in &self.directory.mappings {
            rid_to_page.write_u64(rid.0);
            rid_to_page.write_u32(address.fid.0);
            rid_to_page.write_u32(address.pid.0);
            rid_to_page.write_u32(address.sid.0 as u32);

            rid_to_entity.write_u64(rid.0);
            rid_to_entity.write_u32(address.cid.0);
            rid_to_entity.write_u32(address.eid.0);

            commit_state.write_u64(rid.0);
            commit_state.write_u8(u8::from(!self.deleted.contains(rid)));
        }
        let mut sequence = BinaryWriter::new();
        sequence.write_u64(self.next_rid);
        sequence.write_u32(self.next_sid.min(u32::from(u16::MAX)));
        sequence.write_u32(self.current_pid.0);

        write_sidecar(&page_path, rid_to_page.into_inner())?;
        write_sidecar(&entity_path, rid_to_entity.into_inner())?;
        write_sidecar(&commit_path, commit_state.into_inner())?;
        write_sidecar(&sequence_path, sequence.into_inner())?;
        Ok(())
    }
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}

fn write_sidecar(path: &Path, bytes: Vec<u8>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypedFieldCell {
    field: FieldId,
    type_code: TypeCode,
    storage_class: StorageClass,
    inline_bytes: Vec<u8>,
    pointer: Option<ExternalPointer>,
}

fn encode_typed_cells(cells: &[TypedFieldCell]) -> Result<Vec<u8>> {
    u32::try_from(cells.len()).map_err(|_| {
        PraxisError::InvalidConfig("typed field count exceeds its v1 length field".to_string())
    })?;
    let mut encoded_len = 17_usize; // v1 envelope plus the cell count.
    for cell in cells {
        u32::try_from(cell.inline_bytes.len()).map_err(|_| {
            PraxisError::InvalidConfig("typed inline field exceeds its v1 length field".to_string())
        })?;
        let pointer_len = match &cell.pointer {
            None => 1,
            Some(ExternalPointer::Overflow { .. }) => 21,
            Some(ExternalPointer::Segment { .. }) => 22,
            Some(ExternalPointer::Catalog { catalog, .. }) => {
                u32::try_from(catalog.len()).map_err(|_| {
                    PraxisError::InvalidConfig(
                        "typed catalog name exceeds its v1 length field".to_string(),
                    )
                })?;
                catalog
                    .len()
                    .checked_add(13)
                    .ok_or_else(|| PraxisError::WriteStalled {
                        reason: "typed record length overflow".to_string(),
                    })?
            }
        };
        encoded_len = encoded_len
            .checked_add(11)
            .and_then(|len| len.checked_add(cell.inline_bytes.len()))
            .and_then(|len| len.checked_add(pointer_len))
            .ok_or_else(|| PraxisError::WriteStalled {
                reason: "typed record length overflow".to_string(),
            })?;
        if encoded_len > crate::page::DEFAULT_PAGE_SIZE as usize - 16 {
            return Err(PraxisError::WriteStalled {
                reason: "typed record metadata cannot fit in a fresh page".to_string(),
            });
        }
    }
    let mut payload = BinaryWriter::new();
    payload.write_u32(cells.len() as u32);
    for cell in cells {
        write_field(&mut payload, cell.field);
        payload.write_u8(cell.type_code as u8);
        payload.write_u8(storage_class_to_tag(cell.storage_class));
        payload.write_len_bytes(&cell.inline_bytes);
        write_external_pointer(&mut payload, cell.pointer.clone());
    }
    let payload = payload.into_inner();
    let mut out = BinaryWriter::new();
    out.write_u32(TYPED_RECORD_MAGIC);
    out.write_u8(TYPED_RECORD_VERSION);
    out.write_u32(payload.len() as u32);
    out.write_u32(crc32c(&payload));
    out.write_bytes(&payload);
    Ok(out.into_inner())
}

fn decode_typed_record(bytes: &[u8], source: &Path) -> Result<Vec<TypedFieldCell>> {
    if bytes.len() < 13 {
        return corrupt(source, "truncated typed record header");
    }
    if u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != TYPED_RECORD_MAGIC {
        return corrupt(source, "bad typed record magic");
    }
    if bytes[4] != TYPED_RECORD_VERSION {
        return corrupt(
            source,
            &format!("unsupported typed record version {}", bytes[4]),
        );
    }
    let len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    let expected = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    if len.checked_add(13) != Some(bytes.len()) {
        return corrupt(
            source,
            "typed record payload length does not match its envelope",
        );
    }
    let payload = &bytes[13..13 + len];
    let actual = crc32c(payload);
    if actual != expected {
        return corrupt(
            source,
            &format!(
                "typed record checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
            ),
        );
    }
    let mut reader = BinaryReader::new(payload, source.to_path_buf());
    let count = reader.read_u32()? as usize;
    // Even an empty inline cell needs a field tag/id, type, storage class,
    // length and pointer tag. Prove the count from actual input before reserve.
    if count > reader.remaining() / 12 {
        return corrupt(source, "typed cell count exceeds remaining payload");
    }
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "cannot reserve validated typed cell count".to_string(),
        })?;
    for _ in 0..count {
        let cell = TypedFieldCell {
            field: read_field(&mut reader, source)?,
            type_code: tag_to_type_code(reader.read_u8()?, source)?,
            storage_class: tag_to_storage_class(reader.read_u8()?, source)?,
            inline_bytes: copy_typed_bytes(reader.read_len_slice()?, source)?,
            pointer: read_external_pointer(&mut reader, source)?,
        };
        validate_typed_cell(&cell, source)?;
        cells.push(cell);
    }
    if reader.remaining() != 0 {
        return corrupt(source, "trailing bytes in typed record payload");
    }
    Ok(cells)
}

fn copy_typed_bytes(bytes: &[u8], source: &Path) -> Result<Vec<u8>> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "cannot reserve validated typed field bytes".to_string(),
        })?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn validate_typed_cell(cell: &TypedFieldCell, source: &Path) -> Result<()> {
    let valid = match (cell.storage_class, &cell.pointer) {
        (StorageClass::Inline, None) => true,
        (
            StorageClass::External,
            Some(ExternalPointer::Overflow {
                page_id,
                offset,
                len,
                ..
            }),
        ) => {
            cell.inline_bytes.is_empty()
                && *page_id == 1
                && *offset >= 5
                && u64::from(*offset)
                    .checked_add(8)
                    .and_then(|end| end.checked_add(u64::from(*len)))
                    .is_some()
        }
        (
            StorageClass::Segment,
            Some(ExternalPointer::Segment {
                segment_id,
                offset,
                len,
                ..
            }),
        ) => {
            cell.inline_bytes.is_empty()
                && *segment_id == 1
                && *offset >= 5
                && offset
                    .checked_add(8)
                    .and_then(|end| end.checked_add(u64::from(*len)))
                    .is_some()
        }
        (StorageClass::Catalog, Some(ExternalPointer::Catalog { .. })) => {
            cell.inline_bytes.is_empty()
        }
        _ => false,
    };
    if !valid {
        return corrupt(source, "typed storage class and pointer shape do not agree");
    }
    Ok(())
}

fn pointer_family(pointer: Option<ExternalPointer>) -> Result<SegmentFamily> {
    match pointer {
        Some(ExternalPointer::Segment { family, .. }) => Ok(family),
        _ => Err(PraxisError::InvalidConfig(
            "segment value did not include segment family".to_string(),
        )),
    }
}

fn write_field(writer: &mut BinaryWriter, field: FieldId) {
    match field {
        FieldId::Fixed(aid) => {
            writer.write_u8(1);
            writer.write_u32(aid.0 as u32);
        }
        FieldId::Dynamic(did) => {
            writer.write_u8(2);
            writer.write_u32(did.0 as u32);
        }
    }
}

fn read_field(reader: &mut BinaryReader<'_>, source: &Path) -> Result<FieldId> {
    let tag = reader.read_u8()?;
    if !matches!(tag, 1 | 2) {
        return corrupt(source, &format!("invalid typed field tag {tag}"));
    }
    let id = u16::try_from(reader.read_u32()?).map_err(|_| PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: "typed field ID exceeds its identifier range".to_string(),
    })?;
    Ok(match tag {
        1 => FieldId::Fixed(Aid(id)),
        _ => FieldId::Dynamic(Did(id)),
    })
}

fn write_external_pointer(writer: &mut BinaryWriter, pointer: Option<ExternalPointer>) {
    match pointer {
        None => writer.write_u8(0),
        Some(ExternalPointer::Overflow {
            page_id,
            offset,
            len,
            checksum,
        }) => {
            writer.write_u8(1);
            writer.write_u64(page_id);
            writer.write_u32(offset);
            writer.write_u32(len);
            writer.write_u32(checksum);
        }
        Some(ExternalPointer::Segment {
            family,
            segment_id,
            offset,
            len,
        }) => {
            writer.write_u8(2);
            writer.write_u8(segment_family_to_tag(family));
            writer.write_u64(segment_id);
            writer.write_u64(offset);
            writer.write_u32(len);
        }
        Some(ExternalPointer::Catalog { catalog, key }) => {
            writer.write_u8(3);
            writer.write_len_bytes(catalog.as_bytes());
            writer.write_u64(key);
        }
    }
}

fn read_external_pointer(
    reader: &mut BinaryReader<'_>,
    source: &Path,
) -> Result<Option<ExternalPointer>> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(ExternalPointer::Overflow {
            page_id: reader.read_u64()?,
            offset: reader.read_u32()?,
            len: reader.read_u32()?,
            checksum: reader.read_u32()?,
        })),
        2 => Ok(Some(ExternalPointer::Segment {
            family: tag_to_segment_family(reader.read_u8()?, source)?,
            segment_id: reader.read_u64()?,
            offset: reader.read_u64()?,
            len: reader.read_u32()?,
        })),
        3 => {
            let catalog = String::from_utf8(copy_typed_bytes(reader.read_len_slice()?, source)?)
                .map_err(|_| PraxisError::Corrupt {
                    path: source.to_path_buf(),
                    reason: "typed catalog name is not UTF-8".to_string(),
                })?;
            Ok(Some(ExternalPointer::Catalog {
                catalog,
                key: reader.read_u64()?,
            }))
        }
        tag => corrupt(source, &format!("invalid typed pointer tag {tag}")),
    }
}

fn storage_class_to_tag(storage_class: StorageClass) -> u8 {
    match storage_class {
        StorageClass::Inline => 1,
        StorageClass::External => 2,
        StorageClass::Segment => 3,
        StorageClass::Catalog => 4,
    }
}

fn tag_to_storage_class(tag: u8, source: &Path) -> Result<StorageClass> {
    match tag {
        1 => Ok(StorageClass::Inline),
        2 => Ok(StorageClass::External),
        3 => Ok(StorageClass::Segment),
        4 => Ok(StorageClass::Catalog),
        _ => corrupt(source, &format!("invalid storage class tag {tag}")),
    }
}

fn segment_family_to_tag(family: SegmentFamily) -> u8 {
    match family {
        SegmentFamily::Vector => 1,
        SegmentFamily::Edge => 2,
        SegmentFamily::FullText => 3,
    }
}

fn tag_to_segment_family(tag: u8, source: &Path) -> Result<SegmentFamily> {
    match tag {
        1 => Ok(SegmentFamily::Vector),
        2 => Ok(SegmentFamily::Edge),
        3 => Ok(SegmentFamily::FullText),
        _ => corrupt(source, &format!("invalid segment family tag {tag}")),
    }
}

fn tag_to_type_code(tag: u8, source: &Path) -> Result<TypeCode> {
    match tag {
        0x01 => Ok(TypeCode::Int2),
        0x02 => Ok(TypeCode::Int4),
        0x03 => Ok(TypeCode::Int8),
        0x04 => Ok(TypeCode::UInt8),
        0x10 => Ok(TypeCode::Float4),
        0x11 => Ok(TypeCode::Float8),
        0x12 => Ok(TypeCode::Numeric),
        0x20 => Ok(TypeCode::Bool),
        0x30 => Ok(TypeCode::TextInline),
        0x31 => Ok(TypeCode::Json),
        0x32 => Ok(TypeCode::Jsonb),
        0x40 => Ok(TypeCode::Uuid),
        0x50 => Ok(TypeCode::Date),
        0x51 => Ok(TypeCode::Time),
        0x53 => Ok(TypeCode::Timestamp),
        0x60 => Ok(TypeCode::Money),
        0x61 => Ok(TypeCode::Enum),
        0x70 => Ok(TypeCode::Bytea),
        0x80 => Ok(TypeCode::List),
        0x81 => Ok(TypeCode::Set),
        0x82 => Ok(TypeCode::Dict),
        0x83 => Ok(TypeCode::Range),
        0x90 => Ok(TypeCode::Vec32),
        0x91 => Ok(TypeCode::Vec16),
        0x92 => Ok(TypeCode::Vec8),
        0x93 => Ok(TypeCode::VecBin),
        0x94 => Ok(TypeCode::Embedding),
        0x95 => Ok(TypeCode::SparseVec),
        0xA0 => Ok(TypeCode::EdgeRef),
        0xA1 => Ok(TypeCode::EdgeList),
        0xA2 => Ok(TypeCode::Path),
        0xA3 => Ok(TypeCode::Subgraph),
        0xB0 => Ok(TypeCode::TsVector),
        0xC0 => Ok(TypeCode::GeoPoint),
        0xC1 => Ok(TypeCode::GeoShape),
        0xD0 => Ok(TypeCode::Cidr),
        0xD1 => Ok(TypeCode::Inet),
        0xE0 => Ok(TypeCode::CommitRef),
        0xE1 => Ok(TypeCode::BranchRef),
        0xE2 => Ok(TypeCode::RidRef),
        _ => corrupt(source, &format!("invalid type code tag {tag:#04x}")),
    }
}
