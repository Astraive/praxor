//! Read-only protected evidence validation. F1a intentionally refuses every
//! nonbootstrap record transition until the sealed F1b planner is installed.
use super::codec::{Allocator, Key, Kind, Role, Row};
use super::schema::{RESERVED_PREFIX, corrupt};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::segments::codec::RawEntry;
use crate::transactions::BatchOp;
use crate::types::{StoredValue, ValuePointer};
use crate::wal::record::CoreWalRecord;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) struct Evidence {
    source: PathBuf,
    authority: Option<([u8; 16], u32)>,
    flushed_sequence: u64,
    meta: BTreeMap<Vec<u8>, Vec<u8>>,
    previous_wal_sequence: Option<u64>,
}

impl Evidence {
    pub(crate) fn new(manifest: &Manifest, source: &Path) -> Result<Self> {
        let authority = manifest
            .record_authority
            .as_ref()
            .map(|a| a.identity(source).map(|id| (id, a.index_descriptor_count)))
            .transpose()?;
        Ok(Self {
            source: source.to_path_buf(),
            authority,
            flushed_sequence: manifest.flushed_sequence,
            meta: BTreeMap::new(),
            previous_wal_sequence: None,
        })
    }

    pub(crate) fn segment(
        &mut self,
        raw: &RawEntry,
        mut read_blob: impl FnMut(&ValuePointer) -> Result<Vec<u8>>,
    ) -> Result<()> {
        if self.authority.is_none() {
            return Ok(());
        }
        let entry = &raw.entry;
        if entry.version.sequence > self.flushed_sequence {
            return Err(corrupt(
                &self.source,
                "segment row exceeds the installed authority flush cutoff",
            ));
        }
        let Some(role) = Role::from_cf(&entry.cf.0) else {
            if entry.cf.0.starts_with(RESERVED_PREFIX) {
                return Err(corrupt(
                    &self.source,
                    "segment uses an unbound reserved record role",
                ));
            }
            if entry.version.sequence <= 1 {
                return Err(corrupt(
                    &self.source,
                    "ordinary segment row precedes or shares authority bootstrap",
                ));
            }
            return Ok(());
        };
        if raw.blob_expiry.is_some() {
            return Err(corrupt(
                &self.source,
                "protected segment row has expiration",
            ));
        }
        let value = match &entry.version.value {
            StoredValue::Put(value) => value.clone(),
            StoredValue::BlobPointer(pointer) => read_blob(pointer)?,
            _ => {
                return Err(corrupt(
                    &self.source,
                    "protected segment row has forbidden operation",
                ));
            }
        };
        self.row(role, &entry.key, &value)?;
        // Foundation only creates bootstrap metadata. Even if a later writer
        // flushed away its envelope, this checkpoint must not admit its rows.
        if entry.version.sequence != 1 || self.flushed_sequence < 1 {
            return Err(unsupported(
                &self.source,
                "nonbootstrap protected segment version",
            ));
        }
        self.install_meta(role, &entry.key, &value)
    }

    pub(crate) fn wal(&mut self, record: &CoreWalRecord) -> Result<()> {
        if self.authority.is_some() {
            let sequence = record.sequence();
            if sequence == 0
                || self
                    .previous_wal_sequence
                    .is_some_and(|previous| sequence <= previous)
            {
                return Err(corrupt(
                    &self.source,
                    "authority WAL sequences are not strictly ordered",
                ));
            }
            self.previous_wal_sequence = Some(sequence);
        }
        match (self.authority, record) {
            (None, CoreWalRecord::User(_)) => Ok(()),
            (None, CoreWalRecord::Record { .. }) => Err(PraxisError::RecordAuthorityWalRequired {
                path: self.source.clone(),
            }),
            (Some(_), CoreWalRecord::User(record)) => {
                for op in record.batch.ops() {
                    let cf = match op {
                        BatchOp::Put { cf, .. }
                        | BatchOp::PutWithExpiry { cf, .. }
                        | BatchOp::Merge { cf, .. }
                        | BatchOp::Delete { cf, .. } => cf,
                    };
                    if cf.0.starts_with(RESERVED_PREFIX) {
                        return Err(corrupt(
                            &self.source,
                            "ordinary WAL request accesses protected record namespace",
                        ));
                    }
                }
                if record.sequence <= 1 {
                    return Err(corrupt(
                        &self.source,
                        "ordinary WAL request precedes authority bootstrap",
                    ));
                }
                Ok(())
            }
            (
                Some((id, count)),
                CoreWalRecord::Record {
                    sequence,
                    envelope,
                    batch,
                },
            ) => {
                envelope.validate(*sequence, &self.source)?;
                if envelope.database_id != id {
                    return Err(corrupt(
                        &self.source,
                        "record WAL identity does not match manifest",
                    ));
                }
                if envelope.kind != Kind::Bootstrap {
                    return Err(unsupported(
                        &self.source,
                        "nonbootstrap record transition requires F1b",
                    ));
                }
                if batch.len().checked_sub(2) != Some(count as usize) {
                    return Err(corrupt(
                        &self.source,
                        "bootstrap operation count does not match registry",
                    ));
                }
                for (index, op) in batch.ops().iter().enumerate() {
                    let BatchOp::Put { cf, key, value } = op else {
                        return Err(corrupt(
                            &self.source,
                            "bootstrap contains a non-put operation",
                        ));
                    };
                    let expected = match index {
                        0 => Key::Binding,
                        1 => Key::Allocator,
                        _ => Key::Descriptor(u32::try_from(index - 1).map_err(|_| {
                            corrupt(&self.source, "bootstrap registry ID overflow")
                        })?),
                    }
                    .encode()?;
                    if cf.0 != Role::Meta.cf() || key != &expected {
                        return Err(corrupt(
                            &self.source,
                            "bootstrap operation order/role/key mismatch",
                        ));
                    }
                    self.row(Role::Meta, key, value)?;
                    self.install_meta(Role::Meta, key, value)?;
                }
                Ok(())
            }
        }
    }

    fn row(&self, role: Role, key: &[u8], value: &[u8]) -> Result<()> {
        let key = Key::decode(role, key, &self.source)?;
        let row = Row::decode(&key, value, &self.source)?;
        let Some((id, count)) = self.authority else {
            return Ok(());
        };
        match row {
            Row::Binding {
                database_id,
                descriptor_count,
            } if database_id == id && descriptor_count == count => Ok(()),
            Row::Allocator(value) if value == Allocator::default() => Ok(()),
            Row::Descriptor { .. } if matches!(key, Key::Descriptor(index) if index <= count) => {
                Ok(())
            }
            Row::Binding { .. } => Err(corrupt(
                &self.source,
                "protected binding differs from manifest",
            )),
            Row::Descriptor { .. } => {
                Err(corrupt(&self.source, "unregistered mapping descriptor ID"))
            }
            _ => Err(unsupported(
                &self.source,
                "nonbootstrap protected state requires F1b",
            )),
        }
    }

    fn install_meta(&mut self, role: Role, key: &[u8], value: &[u8]) -> Result<()> {
        if role != Role::Meta {
            return Err(unsupported(&self.source, "nonbootstrap protected role"));
        }
        if let Some(previous) = self.meta.insert(key.to_vec(), value.to_vec())
            && previous != value
        {
            return Err(corrupt(
                &self.source,
                "immutable bootstrap metadata was rewritten",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<()> {
        let Some((_, count)) = self.authority else {
            return Ok(());
        };
        if self.meta.len().checked_sub(2) != Some(count as usize)
            || !self.meta.contains_key(&[0][..])
            || !self.meta.contains_key(&[1][..])
        {
            return Err(corrupt(
                &self.source,
                "missing bootstrap binding/allocator/registry evidence",
            ));
        }
        let mut previous: Option<&str> = None;
        for (index, (key, value)) in self.meta.iter().skip(2).enumerate() {
            let expected = Key::Descriptor(
                u32::try_from(index + 1)
                    .map_err(|_| corrupt(&self.source, "registry ID overflow"))?,
            );
            if Key::decode(Role::Meta, key, &self.source)? != expected {
                return Err(corrupt(&self.source, "registry IDs are not contiguous"));
            }
            let Row::Descriptor { name, .. } = Row::decode(&expected, value, &self.source)? else {
                unreachable!()
            };
            if previous.is_some_and(|prior| prior.as_bytes() >= name.as_bytes()) {
                return Err(corrupt(
                    &self.source,
                    "registry index names are not unique canonical UTF-8 order",
                ));
            }
            previous = Some(name);
        }
        Ok(())
    }
}

pub(crate) fn unsupported(source: &Path, reason: &str) -> PraxisError {
    PraxisError::StorageFormatUnsupported {
        path: source.to_path_buf(),
        expected: crate::storage::root_format::RootOwner::Core,
        reason: reason.into(),
        evidence: vec![source.to_path_buf()],
    }
}

/// Resolve only a previously validated physical value role. The row's maximum
/// wire size is the existing atomic WAL bound, not an arbitrary diagnostic cap.
pub(crate) fn read_blob_at(pointer: &ValuePointer, physical: &Path) -> Result<Vec<u8>> {
    if pointer.len > crate::wal::record::MAX_WAL_PAYLOAD_BYTES as u64
        || pointer
            .offset
            .checked_add(12)
            .and_then(|end| end.checked_add(pointer.len))
            .is_none_or(|end| std::fs::metadata(physical).map_or(true, |meta| end > meta.len()))
    {
        return Err(corrupt(
            physical,
            "protected value pointer exceeds actual file or atomic row bound",
        ));
    }
    let mut local = pointer.clone();
    local.path = physical.to_string_lossy().into_owned();
    crate::values::ValueLog::read_pointer(&local)
}

/// Validate the complete authority before any reconcile/save/truncate/create.
/// The retained owner lease stabilizes these physical paths throughout this scan.
pub(crate) fn validate_owner(
    root: &Path,
    manifest: &Manifest,
    accelerator: &dyn crate::accel::Accelerator,
) -> Result<Vec<CoreWalRecord>> {
    let source = root.join("MANIFEST");
    let mut evidence = Evidence::new(manifest, &source)?;
    for metadata in &manifest.segments {
        let expected = root
            .join("segments")
            .join(metadata.level.to_string())
            .join(format!("{:020}.tseg", metadata.id));
        if Path::new(&metadata.path) != expected {
            return Err(corrupt(
                &source,
                "protected owner segment label is outside its exact file role",
            ));
        }
        real_file(&expected)?;
        let bytes = std::fs::read(&expected)?;
        if blake3::hash(&bytes).to_hex().as_str() != metadata.file_digest {
            return Err(corrupt(&expected, "segment digest mismatch"));
        }
        let raw = crate::segments::codec::decode_segment(&bytes, &expected, accelerator)?;
        if raw.id != metadata.id
            || raw.level != metadata.level
            || raw
                .blocks
                .iter()
                .map(|block| block.len() as u64)
                .sum::<u64>()
                != metadata.entries
        {
            return Err(corrupt(&expected, "segment identity/count mismatch"));
        }
        for row in raw.blocks.iter().flatten() {
            evidence.segment(row, |pointer| {
                let path = Path::new(&pointer.path);
                let id = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .filter(|stem| {
                        stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .and_then(|stem| stem.parse::<u64>().ok())
                    .filter(|id| *id != 0 && *id < manifest.next_segment_id)
                    .ok_or_else(|| corrupt(path, "invalid protected value role identity"))?;
                let expected = root.join("values").join(format!("{id:020}.tval"));
                if path != expected {
                    return Err(corrupt(
                        path,
                        "protected value label is outside its exact file role",
                    ));
                }
                real_file(&expected)?;
                read_blob_at(pointer, &expected)
            })?;
        }
    }
    let records = read_owner_wals(root, manifest)?;
    for record in &records {
        evidence.wal(record)?;
    }
    evidence.finish()?;
    Ok(records)
}

fn real_file(path: &Path) -> Result<()> {
    let mut current = path;
    loop {
        let metadata = std::fs::symlink_metadata(current)?;
        if metadata.file_type().is_symlink() {
            return Err(corrupt(current, "authority file role contains an alias"));
        }
        if current == path && !metadata.is_file() {
            return Err(corrupt(current, "authority file role is not regular"));
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    Ok(())
}

fn read_owner_wals(root: &Path, manifest: &Manifest) -> Result<Vec<CoreWalRecord>> {
    if manifest.flushed_sequence > manifest.last_sequence
        || manifest.flushed_wal_id >= manifest.active_wal_id
        || manifest.next_wal_id <= manifest.active_wal_id
    {
        return Err(corrupt(root, "invalid record authority WAL cutoffs"));
    }
    let mut paths = BTreeMap::new();
    for entry in std::fs::read_dir(root.join("wal"))? {
        let path = entry?.path();
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                name.len() == 24
                    && name.ends_with(".wal")
                    && name.as_bytes()[..20].iter().all(u8::is_ascii_digit)
            })
            .and_then(|name| name[..20].parse::<u64>().ok())
            .filter(|id| *id != 0 && *id <= manifest.active_wal_id)
            .ok_or_else(|| corrupt(&path, "unexpected authority WAL role"))?;
        real_file(&path)?;
        paths.insert(id, path);
    }
    let mut previous_id = manifest.flushed_wal_id;
    for id in paths.keys().filter(|id| **id > manifest.flushed_wal_id) {
        if previous_id.checked_add(1) != Some(*id) {
            return Err(corrupt(root, "required authority WAL identity is missing"));
        }
        previous_id = *id;
    }
    if previous_id != manifest.active_wal_id {
        return Err(corrupt(root, "active authority WAL is missing"));
    }
    let mut records = Vec::new();
    let mut previous_sequence = None;
    let mut covered = manifest.flushed_sequence;
    for (id, path) in paths {
        let bytes = std::fs::read(&path)?;
        let header = [
            0x5457_4146u32.to_le_bytes().as_slice(),
            1u32.to_le_bytes().as_slice(),
            id.to_le_bytes().as_slice(),
        ]
        .concat();
        if (bytes.len() < 16 && !header.starts_with(&bytes))
            || (bytes.len() >= 16 && bytes[..16] != header)
        {
            return Err(corrupt(&path, "authority WAL header/identity mismatch"));
        }
        let (file_records, end) = crate::wal::writer::replay_core_records(&bytes, &path)?;
        if id != manifest.active_wal_id && (bytes.len() < 16 || end != bytes.len()) {
            return Err(corrupt(&path, "inactive authority WAL is incomplete"));
        }
        for record in file_records {
            let sequence = record.sequence();
            if sequence == 0 || previous_sequence.is_some_and(|previous| sequence <= previous) {
                return Err(corrupt(
                    &path,
                    "authority WAL sequences are not strictly ordered",
                ));
            }
            previous_sequence = Some(sequence);
            if sequence > manifest.flushed_sequence {
                if covered.checked_add(1) != Some(sequence) {
                    return Err(corrupt(
                        &path,
                        "authority WAL committed suffix is incomplete",
                    ));
                }
                covered = sequence;
            }
            records.push(record);
        }
    }
    if covered < manifest.last_sequence {
        return Err(corrupt(
            root,
            "authority WAL is missing persisted committed sequence",
        ));
    }
    Ok(records)
}
