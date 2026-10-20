//! Discardable physical evidence for one writer-produced value file.
//!
//! This first cut accepts protected catalog and fixed-size record pointers to
//! one canonical file. It does not grant an installed owner or admit variable
//! record Payload/Descriptor extents.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue, Field};
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole, SegmentPhysicalId,
    physical_id,
};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::types::ValuePointer;
use crate::wal::catalog_witness::{PhysicalWitnessBudget, path_charge, vector_charge};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const HEADER_BYTES: u64 = 12;
const CATALOG_MAX_BYTES: usize = 33_947;
const MAX_SCHEMA_FIELDS: usize = 128;
const HASH_CHUNK_BYTES: usize = 64 * 1024;
const MAX_REFERENCED_VALUE_FILES: usize = 4_096;

#[derive(Debug)]
pub(super) struct ValueFileWitness {
    pub(super) id: u64,
    pub(super) path: PathBuf,
    pub(super) identity: SegmentPhysicalId,
    pub(super) len: u64,
    pub(super) digest: blake3::Hash,
}

#[derive(Debug)]
pub(super) struct ValueExtentWitness {
    pub(super) file_id: u64,
    pub(super) offset: u64,
    pub(super) len: u64,
    pub(super) checksum: u32,
    pub(super) payload_digest: blake3::Hash,
    row_index: usize,
}

#[derive(Debug)]
pub(super) struct ValueWitnessCandidate {
    pub(super) files: Vec<ValueFileWitness>,
    pub(super) extents: Vec<ValueExtentWitness>,
    pub(super) retained_bytes: usize,
}

impl ValueWitnessCandidate {
    pub(super) fn discard(self, root: &Path, budget: &mut PhysicalWitnessBudget) -> Result<()> {
        let Self {
            files,
            extents,
            retained_bytes,
        } = self;
        drop(files);
        drop(extents);
        budget.release(root, retained_bytes)
    }
}

#[derive(Default)]
pub(super) struct ValueFileScanProbe {
    pub(super) proof_full_file_hashes: usize,
    pub(super) recheck_full_file_hashes: usize,
}

fn corrupt(path: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn budget_error(path: &Path) -> PraxisError {
    corrupt(path, "external value witness metadata budget exceeded")
}

/// Own every debit until the backing paths and vectors have dropped. A
/// successful candidate takes over only the retained debit via discard().
struct ValueAttempt<'a> {
    root: &'a Path,
    budget: &'a mut PhysicalWitnessBudget,
    charged: usize,
    armed: bool,
}

impl<'a> ValueAttempt<'a> {
    fn new(root: &'a Path, budget: &'a mut PhysicalWitnessBudget) -> Self {
        Self {
            root,
            budget,
            charged: 0,
            armed: true,
        }
    }

    fn charge(&mut self, path: &Path, bytes: usize) -> Result<()> {
        let total = self
            .charged
            .checked_add(bytes)
            .ok_or_else(|| budget_error(path))?;
        self.budget.charge(path, bytes)?;
        self.charged = total;
        Ok(())
    }

    fn release(&mut self, path: &Path, bytes: usize) -> Result<()> {
        let remaining = self
            .charged
            .checked_sub(bytes)
            .ok_or_else(|| budget_error(path))?;
        self.budget.release(path, bytes)?;
        self.charged = remaining;
        Ok(())
    }

    fn transfer(&mut self, expected: usize) -> Result<()> {
        if self.charged != expected {
            return Err(budget_error(self.root));
        }
        self.charged = 0;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ValueAttempt<'_> {
    fn drop(&mut self) {
        if self.armed && self.charged != 0 && self.budget.release(self.root, self.charged).is_err()
        {
            std::process::abort();
        }
    }
}

/// Parse the ID from borrowed path components. Path equality normalizes some
/// aliases, so collection also compares the raw spelling with DiskLayout.
fn canonical_id(root: &Path, manifest: &Manifest, claimed: &str) -> Result<u64> {
    let path = Path::new(claimed);
    let parent = path
        .parent()
        .ok_or_else(|| corrupt(path, "external value path has no parent"))?;
    if parent.file_name() != Some(OsStr::new("values")) || parent.parent() != Some(root) {
        return Err(corrupt(path, "external value path is not canonical"));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "external value file has no UTF-8 name"))?;
    let digits = name
        .strip_suffix(".tval")
        .filter(|digits| digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| corrupt(path, "external value file has no canonical ID"))?;
    let id = digits
        .parse::<u64>()
        .map_err(|_| corrupt(path, "external value file ID overflows"))?;
    if id == 0 || id >= manifest.next_segment_id {
        return Err(corrupt(path, "external value file ID is unowned"));
    }
    Ok(id)
}

/// DiskLayout::at(root).value_log_path allocates a root clone, an intermediate
/// directory, a formatted filename, and the final path. Precharge all four
/// transient buffers before constructing it; only the final path remains live
/// after the checked refund in collect_value_witness.
fn canonical_path_build_charge(root: &Path) -> Result<usize> {
    root.as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(40)
        .and_then(|maximum_encoded_path| maximum_encoded_path.checked_mul(24))
        .and_then(|bytes| bytes.checked_add(512))
        .ok_or_else(|| budget_error(root))
}

fn pointer_spec<'a>(
    root: &Path,
    manifest: &Manifest,
    row: &'a ObservedSegmentRow,
) -> Result<Option<(u64, &'a ValuePointer)>> {
    let ObservedSegmentValue::Pointer {
        pointer,
        expires_at_ms,
    } = &row.value
    else {
        return Ok(None);
    };
    if expires_at_ms.is_some() {
        return Err(corrupt(root, "protected external value pointer expires"));
    }
    if row.cf == CATALOG_CF
        && row.classification == PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
    {
        let key = CatalogKey::decode(&row.key, root)?;
        let cap = match &key {
            CatalogKey::Head if row.sequence >= 1 => 48,
            CatalogKey::Anchor if row.sequence == 1 => 72,
            CatalogKey::Name(_) if row.sequence >= 2 => 12,
            CatalogKey::Namespace(_) if row.sequence >= 2 => 16,
            CatalogKey::Schema(_) if row.sequence >= 2 => CATALOG_MAX_BYTES as u64,
            _ => return Err(corrupt(root, "external catalog key sequence is invalid")),
        };
        if pointer.len == 0
            || pointer.len > cap
            || (cap != CATALOG_MAX_BYTES as u64 && pointer.len != cap)
        {
            return Err(corrupt(
                root,
                "external catalog pointer exceeds its key cap",
            ));
        }
    } else if let Some(role) = RecordRole::from_cf(&row.cf) {
        let expected_role = match role {
            RecordRole::Meta => ProtectedRole::Meta,
            RecordRole::Payload => ProtectedRole::Payload,
            RecordRole::State => ProtectedRole::State,
            RecordRole::Index => ProtectedRole::Index,
        };
        if row.classification != PhysicalRowClass::BoundProtected(expected_role) {
            return Err(corrupt(root, "external record pointer is not protected"));
        }
        let key = RecordKey::decode(role, &row.key, root)?;
        let exact_len = match key {
            RecordKey::Binding => 80,
            RecordKey::Allocator => 56,
            RecordKey::State(_) => 24,
            RecordKey::Fact { .. } => 32,
            RecordKey::Head { .. } => 40,
            RecordKey::Descriptor(_) | RecordKey::Payload(_) => {
                return Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "variable-length record extents await streamed value witness",
                });
            }
        };
        if pointer.len != exact_len {
            return Err(corrupt(
                root,
                "external fixed record pointer has wrong length",
            ));
        }
    } else {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "unbound external value witness awaits the owner cut",
        });
    }
    let id = canonical_id(root, manifest, &pointer.path)?;
    pointer
        .offset
        .checked_add(HEADER_BYTES)
        .and_then(|end| end.checked_add(pointer.len))
        .ok_or_else(|| corrupt(Path::new(&pointer.path), "external value extent overflows"))?;
    Ok(Some((id, pointer)))
}

fn check_real_value_path(path: &Path) -> Result<()> {
    for (index, entry) in path.ancestors().enumerate() {
        if entry.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(entry)
            .map_err(|_| corrupt(entry, "external value path disappeared"))?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(
                entry,
                "external value path crosses a symbolic link",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(
                    entry,
                    "external value path crosses a reparse point",
                ));
            }
        }
        if (index == 0 && !meta.is_file()) || (index != 0 && !meta.is_dir()) {
            return Err(corrupt(
                entry,
                "external value path is not a regular file under real directories",
            ));
        }
    }
    Ok(())
}

fn open_checked(path: &Path) -> Result<(File, SegmentPhysicalId, u64)> {
    check_real_value_path(path)?;
    let file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(corrupt(path, "opened external value is not a regular file"));
    }
    let id = physical_id(&file, path)?;
    check_real_value_path(path)?;
    Ok((file, id, meta.len()))
}

fn recheck_opened_path(
    path: &Path,
    file: &File,
    expected_id: SegmentPhysicalId,
    expected_len: u64,
) -> Result<()> {
    if file.metadata()?.len() != expected_len || physical_id(file, path)? != expected_id {
        return Err(corrupt(path, "opened external value changed during scan"));
    }
    let (reopened, id, len) = open_checked(path)?;
    if id != expected_id || len != expected_len {
        return Err(corrupt(path, "external value path changed during scan"));
    }
    drop(reopened);
    check_real_value_path(path)
}

#[derive(Clone, Copy)]
struct ExtentSpec {
    offset: u64,
    len: u64,
    checksum: u32,
    row_index: usize,
}

trait ExtentSink {
    fn len(&self) -> usize;
    fn spec(&self, index: usize) -> ExtentSpec;
    fn observe(&mut self, index: usize, digest: blake3::Hash, path: &Path) -> Result<()>;
}

struct BuildExtents<'a>(&'a mut [ValueExtentWitness]);

impl ExtentSink for BuildExtents<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn spec(&self, index: usize) -> ExtentSpec {
        let item = &self.0[index];
        ExtentSpec {
            offset: item.offset,
            len: item.len,
            checksum: item.checksum,
            row_index: item.row_index,
        }
    }
    fn observe(&mut self, index: usize, digest: blake3::Hash, _path: &Path) -> Result<()> {
        self.0[index].payload_digest = digest;
        Ok(())
    }
}

struct CheckExtents<'a>(&'a [ValueExtentWitness]);

impl ExtentSink for CheckExtents<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn spec(&self, index: usize) -> ExtentSpec {
        let item = &self.0[index];
        ExtentSpec {
            offset: item.offset,
            len: item.len,
            checksum: item.checksum,
            row_index: item.row_index,
        }
    }
    fn observe(&mut self, index: usize, digest: blake3::Hash, path: &Path) -> Result<()> {
        if digest != self.0[index].payload_digest {
            return Err(corrupt(path, "external value extent digest changed"));
        }
        Ok(())
    }
}

fn read_hashed(
    file: &mut File,
    mut bytes: u64,
    full: &mut blake3::Hasher,
    buffer: &mut [u8; HASH_CHUNK_BYTES],
) -> Result<()> {
    while bytes != 0 {
        let count = bytes.min(HASH_CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        full.update(&buffer[..count]);
        bytes -= count as u64;
    }
    Ok(())
}

/// Complete byte walk, including gaps and an unreferenced tail. The writer's
/// IEEE CRC32 is recomputed incrementally; no value-log payload Vec is made.
fn scan_file(
    file: &mut File,
    path: &Path,
    observed_len: u64,
    extents: &mut impl ExtentSink,
    mut validate: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<blake3::Hash> {
    let mut full = blake3::Hasher::new();
    let mut buffer = [0_u8; HASH_CHUNK_BYTES];
    let mut catalog = [0_u8; CATALOG_MAX_BYTES];
    let mut position = 0_u64;
    for index in 0..extents.len() {
        let spec = extents.spec(index);
        let end = spec
            .offset
            .checked_add(HEADER_BYTES)
            .and_then(|n| n.checked_add(spec.len))
            .ok_or_else(|| corrupt(path, "external value extent overflows"))?;
        if spec.offset < position || end > observed_len {
            return Err(corrupt(
                path,
                "external value extents overlap or exceed file length",
            ));
        }
        let len = usize::try_from(spec.len)
            .ok()
            .filter(|len| *len <= CATALOG_MAX_BYTES)
            .ok_or_else(|| corrupt(path, "external value extent exceeds catalog cap"))?;
        read_hashed(file, spec.offset - position, &mut full, &mut buffer)?;
        let mut header = [0_u8; HEADER_BYTES as usize];
        file.read_exact(&mut header)?;
        full.update(&header);
        if u64::from_le_bytes(header[..8].try_into().unwrap()) != spec.len
            || u32::from_le_bytes(header[8..].try_into().unwrap()) != spec.checksum
        {
            return Err(corrupt(
                path,
                "external value header disagrees with pointer",
            ));
        }
        let mut crc = crc32fast::Hasher::new();
        let mut payload = blake3::Hasher::new();
        let mut copied = 0;
        while copied < len {
            let count = (len - copied).min(HASH_CHUNK_BYTES);
            file.read_exact(&mut buffer[..count])?;
            full.update(&buffer[..count]);
            crc.update(&buffer[..count]);
            payload.update(&buffer[..count]);
            catalog[copied..copied + count].copy_from_slice(&buffer[..count]);
            copied += count;
        }
        if crc.finalize() != spec.checksum {
            return Err(corrupt(path, "external value payload checksum mismatch"));
        }
        extents.observe(index, payload.finalize(), path)?;
        validate(spec.row_index, &catalog[..len])?;
        position = end;
    }
    read_hashed(file, observed_len - position, &mut full, &mut buffer)?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(corrupt(path, "external value grew during scan"));
    }
    Ok(full.finalize())
}

struct SchemaDecodeCharge<'a> {
    budget: &'a mut PhysicalWitnessBudget,
    path: &'a Path,
    bytes: usize,
}

impl Drop for SchemaDecodeCharge<'_> {
    fn drop(&mut self) {
        if self.budget.release(self.path, self.bytes).is_err() {
            std::process::abort();
        }
    }
}

fn validate_catalog_payload(
    row: &ObservedSegmentRow,
    bytes: &[u8],
    path: &Path,
    budget: &mut PhysicalWitnessBudget,
) -> Result<()> {
    if row.cf != CATALOG_CF {
        let role = RecordRole::from_cf(&row.cf)
            .ok_or_else(|| corrupt(path, "external record has no protected role"))?;
        let key = RecordKey::decode(role, &row.key, path)?;
        let _decoded = RecordRow::decode(&key, bytes, path)?;
        return Ok(());
    }
    let key = CatalogKey::decode(&row.key, path)?;
    if matches!(&key, CatalogKey::Schema(_)) {
        let allowance = vector_charge::<Field<'static>>(path, MAX_SCHEMA_FIELDS * 2)?;
        budget.charge(path, allowance)?;
        let charge = SchemaDecodeCharge {
            budget,
            path,
            bytes: allowance,
        };
        let value = CatalogValue::decode(&key, bytes, path)?;
        let CatalogValue::Schema(schema) = value else {
            return Err(corrupt(path, "external Schema has the wrong value tag"));
        };
        if schema.fields.capacity() > MAX_SCHEMA_FIELDS * 2 {
            return Err(budget_error(path));
        }
        drop(schema);
        drop(charge);
    } else if !matches!(
        (&key, CatalogValue::decode(&key, bytes, path)?),
        (CatalogKey::Head, CatalogValue::Head(_))
            | (CatalogKey::Anchor, CatalogValue::Anchor(_))
            | (CatalogKey::Name(_), CatalogValue::Name(_))
            | (CatalogKey::Namespace(_), CatalogValue::Namespace(_))
    ) {
        return Err(corrupt(path, "external catalog value has the wrong tag"));
    }
    Ok(())
}

pub(super) fn collect_value_witness(
    root: &Path,
    manifest: &Manifest,
    rows: &[ObservedSegmentRow],
    budget: &mut PhysicalWitnessBudget,
    probe: &mut ValueFileScanProbe,
) -> Result<ValueWitnessCandidate> {
    let mut first: Option<u64> = None;
    let mut count = 0_usize;
    let mut referenced_files = 0_usize;
    for row in rows {
        if let Some((id, _)) = pointer_spec(root, manifest, row)? {
            count = count
                .checked_add(1)
                .filter(|count| *count <= 65_536)
                .ok_or_else(|| corrupt(root, "external value pointer stage exceeds limit"))?;
            match first {
                None => {
                    referenced_files = referenced_files
                        .checked_add(1)
                        .filter(|files| *files <= MAX_REFERENCED_VALUE_FILES)
                        .ok_or_else(|| corrupt(root, "too many referenced value files"))?;
                    first = Some(id);
                }
                Some(first_id) if first_id == id => {}
                _ => {
                    let _next = referenced_files
                        .checked_add(1)
                        .filter(|files| *files <= MAX_REFERENCED_VALUE_FILES)
                        .ok_or_else(|| corrupt(root, "too many referenced value files"))?;
                    return Err(PraxisError::UnsupportedCatalogFeature {
                        feature: "multiple referenced value files await the inventory cut",
                    });
                }
            }
        }
    }
    let id = first.ok_or(PraxisError::UnsupportedCatalogFeature {
        feature: "no protected external value to witness",
    })?;
    let mut attempt = ValueAttempt::new(root, budget);
    let build_allowance = canonical_path_build_charge(root)?;
    attempt.charge(root, build_allowance)?;
    let path = {
        let layout = DiskLayout::at(root);
        layout.value_log_path(id)
    };
    let canonical = path
        .to_str()
        .ok_or_else(|| corrupt(&path, "external value canonical path is not UTF-8"))?;
    for row in rows {
        if pointer_spec(root, manifest, row)?.is_some_and(|(pointer_id, pointer)| {
            pointer_id != id || pointer.path.as_str() != canonical
        }) {
            return Err(corrupt(
                &path,
                "external value pointer path is not the exact canonical spelling",
            ));
        }
    }
    let path_allowance = path_charge(&path)?;
    if path.capacity() > path_allowance || path_allowance > build_allowance {
        return Err(budget_error(&path));
    }
    // The temporary layout, intermediate directory and filename have dropped;
    // retain the final path's own debit before refunding the temporary excess.
    attempt.release(root, build_allowance - path_allowance)?;
    let file_allowance = vector_charge::<ValueFileWitness>(&path, 1)?;
    attempt.charge(&path, file_allowance)?;
    let mut files = Vec::new();
    files
        .try_reserve_exact(1)
        .map_err(|_| corrupt(&path, "external value file witness reservation failed"))?;
    if vector_charge::<ValueFileWitness>(&path, files.capacity())? > file_allowance {
        return Err(budget_error(&path));
    }
    let extent_allowance = vector_charge::<ValueExtentWitness>(&path, count)?;
    attempt.charge(&path, extent_allowance)?;
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(count)
        .map_err(|_| corrupt(&path, "external value extent witness reservation failed"))?;
    if vector_charge::<ValueExtentWitness>(&path, extents.capacity())? > extent_allowance {
        return Err(budget_error(&path));
    }
    for (row_index, row) in rows.iter().enumerate() {
        if let Some((pointer_id, pointer)) = pointer_spec(root, manifest, row)? {
            if pointer_id != id || pointer.path.as_str() != canonical {
                return Err(corrupt(
                    &path,
                    "external value pointer changed during preflight",
                ));
            }
            extents.push(ValueExtentWitness {
                file_id: id,
                offset: pointer.offset,
                len: pointer.len,
                checksum: pointer.checksum,
                payload_digest: blake3::hash(&[]),
                row_index,
            });
        }
    }
    extents.sort_unstable_by_key(|item| item.offset);
    for pair in extents.windows(2) {
        let end = pair[0]
            .offset
            .checked_add(HEADER_BYTES)
            .and_then(|n| n.checked_add(pair[0].len))
            .ok_or_else(|| corrupt(&path, "external value extent overflows"))?;
        if end > pair[1].offset {
            return Err(corrupt(&path, "external value extents overlap"));
        }
    }
    let (mut opened, identity, len) = open_checked(&path)?;
    probe.proof_full_file_hashes = probe
        .proof_full_file_hashes
        .checked_add(1)
        .ok_or_else(|| corrupt(&path, "external value proof scan counter overflows"))?;
    let digest = {
        let mut sink = BuildExtents(&mut extents);
        scan_file(&mut opened, &path, len, &mut sink, |row_index, bytes| {
            validate_catalog_payload(&rows[row_index], bytes, &path, attempt.budget)
        })?
    };
    recheck_opened_path(&path, &opened, identity, len)?;
    drop(opened);
    files.push(ValueFileWitness {
        id,
        path,
        identity,
        len,
        digest,
    });
    let retained_bytes = attempt.charged;
    attempt.transfer(retained_bytes)?;
    Ok(ValueWitnessCandidate {
        files,
        extents,
        retained_bytes,
    })
}

pub(super) fn recheck_value_witness(
    root: &Path,
    manifest: &Manifest,
    candidate: &ValueWitnessCandidate,
    probe: &mut ValueFileScanProbe,
) -> Result<()> {
    let [witness] = candidate.files.as_slice() else {
        return Err(corrupt(
            root,
            "external value candidate is not the one-file cut",
        ));
    };
    if canonical_id(
        root,
        manifest,
        witness
            .path
            .to_str()
            .ok_or_else(|| corrupt(&witness.path, "external value path is not UTF-8"))?,
    )? != witness.id
    {
        return Err(corrupt(
            &witness.path,
            "external value candidate ID changed",
        ));
    }
    if candidate.extents.is_empty()
        || candidate
            .extents
            .iter()
            .any(|item| item.file_id != witness.id)
    {
        return Err(corrupt(
            &witness.path,
            "external value candidate has unowned extents",
        ));
    }
    let (mut opened, identity, len) = open_checked(&witness.path)?;
    if identity != witness.identity || len != witness.len {
        return Err(corrupt(
            &witness.path,
            "external value file identity or length changed",
        ));
    }
    probe.recheck_full_file_hashes =
        probe
            .recheck_full_file_hashes
            .checked_add(1)
            .ok_or_else(|| {
                corrupt(
                    &witness.path,
                    "external value recheck scan counter overflows",
                )
            })?;
    let mut sink = CheckExtents(candidate.extents.as_slice());
    let digest = scan_file(&mut opened, &witness.path, len, &mut sink, |_, _| Ok(()))?;
    recheck_opened_path(&witness.path, &opened, identity, len)?;
    if digest != witness.digest {
        return Err(corrupt(
            &witness.path,
            "external value full-file digest changed",
        ));
    }
    Ok(())
}
