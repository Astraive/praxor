//! Discardable physical evidence for writer-produced value files.
//!
//! This private cut accepts protected catalog and record pointers to canonical
//! files. It does not grant an installed owner.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue, Field};
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole, SegmentPhysicalId,
    SegmentSource, physical_id,
};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};
use crate::core_records::variable_stream::{VariableKind, VariableRowStream, VariableSummary};
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::types::ValuePointer;
use crate::wal::catalog_witness::{PhysicalWitnessBudget, path_charge, vector_charge};
use crate::wal::record::MAX_WAL_PAYLOAD_BYTES;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const HEADER_BYTES: u64 = 12;
const CATALOG_MAX_BYTES: usize = 33_947;
const MAX_SCHEMA_FIELDS: usize = 128;
const HASH_CHUNK_BYTES: usize = 64 * 1024;
const MAX_REFERENCED_VALUE_FILES: usize = 4_096;
const MAX_STAGED_VALUE_POINTERS: usize = 65_536;
const MAX_COPY_REPLAY_READ_BYTES: u64 = 512 * 1024 * 1024;
const MAX_COPY_REPLAY_OPENS: usize = 8_192;
const COPY_REPLAY_SCRATCH_BYTES: usize =
    HASH_CHUNK_BYTES + CATALOG_MAX_BYTES + HEADER_BYTES as usize + 1;

struct PreparedValueFile {
    id: u64,
    path: PathBuf,
    extent_start: usize,
    extent_end: usize,
}

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
    pub(super) kind: Option<VariableKind>,
    pub(super) payload_digest: blake3::Hash,
    pub(super) locator: ValueRowLocator,
    row_index: usize,
}

/// The original segment position remains attached to its value extent after
/// the staged `ObservedSegmentRow` vector has been discarded by the copy ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ValueRowLocator {
    pub(super) source: SegmentSource,
    pub(super) block_offset: u64,
    pub(super) row_ordinal: u32,
}

impl ValueRowLocator {
    fn from_row(row: &ObservedSegmentRow) -> Self {
        Self {
            source: row.source,
            block_offset: row.block_offset,
            row_ordinal: row.row_ordinal,
        }
    }

    fn sort_key(self) -> (u32, u64, usize, u64, u32) {
        (
            self.source.level,
            self.source.id,
            self.source.manifest_ordinal,
            self.block_offset,
            self.row_ordinal,
        )
    }
}

#[derive(Debug)]
pub(super) struct ValueRecordSummaryWitness {
    pub(super) extent_index: usize,
    pub(super) summary: VariableSummary,
}

#[derive(Debug)]
pub(super) struct ValueWitnessCandidate {
    pub(super) files: Vec<ValueFileWitness>,
    pub(super) extents: Vec<ValueExtentWitness>,
    locator_order: Vec<usize>,
    pub(super) variable_summaries: Vec<ValueRecordSummaryWitness>,
    pub(super) retained_bytes: usize,
}

impl ValueWitnessCandidate {
    pub(super) fn discard(self, root: &Path, budget: &mut PhysicalWitnessBudget) -> Result<()> {
        let Self {
            files,
            extents,
            locator_order,
            variable_summaries,
            retained_bytes,
        } = self;
        drop(files);
        drop(extents);
        drop(locator_order);
        drop(variable_summaries);
        budget.release(root, retained_bytes)
    }
}

#[cfg(test)]
pub(super) type ValueFileRaceHook = Box<dyn FnMut(ValueFileRacePoint, &Path)>;

#[derive(Default)]
pub(super) struct ValueFileScanProbe {
    pub(super) proof_full_file_hashes: usize,
    pub(super) recheck_full_file_hashes: usize,
    #[cfg(test)]
    pub(super) race_hook: Option<ValueFileRaceHook>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ValueFileRacePoint {
    AfterPathPreflight,
    AfterObservedLength,
}

#[cfg(test)]
impl ValueFileScanProbe {
    fn inject_race(&mut self, point: ValueFileRacePoint, path: &Path) {
        if let Some(hook) = &mut self.race_hook {
            hook(point, path);
        }
    }
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

fn replay_limit() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "external value copy replay exceeds the bounded private profile",
    }
}

/// Cumulative physical work is charged before any selected-file replay. An
/// attempt that fails still consumes its reserved work allowance.
#[allow(dead_code)] // Used when the private #82 copy ledger integrates replay.
#[derive(Default)]
pub(super) struct ValueReplayWork {
    pub(super) read_bytes: u64,
    pub(super) open_attempts: usize,
}

#[allow(dead_code)] // Used when the private #82 copy ledger integrates replay.
#[derive(Default)]
pub(super) struct ValueReplayContext {
    pub(super) work: ValueReplayWork,
    pub(super) probe: ValueFileScanProbe,
}

impl ValueReplayWork {
    fn reserve(&mut self, file_len: u64) -> Result<()> {
        let read_bytes = file_len
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2))
            .and_then(|bytes| self.read_bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= MAX_COPY_REPLAY_READ_BYTES)
            .ok_or_else(replay_limit)?;
        let open_attempts = self
            .open_attempts
            .checked_add(3)
            .filter(|opens| *opens <= MAX_COPY_REPLAY_OPENS)
            .ok_or_else(replay_limit)?;
        self.read_bytes = read_bytes;
        self.open_attempts = open_attempts;
        Ok(())
    }
}

struct ReplayScratch<'a> {
    budget: &'a mut PhysicalWitnessBudget,
    path: &'a Path,
}

impl<'a> ReplayScratch<'a> {
    fn new(path: &'a Path, budget: &'a mut PhysicalWitnessBudget) -> Result<Self> {
        budget.charge(path, COPY_REPLAY_SCRATCH_BYTES)?;
        Ok(ReplayScratch { budget, path })
    }
}

impl Drop for ReplayScratch<'_> {
    fn drop(&mut self) {
        if self
            .budget
            .release(self.path, COPY_REPLAY_SCRATCH_BYTES)
            .is_err()
        {
            std::process::abort();
        }
    }
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

/// Charge a conservative prospective capacity before asking Vec to allocate.
/// The observed capacity must fit that charge; no subsequent push may grow it.
fn reserve_value_vec<T>(
    path: &Path,
    count: usize,
    attempt: &mut ValueAttempt<'_>,
) -> Result<(Vec<T>, usize)> {
    let prospective = count.checked_mul(2).ok_or_else(|| budget_error(path))?;
    let allowance = vector_charge::<T>(path, prospective)?;
    attempt.charge(path, allowance)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| corrupt(path, "external value witness reservation failed"))?;
    let observed = vector_charge::<T>(path, values.capacity())?;
    if values.capacity() < count || observed > allowance {
        return Err(budget_error(path));
    }
    attempt.release(path, allowance - observed)?;
    Ok((values, observed))
}

/// Extents are already sorted in place by (file ID, offset). Repeated pointers
/// to one file consume only one of the 4,096 file slots.
fn count_distinct_sorted_ids(path: &Path, extents: &[ValueExtentWitness]) -> Result<usize> {
    let mut previous = 0_u64;
    let mut count = 0_usize;
    for extent in extents {
        if extent.file_id == 0 || extent.file_id < previous {
            return Err(corrupt(path, "external value IDs are not sorted and owned"));
        }
        if extent.file_id != previous {
            count = count
                .checked_add(1)
                .filter(|count| *count <= MAX_REFERENCED_VALUE_FILES)
                .ok_or_else(|| corrupt(path, "too many referenced value files"))?;
            previous = extent.file_id;
        }
    }
    Ok(count)
}

fn validate_extent_layout(path: &Path, extents: &[ValueExtentWitness]) -> Result<()> {
    for pair in extents.windows(2) {
        if pair[0].file_id == pair[1].file_id {
            let end = pair[0]
                .offset
                .checked_add(HEADER_BYTES)
                .and_then(|n| n.checked_add(pair[0].len))
                .ok_or_else(|| corrupt(path, "external value extent overflows"))?;
            if end > pair[1].offset {
                return Err(corrupt(path, "external value extents overlap"));
            }
        }
    }
    Ok(())
}

/// The index is a charged permutation of extents, sorted by physical segment
/// locator. Repeated locators cannot silently bind two different value ranges.
fn validate_locator_order(
    path: &Path,
    extents: &[ValueExtentWitness],
    order: &[usize],
) -> Result<()> {
    if order.len() != extents.len() {
        return Err(corrupt(path, "external value locator index count changed"));
    }
    let mut previous = None;
    for &index in order {
        let key = extents
            .get(index)
            .ok_or_else(|| corrupt(path, "external value locator index is out of range"))?
            .locator
            .sort_key();
        if previous.is_some_and(|prior| prior >= key) {
            return Err(corrupt(
                path,
                "external value locator is duplicated or unordered",
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

/// A sorted, precharged Vec avoids HashSet's speculative bucket allocation.
fn register_physical_identity(
    path: &Path,
    identities: &mut Vec<SegmentPhysicalId>,
    identity: SegmentPhysicalId,
) -> Result<()> {
    let position = identities.binary_search_by(|existing| {
        existing
            .volume
            .cmp(&identity.volume)
            .then_with(|| existing.file.cmp(&identity.file))
    });
    let index = match position {
        Ok(_) => {
            return Err(corrupt(
                path,
                "external value files share a physical identity",
            ));
        }
        Err(index) => index,
    };
    if identities.len() == identities.capacity() {
        return Err(budget_error(path));
    }
    identities.insert(index, identity);
    Ok(())
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
) -> Result<Option<(u64, &'a ValuePointer, Option<VariableKind>)>> {
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
    let mut variable_kind = None;
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
            RecordKey::Binding => Some(80),
            RecordKey::Allocator => Some(56),
            RecordKey::State(_) => Some(24),
            RecordKey::Fact { .. } => Some(32),
            RecordKey::Head { .. } => Some(40),
            RecordKey::Descriptor(_) => {
                variable_kind = Some(VariableKind::Descriptor);
                None
            }
            RecordKey::Payload(_) => {
                variable_kind = Some(VariableKind::Payload);
                None
            }
        };
        if let Some(exact_len) = exact_len {
            if pointer.len != exact_len {
                return Err(corrupt(
                    root,
                    "external fixed record pointer has wrong length",
                ));
            }
        } else if variable_kind.is_some_and(|kind| {
            pointer.len < kind.minimum_len() || pointer.len > MAX_WAL_PAYLOAD_BYTES as u64
        }) {
            return Err(corrupt(
                root,
                "external variable record pointer exceeds wire bound",
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
    Ok(Some((id, pointer, variable_kind)))
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

fn open_checked(
    path: &Path,
    probe: &mut ValueFileScanProbe,
) -> Result<(File, SegmentPhysicalId, u64)> {
    check_real_value_path(path)?;
    #[cfg(test)]
    probe.inject_race(ValueFileRacePoint::AfterPathPreflight, path);
    #[cfg(not(test))]
    let _ = probe;
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            corrupt(path, "external value path disappeared during open")
        } else {
            error.into()
        }
    })?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(corrupt(path, "opened external value is not a regular file"));
    }
    let id = physical_id(&file, path)?;
    check_real_value_path(path)?;
    Ok((file, id, meta.len()))
}

fn read_value_exact(file: &mut File, bytes: &mut [u8], path: &Path) -> Result<()> {
    file.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            corrupt(path, "external value file truncated during scan")
        } else {
            error.into()
        }
    })
}

fn recheck_opened_path(
    path: &Path,
    file: &File,
    expected_id: SegmentPhysicalId,
    expected_len: u64,
    probe: &mut ValueFileScanProbe,
) -> Result<()> {
    if file.metadata()?.len() != expected_len || physical_id(file, path)? != expected_id {
        return Err(corrupt(path, "opened external value changed during scan"));
    }
    let (reopened, id, len) = open_checked(path, probe)?;
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
    kind: Option<VariableKind>,
    row_index: usize,
}

trait ExtentSink {
    fn len(&self) -> usize;
    fn spec(&self, index: usize) -> ExtentSpec;
    fn proof(&self) -> bool;
    fn observe(
        &mut self,
        index: usize,
        digest: blake3::Hash,
        summary: Option<VariableSummary>,
        path: &Path,
    ) -> Result<()>;
}

struct BuildExtents<'a> {
    extents: &'a mut [ValueExtentWitness],
    summaries: &'a mut Vec<ValueRecordSummaryWitness>,
    base_index: usize,
}

impl ExtentSink for BuildExtents<'_> {
    fn len(&self) -> usize {
        self.extents.len()
    }
    fn spec(&self, index: usize) -> ExtentSpec {
        let item = &self.extents[index];
        ExtentSpec {
            offset: item.offset,
            len: item.len,
            checksum: item.checksum,
            kind: item.kind,
            row_index: item.row_index,
        }
    }
    fn proof(&self) -> bool {
        true
    }
    fn observe(
        &mut self,
        index: usize,
        digest: blake3::Hash,
        summary: Option<VariableSummary>,
        path: &Path,
    ) -> Result<()> {
        self.extents[index].payload_digest = digest;
        if let Some(summary) = summary {
            if self.summaries.len() == self.summaries.capacity() {
                return Err(budget_error(path));
            }
            self.summaries.push(ValueRecordSummaryWitness {
                extent_index: self.base_index + index,
                summary,
            });
        } else if self.extents[index].kind.is_some() {
            return Err(corrupt(path, "external variable record has no summary"));
        }
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
            kind: item.kind,
            row_index: item.row_index,
        }
    }
    fn proof(&self) -> bool {
        false
    }
    fn observe(
        &mut self,
        index: usize,
        digest: blake3::Hash,
        summary: Option<VariableSummary>,
        path: &Path,
    ) -> Result<()> {
        if summary.is_some() {
            return Err(corrupt(
                path,
                "external value recheck created a new summary",
            ));
        }
        if digest != self.0[index].payload_digest {
            return Err(corrupt(path, "external value extent digest changed"));
        }
        Ok(())
    }
}

fn read_hashed(
    file: &mut File,
    path: &Path,
    mut bytes: u64,
    full: &mut blake3::Hasher,
    buffer: &mut [u8; HASH_CHUNK_BYTES],
) -> Result<()> {
    while bytes != 0 {
        let count = bytes.min(HASH_CHUNK_BYTES as u64) as usize;
        read_value_exact(file, &mut buffer[..count], path)?;
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
    mut on_chunk: impl FnMut(usize, &[u8]) -> Result<()>,
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
            .filter(|len| match spec.kind {
                Some(kind) => (*len as u64) >= kind.minimum_len() && *len <= MAX_WAL_PAYLOAD_BYTES,
                None => *len <= CATALOG_MAX_BYTES,
            })
            .ok_or_else(|| corrupt(path, "external value extent exceeds decoded key cap"))?;
        read_hashed(file, path, spec.offset - position, &mut full, &mut buffer)?;
        let mut header = [0_u8; HEADER_BYTES as usize];
        read_value_exact(file, &mut header, path)?;
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
        let mut variable = if extents.proof() {
            spec.kind
                .map(|kind| VariableRowStream::new(kind, spec.len, path))
                .transpose()?
        } else {
            None
        };
        let mut copied = 0;
        while copied < len {
            let count = (len - copied).min(HASH_CHUNK_BYTES);
            read_value_exact(file, &mut buffer[..count], path)?;
            full.update(&buffer[..count]);
            crc.update(&buffer[..count]);
            payload.update(&buffer[..count]);
            if let Some(parser) = &mut variable {
                parser.feed(&buffer[..count], path)?;
            } else if spec.kind.is_none() && extents.proof() {
                catalog[copied..copied + count].copy_from_slice(&buffer[..count]);
            }
            on_chunk(index, &buffer[..count])?;
            copied += count;
        }
        if crc.finalize() != spec.checksum {
            return Err(corrupt(path, "external value payload checksum mismatch"));
        }
        let summary = variable.map(|parser| parser.finish(path)).transpose()?;
        extents.observe(index, payload.finalize(), summary, path)?;
        if extents.proof() && spec.kind.is_none() {
            validate(spec.row_index, &catalog[..len])?;
        }
        position = end;
    }
    read_hashed(file, path, observed_len - position, &mut full, &mut buffer)?;
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

/// Reuse the value-witness Schema decoder's checked field-vector charge for an
/// inline protected Schema Put in the physical-copy ledger. This only checks
/// the row's syntax; it grants neither copy equivalence nor owner authority.
#[allow(dead_code)] // Used by the later private #82 ledger integrator.
pub(super) fn validate_inline_catalog_schema_put(
    root: &Path,
    row: &ObservedSegmentRow,
    budget: &mut PhysicalWitnessBudget,
) -> Result<()> {
    if row.cf != CATALOG_CF
        || row.classification != PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        || !matches!(CatalogKey::decode(&row.key, root)?, CatalogKey::Schema(_))
    {
        return Err(corrupt(
            root,
            "inline Schema Put lacks a bound catalog role",
        ));
    }
    let ObservedSegmentValue::Put(bytes) = &row.value else {
        return Err(corrupt(root, "inline Schema has the wrong operation"));
    };
    validate_catalog_payload(row, bytes, root, budget)
}

pub(super) fn collect_value_witness(
    root: &Path,
    manifest: &Manifest,
    rows: &[ObservedSegmentRow],
    budget: &mut PhysicalWitnessBudget,
    probe: &mut ValueFileScanProbe,
) -> Result<ValueWitnessCandidate> {
    let mut count = 0_usize;
    let mut variable_count = 0_usize;
    for row in rows {
        if let Some((_, _, kind)) = pointer_spec(root, manifest, row)? {
            count = count
                .checked_add(1)
                .filter(|count| *count <= MAX_STAGED_VALUE_POINTERS)
                .ok_or_else(|| corrupt(root, "external value pointer stage exceeds limit"))?;
            if kind.is_some() {
                variable_count += 1;
            }
        }
    }
    if count == 0 {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "no protected external value to witness",
        });
    }

    // Declare the attempt before every allocation it owns. On any error, all
    // later paths and vectors drop before its Drop returns their shared debit.
    let mut attempt = ValueAttempt::new(root, budget);
    let (mut extents, extent_charge) =
        reserve_value_vec::<ValueExtentWitness>(root, count, &mut attempt)?;
    for (row_index, row) in rows.iter().enumerate() {
        if let Some((id, pointer, kind)) = pointer_spec(root, manifest, row)? {
            if extents.len() == extents.capacity() {
                return Err(budget_error(root));
            }
            extents.push(ValueExtentWitness {
                file_id: id,
                offset: pointer.offset,
                len: pointer.len,
                checksum: pointer.checksum,
                kind,
                payload_digest: blake3::hash(&[]),
                locator: ValueRowLocator::from_row(row),
                row_index,
            });
        }
    }
    if extents.len() != count {
        return Err(corrupt(root, "external value pointer count changed"));
    }
    extents.sort_unstable_by_key(|item| (item.file_id, item.offset));
    let (mut locator_order, locator_charge) =
        reserve_value_vec::<usize>(root, count, &mut attempt)?;
    for index in 0..extents.len() {
        if locator_order.len() == locator_order.capacity() {
            return Err(budget_error(root));
        }
        locator_order.push(index);
    }
    locator_order.sort_unstable_by_key(|&index| extents[index].locator.sort_key());
    validate_locator_order(root, &extents, &locator_order)?;
    let (mut variable_summaries, summary_charge) = if variable_count == 0 {
        (Vec::new(), 0)
    } else {
        reserve_value_vec::<ValueRecordSummaryWitness>(root, variable_count, &mut attempt)?
    };
    let referenced_files = count_distinct_sorted_ids(root, &extents)?;
    validate_extent_layout(root, &extents)?;

    // Prepare and compare every exact raw pointer spelling before opening or
    // hashing the first file. Each retained path has its own live debit.
    let (mut prepared, prepared_charge) =
        reserve_value_vec::<PreparedValueFile>(root, referenced_files, &mut attempt)?;
    let mut extent_start = 0;
    while extent_start < extents.len() {
        let id = extents[extent_start].file_id;
        let mut extent_end = extent_start + 1;
        while extent_end < extents.len() && extents[extent_end].file_id == id {
            extent_end += 1;
        }
        let build_allowance = canonical_path_build_charge(root)?;
        attempt.charge(root, build_allowance)?;
        let path = {
            let layout = DiskLayout::at(root);
            layout.value_log_path(id)
        };
        let canonical = path
            .to_str()
            .ok_or_else(|| corrupt(&path, "external value canonical path is not UTF-8"))?;
        for extent in &extents[extent_start..extent_end] {
            let row = rows
                .get(extent.row_index)
                .ok_or_else(|| corrupt(&path, "external value row index is unowned"))?;
            let Some((pointer_id, pointer, kind)) = pointer_spec(root, manifest, row)? else {
                return Err(corrupt(&path, "external value row lost its pointer"));
            };
            if pointer_id != id
                || pointer.path.as_str() != canonical
                || pointer.offset != extent.offset
                || pointer.len != extent.len
                || pointer.checksum != extent.checksum
                || kind != extent.kind
                || ValueRowLocator::from_row(row) != extent.locator
            {
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
        // Layout, directory and filename temporaries have dropped. The final
        // PathBuf remains charged until candidate discard or error unwind.
        attempt.release(root, build_allowance - path_allowance)?;
        if prepared.len() == prepared.capacity() {
            return Err(budget_error(&path));
        }
        prepared.push(PreparedValueFile {
            id,
            path,
            extent_start,
            extent_end,
        });
        extent_start = extent_end;
    }
    if prepared.len() != referenced_files {
        return Err(corrupt(root, "external value file inventory count changed"));
    }

    let (mut files, file_charge) =
        reserve_value_vec::<ValueFileWitness>(root, referenced_files, &mut attempt)?;
    let (mut physical_ids, physical_charge) =
        reserve_value_vec::<SegmentPhysicalId>(root, referenced_files, &mut attempt)?;
    for plan in prepared.drain(..) {
        let PreparedValueFile {
            id,
            path,
            extent_start,
            extent_end,
        } = plan;
        let (mut opened, identity, len) = open_checked(&path, probe)?;
        register_physical_identity(&path, &mut physical_ids, identity)?;
        probe.proof_full_file_hashes = probe
            .proof_full_file_hashes
            .checked_add(1)
            .ok_or_else(|| corrupt(&path, "external value proof scan counter overflows"))?;
        #[cfg(test)]
        probe.inject_race(ValueFileRacePoint::AfterObservedLength, &path);
        let digest = {
            let mut sink = BuildExtents {
                extents: &mut extents[extent_start..extent_end],
                summaries: &mut variable_summaries,
                base_index: extent_start,
            };
            scan_file(
                &mut opened,
                &path,
                len,
                &mut sink,
                |row_index, bytes| {
                    let row = rows
                        .get(row_index)
                        .ok_or_else(|| corrupt(&path, "external value row index is unowned"))?;
                    validate_catalog_payload(row, bytes, &path, attempt.budget)
                },
                |_, _| Ok(()),
            )?
        };
        recheck_opened_path(&path, &opened, identity, len, probe)?;
        drop(opened);
        if files.len() == files.capacity() {
            return Err(budget_error(&path));
        }
        files.push(ValueFileWitness {
            id,
            path,
            identity,
            len,
            digest,
        });
    }
    drop(prepared);
    attempt.release(root, prepared_charge)?;
    drop(physical_ids);
    attempt.release(root, physical_charge)?;

    if variable_summaries.len() != variable_count {
        return Err(corrupt(root, "external variable summary count changed"));
    }

    let mut retained_bytes = extent_charge
        .checked_add(locator_charge)
        .and_then(|bytes| bytes.checked_add(file_charge))
        .and_then(|bytes| bytes.checked_add(summary_charge))
        .ok_or_else(|| budget_error(root))?;
    for file in &files {
        retained_bytes = retained_bytes
            .checked_add(path_charge(&file.path)?)
            .ok_or_else(|| budget_error(&file.path))?;
    }
    attempt.transfer(retained_bytes)?;
    Ok(ValueWitnessCandidate {
        files,
        extents,
        locator_order,
        variable_summaries,
        retained_bytes,
    })
}

pub(super) fn recheck_value_witness(
    root: &Path,
    manifest: &Manifest,
    candidate: &ValueWitnessCandidate,
    probe: &mut ValueFileScanProbe,
) -> Result<()> {
    if candidate.files.is_empty()
        || candidate.files.len() > MAX_REFERENCED_VALUE_FILES
        || candidate.extents.is_empty()
        || candidate.extents.len() > MAX_STAGED_VALUE_POINTERS
    {
        return Err(corrupt(root, "external value candidate count is invalid"));
    }
    validate_locator_order(root, &candidate.extents, &candidate.locator_order)?;
    validate_extent_layout(root, &candidate.extents)?;
    let mut summary_index = 0;
    for (index, extent) in candidate.extents.iter().enumerate() {
        if let Some(kind) = extent.kind {
            let summary = candidate
                .variable_summaries
                .get(summary_index)
                .ok_or_else(|| corrupt(root, "external variable record summary is missing"))?;
            if summary.extent_index != index
                || !matches!(
                    (kind, summary.summary),
                    (VariableKind::Descriptor, VariableSummary::Descriptor { .. })
                        | (VariableKind::Payload, VariableSummary::Payload { .. })
                )
            {
                return Err(corrupt(root, "external variable record summary is unbound"));
            }
            summary_index += 1;
        }
    }
    if summary_index != candidate.variable_summaries.len() {
        return Err(corrupt(
            root,
            "external variable record summary count is invalid",
        ));
    }
    let mut previous_id = 0_u64;
    let mut extent_start = 0_usize;
    for witness in &candidate.files {
        if witness.id <= previous_id
            || canonical_id(
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
                "external value candidate IDs are not strictly ordered",
            ));
        }
        previous_id = witness.id;
        let mut extent_end = extent_start;
        while candidate
            .extents
            .get(extent_end)
            .is_some_and(|item| item.file_id == witness.id)
        {
            extent_end += 1;
        }
        if extent_end == extent_start {
            return Err(corrupt(
                &witness.path,
                "external value candidate has no extents for file",
            ));
        }
        let (mut opened, identity, len) = open_checked(&witness.path, probe)?;
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
        let mut sink = CheckExtents(&candidate.extents[extent_start..extent_end]);
        let digest = scan_file(
            &mut opened,
            &witness.path,
            len,
            &mut sink,
            |_, _| Ok(()),
            |_, _| Ok(()),
        )?;
        recheck_opened_path(&witness.path, &opened, identity, len, probe)?;
        if digest != witness.digest {
            return Err(corrupt(
                &witness.path,
                "external value full-file digest changed",
            ));
        }
        extent_start = extent_end;
    }
    if extent_start != candidate.extents.len() {
        return Err(corrupt(
            root,
            "external value candidate has unowned extents",
        ));
    }
    Ok(())
}

/// Stream one witnessed external payload by its original physical segment
/// locator. Bytes handed to `on_chunk` are provisional: the caller must not
/// publish a comparison or mutate owner state until this returns `Ok(())` and
/// the whole candidate receives its final `recheck_value_witness` fence.
///
/// Both passes use the same opened file handle. Each pass verifies all extents,
/// gaps, tail and the full-file digest, followed by path/identity/length checks.
/// A cumulative work allowance prevents repeated same-file lookups from
/// turning this selected-row API into unbounded quadratic physical I/O.
#[allow(dead_code)] // Called by the later private #82 equality integrator.
pub(super) fn with_authenticated_value_payload(
    root: &Path,
    manifest: &Manifest,
    candidate: &ValueWitnessCandidate,
    locator: ValueRowLocator,
    context: &mut ValueReplayContext,
    budget: &mut PhysicalWitnessBudget,
    mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if candidate.files.is_empty()
        || candidate.files.len() > MAX_REFERENCED_VALUE_FILES
        || candidate.extents.is_empty()
        || candidate.extents.len() > MAX_STAGED_VALUE_POINTERS
        || candidate.locator_order.len() != candidate.extents.len()
    {
        return Err(corrupt(
            root,
            "external value replay candidate count is invalid",
        ));
    }
    let position = candidate
        .locator_order
        .binary_search_by_key(&locator.sort_key(), |&index| {
            candidate.extents[index].locator.sort_key()
        })
        .map_err(|_| corrupt(root, "external value row locator is unwitnessed"))?;
    let extent_index = candidate.locator_order[position];
    let extent = &candidate.extents[extent_index];
    if extent.locator != locator {
        return Err(corrupt(root, "external value row locator changed"));
    }
    let file_index = candidate
        .files
        .binary_search_by_key(&extent.file_id, |file| file.id)
        .map_err(|_| corrupt(root, "external value extent has no file witness"))?;
    let witness = &candidate.files[file_index];
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
            "external value witness path is unowned",
        ));
    }
    let extent_start = candidate
        .extents
        .partition_point(|item| item.file_id < witness.id);
    let extent_end = candidate
        .extents
        .partition_point(|item| item.file_id <= witness.id);
    if extent_index < extent_start || extent_index >= extent_end {
        return Err(corrupt(
            &witness.path,
            "external value extent/file binding changed",
        ));
    }
    let relative_index = extent_index - extent_start;
    let _scratch = ReplayScratch::new(&witness.path, budget)?;
    context.work.reserve(witness.len)?;
    let (mut opened, identity, len) = open_checked(&witness.path, &mut context.probe)?;
    if identity != witness.identity || len != witness.len {
        return Err(corrupt(
            &witness.path,
            "external value replay file identity or length changed",
        ));
    }
    context.probe.recheck_full_file_hashes = context
        .probe
        .recheck_full_file_hashes
        .checked_add(2)
        .ok_or_else(|| corrupt(&witness.path, "external value replay counter overflows"))?;
    let mut streamed = 0_u64;
    let mut first_sink = CheckExtents(&candidate.extents[extent_start..extent_end]);
    let first_digest = scan_file(
        &mut opened,
        &witness.path,
        len,
        &mut first_sink,
        |_, _| Ok(()),
        |index, bytes| {
            if index == relative_index {
                streamed = streamed
                    .checked_add(bytes.len() as u64)
                    .filter(|count| *count <= extent.len)
                    .ok_or_else(|| corrupt(&witness.path, "external value replay overflowed"))?;
                on_chunk(bytes)?;
            }
            Ok(())
        },
    )?;
    if first_digest != witness.digest || streamed != extent.len {
        return Err(corrupt(
            &witness.path,
            "external value replay digest changed",
        ));
    }
    recheck_opened_path(&witness.path, &opened, identity, len, &mut context.probe)?;
    opened.seek(SeekFrom::Start(0))?;
    let mut second_sink = CheckExtents(&candidate.extents[extent_start..extent_end]);
    let second_digest = scan_file(
        &mut opened,
        &witness.path,
        len,
        &mut second_sink,
        |_, _| Ok(()),
        |_, _| Ok(()),
    )?;
    if second_digest != witness.digest {
        return Err(corrupt(
            &witness.path,
            "external value final digest changed",
        ));
    }
    recheck_opened_path(&witness.path, &opened, identity, len, &mut context.probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_extent(file_id: u64) -> ValueExtentWitness {
        ValueExtentWitness {
            file_id,
            offset: 0,
            len: 1,
            checksum: 0,
            kind: None,
            payload_digest: blake3::hash(&[]),
            locator: ValueRowLocator {
                source: SegmentSource {
                    level: 0,
                    id: file_id,
                    manifest_ordinal: file_id as usize,
                },
                block_offset: 0,
                row_ordinal: 0,
            },
            row_index: 0,
        }
    }

    #[test]
    fn locator_index_distinguishes_equal_bytes_and_rejects_reused_position_or_alias() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("two-equal-values.tval");
        let payload = b"x";
        let checksum = crc32fast::hash(payload);
        let mut file_bytes = Vec::new();
        for _ in 0..2 {
            file_bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            file_bytes.extend_from_slice(&checksum.to_le_bytes());
            file_bytes.extend_from_slice(payload);
        }
        std::fs::write(&path, &file_bytes).unwrap();
        let root = dir.path();
        let mut first = test_extent(1);
        first.checksum = checksum;
        first.payload_digest = blake3::hash(payload);
        let mut second = test_extent(1);
        second.offset = HEADER_BYTES + first.len;
        second.checksum = checksum;
        second.payload_digest = first.payload_digest;
        second.locator.row_ordinal = 1;
        second.row_index = 1;
        let mut extents = [first, second];
        let mut order = [1, 0];
        order.sort_unstable_by_key(|&index| extents[index].locator.sort_key());
        validate_locator_order(root, &extents, &order).unwrap();
        validate_extent_layout(root, &extents).unwrap();
        assert_eq!(order, [0, 1]);
        assert_eq!(extents[0].payload_digest, extents[1].payload_digest);
        assert_ne!(extents[0].locator, extents[1].locator);
        let mut observed = Vec::new();
        let mut sink = CheckExtents(&extents);
        let digest = scan_file(
            &mut std::fs::File::open(&path).unwrap(),
            &path,
            file_bytes.len() as u64,
            &mut sink,
            |_, _| Ok(()),
            |index, bytes| {
                observed.push((index, bytes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(digest, blake3::hash(&file_bytes));
        assert_eq!(observed, vec![(0, payload.to_vec()), (1, payload.to_vec())]);

        extents[1].locator = extents[0].locator;
        assert!(matches!(
            validate_locator_order(root, &extents, &order),
            Err(PraxisError::Corrupt { .. })
        ));
        extents[1].locator.row_ordinal = 1;
        extents[1].offset = extents[0].offset;
        assert!(matches!(
            validate_extent_layout(root, &extents),
            Err(PraxisError::Corrupt { .. })
        ));
    }

    #[test]
    fn distinct_inventory_counts_repeated_ids_and_refuses_the_4097th() {
        let root = Path::new("value-inventory-test");
        let mut extents = (1..=MAX_REFERENCED_VALUE_FILES as u64)
            .flat_map(|id| [test_extent(id), test_extent(id)])
            .collect::<Vec<_>>();
        assert_eq!(extents.len(), MAX_REFERENCED_VALUE_FILES * 2);
        assert_eq!(
            count_distinct_sorted_ids(root, &extents).unwrap(),
            MAX_REFERENCED_VALUE_FILES
        );
        extents.push(test_extent(MAX_REFERENCED_VALUE_FILES as u64 + 1));
        assert!(matches!(
            count_distinct_sorted_ids(root, &extents),
            Err(PraxisError::Corrupt { .. })
        ));
        extents.pop();
        extents.swap(0, 2);
        assert!(matches!(
            count_distinct_sorted_ids(root, &extents),
            Err(PraxisError::Corrupt { .. })
        ));
    }

    #[test]
    fn physical_inventory_refuses_a_duplicate_opened_identity() {
        let root = Path::new("value-inventory-test");
        let first = SegmentPhysicalId {
            volume: 1,
            file: [1; 16],
        };
        let second = SegmentPhysicalId {
            volume: 1,
            file: [2; 16],
        };
        let mut identities = Vec::with_capacity(2);
        register_physical_identity(root, &mut identities, second).unwrap();
        register_physical_identity(root, &mut identities, first).unwrap();
        assert_eq!(identities, [first, second]);
        assert!(matches!(
            register_physical_identity(root, &mut identities, first),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(identities, [first, second]);
    }
}
