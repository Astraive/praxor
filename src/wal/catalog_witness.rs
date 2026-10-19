//! Private, read-only candidate evidence for v4 WAL files.
//!
//! The visitor observes provisional records. It must only validate or stage
//! data: a later owner needs a writer fence and an exact witness recheck
//! before publishing replay state or making its first mutation.
use crate::errors::{PraxisError, Result};
use crate::io::crc32c;
use crate::wal::record::{
    CoreRecordPrefix, CoreWalRecord, MAX_CATALOG_WAL_FRAME_BYTES, MAX_WAL_PAYLOAD_BYTES,
    WAL_RECORD_HEADER_LEN, WAL_V2_MAGIC, parse_core_record_prefix,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const CHUNK: usize = 64 * 1024;
const FILE_MAGIC: u32 = 0x5457_4146;
const FILE_VERSION: u32 = 1;
const FILE_HEADER_LEN: u64 = 16;
const MAX_OBSERVED_WAL_FILES: usize = 4_096;
const PHYSICAL_WITNESS_METADATA_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PhysicalId {
    volume: u64,
    file: [u8; 16],
}

#[cfg(windows)]
fn physical_id(file: &File, path: &Path) -> Result<PhysicalId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    };
    let mut info = FILE_ID_INFO::default();
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut links = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut links) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if links.nNumberOfLinks != 1 {
        return Err(corrupt(path, "v4 WAL file has an external hardlink alias"));
    }
    Ok(PhysicalId {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}

#[cfg(unix)]
fn physical_id(file: &File, path: &Path) -> Result<PhysicalId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    if meta.nlink() != 1 {
        return Err(corrupt(path, "v4 WAL file has an external hardlink alias"));
    }
    let mut id = [0; 16];
    id[..8].copy_from_slice(&meta.ino().to_le_bytes());
    Ok(PhysicalId {
        volume: meta.dev(),
        file: id,
    })
}

#[cfg(not(any(unix, windows)))]
compile_error!("v4 WAL witnesses require opened-handle physical file identity");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalCut {
    pub(crate) flushed_sequence: u64,
    pub(crate) last_sequence: u64,
    pub(crate) flushed_wal_id: u64,
    pub(crate) active_wal_id: u64,
    pub(crate) next_wal_id: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct WalFileWitness {
    pub(crate) id: u64,
    pub(crate) path: PathBuf,
    cut: WalCut,
    identity: PhysicalId,
    pub(crate) full_len: u64,
    pub(crate) full_digest: blake3::Hash,
    pub(crate) prefix_len: u64,
    pub(crate) prefix_digest: blake3::Hash,
    pub(crate) torn_start: Option<u64>,
    pub(crate) first_sequence: Option<u64>,
    pub(crate) last_sequence: Option<u64>,
    pub(crate) record_count: u64,
    pub(crate) catalog_bootstraps: u64,
    pub(crate) catalog_creates: u64,
}

#[derive(Eq, PartialEq)]
struct ListedFile {
    id: u64,
    path: PathBuf,
    identity: PhysicalId,
}

struct Inventory {
    files: Vec<ListedFile>,
    // The listed vector and its retained paths remain live after the
    // temporary physical-ID set has been released.
    charged_bytes: usize,
}

/// Conservative remaining metadata admission for a future physical owner.
/// Frame decoding has its own independent bounded workspace.
#[derive(Debug)]
pub(crate) struct PhysicalWitnessBudget {
    limit: usize,
    used: usize,
}

impl PhysicalWitnessBudget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    #[allow(dead_code)] // Consumed by the later #75 segment/value inventory.
    pub(crate) fn remaining_bytes(&self) -> usize {
        self.limit - self.used
    }

    pub(crate) fn charge(&mut self, path: &Path, bytes: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= self.limit)
            .ok_or_else(|| budget_error(path))?;
        Ok(())
    }

    /// Release a temporary charge only after its backing allocation is dropped.
    pub(crate) fn release(&mut self, path: &Path, bytes: usize) -> Result<()> {
        self.used = budget_arithmetic(path, self.used.checked_sub(bytes))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReservationKind {
    Listed,
    Physical,
    Witness,
}

fn budget_error(path: &Path) -> PraxisError {
    corrupt(path, "v4 WAL physical witness metadata budget exceeded")
}

fn budget_arithmetic<T>(path: &Path, value: Option<T>) -> Result<T> {
    value.ok_or_else(|| budget_error(path))
}

pub(crate) fn path_charge(path: &Path) -> Result<usize> {
    // Windows native paths may use two bytes per encoded ASCII byte. Allow
    // additional capacity and allocator slack for every retained path and
    // cloned witness path, rather than charging only the logical filename.
    let encoded = path.as_os_str().as_encoded_bytes().len();
    budget_arithmetic(path, encoded.checked_mul(6).and_then(|n| n.checked_add(64)))
}

pub(crate) fn vector_charge<T>(path: &Path, capacity: usize) -> Result<usize> {
    if capacity == 0 {
        return Ok(0);
    }
    budget_arithmetic(
        path,
        capacity
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(64)),
    )
}

pub(crate) fn physical_set_charge<T>(path: &Path, capacity: usize) -> Result<usize> {
    if capacity == 0 {
        return Ok(0);
    }
    // HashSet::capacity counts usable elements, not all buckets. This
    // includes bucket/control overhead and a further twofold allowance.
    budget_arithmetic(
        path,
        capacity
            .checked_mul(std::mem::size_of::<T>() + 8)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(64)),
    )
}

fn next_capacity(path: &Path, current: usize) -> Result<usize> {
    let next = if current == 0 {
        4
    } else {
        budget_arithmetic(path, current.checked_mul(2))?
    };
    Ok(next.min(MAX_OBSERVED_WAL_FILES))
}

fn check_reservation(kind: ReservationKind, path: &Path) -> Result<()> {
    #[cfg(test)]
    if RESERVATION_FAILURE.with(|slot| {
        if slot.get() == Some(kind) {
            slot.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(corrupt(
            path,
            "v4 WAL physical witness budget reservation failed",
        ));
    }
    let _ = kind;
    let _ = path;
    Ok(())
}

pub(crate) fn reserve_vector<T>(
    vec: &mut Vec<T>,
    kind: ReservationKind,
    path: &Path,
    budget: &mut PhysicalWitnessBudget,
) -> Result<()> {
    if vec.len() < vec.capacity() {
        return Ok(());
    }
    let old_charge = vector_charge::<T>(path, vec.capacity())?;
    let target = next_capacity(path, vec.capacity())?;
    let prospective = budget_arithmetic(path, target.checked_mul(2))?;
    let reserved_charge = vector_charge::<T>(path, prospective)?;
    // During a reallocation, the old and new buffers may overlap in life.
    budget.charge(path, reserved_charge)?;
    check_reservation(kind, path)?;
    vec.try_reserve_exact(target - vec.len())
        .map_err(|_| corrupt(path, "v4 WAL physical witness budget reservation failed"))?;
    let actual_charge = vector_charge::<T>(path, vec.capacity())?;
    if actual_charge > reserved_charge {
        return Err(budget_error(path));
    }
    let refund = budget_arithmetic(
        path,
        old_charge
            .checked_add(reserved_charge)
            .and_then(|n| n.checked_sub(actual_charge)),
    )?;
    budget.release(path, refund)?;
    Ok(())
}

pub(crate) fn reserve_physical_set<T: Eq + std::hash::Hash>(
    set: &mut HashSet<T>,
    path: &Path,
    budget: &mut PhysicalWitnessBudget,
) -> Result<()> {
    if set.len() < set.capacity() {
        return Ok(());
    }
    let old_charge = physical_set_charge::<T>(path, set.capacity())?;
    let target = next_capacity(path, set.capacity())?;
    let prospective = budget_arithmetic(path, target.checked_mul(2))?;
    let reserved_charge = physical_set_charge::<T>(path, prospective)?;
    budget.charge(path, reserved_charge)?;
    check_reservation(ReservationKind::Physical, path)?;
    set.try_reserve(target - set.len())
        .map_err(|_| corrupt(path, "v4 WAL physical witness budget reservation failed"))?;
    let actual_charge = physical_set_charge::<T>(path, set.capacity())?;
    if actual_charge > reserved_charge {
        return Err(budget_error(path));
    }
    let refund = budget_arithmetic(
        path,
        old_charge
            .checked_add(reserved_charge)
            .and_then(|n| n.checked_sub(actual_charge)),
    )?;
    budget.release(path, refund)?;
    Ok(())
}

fn corrupt(path: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn check_real(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue; // The final ancestor of a relative root is empty.
        }
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(ancestor, "v4 WAL path crosses a symbolic link"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(ancestor, "v4 WAL path crosses a reparse point"));
            }
        }
    }
    Ok(())
}

fn parse_id(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "invalid v4 WAL name"))?;
    let digits = name
        .strip_suffix(".wal")
        .filter(|digits| digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| corrupt(path, "invalid v4 WAL name"))?;
    let id: u64 = digits
        .parse()
        .map_err(|_| corrupt(path, "v4 WAL id overflows u64"))?;
    if id == 0 {
        return Err(corrupt(path, "zero v4 WAL id"));
    }
    Ok(id)
}

fn inventory(root: &Path, cut: WalCut, budget: &mut PhysicalWitnessBudget) -> Result<Inventory> {
    if cut.flushed_sequence > cut.last_sequence
        || cut.active_wal_id == 0
        || cut.flushed_wal_id >= cut.active_wal_id
        || cut.active_wal_id >= cut.next_wal_id
    {
        return Err(corrupt(root, "invalid v4 WAL cut"));
    }
    let wal_dir = root.join("wal");
    check_real(&wal_dir)?;
    if !fs::metadata(&wal_dir)?.is_dir() {
        return Err(corrupt(&wal_dir, "v4 WAL namespace is not a directory"));
    }
    let mut listed = Vec::new();
    let mut physical = HashSet::new();
    let mut retained_path_bytes = 0usize;
    for entry in fs::read_dir(&wal_dir)? {
        if listed.len() == MAX_OBSERVED_WAL_FILES {
            return Err(corrupt(&wal_dir, "v4 WAL observed-file budget exceeded"));
        }
        let path = entry?.path();
        let id = parse_id(&path)?;
        if id > cut.active_wal_id {
            return Err(corrupt(&path, "v4 WAL exceeds active id"));
        }
        check_real(&path)?;
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err(corrupt(&path, "v4 WAL entry is not a regular file"));
        }
        // Opened-handle IDs are compact. This handle is closed before the
        // next entry, avoiding O(file count) operating-system handles.
        let file = File::open(&path)?;
        let identity = physical_id(&file, &path)?;
        let charged_path = path_charge(&path)?;
        if path.capacity() > charged_path {
            return Err(budget_error(&path));
        }
        budget.charge(&path, charged_path)?;
        retained_path_bytes =
            budget_arithmetic(&path, retained_path_bytes.checked_add(charged_path))?;
        reserve_vector(&mut listed, ReservationKind::Listed, &path, budget)?;
        reserve_physical_set(&mut physical, &path, budget)?;
        if !physical.insert(identity) {
            return Err(corrupt(&path, "v4 WAL files alias the same physical file"));
        }
        listed.push(ListedFile { id, path, identity });
    }
    listed.sort_unstable_by_key(|file| file.id);
    let mut previous = cut.flushed_wal_id;
    for item in &listed {
        if item.id > cut.flushed_wal_id {
            if previous.checked_add(1) != Some(item.id) {
                return Err(corrupt(&item.path, "missing required v4 WAL id"));
            }
            previous = item.id;
        }
    }
    if previous != cut.active_wal_id {
        return Err(corrupt(&wal_dir, "active v4 WAL is absent"));
    }
    let charged_bytes = budget_arithmetic(
        &wal_dir,
        retained_path_bytes.checked_add(vector_charge::<ListedFile>(&wal_dir, listed.capacity())?),
    )?;
    let physical_bytes = physical_set_charge::<PhysicalId>(&wal_dir, physical.capacity())?;
    drop(physical);
    budget.release(&wal_dir, physical_bytes)?;
    Ok(Inventory {
        files: listed,
        charged_bytes,
    })
}

fn hash_exact(file: &mut File, len: u64) -> Result<blake3::Hash> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = len;
    let mut buf = [0; CHUNK];
    let mut digest = blake3::Hasher::new();
    while remaining != 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        file.read_exact(&mut buf[..count])?;
        digest.update(&buf[..count]);
        remaining -= count as u64;
    }
    Ok(digest.finalize())
}

fn hash_full_and_prefix(
    file: &mut File,
    full_len: u64,
    prefix_len: u64,
) -> Result<(blake3::Hash, blake3::Hash)> {
    if prefix_len > full_len {
        return Err(PraxisError::InvalidConfig(
            "v4 WAL prefix exceeds file".into(),
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0;
    let mut buf = [0; CHUNK];
    let mut full = blake3::Hasher::new();
    let mut prefix = blake3::Hasher::new();
    while offset < full_len {
        let count = (full_len - offset).min(CHUNK as u64) as usize;
        file.read_exact(&mut buf[..count])?;
        full.update(&buf[..count]);
        let accepted = (prefix_len - prefix_len.min(offset)).min(count as u64) as usize;
        prefix.update(&buf[..accepted]);
        offset += count as u64;
    }
    Ok((full.finalize(), prefix.finalize()))
}

fn hash_remainder(file: &mut File, remaining: u64, digest: &mut blake3::Hasher) -> Result<()> {
    let mut left = remaining;
    let mut buf = [0; CHUNK];
    while left != 0 {
        let count = left.min(CHUNK as u64) as usize;
        file.read_exact(&mut buf[..count])?;
        digest.update(&buf[..count]);
        left -= count as u64;
    }
    Ok(())
}

fn scan_file(
    listed: &ListedFile,
    active: bool,
    cut: WalCut,
    witness_path: PathBuf,
    visit: &mut impl FnMut(u64, u64, u64, &CoreWalRecord) -> Result<()>,
) -> Result<WalFileWitness> {
    check_real(&listed.path)?;
    let mut file = File::open(&listed.path)?;
    if physical_id(&file, &listed.path)? != listed.identity {
        return Err(corrupt(&listed.path, "v4 WAL identity changed before scan"));
    }
    let len = file.metadata()?.len();
    if len < FILE_HEADER_LEN {
        return Err(corrupt(&listed.path, "short v4 WAL file header"));
    }
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    if u32::from_le_bytes(header[..4].try_into().unwrap()) != FILE_MAGIC
        || u32::from_le_bytes(header[4..8].try_into().unwrap()) != FILE_VERSION
        || u64::from_le_bytes(header[8..16].try_into().unwrap()) != listed.id
    {
        return Err(corrupt(&listed.path, "invalid v4 WAL file header or id"));
    }
    let mut full = blake3::Hasher::new();
    let mut prefix = blake3::Hasher::new();
    full.update(&header);
    prefix.update(&header);
    let mut offset = FILE_HEADER_LEN;
    let mut result = WalFileWitness {
        id: listed.id,
        path: witness_path,
        cut,
        identity: listed.identity,
        full_len: len,
        full_digest: blake3::hash(&[]),
        prefix_len: offset,
        prefix_digest: blake3::hash(&[]),
        torn_start: None,
        first_sequence: None,
        last_sequence: None,
        record_count: 0,
        catalog_bootstraps: 0,
        catalog_creates: 0,
    };
    while offset < len {
        let remaining = len - offset;
        if remaining < WAL_RECORD_HEADER_LEN as u64 {
            if !active {
                return Err(corrupt(&listed.path, "torn retired v4 WAL frame header"));
            }
            result.torn_start = Some(offset);
            hash_remainder(&mut file, remaining, &mut full)?;
            break;
        }
        let mut frame_header = [0; WAL_RECORD_HEADER_LEN];
        file.read_exact(&mut frame_header)?;
        if u32::from_le_bytes(frame_header[..4].try_into().unwrap()) != WAL_V2_MAGIC {
            return Err(corrupt(&listed.path, "v4 WAL requires v2 record frames"));
        }
        if crc32c(&frame_header[..12])
            != u32::from_le_bytes(frame_header[12..16].try_into().unwrap())
        {
            return Err(corrupt(&listed.path, "WAL header checksum mismatch"));
        }
        let payload_len = u32::from_le_bytes(frame_header[4..8].try_into().unwrap()) as usize;
        if !(12..=MAX_WAL_PAYLOAD_BYTES).contains(&payload_len) {
            return Err(corrupt(&listed.path, "invalid v2 WAL payload length"));
        }
        let frame_len = WAL_RECORD_HEADER_LEN + payload_len;
        if frame_len as u64 > remaining {
            if !active {
                return Err(corrupt(&listed.path, "torn retired v4 WAL frame body"));
            }
            result.torn_start = Some(offset);
            full.update(&frame_header);
            hash_remainder(
                &mut file,
                remaining - WAL_RECORD_HEADER_LEN as u64,
                &mut full,
            )?;
            break;
        }
        // The fixed 13-byte prefix reveals a tag-6/7 catalog frame without
        // allocating its claimed length. Full payload CRC still decides first.
        let mut first = [0; 13];
        let first_len = payload_len.min(first.len());
        file.read_exact(&mut first[..first_len])?;
        let catalog = first_len == 13
            && u32::from_le_bytes(first[8..12].try_into().unwrap()) != 0
            && matches!(first[12], 6 | 7);
        if catalog && frame_len > MAX_CATALOG_WAL_FRAME_BYTES {
            let mut crc = crc32fast::Hasher::new();
            crc.update(&first[..first_len]);
            let mut buf = [0; CHUNK];
            let mut left = payload_len - first_len;
            while left != 0 {
                let count = left.min(CHUNK);
                file.read_exact(&mut buf[..count])?;
                crc.update(&buf[..count]);
                left -= count;
            }
            if crc.finalize() != u32::from_le_bytes(frame_header[8..12].try_into().unwrap()) {
                return Err(corrupt(&listed.path, "WAL checksum mismatch"));
            }
            return Err(corrupt(
                &listed.path,
                "catalog WAL frame exceeds 1 MiB limit",
            ));
        }
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| corrupt(&listed.path, "cannot reserve bounded v4 WAL frame"))?;
        frame.extend_from_slice(&frame_header);
        frame.extend_from_slice(&first[..first_len]);
        frame.resize(frame_len, 0);
        file.read_exact(&mut frame[WAL_RECORD_HEADER_LEN + first_len..])?;
        let record = match parse_core_record_prefix(&frame, &listed.path)? {
            CoreRecordPrefix::Complete {
                record,
                encoded_len,
            } if encoded_len == frame_len => record,
            _ => return Err(corrupt(&listed.path, "invalid complete v4 WAL frame")),
        };
        let end = offset + frame_len as u64;
        full.update(&frame);
        prefix.update(&frame);
        result.record_count += 1;
        result.first_sequence.get_or_insert(record.sequence());
        result.last_sequence = Some(record.sequence());
        if let CoreWalRecord::Catalog { control, .. } = &record {
            match control {
                crate::core_catalog::CatalogControl::Bootstrap { .. } => {
                    result.catalog_bootstraps += 1;
                }
                crate::core_catalog::CatalogControl::Create { .. } => {
                    result.catalog_creates += 1;
                }
            }
        }
        visit(listed.id, offset, end, &record)?;
        offset = end;
        result.prefix_len = offset;
    }
    result.full_digest = full.finalize();
    result.prefix_digest = prefix.finalize();
    if file.metadata()?.len() != len || physical_id(&file, &listed.path)? != listed.identity {
        return Err(corrupt(&listed.path, "v4 WAL changed during scan"));
    }
    second_pass_hook();
    if hash_exact(&mut file, len)? != result.full_digest {
        return Err(corrupt(&listed.path, "v4 WAL changed during scan"));
    }
    check_real(&listed.path)?;
    let path_file = File::open(&listed.path)?;
    if physical_id(&path_file, &listed.path)? != listed.identity
        || path_file.metadata()?.len() != len
    {
        return Err(corrupt(&listed.path, "v4 WAL path changed during scan"));
    }
    Ok(result)
}

#[cfg(test)]
thread_local! {
    static SECOND_PASS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static RECHECK_FINAL_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static SCAN_BEFORE_FIRST_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static RESERVATION_FAILURE: std::cell::Cell<Option<ReservationKind>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn set_reservation_failure(kind: ReservationKind) {
    RESERVATION_FAILURE.with(|slot| slot.set(Some(kind)));
}

#[cfg(test)]
pub(super) fn set_second_pass_hook(hook: impl FnOnce() + 'static) {
    SECOND_PASS_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn set_recheck_final_open_hook(hook: impl FnOnce() + 'static) {
    RECHECK_FINAL_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn set_scan_before_first_open_hook(hook: impl FnOnce() + 'static) {
    SCAN_BEFORE_FIRST_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn second_pass_hook() {
    #[cfg(test)]
    SECOND_PASS_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn recheck_final_open_hook() {
    #[cfg(test)]
    RECHECK_FINAL_OPEN_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn scan_before_first_open_hook() {
    #[cfg(test)]
    SCAN_BEFORE_FIRST_OPEN_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

pub(crate) fn clone_witness_path(path: &Path) -> Result<PathBuf> {
    let mut copy = PathBuf::new();
    let native_capacity = budget_arithmetic(
        path,
        path.as_os_str().as_encoded_bytes().len().checked_mul(2),
    )?;
    copy.try_reserve_exact(native_capacity)
        .map_err(|_| corrupt(path, "v4 WAL physical witness budget reservation failed"))?;
    copy.push(path);
    if copy.capacity() > path_charge(path)? {
        return Err(budget_error(path));
    }
    Ok(copy)
}

fn precharge_witnesses(
    witnesses: &[WalFileWitness],
    root: &Path,
    budget: &mut PhysicalWitnessBudget,
) -> Result<()> {
    if witnesses.len() > MAX_OBSERVED_WAL_FILES {
        return Err(corrupt(root, "v4 WAL observed-file budget exceeded"));
    }
    // A slice does not expose its backing Vec capacity. Carry a twofold
    // allowance, matching the precharge made by the producing scanner.
    let prospective = budget_arithmetic(root, witnesses.len().checked_mul(2))?;
    budget.charge(root, vector_charge::<WalFileWitness>(root, prospective)?)?;
    for witness in witnesses {
        let conservative = path_charge(&witness.path)?;
        budget.charge(&witness.path, conservative.max(witness.path.capacity()))?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn charged_existing_witness_bytes_for_test(
    witnesses: &[WalFileWitness],
    root: &Path,
) -> Result<usize> {
    let mut budget = PhysicalWitnessBudget::new(PHYSICAL_WITNESS_METADATA_BYTES);
    precharge_witnesses(witnesses, root, &mut budget)?;
    Ok(PHYSICAL_WITNESS_METADATA_BYTES - budget.remaining_bytes())
}

fn inventory_matches_witnesses(
    root: &Path,
    cut: WalCut,
    listed: &[ListedFile],
    witnesses: &[WalFileWitness],
) -> Result<()> {
    if listed.len() != witnesses.len() {
        return Err(corrupt(&root.join("wal"), "v4 WAL inventory changed"));
    }
    for (item, expected) in listed.iter().zip(witnesses) {
        if item.id != expected.id
            || item.path != expected.path
            || item.identity != expected.identity
            || expected.cut != cut
        {
            return Err(corrupt(&item.path, "v4 WAL inventory identity changed"));
        }
    }
    Ok(())
}

fn scan_v4_wals_with_limit(
    root: &Path,
    cut: WalCut,
    limit: usize,
    mut visit: impl FnMut(u64, u64, u64, &CoreWalRecord) -> Result<()>,
) -> Result<(Vec<WalFileWitness>, PhysicalWitnessBudget)> {
    let mut budget = PhysicalWitnessBudget::new(limit);
    let listed = inventory(root, cut, &mut budget)?;
    let mut result = Vec::new();
    let mut prepared_paths = Vec::new();
    let mut prepared_charge = 0;
    if !listed.files.is_empty() {
        // Charge both the live listed inventory and all prospective witness
        // paths/vector before a single callback can observe a record.
        let prospective = budget_arithmetic(root, listed.files.len().checked_mul(2))?;
        budget.charge(root, vector_charge::<WalFileWitness>(root, prospective)?)?;
        for item in &listed.files {
            budget.charge(&item.path, path_charge(&item.path)?)?;
        }
        prepared_charge = vector_charge::<PathBuf>(root, prospective)?;
        budget.charge(root, prepared_charge)?;
        check_reservation(ReservationKind::Witness, root)?;
        result
            .try_reserve_exact(listed.files.len())
            .map_err(|_| corrupt(root, "v4 WAL physical witness budget reservation failed"))?;
        if result.capacity() > prospective {
            return Err(budget_error(root));
        }
        prepared_paths
            .try_reserve_exact(listed.files.len())
            .map_err(|_| corrupt(root, "v4 WAL physical witness budget reservation failed"))?;
        if prepared_paths.capacity() > prospective {
            return Err(budget_error(root));
        }
        for item in &listed.files {
            prepared_paths.push(clone_witness_path(&item.path)?);
        }
    }
    scan_before_first_open_hook();
    for (item, witness_path) in listed.files.iter().zip(prepared_paths) {
        result.push(scan_file(
            item,
            item.id == cut.active_wal_id,
            cut,
            witness_path,
            &mut visit,
        )?);
    }
    budget.release(root, prepared_charge)?;
    let initial_charge = listed.charged_bytes;
    drop(listed);
    budget.release(root, initial_charge)?;
    let final_inventory = inventory(root, cut, &mut budget)?;
    inventory_matches_witnesses(root, cut, &final_inventory.files, &result)?;
    let final_charge = final_inventory.charged_bytes;
    drop(final_inventory);
    budget.release(root, final_charge)?;
    Ok((result, budget))
}

pub(crate) fn scan_v4_wals_with_budget(
    root: &Path,
    cut: WalCut,
    visit: impl FnMut(u64, u64, u64, &CoreWalRecord) -> Result<()>,
) -> Result<(Vec<WalFileWitness>, PhysicalWitnessBudget)> {
    scan_v4_wals_with_limit(root, cut, PHYSICAL_WITNESS_METADATA_BYTES, visit)
}

pub(crate) fn scan_v4_wals(
    root: &Path,
    cut: WalCut,
    visit: impl FnMut(u64, u64, u64, &CoreWalRecord) -> Result<()>,
) -> Result<Vec<WalFileWitness>> {
    scan_v4_wals_with_budget(root, cut, visit).map(|(witnesses, _)| witnesses)
}

#[cfg(test)]
pub(super) fn scan_v4_wals_with_budget_limit(
    root: &Path,
    cut: WalCut,
    limit: usize,
    visit: impl FnMut(u64, u64, u64, &CoreWalRecord) -> Result<()>,
) -> Result<Vec<WalFileWitness>> {
    scan_v4_wals_with_limit(root, cut, limit, visit).map(|(witnesses, _)| witnesses)
}

/// Recheck evidence immediately before a future fenced owner may use it.
pub(crate) fn recheck_v4_wals(
    root: &Path,
    cut: WalCut,
    witnesses: &[WalFileWitness],
) -> Result<()> {
    let mut budget = PhysicalWitnessBudget::new(PHYSICAL_WITNESS_METADATA_BYTES);
    precharge_witnesses(witnesses, root, &mut budget)?;
    let listed = inventory(root, cut, &mut budget)?;
    inventory_matches_witnesses(root, cut, &listed.files, witnesses)?;
    for (item, expected) in listed.files.iter().zip(witnesses) {
        check_real(&item.path)?;
        let mut file = File::open(&item.path)?;
        if physical_id(&file, &item.path)? != expected.identity
            || file.metadata()?.len() != expected.full_len
        {
            return Err(corrupt(&item.path, "v4 WAL changed after scan"));
        }
        let (full, prefix) =
            hash_full_and_prefix(&mut file, expected.full_len, expected.prefix_len)?;
        if prefix != expected.prefix_digest
            || full != expected.full_digest
            || file.metadata()?.len() != expected.full_len
        {
            return Err(corrupt(&item.path, "v4 WAL changed after scan"));
        }
        recheck_final_open_hook();
        check_real(&item.path)?;
        let path_file = File::open(&item.path)?;
        if physical_id(&path_file, &item.path)? != expected.identity
            || path_file.metadata()?.len() != expected.full_len
        {
            return Err(corrupt(&item.path, "v4 WAL path changed after scan"));
        }
    }
    let initial_charge = listed.charged_bytes;
    drop(listed);
    budget.release(root, initial_charge)?;
    let final_inventory = inventory(root, cut, &mut budget)?;
    inventory_matches_witnesses(root, cut, &final_inventory.files, witnesses)?;
    Ok(())
}
