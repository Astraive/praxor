//! Provisional, read-only evidence for every physical v4 segment row.
//!
//! No caller may turn these observations into an owner proof until the later
//! protected-copy, installed-relation, and WAL-history proofs are complete.

use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::types::ValuePointer;
use crate::wal::catalog_witness::{
    PhysicalWitnessBudget, clone_witness_path, path_charge, physical_set_charge, vector_charge,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::Hash;
use std::path::{Path, PathBuf};

const MAX_SEGMENT_FILES: usize = 4_096;
const MAX_SEGMENT_LEVELS: usize = 4_096;
const MAX_ROOT_ENCODED_BYTES: usize = 65_536;

/// This position is from the original, unsorted MANIFEST segment vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentSource {
    pub(crate) level: u32,
    pub(crate) id: u64,
    pub(crate) manifest_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedRole {
    Meta,
    Payload,
    State,
    Index,
    Catalog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalRowClass {
    BoundProtected(ProtectedRole),
    ReservedUnbound,
    Other,
}

/// This retains the wire tag, including unresolved pointer expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObservedSegmentValue {
    Put(Vec<u8>),
    Delete,
    Pointer {
        pointer: ValuePointer,
        expires_at_ms: Option<u64>,
    },
    PutWithExpiry {
        value: Vec<u8>,
        expires_at_ms: u64,
    },
    Merge(Vec<u8>),
}

/// All fields are owned; no borrowed bytes can outlive a file buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedSegmentRow {
    pub(crate) source: SegmentSource,
    pub(crate) block_offset: u64,
    /// Zero-based position within this block.
    pub(crate) row_ordinal: u32,
    pub(crate) classification: PhysicalRowClass,
    pub(crate) cf: String,
    pub(crate) key: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) value: ObservedSegmentValue,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SegmentPhysicalId {
    pub(crate) volume: u64,
    pub(crate) file: [u8; 16],
}

/// Witnesses are only candidates until a complete final namespace recheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentFileWitness {
    pub(crate) source: SegmentSource,
    pub(crate) path: PathBuf,
    pub(crate) identity: SegmentPhysicalId,
    pub(crate) len: u64,
    pub(crate) digest: blake3::Hash,
    pub(crate) observed_rows: u64,
}

#[allow(dead_code)] // The next cut consumes these admitted locators and witness slots.
struct SegmentLocator {
    source: SegmentSource,
    path: PathBuf,
    witness_path: Option<PathBuf>,
    identity: Option<SegmentPhysicalId>,
}

#[allow(dead_code)] // Kept charged until the visitor has finished or refused.
struct SegmentInventory {
    locators: Vec<SegmentLocator>,
    witnesses: Vec<SegmentFileWitness>,
    charged_bytes: usize,
}

fn corrupt(path: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn budget_error(path: &Path) -> PraxisError {
    corrupt(path, "v4 segment physical witness metadata budget exceeded")
}

fn checked_double(path: &Path, count: usize) -> Result<usize> {
    count.checked_mul(2).ok_or_else(|| budget_error(path))
}

fn debit(
    budget: &mut PhysicalWitnessBudget,
    charged: &mut usize,
    path: &Path,
    bytes: usize,
) -> Result<()> {
    let total = charged
        .checked_add(bytes)
        .ok_or_else(|| budget_error(path))?;
    budget.charge(path, bytes)?;
    *charged = total;
    Ok(())
}

fn refund(
    budget: &mut PhysicalWitnessBudget,
    charged: &mut usize,
    path: &Path,
    bytes: usize,
) -> Result<()> {
    let total = charged
        .checked_sub(bytes)
        .ok_or_else(|| budget_error(path))?;
    budget.release(path, bytes)?;
    *charged = total;
    Ok(())
}

fn reserved_vec<T>(
    count: usize,
    path: &Path,
    budget: &mut PhysicalWitnessBudget,
    charged: &mut usize,
) -> Result<(Vec<T>, usize)> {
    let allowance = vector_charge::<T>(path, checked_double(path, count)?)?;
    debit(budget, charged, path, allowance)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| corrupt(path, "v4 segment metadata budget reservation failed"))?;
    if vector_charge::<T>(path, values.capacity())? > allowance {
        return Err(budget_error(path));
    }
    Ok((values, allowance))
}

fn reserved_set<T: Eq + Hash>(
    count: usize,
    path: &Path,
    budget: &mut PhysicalWitnessBudget,
    charged: &mut usize,
) -> Result<(HashSet<T>, usize)> {
    let prospective = count
        .checked_mul(4)
        .map(|count| count.max(16))
        .ok_or_else(|| budget_error(path))?;
    let allowance = physical_set_charge::<T>(path, prospective)?;
    debit(budget, charged, path, allowance)?;
    let mut values = HashSet::new();
    values
        .try_reserve(count)
        .map_err(|_| corrupt(path, "v4 segment metadata budget reservation failed"))?;
    if physical_set_charge::<T>(path, values.capacity())? > allowance {
        return Err(budget_error(path));
    }
    Ok((values, allowance))
}

fn check_real(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(ancestor, "v4 segment path crosses a symbolic link"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(ancestor, "v4 segment path crosses a reparse point"));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn physical_id(file: &File, path: &Path) -> Result<SegmentPhysicalId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    };

    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut links = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut links) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if links.nNumberOfLinks != 1 {
        return Err(corrupt(path, "v4 segment has an external hardlink alias"));
    }
    Ok(SegmentPhysicalId {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}

#[cfg(unix)]
fn physical_id(file: &File, path: &Path) -> Result<SegmentPhysicalId> {
    use std::os::unix::fs::MetadataExt;

    let meta = file.metadata()?;
    if meta.nlink() != 1 {
        return Err(corrupt(path, "v4 segment has an external hardlink alias"));
    }
    let mut id = [0; 16];
    id[..8].copy_from_slice(&meta.ino().to_le_bytes());
    Ok(SegmentPhysicalId {
        volume: meta.dev(),
        file: id,
    })
}

#[cfg(not(any(unix, windows)))]
compile_error!("v4 segment witnesses require opened-handle physical identity");

fn parse_level(path: &Path) -> Result<u32> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "invalid v4 segment level name"))?;
    let level: u32 = name
        .parse()
        .map_err(|_| corrupt(path, "invalid v4 segment level name"))?;
    if level.to_string() != name {
        return Err(corrupt(path, "noncanonical v4 segment level name"));
    }
    Ok(level)
}

fn parse_segment_id(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "invalid v4 segment file name"))?;
    let digits = name
        .strip_suffix(".tseg")
        .filter(|digits| digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| corrupt(path, "invalid v4 segment file name"))?;
    let id: u64 = digits
        .parse()
        .map_err(|_| corrupt(path, "v4 segment id overflows u64"))?;
    if id == 0 {
        return Err(corrupt(path, "zero v4 segment id"));
    }
    Ok(id)
}

fn inventory(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
) -> Result<SegmentInventory> {
    if root.as_os_str().as_encoded_bytes().len() > MAX_ROOT_ENCODED_BYTES || root.to_str().is_none()
    {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 segment root path exceeds the private proof profile",
        });
    }
    if manifest.format_version != 4 {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 segment visitor requires a strict v4 manifest",
        });
    }
    manifest.validate_v4(&root.join("MANIFEST"))?;
    if manifest.segments.len() > MAX_SEGMENT_FILES {
        return Err(corrupt(root, "v4 segment listed-file limit exceeded"));
    }

    let mut charged = 0;
    let result = (|| -> Result<SegmentInventory> {
        let layout = DiskLayout::at(root);
        let segment_root = layout.segment_root();
        check_real(&segment_root)?;
        if !fs::symlink_metadata(&segment_root)?.is_dir() {
            return Err(corrupt(&segment_root, "v4 segment root is not a directory"));
        }

        let count = manifest.segments.len();
        let (mut locators, _) = reserved_vec::<SegmentLocator>(count, root, budget, &mut charged)?;
        let (mut global_ids, global_set_charge) =
            reserved_set::<u64>(count, root, budget, &mut charged)?;
        for (manifest_ordinal, meta) in manifest.segments.iter().enumerate() {
            if meta.id == 0 || !global_ids.insert(meta.id) {
                return Err(corrupt(root, "duplicate or zero v4 segment global id"));
            }
            let path = layout.segment_path(meta.level, meta.id);
            let encoded = path
                .to_str()
                .ok_or(PraxisError::UnsupportedCatalogFeature {
                    feature: "v4 segment path is not representable as UTF-8",
                })?;
            if meta.path != encoded {
                return Err(corrupt(&path, "noncanonical v4 segment MANIFEST path"));
            }
            let path_bytes = path_charge(&path)?;
            if path.capacity() > path_bytes {
                return Err(budget_error(&path));
            }
            debit(budget, &mut charged, &path, path_bytes)?;
            locators.push(SegmentLocator {
                source: SegmentSource {
                    level: meta.level,
                    id: meta.id,
                    manifest_ordinal,
                },
                path,
                witness_path: None,
                identity: None,
            });
        }
        locators.sort_unstable_by_key(|item| (item.source.level, item.source.id));
        drop(global_ids);
        refund(budget, &mut charged, root, global_set_charge)?;

        let (mut seen, seen_charge) = reserved_vec::<u8>(count, root, budget, &mut charged)?;
        seen.resize(count, 0);
        let (mut physical_ids, physical_set_charge) =
            reserved_set::<SegmentPhysicalId>(count, root, budget, &mut charged)?;
        let mut observed = 0;
        for (levels, level_entry) in fs::read_dir(&segment_root)?.enumerate() {
            if levels == MAX_SEGMENT_LEVELS {
                return Err(corrupt(
                    &segment_root,
                    "v4 segment level-entry limit exceeded",
                ));
            }
            let level_path = level_entry?.path();
            check_real(&level_path)?;
            if !fs::symlink_metadata(&level_path)?.is_dir() {
                return Err(corrupt(
                    &level_path,
                    "v4 segment level entry is not a directory",
                ));
            }
            let level = parse_level(&level_path)?;
            for file_entry in fs::read_dir(&level_path)? {
                if observed == MAX_SEGMENT_FILES {
                    return Err(corrupt(
                        &level_path,
                        "v4 segment observed-file limit exceeded",
                    ));
                }
                observed += 1;
                let path = file_entry?.path();
                check_real(&path)?;
                if !fs::symlink_metadata(&path)?.is_file() {
                    return Err(corrupt(&path, "v4 segment entry is not a regular file"));
                }
                let id = parse_segment_id(&path)?;
                let position = locators
                    .binary_search_by_key(&(level, id), |item| (item.source.level, item.source.id))
                    .map_err(|_| corrupt(&path, "unlisted v4 segment file"))?;
                if path != locators[position].path || seen[position] != 0 {
                    return Err(corrupt(&path, "v4 segment path is aliased or repeated"));
                }
                let file = File::open(&path)?;
                if !file.metadata()?.is_file() {
                    return Err(corrupt(&path, "v4 segment opened entry is not a file"));
                }
                let identity = physical_id(&file, &path)?;
                check_real(&path)?;
                let reopened = File::open(&path)?;
                if physical_id(&reopened, &path)? != identity {
                    return Err(corrupt(
                        &path,
                        "v4 segment identity changed during inventory",
                    ));
                }
                if !physical_ids.insert(identity) {
                    return Err(corrupt(&path, "v4 segment files alias one physical file"));
                }
                locators[position].identity = Some(identity);
                seen[position] = 1;
            }
        }
        if observed != count || seen.contains(&0) {
            return Err(corrupt(&segment_root, "listed v4 segment file is missing"));
        }

        drop(physical_ids);
        refund(budget, &mut charged, root, physical_set_charge)?;
        drop(seen);
        refund(budget, &mut charged, root, seen_charge)?;

        let (witnesses, _) = reserved_vec::<SegmentFileWitness>(count, root, budget, &mut charged)?;
        for locator in &mut locators {
            let path_bytes = path_charge(&locator.path)?;
            debit(budget, &mut charged, &locator.path, path_bytes)?;
            locator.witness_path = Some(clone_witness_path(&locator.path)?);
        }
        Ok(SegmentInventory {
            locators,
            witnesses,
            charged_bytes: charged,
        })
    })();
    if result.is_err() {
        // All allocations owned by the failed closure have been dropped.
        budget.release(root, charged)?;
    }
    result
}

pub(crate) fn visit_v4_segments(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    _visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<Vec<SegmentFileWitness>> {
    let admitted = inventory(root, manifest, budget)?;
    let charged = admitted.charged_bytes;
    drop(admitted);
    budget.release(root, charged)?;
    Err(PraxisError::UnsupportedCatalogFeature {
        feature: "bounded v4 physical segment visitor is not yet admitted",
    })
}
