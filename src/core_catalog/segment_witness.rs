//! Provisional, read-only evidence for every physical v4 segment row.
//!
//! No caller may turn these observations into an owner proof until the later
//! protected-copy, installed-relation, and WAL-history proofs are complete.

use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, crc32c};
use crate::manifest::{Manifest, SegmentMetadata};
use crate::segments::BloomFilter;
use crate::segments::format::{SEGMENT_FOOTER_MAGIC, SEGMENT_MAGIC, SEGMENT_VERSION};
use crate::types::ValuePointer;
use crate::wal::catalog_witness::{
    PhysicalWitnessBudget, clone_witness_path, path_charge, physical_set_charge, vector_charge,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::Hash;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_SEGMENT_FILES: usize = 4_096;
const MAX_SEGMENT_LEVELS: usize = 4_096;
const MAX_ROOT_ENCODED_BYTES: usize = 65_536;
const MAX_LITERAL_SEGMENT_BYTES: usize = 1_048_576;
const MAX_LITERAL_ROWS: usize = MAX_LITERAL_SEGMENT_BYTES / 17;
const SEGMENT_HEADER_BYTES: usize = 21;
const SEGMENT_TRAILER_BYTES: usize = 12;
const BLOCK_HEADER_BYTES: usize = 12;
const HASH_CHUNK_BYTES: usize = 64 * 1024;

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

struct SegmentLocator {
    source: SegmentSource,
    path: PathBuf,
    witness_path: Option<PathBuf>,
    identity: Option<SegmentPhysicalId>,
    rechecked: bool,
}

struct SegmentInventory {
    locators: Vec<SegmentLocator>,
    witnesses: Vec<SegmentFileWitness>,
    charged_bytes: usize,
    retained_witness_bytes: usize,
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
                rechecked: false,
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

        let (witnesses, witness_charge) =
            reserved_vec::<SegmentFileWitness>(count, root, budget, &mut charged)?;
        let mut retained_witness_bytes = witness_charge;
        for locator in &mut locators {
            let path_bytes = path_charge(&locator.path)?;
            retained_witness_bytes = retained_witness_bytes
                .checked_add(path_bytes)
                .ok_or_else(|| budget_error(&locator.path))?;
            debit(budget, &mut charged, &locator.path, path_bytes)?;
            locator.witness_path = Some(clone_witness_path(&locator.path)?);
        }
        Ok(SegmentInventory {
            locators,
            witnesses,
            charged_bytes: charged,
            retained_witness_bytes,
        })
    })();
    if result.is_err() {
        // All allocations owned by the failed closure have been dropped.
        budget.release(root, charged)?;
    }
    result
}

#[derive(Clone, Copy)]
enum BorrowedValue<'a> {
    Put(&'a [u8]),
    Delete,
    Pointer {
        path: &'a str,
        offset: u64,
        len: u64,
        checksum: u32,
        expires_at_ms: Option<u64>,
    },
    PutWithExpiry {
        value: &'a [u8],
        expires_at_ms: u64,
    },
    Merge(&'a [u8]),
}

#[derive(Clone, Copy)]
struct BorrowedRow<'a> {
    cf: &'a str,
    key: &'a [u8],
    sequence: u64,
    value: BorrowedValue<'a>,
}

fn borrowed_row<'a>(reader: &mut BinaryReader<'a>, path: &Path) -> Result<BorrowedRow<'a>> {
    let cf = std::str::from_utf8(reader.read_len_slice()?)
        .map_err(|_| corrupt(path, "invalid v4 segment family UTF-8"))?;
    let key = reader.read_len_slice()?;
    let sequence = reader.read_u64()?;
    let value = match reader.read_u8()? {
        1 => BorrowedValue::Put(reader.read_len_slice()?),
        2 => BorrowedValue::Delete,
        tag @ (3 | 4) => {
            let expires_at_ms = if tag == 4 {
                Some(reader.read_u64()?)
            } else {
                None
            };
            let pointer_path = std::str::from_utf8(reader.read_len_slice()?)
                .map_err(|_| corrupt(path, "invalid v4 segment pointer UTF-8"))?;
            BorrowedValue::Pointer {
                path: pointer_path,
                offset: reader.read_u64()?,
                len: reader.read_u64()?,
                checksum: reader.read_u32()?,
                expires_at_ms,
            }
        }
        5 => BorrowedValue::PutWithExpiry {
            expires_at_ms: reader.read_u64()?,
            value: reader.read_len_slice()?,
        },
        6 => BorrowedValue::Merge(reader.read_len_slice()?),
        _ => return Err(corrupt(path, "unknown v4 segment value tag")),
    };
    Ok(BorrowedRow {
        cf,
        key,
        sequence,
        value,
    })
}

fn owned_bytes(bytes: &[u8], path: &Path) -> Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| corrupt(path, "v4 segment owned row allocation failed"))?;
    if owned.capacity() > MAX_LITERAL_SEGMENT_BYTES * 2 + 64 {
        return Err(corrupt(path, "v4 segment owned row allocation exceeds cap"));
    }
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn owned_string(value: &str, path: &Path) -> Result<String> {
    String::from_utf8(owned_bytes(value.as_bytes(), path)?)
        .map_err(|_| corrupt(path, "invalid v4 segment owned string"))
}

fn classify(cf: &str) -> PhysicalRowClass {
    let role = match cf {
        "__praxor_record_meta_v1" => Some(ProtectedRole::Meta),
        "__praxor_record_payload_v1" => Some(ProtectedRole::Payload),
        "__praxor_record_state_v1" => Some(ProtectedRole::State),
        "__praxor_record_index_v1" => Some(ProtectedRole::Index),
        "__praxor_record_catalog_v1" => Some(ProtectedRole::Catalog),
        _ => None,
    };
    if let Some(role) = role {
        PhysicalRowClass::BoundProtected(role)
    } else if cf.starts_with("__praxor_record_") {
        PhysicalRowClass::ReservedUnbound
    } else {
        PhysicalRowClass::Other
    }
}

fn owned_row(
    row: BorrowedRow<'_>,
    source: SegmentSource,
    block_offset: u64,
    row_ordinal: u32,
    path: &Path,
) -> Result<ObservedSegmentRow> {
    let value = match row.value {
        BorrowedValue::Put(value) => ObservedSegmentValue::Put(owned_bytes(value, path)?),
        BorrowedValue::Delete => ObservedSegmentValue::Delete,
        BorrowedValue::Pointer {
            path: pointer_path,
            offset,
            len,
            checksum,
            expires_at_ms,
        } => ObservedSegmentValue::Pointer {
            pointer: ValuePointer {
                path: owned_string(pointer_path, path)?,
                offset,
                len,
                checksum,
            },
            expires_at_ms,
        },
        BorrowedValue::PutWithExpiry {
            value,
            expires_at_ms,
        } => ObservedSegmentValue::PutWithExpiry {
            value: owned_bytes(value, path)?,
            expires_at_ms,
        },
        BorrowedValue::Merge(value) => ObservedSegmentValue::Merge(owned_bytes(value, path)?),
    };
    Ok(ObservedSegmentRow {
        source,
        block_offset,
        row_ordinal,
        classification: classify(row.cf),
        cf: owned_string(row.cf, path)?,
        key: owned_bytes(row.key, path)?,
        sequence: row.sequence,
        value,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct WalkFacts<'a> {
    rows: usize,
    first_key: Option<&'a [u8]>,
    last_key: Option<&'a [u8]>,
}

fn walk_literal<'a>(
    bytes: &'a [u8],
    path: &Path,
    mut visit: impl FnMut(u64, u32, BorrowedRow<'a>) -> Result<()>,
) -> Result<WalkFacts<'a>> {
    if bytes.len() < SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES {
        return Err(corrupt(path, "short v4 segment"));
    }
    let trailer_start = bytes.len() - SEGMENT_TRAILER_BYTES;
    let mut trailer = BinaryReader::new(&bytes[trailer_start..], path);
    let footer_len = trailer.read_u32()? as usize;
    let footer_checksum = trailer.read_u32()?;
    if trailer.read_u32()? != SEGMENT_FOOTER_MAGIC {
        return Err(corrupt(path, "bad v4 segment footer magic"));
    }
    let footer_start = trailer_start
        .checked_sub(footer_len)
        .filter(|start| *start >= SEGMENT_HEADER_BYTES)
        .ok_or_else(|| corrupt(path, "v4 segment footer out of bounds"))?;
    let footer_bytes = &bytes[footer_start..trailer_start];
    if crc32c(footer_bytes) != footer_checksum {
        return Err(corrupt(path, "v4 segment footer checksum mismatch"));
    }
    let mut footer = BinaryReader::new(footer_bytes, path);
    let block_count = footer.read_u32()? as usize;
    if block_count > footer.remaining() / 24 {
        return Err(corrupt(path, "v4 segment block count exceeds footer"));
    }
    let mut previous_end = SEGMENT_HEADER_BYTES;
    let mut previous_row: Option<(&str, &[u8])> = None;
    let mut facts = WalkFacts {
        rows: 0,
        first_key: None,
        last_key: None,
    };
    for _ in 0..block_count {
        let first_key = footer.read_len_slice()?;
        let last_key = footer.read_len_slice()?;
        let offset = usize::try_from(footer.read_u64()?)
            .map_err(|_| corrupt(path, "v4 segment block offset overflows platform"))?;
        let len = usize::try_from(footer.read_u64()?)
            .map_err(|_| corrupt(path, "v4 segment block length overflows platform"))?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| corrupt(path, "v4 segment block offset overflow"))?;
        if offset != previous_end || end > footer_start || len < BLOCK_HEADER_BYTES {
            return Err(corrupt(path, "v4 segment block is not contiguous"));
        }
        let mut block = BinaryReader::new(&bytes[offset..end], path);
        let encoded_len = block.read_u32()? as usize;
        let decoded_len = block.read_u32()? as usize;
        let checksum = block.read_u32()?;
        let payload = block.read_slice(encoded_len)?;
        if block.remaining() != 0 || encoded_len != decoded_len || crc32c(payload) != checksum {
            return Err(corrupt(
                path,
                "v4 literal segment block length or checksum mismatch",
            ));
        }
        let mut rows = BinaryReader::new(payload, path);
        let row_count = rows.read_u32()? as usize;
        if row_count == 0 || row_count > rows.remaining() / 17 {
            return Err(corrupt(path, "v4 segment row count exceeds block"));
        }
        let mut block_first: Option<&[u8]> = None;
        let mut block_last: Option<&[u8]> = None;
        for row_index in 0..row_count {
            let row = borrowed_row(&mut rows, path)?;
            if let Some((cf, key)) = previous_row
                && (row.cf.as_bytes(), row.key) < (cf.as_bytes(), key)
            {
                return Err(corrupt(path, "v4 segment rows are out of writer order"));
            }
            previous_row = Some((row.cf, row.key));
            block_first.get_or_insert(row.key);
            block_last = Some(row.key);
            facts.first_key.get_or_insert(row.key);
            facts.last_key = Some(row.key);
            facts.rows = facts
                .rows
                .checked_add(1)
                .filter(|count| *count <= MAX_LITERAL_ROWS)
                .ok_or_else(|| corrupt(path, "v4 literal segment row limit exceeded"))?;
            let row_ordinal = u32::try_from(row_index)
                .map_err(|_| corrupt(path, "v4 segment row ordinal overflow"))?;
            visit(offset as u64, row_ordinal, row)?;
        }
        if rows.remaining() != 0 || block_first != Some(first_key) || block_last != Some(last_key) {
            return Err(corrupt(
                path,
                "v4 segment block key range or framing mismatch",
            ));
        }
        previous_end = end;
    }
    if footer.remaining() != 0 || previous_end != footer_start {
        return Err(corrupt(path, "unconsumed v4 segment framing bytes"));
    }
    Ok(facts)
}

fn unsupported(feature: &'static str) -> PraxisError {
    PraxisError::UnsupportedCatalogFeature { feature }
}

fn hash_exact(file: &mut File, expected_len: u64, path: &Path) -> Result<blake3::Hash> {
    let mut remaining = expected_len;
    let mut buffer = [0_u8; HASH_CHUNK_BYTES];
    let mut hasher = blake3::Hasher::new();
    while remaining != 0 {
        let amount = remaining.min(HASH_CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..amount])
            .map_err(|_| corrupt(path, "v4 segment truncated during recheck"))?;
        hasher.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 || file.metadata()?.len() != expected_len {
        return Err(corrupt(path, "v4 segment length changed during recheck"));
    }
    Ok(hasher.finalize())
}

fn capture_literal(file: &mut File, path: &Path) -> Result<(Vec<u8>, u64)> {
    let len = file.metadata()?.len();
    if len > MAX_LITERAL_SEGMENT_BYTES as u64 {
        return Err(unsupported(
            "v4 segment exceeds the 1 MiB literal proof profile",
        ));
    }
    let count = usize::try_from(len)
        .map_err(|_| corrupt(path, "v4 segment length exceeds platform range"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count)
        .map_err(|_| corrupt(path, "v4 segment capture allocation failed"))?;
    if bytes.capacity() > MAX_LITERAL_SEGMENT_BYTES * 2 + 64 {
        return Err(unsupported(
            "v4 segment capture allocation exceeds proof profile",
        ));
    }
    bytes.resize(count, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| corrupt(path, "v4 segment truncated during capture"))?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 || file.metadata()?.len() != len {
        return Err(corrupt(path, "v4 segment length changed during capture"));
    }
    Ok((bytes, len))
}

struct ScannedSegment {
    len: u64,
    digest: blake3::Hash,
    observed_rows: u64,
}

fn scan_literal_segment(
    locator: &SegmentLocator,
    meta: &SegmentMetadata,
    visit: &mut impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<ScannedSegment> {
    let path = &locator.path;
    let expected_identity = locator
        .identity
        .ok_or_else(|| corrupt(path, "v4 segment lacks admitted physical identity"))?;
    check_real(path)?;
    let mut file = File::open(path)?;
    if physical_id(&file, path)? != expected_identity {
        return Err(corrupt(path, "v4 segment identity changed before capture"));
    }
    let (bytes, len) = capture_literal(&mut file, path)?;
    drop(file);
    let digest = blake3::hash(&bytes);
    if digest.to_hex().as_str() != meta.file_digest.as_str() {
        return Err(corrupt(path, "v4 segment full-file digest mismatch"));
    }
    if bytes.len() < SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES {
        return Err(corrupt(path, "short v4 segment header"));
    }
    let mut header = BinaryReader::new(&bytes, path);
    if header.read_u32()? != SEGMENT_MAGIC || header.read_u32()? != SEGMENT_VERSION {
        return Err(corrupt(path, "bad v4 segment magic or version"));
    }
    let compression = header.read_u8()?;
    if header.read_u32()? != locator.source.level || header.read_u64()? != locator.source.id {
        return Err(corrupt(path, "v4 segment header level or id mismatch"));
    }
    match compression {
        0 => {}
        1 | 2 => {
            return Err(unsupported(
                "compressed v4 segments need a bounded proof profile",
            ));
        }
        _ => return Err(corrupt(path, "unknown v4 segment compression tag")),
    }
    if meta.partitioned_bloom_filter.is_some() {
        return Err(unsupported(
            "partitioned v4 segment Bloom is not yet proven",
        ));
    }

    let first = walk_literal(&bytes, path, |_, _, _| Ok(()))?;
    if u64::try_from(first.rows).ok() != Some(meta.entries)
        || first.first_key.unwrap_or_default() != meta.min_key.as_slice()
        || first.last_key.unwrap_or_default() != meta.max_key.as_slice()
    {
        return Err(corrupt(
            path,
            "v4 segment observed count or key range mismatch",
        ));
    }
    let mut bloom = BloomFilter::try_with_observed_items(first.rows, MAX_LITERAL_ROWS)
        .map_err(|_| corrupt(path, "v4 segment observed Bloom allocation failed"))?;
    let mut scratch = Vec::new();
    let second = walk_literal(&bytes, path, |_, _, row| {
        bloom
            .try_insert_parts(row.cf, row.key, &mut scratch, MAX_LITERAL_SEGMENT_BYTES)
            .map_err(|_| corrupt(path, "v4 segment observed Bloom scratch exceeds cap"))
    })?;
    if second != first || bloom != meta.bloom_filter {
        return Err(corrupt(path, "v4 segment Bloom or semantic pass mismatch"));
    }

    check_real(path)?;
    let mut reopened = File::open(path)?;
    if physical_id(&reopened, path)? != expected_identity
        || hash_exact(&mut reopened, len, path)? != digest
    {
        return Err(corrupt(path, "v4 segment changed before callbacks"));
    }
    drop(reopened);
    let third = walk_literal(&bytes, path, |block_offset, row_ordinal, row| {
        visit(owned_row(
            row,
            locator.source,
            block_offset,
            row_ordinal,
            path,
        )?)
    })?;
    if third != first {
        return Err(corrupt(path, "v4 segment changed between semantic passes"));
    }
    Ok(ScannedSegment {
        len,
        digest,
        observed_rows: first.rows as u64,
    })
}

fn recheck_namespace(root: &Path, admitted: &mut SegmentInventory) -> Result<()> {
    let segment_root = DiskLayout::at(root).segment_root();
    check_real(&segment_root)?;
    if !fs::symlink_metadata(&segment_root)?.is_dir() {
        return Err(corrupt(
            &segment_root,
            "v4 segment root changed before final recheck",
        ));
    }
    for locator in &mut admitted.locators {
        locator.rechecked = false;
    }
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
                "v4 segment level changed before final recheck",
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
                return Err(corrupt(
                    &path,
                    "v4 segment file changed kind before recheck",
                ));
            }
            let id = parse_segment_id(&path)?;
            let position = admitted
                .locators
                .binary_search_by_key(&(level, id), |item| (item.source.level, item.source.id))
                .map_err(|_| corrupt(&path, "unlisted v4 segment during final recheck"))?;
            let locator = &mut admitted.locators[position];
            let witness = &admitted.witnesses[position];
            if locator.rechecked || path != locator.path || witness.source != locator.source {
                return Err(corrupt(
                    &path,
                    "v4 segment identity changed before final recheck",
                ));
            }
            let mut file = File::open(&path)?;
            if Some(physical_id(&file, &path)?) != locator.identity
                || hash_exact(&mut file, witness.len, &path)? != witness.digest
            {
                return Err(corrupt(&path, "v4 segment bytes or identity changed"));
            }
            check_real(&path)?;
            let reopened = File::open(&path)?;
            if Some(physical_id(&reopened, &path)?) != locator.identity {
                return Err(corrupt(
                    &path,
                    "v4 segment path changed during final recheck",
                ));
            }
            locator.rechecked = true;
        }
    }
    if observed != admitted.locators.len() || admitted.locators.iter().any(|item| !item.rechecked) {
        return Err(corrupt(
            &segment_root,
            "v4 segment disappeared before final recheck",
        ));
    }
    Ok(())
}

pub(crate) fn visit_v4_segments(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    mut visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<Vec<SegmentFileWitness>> {
    let mut admitted = inventory(root, manifest, budget)?;
    let result = (|| -> Result<()> {
        let (locators, witnesses) = (&mut admitted.locators, &mut admitted.witnesses);
        for locator in locators {
            let meta = &manifest.segments[locator.source.manifest_ordinal];
            let scanned = scan_literal_segment(locator, meta, &mut visit)?;
            if witnesses.len() == witnesses.capacity() {
                return Err(budget_error(&locator.path));
            }
            let path = locator.witness_path.take().ok_or_else(|| {
                corrupt(&locator.path, "v4 segment witness path was not precharged")
            })?;
            witnesses.push(SegmentFileWitness {
                source: locator.source,
                path,
                identity: locator.identity.ok_or_else(|| {
                    corrupt(&locator.path, "v4 segment witness has no physical identity")
                })?,
                len: scanned.len,
                digest: scanned.digest,
                observed_rows: scanned.observed_rows,
            });
        }
        recheck_namespace(root, &mut admitted)
    })();
    let charged = admitted.charged_bytes;
    match result {
        Ok(()) => {
            let retained = admitted.retained_witness_bytes;
            let temporary = match charged.checked_sub(retained) {
                Some(temporary) => temporary,
                None => {
                    drop(admitted);
                    budget.release(root, charged)?;
                    return Err(budget_error(root));
                }
            };
            let witnesses = std::mem::take(&mut admitted.witnesses);
            drop(admitted);
            budget.release(root, temporary)?;
            Ok(witnesses)
        }
        Err(error) => {
            drop(admitted);
            budget.release(root, charged)?;
            Err(error)
        }
    }
}
