//! A private, discardable read of one writer-produced external catalog Head.
//! This does not establish the complete external-file witness or admit an owner.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue};
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole,
};
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::io::crc32c;
use crate::manifest::Manifest;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const HEAD_BYTES: u64 = 48;
const VALUE_HEADER_BYTES: u64 = 12;

/// Decoded Head bytes only; no external-file witness or owner authority is attached.
#[derive(Debug)]
pub(super) struct UnwitnessedHeadBytes([u8; HEAD_BYTES as usize]);

impl UnwitnessedHeadBytes {
    pub(super) fn as_bytes(&self) -> &[u8; HEAD_BYTES as usize] {
        &self.0
    }
}

#[derive(Default)]
pub(super) struct ValuePayloadProbe {
    pub(super) open_attempts: usize,
    pub(super) reserve_attempts: usize,
    pub(super) read_attempts: usize,
}

fn corrupt(path: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn canonical_value_path(root: &Path, manifest: &Manifest, path: &str) -> Result<PathBuf> {
    let claimed = Path::new(path);
    let file_name = claimed
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(claimed, "external catalog Head has no value-file name"))?;
    let digits = file_name.strip_suffix(".tval").ok_or_else(|| {
        corrupt(
            claimed,
            "external catalog Head has a noncanonical value-file name",
        )
    })?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(corrupt(
            claimed,
            "external catalog Head has a noncanonical value-file ID",
        ));
    }
    let id = digits
        .parse::<u64>()
        .map_err(|_| corrupt(claimed, "external catalog Head value-file ID overflows"))?;
    if id == 0 || id >= manifest.next_segment_id {
        return Err(corrupt(
            claimed,
            "external catalog Head value-file ID is unowned",
        ));
    }
    let canonical = DiskLayout::at(root).value_log_path(id);
    if canonical.to_str() != Some(path) {
        return Err(corrupt(
            claimed,
            "external catalog Head value-file path is not canonical",
        ));
    }
    Ok(canonical)
}

fn check_real_value_path(path: &Path) -> Result<()> {
    for (index, entry) in path.ancestors().enumerate() {
        if entry.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(entry)
            .map_err(|_| corrupt(entry, "external catalog Head path is not a stable entry"))?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(
                entry,
                "external catalog Head path crosses a symbolic link",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(
                    entry,
                    "external catalog Head path crosses a reparse point",
                ));
            }
        }
        if (index == 0 && !meta.is_file()) || (index != 0 && !meta.is_dir()) {
            return Err(corrupt(
                entry,
                "external catalog Head path is not a regular file under real directories",
            ));
        }
    }
    Ok(())
}

pub(super) fn resolve_catalog_head_external(
    root: &Path,
    manifest: &Manifest,
    row: &ObservedSegmentRow,
    probe: &mut ValuePayloadProbe,
) -> Result<UnwitnessedHeadBytes> {
    if row.classification != PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        || row.cf != CATALOG_CF
        || !matches!(CatalogKey::decode(&row.key, root)?, CatalogKey::Head)
    {
        return Err(corrupt(
            root,
            "external catalog Head row is not a protected Head",
        ));
    }
    let ObservedSegmentValue::Pointer {
        pointer,
        expires_at_ms: None,
    } = &row.value
    else {
        return Err(corrupt(
            root,
            "external catalog Head is not a nonexpiring pointer",
        ));
    };
    if pointer.len != HEAD_BYTES {
        return Err(corrupt(
            root,
            "external catalog Head pointer length is not 48 bytes",
        ));
    }
    let path = canonical_value_path(root, manifest, &pointer.path)?;
    check_real_value_path(&path)?;
    let extent_end = pointer
        .offset
        .checked_add(VALUE_HEADER_BYTES)
        .and_then(|offset| offset.checked_add(HEAD_BYTES))
        .ok_or_else(|| corrupt(&path, "external catalog Head extent overflows"))?;

    probe.open_attempts += 1;
    let mut file = File::open(&path)?;
    let file_len = file.metadata()?.len();
    if extent_end > file_len {
        return Err(corrupt(
            &path,
            "external catalog Head extent exceeds value-file length",
        ));
    }
    file.seek(SeekFrom::Start(pointer.offset))?;
    let mut header = [0_u8; VALUE_HEADER_BYTES as usize];
    probe.read_attempts += 1;
    file.read_exact(&mut header)?;
    let length = u64::from_le_bytes(header[..8].try_into().unwrap());
    let checksum = u32::from_le_bytes(header[8..].try_into().unwrap());
    if length != HEAD_BYTES || length != pointer.len || checksum != pointer.checksum {
        return Err(corrupt(
            &path,
            "external catalog Head header disagrees with pointer",
        ));
    }
    let mut bytes = [0_u8; HEAD_BYTES as usize];
    probe.read_attempts += 1;
    file.read_exact(&mut bytes)?;
    if crc32c(&bytes) != pointer.checksum {
        return Err(corrupt(
            &path,
            "external catalog Head payload checksum mismatch",
        ));
    }
    if !matches!(
        CatalogValue::decode(&CatalogKey::Head, &bytes, &path)?,
        CatalogValue::Head(_)
    ) {
        return Err(corrupt(
            &path,
            "external catalog Head payload has the wrong value tag",
        ));
    }
    Ok(UnwitnessedHeadBytes(bytes))
}
