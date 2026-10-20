//! Private, discardable reads of writer-produced external catalog values.
//! This does not establish the complete external-file witness or admit an owner.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue, Field};
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole, physical_id,
};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::io::crc32c;
use crate::manifest::Manifest;
use crate::wal::catalog_witness::{PhysicalWitnessBudget, vector_charge};
use crate::wal::record::MAX_WAL_PAYLOAD_BYTES;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const HEAD_BYTES: u64 = 48;
const VALUE_HEADER_BYTES: u64 = 12;
const ANCHOR_BYTES: u64 = 72;
const NAME_BYTES: u64 = 12;
const NAMESPACE_BYTES: u64 = 16;
const SCHEMA_MAX_BYTES: usize = 33_947;
const SCHEMA_MAX_FIELDS: usize = 128;

/// Bounded inline bytes; no value-payload heap allocation is retained.
#[derive(Debug)]
pub(super) struct UnwitnessedCatalogBytes {
    bytes: [u8; SCHEMA_MAX_BYTES],
    len: usize,
}

/// A private record resolution result with no retained heap allocation.
/// The complete value-file witness and installed owner checks are separate.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum UnwitnessedRecordValue {
    Fixed {
        len: usize,
        bytes: [u8; 80],
    },
    Descriptor {
        encoded_len: u64,
        encoded_digest: blake3::Hash,
        name_len: u64,
        namespace_len: u64,
    },
    Payload {
        user_len: u64,
        digest: blake3::Hash,
    },
}

impl UnwitnessedCatalogBytes {
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The Schema codec reserves a temporary Vec<Field>. Its conservative debit
/// must remain live until the decoded value, including that Vec, is dropped.
struct SchemaDecodeCharge<'a> {
    budget: &'a mut PhysicalWitnessBudget,
    path: &'a Path,
    bytes: usize,
}

impl<'a> SchemaDecodeCharge<'a> {
    fn new(budget: &'a mut PhysicalWitnessBudget, path: &'a Path) -> Result<Self> {
        let maximum_capacity = SCHEMA_MAX_FIELDS
            .checked_mul(2)
            .ok_or_else(|| corrupt(path, "external catalog Schema decoder budget overflows"))?;
        let bytes = vector_charge::<Field<'static>>(path, maximum_capacity)?;
        budget.charge(path, bytes)?;
        Ok(Self {
            budget,
            path,
            bytes,
        })
    }
}

impl Drop for SchemaDecodeCharge<'_> {
    fn drop(&mut self) {
        // The exclusive mutable borrow prevents another debit from changing
        // this tally while armed. Never panic while unwinding.
        if self.budget.release(self.path, self.bytes).is_err() {
            std::process::abort();
        }
    }
}

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

/// Resolve one catalog pointer under its decoded key's exact value cap.
/// Returned bytes carry no physical file witness or installed owner authority.
pub(super) fn resolve_catalog_external_caps(
    root: &Path,
    manifest: &Manifest,
    row: &ObservedSegmentRow,
    budget: &mut PhysicalWitnessBudget,
    probe: &mut ValuePayloadProbe,
) -> Result<UnwitnessedCatalogBytes> {
    if row.classification != PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        || row.cf != CATALOG_CF
    {
        return Err(corrupt(
            root,
            "external catalog row is not protected catalog data",
        ));
    }
    let key = CatalogKey::decode(&row.key, root)?;
    let cap = match &key {
        CatalogKey::Head if row.sequence >= 1 => HEAD_BYTES,
        CatalogKey::Anchor if row.sequence == 1 => ANCHOR_BYTES,
        CatalogKey::Name(_) if row.sequence >= 2 => NAME_BYTES,
        CatalogKey::Namespace(_) if row.sequence >= 2 => NAMESPACE_BYTES,
        CatalogKey::Schema(_) if row.sequence >= 2 => SCHEMA_MAX_BYTES as u64,
        _ => {
            return Err(corrupt(
                root,
                "external catalog row has an invalid key sequence",
            ));
        }
    };
    let ObservedSegmentValue::Pointer {
        pointer,
        expires_at_ms: None,
    } = &row.value
    else {
        return Err(corrupt(
            root,
            "external catalog row is not a nonexpiring pointer",
        ));
    };
    if pointer.len == 0
        || pointer.len > cap
        || (cap != SCHEMA_MAX_BYTES as u64 && pointer.len != cap)
    {
        return Err(corrupt(
            root,
            "external catalog pointer exceeds its decoded key cap",
        ));
    }
    let len = usize::try_from(pointer.len)
        .map_err(|_| corrupt(root, "external catalog pointer length overflows"))?;
    let path = canonical_value_path(root, manifest, &pointer.path)?;
    check_real_value_path(&path)?;
    let extent_end = pointer
        .offset
        .checked_add(VALUE_HEADER_BYTES)
        .and_then(|offset| offset.checked_add(pointer.len))
        .ok_or_else(|| corrupt(&path, "external catalog value extent overflows"))?;

    probe.open_attempts += 1;
    let mut file = File::open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(corrupt(
            &path,
            "external catalog opened value is not a regular file",
        ));
    }
    let _opened_id = physical_id(&file, &path)?;
    if extent_end > opened.len() {
        return Err(corrupt(
            &path,
            "external catalog extent exceeds value-file length",
        ));
    }
    file.seek(SeekFrom::Start(pointer.offset))?;
    let mut header = [0_u8; VALUE_HEADER_BYTES as usize];
    probe.read_attempts += 1;
    file.read_exact(&mut header)?;
    let header_len = u64::from_le_bytes(header[..8].try_into().unwrap());
    let header_checksum = u32::from_le_bytes(header[8..].try_into().unwrap());
    if header_len != pointer.len || header_checksum != pointer.checksum {
        return Err(corrupt(
            &path,
            "external catalog header disagrees with pointer",
        ));
    }
    let mut resolved = UnwitnessedCatalogBytes {
        bytes: [0_u8; SCHEMA_MAX_BYTES],
        len,
    };
    probe.read_attempts += 1;
    file.read_exact(&mut resolved.bytes[..len])?;
    if crc32c(resolved.as_bytes()) != pointer.checksum {
        return Err(corrupt(&path, "external catalog payload checksum mismatch"));
    }

    if matches!(&key, CatalogKey::Schema(_)) {
        let charge = SchemaDecodeCharge::new(budget, &path)?;
        probe.reserve_attempts += 1;
        let schema = match CatalogValue::decode(&key, resolved.as_bytes(), &path)? {
            CatalogValue::Schema(schema) => schema,
            _ => {
                return Err(corrupt(
                    &path,
                    "external catalog Schema payload has the wrong value tag",
                ));
            }
        };
        if schema.fields.capacity() > SCHEMA_MAX_FIELDS * 2 {
            return Err(corrupt(
                &path,
                "external catalog Schema decoder exceeded reserved capacity",
            ));
        }
        drop(schema);
        drop(charge);
    } else if !matches!(
        (
            &key,
            CatalogValue::decode(&key, resolved.as_bytes(), &path)?
        ),
        (CatalogKey::Head, CatalogValue::Head(_))
            | (CatalogKey::Anchor, CatalogValue::Anchor(_))
            | (CatalogKey::Name(_), CatalogValue::Name(_))
            | (CatalogKey::Namespace(_), CatalogValue::Namespace(_))
    ) {
        return Err(corrupt(
            &path,
            "external catalog payload has the wrong value tag",
        ));
    }
    Ok(resolved)
}

/// Read a bounded part of a Descriptor while hashing exactly the encoded row.
fn read_descriptor_part(
    file: &mut File,
    path: &Path,
    remaining: &mut u64,
    out: &mut [u8],
    crc: &mut crc32fast::Hasher,
    digest: &mut blake3::Hasher,
    probe: &mut ValuePayloadProbe,
) -> Result<()> {
    let len = out.len() as u64;
    if len > *remaining {
        return Err(corrupt(
            path,
            "external record Descriptor field exceeds extent",
        ));
    }
    if len != 0 {
        probe.read_attempts += 1;
        file.read_exact(out)?;
        crc.update(out);
        digest.update(out);
        *remaining -= len;
    }
    Ok(())
}

/// Validate UTF-8 across chunk boundaries with at most three pending bytes.
fn stream_descriptor_text(
    file: &mut File,
    path: &Path,
    remaining: &mut u64,
    field_len: u64,
    crc: &mut crc32fast::Hasher,
    digest: &mut blake3::Hasher,
    probe: &mut ValuePayloadProbe,
) -> Result<()> {
    if field_len > *remaining {
        return Err(corrupt(
            path,
            "external record Descriptor text exceeds extent",
        ));
    }
    let mut scratch = [0_u8; 64 * 1024 + 3];
    let mut field_remaining = field_len;
    let mut pending = 0;
    while field_remaining != 0 {
        let chunk = field_remaining.min(64 * 1024) as usize;
        read_descriptor_part(
            file,
            path,
            remaining,
            &mut scratch[pending..pending + chunk],
            crc,
            digest,
            probe,
        )?;
        let end = pending + chunk;
        match std::str::from_utf8(&scratch[..end]) {
            Ok(_) => pending = 0,
            Err(error) if error.error_len().is_none() => {
                let start = error.valid_up_to();
                let tail = end - start;
                if tail == 0 || tail > 3 {
                    return Err(corrupt(
                        path,
                        "external record Descriptor text is invalid UTF-8",
                    ));
                }
                scratch.copy_within(start..end, 0);
                pending = tail;
            }
            Err(_) => {
                return Err(corrupt(
                    path,
                    "external record Descriptor text is invalid UTF-8",
                ));
            }
        }
        field_remaining -= chunk as u64;
    }
    if pending != 0 {
        return Err(corrupt(
            path,
            "external record Descriptor text is truncated UTF-8",
        ));
    }
    Ok(())
}

/// Parse exactly the PRD1 wire shape without retaining a variable-size Vec.
fn stream_record_descriptor(
    file: &mut File,
    path: &Path,
    encoded_len: u64,
    expected_crc: u32,
    probe: &mut ValuePayloadProbe,
) -> Result<(u64, u64, blake3::Hash)> {
    let mut remaining = encoded_len;
    let mut crc = crc32fast::Hasher::new();
    let mut digest = blake3::Hasher::new();
    let mut prefix = [0_u8; 20];
    read_descriptor_part(
        file,
        path,
        &mut remaining,
        &mut prefix,
        &mut crc,
        &mut digest,
        probe,
    )?;
    if &prefix[..4] != b"PRD1"
        || prefix[4..8] != [1, 0, 0, 0]
        || prefix[8..12] != [1, 1, 1, 0]
        || u64::from_le_bytes(prefix[12..20].try_into().unwrap()) != 1
    {
        return Err(corrupt(
            path,
            "external record Descriptor fixed fields are invalid",
        ));
    }
    let mut length = [0_u8; 4];
    read_descriptor_part(
        file,
        path,
        &mut remaining,
        &mut length,
        &mut crc,
        &mut digest,
        probe,
    )?;
    let name_len = u32::from_le_bytes(length) as u64;
    if name_len == 0 {
        return Err(corrupt(path, "external record Descriptor name is empty"));
    }
    stream_descriptor_text(
        file,
        path,
        &mut remaining,
        name_len,
        &mut crc,
        &mut digest,
        probe,
    )?;
    read_descriptor_part(
        file,
        path,
        &mut remaining,
        &mut length,
        &mut crc,
        &mut digest,
        probe,
    )?;
    let namespace_len = u32::from_le_bytes(length) as u64;
    stream_descriptor_text(
        file,
        path,
        &mut remaining,
        namespace_len,
        &mut crc,
        &mut digest,
        probe,
    )?;
    let mut config = [0_u8; 4];
    read_descriptor_part(
        file,
        path,
        &mut remaining,
        &mut config,
        &mut crc,
        &mut digest,
        probe,
    )?;
    if config != [0; 4] || remaining != 0 {
        return Err(corrupt(
            path,
            "external record Descriptor trailing bytes are invalid",
        ));
    }
    if crc.finalize() != expected_crc {
        return Err(corrupt(
            path,
            "external record Descriptor checksum mismatch",
        ));
    }
    Ok((name_len, namespace_len, digest.finalize()))
}

/// Resolve one protected record value under its decoded key's wire bound.
/// This private byte check does not witness the whole value file or admit an
/// installed owner. The returned result retains no heap allocation.
pub(super) fn resolve_record_external_caps(
    root: &Path,
    manifest: &Manifest,
    row: &ObservedSegmentRow,
    _budget: &mut PhysicalWitnessBudget,
    probe: &mut ValuePayloadProbe,
) -> Result<UnwitnessedRecordValue> {
    let role = RecordRole::from_cf(&row.cf)
        .ok_or_else(|| corrupt(root, "external record has no protected role"))?;
    let protected_role = match role {
        RecordRole::Meta => ProtectedRole::Meta,
        RecordRole::Payload => ProtectedRole::Payload,
        RecordRole::State => ProtectedRole::State,
        RecordRole::Index => ProtectedRole::Index,
    };
    if row.classification != PhysicalRowClass::BoundProtected(protected_role) {
        return Err(corrupt(root, "external record row is not protected"));
    }
    let key = RecordKey::decode(role, &row.key, root)?;
    let exact_len = match &key {
        RecordKey::Binding => Some(80),
        RecordKey::Allocator => Some(56),
        RecordKey::State(_) => Some(24),
        RecordKey::Fact { .. } => Some(32),
        RecordKey::Head { .. } => Some(40),
        RecordKey::Descriptor(_) | RecordKey::Payload(_) => None,
    };
    let ObservedSegmentValue::Pointer {
        pointer,
        expires_at_ms: None,
    } = &row.value
    else {
        return Err(corrupt(
            root,
            "external record is not a nonexpiring pointer",
        ));
    };
    if pointer.len == 0
        || pointer.len > MAX_WAL_PAYLOAD_BYTES as u64
        || exact_len.is_some_and(|expected| pointer.len != expected)
        || (matches!(&key, RecordKey::Descriptor(_)) && pointer.len < 32)
        || (matches!(&key, RecordKey::Payload(_)) && pointer.len < 12)
    {
        return Err(corrupt(
            root,
            "external record pointer exceeds decoded key bound",
        ));
    }
    let path = canonical_value_path(root, manifest, &pointer.path)?;
    check_real_value_path(&path)?;
    let extent_end = pointer
        .offset
        .checked_add(VALUE_HEADER_BYTES)
        .and_then(|offset| offset.checked_add(pointer.len))
        .ok_or_else(|| corrupt(&path, "external record extent overflows"))?;

    probe.open_attempts += 1;
    let mut file = File::open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(corrupt(
            &path,
            "external record opened value is not regular",
        ));
    }
    let _opened_id = physical_id(&file, &path)?;
    if extent_end > opened.len() {
        return Err(corrupt(
            &path,
            "external record extent exceeds value-file length",
        ));
    }
    file.seek(SeekFrom::Start(pointer.offset))?;
    let mut header = [0_u8; VALUE_HEADER_BYTES as usize];
    probe.read_attempts += 1;
    file.read_exact(&mut header)?;
    let header_len = u64::from_le_bytes(header[..8].try_into().unwrap());
    let header_crc = u32::from_le_bytes(header[8..].try_into().unwrap());
    if header_len != pointer.len || header_crc != pointer.checksum {
        return Err(corrupt(
            &path,
            "external record header disagrees with pointer",
        ));
    }

    match &key {
        RecordKey::Payload(_) => {
            let mut prefix = [0_u8; 12];
            probe.read_attempts += 1;
            file.read_exact(&mut prefix)?;
            if &prefix[..4] != b"PRP1" || prefix[4..8] != [1, 0, 0, 0] {
                return Err(corrupt(&path, "external record Payload header is invalid"));
            }
            let user_len = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as u64;
            if user_len != pointer.len - 12 {
                return Err(corrupt(&path, "external record Payload length disagrees"));
            }
            let mut crc = crc32fast::Hasher::new();
            crc.update(&prefix);
            let mut digest = blake3::Hasher::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut remaining = user_len;
            while remaining != 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                probe.read_attempts += 1;
                file.read_exact(&mut buffer[..chunk])?;
                crc.update(&buffer[..chunk]);
                digest.update(&buffer[..chunk]);
                remaining -= chunk as u64;
            }
            if crc.finalize() != pointer.checksum {
                return Err(corrupt(&path, "external record Payload checksum mismatch"));
            }
            Ok(UnwitnessedRecordValue::Payload {
                user_len,
                digest: digest.finalize(),
            })
        }
        RecordKey::Descriptor(_) => {
            let (name_len, namespace_len, encoded_digest) =
                stream_record_descriptor(&mut file, &path, pointer.len, pointer.checksum, probe)?;
            Ok(UnwitnessedRecordValue::Descriptor {
                encoded_len: pointer.len,
                encoded_digest,
                name_len,
                namespace_len,
            })
        }
        _ => {
            let len = exact_len.expect("fixed record key was selected") as usize;
            let mut bytes = [0_u8; 80];
            probe.read_attempts += 1;
            file.read_exact(&mut bytes[..len])?;
            if crc32c(&bytes[..len]) != pointer.checksum {
                return Err(corrupt(
                    &path,
                    "external record fixed-row checksum mismatch",
                ));
            }
            let _decoded = RecordRow::decode(&key, &bytes[..len], &path)?;
            Ok(UnwitnessedRecordValue::Fixed { len, bytes })
        }
    }
}
