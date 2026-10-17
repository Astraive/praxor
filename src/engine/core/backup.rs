//! A captured authority is copied by file role, never by following stored paths.
use crate::accel::Accelerator;
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::io::{create_dir_all_durable, sync_parent_dir, write_file_with_policy};
use crate::manifest::{Manifest, ManifestStore};
use crate::recovery::write_checkpoint_with_policy;
use crate::segments::codec::decode_segment;
use crate::types::{StoredValue, ValuePointer};
use crate::wal::Wal;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

pub(super) const INCOMPLETE: &str = crate::storage::root_format::CORE_COPY_INCOMPLETE;
const INCOMPLETE_BYTES: &[u8] = b"praxor core copy incomplete v1\n";
const PREPARED_MARKER: &str = "COPY_PUBLICATION_MARKER";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Captured,
    Staged,
    Invalidated,
    Cleared,
    Published,
}

pub(super) fn phase(point: Phase) -> Result<()> {
    #[cfg(test)]
    return hooks::invoke(point);
    #[cfg(not(test))]
    {
        let _ = point;
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Capture {
    root: PathBuf,
    pub manifest: Manifest,
    wals: Vec<(u64, u64)>,
    // v3 validates complete retained evidence even when a flushed file need
    // not be copied. Maintenance retains these exact captured prefixes.
    proof_wals: Vec<(u64, u64)>,
    origin: Option<PathBuf>,
}

pub(super) struct Staged {
    pub manifest: Manifest,
    pub files: Vec<PathBuf>,
}

impl Capture {
    /// Called while maintenance and writer are held (or under an offline lease).
    pub(super) fn new(root: &Path, mut manifest: Manifest) -> Result<Self> {
        manifest.validate_and_upgrade(&root.join("MANIFEST"))?;
        if manifest.flushed_sequence > manifest.last_sequence
            || manifest.active_wal_id == 0
            || manifest.flushed_wal_id >= manifest.active_wal_id
            || manifest.next_wal_id <= manifest.active_wal_id
            || manifest
                .segments
                .iter()
                .any(|segment| segment.id == 0 || segment.id >= manifest.next_segment_id)
        {
            return corrupt(
                root,
                "invalid captured sequence or file allocation counters",
            );
        }
        let mut capture = Self {
            root: root.to_path_buf(),
            manifest,
            wals: Vec::new(),
            proof_wals: Vec::new(),
            origin: None,
        };
        let mut identities = BTreeSet::new();
        for segment in capture.manifest.segments.clone() {
            if !identities.insert(segment.id) {
                return corrupt(root, "duplicate captured segment identity");
            }
            capture.accept_label(&segment.path, &segment_relative(segment.level, segment.id))?;
        }
        if let Some(checkpoint) = capture.manifest.latest_checkpoint.clone() {
            capture.accept_label(&checkpoint.path, &checkpoint_relative(checkpoint.id))?;
            capture.local(&checkpoint_relative(checkpoint.id))?;
        }
        let wal_root = root.join("wal");
        if wal_root.exists() {
            for entry in fs::read_dir(&wal_root)? {
                let path = entry?.path();
                if path.extension().is_none_or(|extension| extension != "wal") {
                    continue;
                }
                let id = file_id(&path, "wal")?;
                if capture.manifest.record_authority.is_some() {
                    if id > capture.manifest.active_wal_id {
                        return corrupt(&path, "WAL beyond captured authority identity");
                    }
                    let local = capture.local(&wal_relative(id))?;
                    capture.proof_wals.push((id, fs::metadata(local)?.len()));
                }
                if id > capture.manifest.flushed_wal_id || id == capture.manifest.active_wal_id {
                    if id > capture.manifest.active_wal_id {
                        return corrupt(&path, "WAL beyond captured active identity");
                    }
                    let local = capture.local(&wal_relative(id))?;
                    capture.wals.push((id, fs::metadata(local)?.len()));
                }
            }
        }
        capture.wals.sort_unstable();
        if capture.manifest.record_authority.is_none() {
            capture.proof_wals = capture.wals.clone();
        }
        capture.proof_wals.sort_unstable();
        let mut previous = capture.manifest.flushed_wal_id;
        for (id, _) in &capture.wals {
            if previous.checked_add(1) != Some(*id) {
                return corrupt(root, "required backup WAL identity is missing");
            }
            previous = *id;
        }
        if previous != capture.manifest.active_wal_id {
            return corrupt(root, "captured active WAL is missing");
        }
        Ok(capture)
    }

    pub(super) fn from_bundle(root: &Path) -> Result<Self> {
        let path = root.join("MANIFEST");
        let bytes = fs::read(&path)?;
        let capture = Self::new(root, Manifest::decode(&bytes, &path)?)?;
        // Offline restore must refuse before acquiring/creating a destination.
        // No live writer guard is held here, so bulk hashing is appropriate.
        capture.validate_checkpoint()?;
        Ok(capture)
    }

    pub(super) fn from_live(root: &Path, manifest: Manifest) -> Result<Self> {
        let capture = Self::new(root, manifest)?;
        if let Some(origin) = &capture.origin
            && fs::canonicalize(origin)? != root
        {
            return corrupt(origin, "live backup reference is outside its owned root");
        }
        Ok(capture)
    }

    pub(super) fn validate(
        mut self,
        accelerator: &dyn Accelerator,
    ) -> Result<crate::recovery::VerificationReport> {
        let mut report = crate::recovery::VerificationReport {
            manifest_generation: self.manifest.next_segment_id,
            ..Default::default()
        };
        let mut value_files = BTreeSet::new();
        let mut value_extents = BTreeSet::new();
        if self.manifest.latest_checkpoint.is_some() {
            report.checkpoints_checked = 1;
            report.bytes_checked = self.validate_checkpoint()?;
        }
        let mut protected = crate::core_records::recovery::Evidence::new(
            &self.manifest,
            &self.root.join("MANIFEST"),
        )?;
        for metadata in self.manifest.segments.clone() {
            let path = self.local(&segment_relative(metadata.level, metadata.id))?;
            let bytes = fs::read(&path)?;
            if blake3::hash(&bytes).to_hex().as_str() != metadata.file_digest {
                return corrupt(&path, "backup segment digest mismatch");
            }
            report.segments_checked += 1;
            report.bytes_checked = report
                .bytes_checked
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| error(&path, "verification byte count overflow"))?;
            let raw = decode_segment(&bytes, &path, accelerator)?;
            if raw.id != metadata.id
                || raw.level != metadata.level
                || raw
                    .blocks
                    .iter()
                    .map(|block| block.len() as u64)
                    .sum::<u64>()
                    != metadata.entries
            {
                return corrupt(&path, "backup segment role/header/count mismatch");
            }
            protected.begin_segment();
            for raw in raw.blocks.iter().flatten() {
                protected.segment(raw, |pointer| {
                    let id = file_id(Path::new(&pointer.path), "tval")?;
                    let relative = value_relative(id);
                    self.accept_label(&pointer.path, &relative)?;
                    crate::core_records::recovery::read_blob_at(pointer, &self.local(&relative)?)
                })?;
                if let StoredValue::BlobPointer(pointer) = &raw.entry.version.value {
                    let id = file_id(Path::new(&pointer.path), "tval")?;
                    let relative = value_relative(id);
                    self.accept_label(&pointer.path, &relative)?;
                    validate_pointer(&self.local(&relative)?, pointer)?;
                    value_files.insert(id);
                    if value_extents.insert((id, pointer.offset, pointer.len, pointer.checksum)) {
                        report.bytes_checked = report
                            .bytes_checked
                            .checked_add(pointer.len)
                            .and_then(|n| n.checked_add(12))
                            .ok_or_else(|| error(&path, "verification byte count overflow"))?;
                    }
                }
            }
        }
        let mut covered = self.manifest.flushed_sequence;
        for (id, len) in &self.proof_wals {
            let path = self.local(&wal_relative(*id))?;
            let mut bytes = Vec::new();
            File::open(&path)?.take(*len).read_to_end(&mut bytes)?;
            if bytes.len() as u64 != *len {
                return corrupt(&path, "backup WAL changed during validation");
            }
            report.bytes_checked = report
                .bytes_checked
                .checked_add(*len)
                .ok_or_else(|| error(&path, "verification byte count overflow"))?;
            let records =
                Wal::validate_backup_prefix(&bytes, &path, *id, self.manifest.last_sequence)?;
            for record in &records {
                protected.wal(record)?;
            }
            extend_coverage(
                &path,
                self.manifest.flushed_sequence,
                &mut covered,
                records.iter().map(|record| record.sequence()),
            )?;
        }
        require_coverage(&self.root, covered, self.manifest.last_sequence)?;
        protected.finish()?;
        report.value_logs_checked = value_files.len() as u64;
        Ok(report)
    }

    /// Bulk checkpoint hashing runs after live capture releases the writer.
    /// Offline/legacy copies use the same policy before creating layout files.
    fn validate_checkpoint(&self) -> Result<u64> {
        let Some(checkpoint) = &self.manifest.latest_checkpoint else {
            return Ok(0);
        };
        let path = self.local(&checkpoint_relative(checkpoint.id))?;
        if crate::io::file_digest(&path)?.to_hex().as_str() != checkpoint.file_digest {
            return corrupt(&path, "captured checkpoint digest mismatch");
        }
        Ok(fs::metadata(path)?.len())
    }

    fn accept_label(&mut self, label: &str, relative: &Path) -> Result<()> {
        let path = Path::new(label);
        if (!cfg!(windows) && label.contains('\\'))
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || !path.ends_with(relative)
        {
            return corrupt(path, "invalid or unsupported backup path label");
        }
        let origin = path
            .ancestors()
            .nth(relative.components().count())
            .ok_or_else(|| error(path, "backup label has no origin"))?;
        if let Some(expected) = &self.origin {
            if expected != origin {
                return corrupt(path, "conflicting backup path origins");
            }
        } else {
            self.origin = Some(origin.to_path_buf());
        }
        Ok(())
    }

    fn local(&self, relative: &Path) -> Result<PathBuf> {
        let mut current = self.root.clone();
        let components = relative.components().collect::<Vec<_>>();
        for (index, part) in components.iter().enumerate() {
            if !matches!(part, Component::Normal(_)) {
                return corrupt(relative, "invalid file role");
            }
            current.push(part.as_os_str());
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink()
                || (index + 1 == components.len() && !metadata.is_file())
                || (index + 1 != components.len() && !metadata.is_dir())
            {
                return corrupt(
                    &current,
                    "backup role must be a local regular file without aliases",
                );
            }
        }
        Ok(current)
    }

    pub(super) fn stage(
        mut self,
        stage: &Path,
        destination: &Path,
        accelerator: &dyn Accelerator,
    ) -> Result<Staged> {
        if self.manifest.record_authority.is_some() {
            self.clone().validate(accelerator)?;
        } else {
            self.validate_checkpoint()?;
        }
        let layout = DiskLayout::create(stage)?;
        let mut files = BTreeSet::new();
        let mut values = BTreeMap::new();
        let mut covered = self.manifest.flushed_sequence;
        for (id, len) in &self.wals {
            let relative = wal_relative(*id);
            let source = self.local(&relative)?;
            let target = stage.join(&relative);
            copy_prefix(&source, &target, *len)?;
            let records = Wal::validate_backup_prefix(
                &fs::read(&target)?,
                &target,
                *id,
                self.manifest.last_sequence,
            )?;
            extend_coverage(
                &target,
                self.manifest.flushed_sequence,
                &mut covered,
                records.iter().map(|record| record.sequence()),
            )?;
            files.insert(relative);
        }
        require_coverage(stage, covered, self.manifest.last_sequence)?;
        for index in 0..self.manifest.segments.len() {
            let metadata = self.manifest.segments[index].clone();
            let relative = segment_relative(metadata.level, metadata.id);
            let source = self.local(&relative)?;
            let bytes = fs::read(&source)?;
            if blake3::hash(&bytes).to_hex().as_str() != metadata.file_digest {
                return corrupt(&source, "captured segment digest mismatch");
            }
            let mut raw = decode_segment(&bytes, &source, accelerator)?;
            if raw.id != metadata.id
                || raw.level != metadata.level
                || raw
                    .blocks
                    .iter()
                    .map(|block| block.len() as u64)
                    .sum::<u64>()
                    != metadata.entries
            {
                return corrupt(&source, "segment role/header/count disagrees with manifest");
            }
            let own_value = value_relative(metadata.id);
            if self.root.join(&own_value).exists() {
                values.insert(metadata.id, self.local(&own_value)?);
            }
            for entry in raw.blocks.iter_mut().flatten() {
                if let StoredValue::BlobPointer(pointer) = &mut entry.entry.version.value {
                    let id = file_id(Path::new(&pointer.path), "tval")?;
                    let relative = value_relative(id);
                    self.accept_label(&pointer.path, &relative)?;
                    let source = self.local(&relative)?;
                    validate_pointer(&source, pointer)?;
                    values.insert(id, source);
                    pointer.path = path_string(&destination.join(value_relative(id)))?;
                }
            }
            let encoded = raw.encode(accelerator)?;
            let target = stage.join(&relative);
            create_dir_all_durable(target.parent().expect("segment parent"))?;
            write_file_with_policy(&target, &encoded, false)?;
            self.manifest.segments[index].path =
                path_string(&destination.join(segment_relative(metadata.level, metadata.id)))?;
            self.manifest.segments[index].file_digest = blake3::hash(&encoded).to_hex().to_string();
            files.insert(relative);
        }
        for (id, source) in values {
            let relative = value_relative(id);
            copy_prefix(
                &source,
                &stage.join(&relative),
                fs::metadata(&source)?.len(),
            )?;
            files.insert(relative);
        }
        let id = self.manifest.last_sequence;
        let mut checkpoint =
            write_checkpoint_with_policy(&layout.checkpoint_path(id), id, &self.manifest, false)?;
        checkpoint.path = path_string(&destination.join(checkpoint_relative(id)))?;
        self.manifest.latest_checkpoint = Some(checkpoint);
        files.insert(checkpoint_relative(id));
        ManifestStore::new(layout.manifest_path()).save(&self.manifest)?;
        // Manifest is always installed after all its dependencies.
        Ok(Staged {
            manifest: self.manifest,
            files: files.into_iter().collect(),
        })
    }
}

fn extend_coverage(
    path: &Path,
    flushed: u64,
    covered: &mut u64,
    sequences: impl IntoIterator<Item = u64>,
) -> Result<()> {
    for sequence in sequences {
        // Retained flushed records and legacy sequence-zero records remain in
        // the copied bytes. They do not prove any later committed sequence.
        if sequence <= flushed {
            continue;
        }
        if covered.checked_add(1) != Some(sequence) {
            return corrupt(
                path,
                "backup WAL cannot prove a contiguous committed prefix",
            );
        }
        *covered = sequence;
    }
    Ok(())
}

fn require_coverage(path: &Path, covered: u64, captured: u64) -> Result<()> {
    if covered != captured {
        return corrupt(
            path,
            "backup WAL is missing committed records through capture",
        );
    }
    Ok(())
}

fn validate_pointer(path: &Path, pointer: &ValuePointer) -> Result<()> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if pointer
        .offset
        .checked_add(12)
        .and_then(|end| end.checked_add(pointer.len))
        .is_none_or(|end| end > size)
    {
        return corrupt(path, "value pointer exceeds captured value file");
    }
    file.seek(SeekFrom::Start(pointer.offset))?;
    let mut header = [0; 12];
    file.read_exact(&mut header)?;
    if u64::from_le_bytes(header[..8].try_into().expect("length")) != pointer.len
        || u32::from_le_bytes(header[8..].try_into().expect("checksum")) != pointer.checksum
    {
        return corrupt(path, "value pointer header mismatch");
    }
    let mut remaining = pointer.len;
    let mut buffer = [0; 64 * 1024];
    let mut hash = crc32fast::Hasher::new();
    while remaining != 0 {
        let n = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if hash.finalize() != pointer.checksum {
        return corrupt(path, "value pointer payload checksum mismatch");
    }
    Ok(())
}

fn copy_prefix(source: &Path, target: &Path, len: u64) -> Result<()> {
    create_dir_all_durable(target.parent().expect("role parent"))?;
    let mut input = File::open(source)?.take(len);
    let mut output = File::create(target)?;
    if std::io::copy(&mut input, &mut output)? != len {
        return corrupt(source, "captured file prefix is truncated");
    }
    output.flush()?;
    output.sync_all()?;
    sync_parent_dir(target)?;
    Ok(())
}

fn file_id(path: &Path, extension: &str) -> Result<u64> {
    let id = path
        .file_stem()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse::<u64>().ok())
        .filter(|id| *id != 0)
        .ok_or_else(|| error(path, "invalid backup file identity"))?;
    if path.file_name().and_then(|name| name.to_str())
        != Some(format!("{id:020}.{extension}").as_str())
    {
        return corrupt(path, "noncanonical backup file identity");
    }
    Ok(id)
}
fn segment_relative(level: u32, id: u64) -> PathBuf {
    PathBuf::from("segments")
        .join(level.to_string())
        .join(format!("{id:020}.tseg"))
}
fn value_relative(id: u64) -> PathBuf {
    PathBuf::from("values").join(format!("{id:020}.tval"))
}
fn wal_relative(id: u64) -> PathBuf {
    PathBuf::from("wal").join(format!("{id:020}.wal"))
}
fn checkpoint_relative(id: u64) -> PathBuf {
    PathBuf::from("checkpoints").join(format!("{id:020}.chk"))
}
fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| error(path, "non-UTF8 backup paths are unsupported"))
}
fn error(path: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}
fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(error(path, reason))
}

/// Normal format admission remains strict. Only an exact private sentinel plus
/// a complete Core-only physical shape permits replacement of missing authority.
pub(super) fn require_destination(root: &Path) -> Result<()> {
    use crate::storage::root_format::{
        DiagnosticKind, InspectionOptions, RootOwner, inspect_storage_root,
    };
    let marker = root.join(INCOMPLETE);
    let retry = match fs::symlink_metadata(&marker) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.len() != INCOMPLETE_BYTES.len() as u64
                || fs::read(&marker)? != INCOMPLETE_BYTES
            {
                return corrupt(&marker, "unrecognized incomplete-copy sentinel");
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let report = inspect_storage_root(root, InspectionOptions::for_admission())?;
    let neutral = neutral_primary(root)?;
    let only_neutral = neutral
        && fs::read_dir(root)?.all(|entry| {
            entry.is_ok_and(|entry| {
                matches!(
                    entry.file_name().to_str(),
                    Some(crate::writer_lease::LOCK_FILE_NAME | "primary")
                )
            })
        });
    if !retry && !only_neutral {
        report.require_compatible(RootOwner::Core)?;
    } else {
        if report.evidence.iter().any(|item| {
            item.owner != RootOwner::Core
                && !(neutral
                    && item.path == root.join("primary")
                    && item.owner == RootOwner::Pointer)
        }) || report.diagnostics.iter().any(|item| {
            !matches!(
                item.kind,
                DiagnosticKind::MissingAuthority | DiagnosticKind::UnexpectedEntry
            ) && !(retry
                && item.kind == DiagnosticKind::DamagedControl
                && item.path == root.join("MANIFEST.tmp"))
        }) {
            return corrupt(
                root,
                "incomplete copy contains foreign or damaged authority",
            );
        }
    }
    core_shape(root, retry, false)
}

fn neutral_primary(root: &Path) -> Result<bool> {
    let path = root.join("primary");
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_name() != crate::writer_lease::LOCK_FILE_NAME
                    || !entry.file_type()?.is_file()
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn core_shape(root: &Path, retry: bool, stage: bool) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| error(&path, "non-UTF8 core role"))?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return corrupt(&path, "copy role must not be an alias");
        }
        match name {
            crate::writer_lease::LOCK_FILE_NAME if kind.is_file() && !stage => {}
            INCOMPLETE if kind.is_file() && retry && !stage => {}
            PREPARED_MARKER if kind.is_file() && stage => {
                let bytes = read_prefix(&path, INCOMPLETE_BYTES.len() + 1)?;
                if !INCOMPLETE_BYTES.starts_with(&bytes) {
                    return corrupt(&path, "unrecognized staged publication marker");
                }
            }
            "MANIFEST" | "MANIFEST.tmp" if kind.is_file() => {
                let bytes = fs::read(&path)?;
                if Manifest::decode(&bytes, &path).is_err() {
                    let signature = b"format_version = 2";
                    if !(stage || (retry && name == "MANIFEST.tmp"))
                        || !(bytes.starts_with(signature) || signature.starts_with(&bytes))
                    {
                        return corrupt(&path, "copy control is not a recognized core manifest");
                    }
                }
            }
            "primary" if kind.is_dir() && !stage => {
                for child in fs::read_dir(&path)? {
                    let child = child?;
                    if child.file_name() != crate::writer_lease::LOCK_FILE_NAME
                        || !child.file_type()?.is_file()
                    {
                        return corrupt(
                            &child.path(),
                            "only a neutral primary lock container is replaceable",
                        );
                    }
                }
            }
            "segments" if kind.is_dir() => {
                for level in fs::read_dir(&path)? {
                    let level = level?;
                    let level_path = level.path();
                    let number = level
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                        .ok_or_else(|| error(&level_path, "invalid segment level role"))?;
                    if !level.file_type()?.is_dir()
                        || level.file_type()?.is_symlink()
                        || level.file_name() != number.to_string().as_str()
                    {
                        return corrupt(&level_path, "invalid segment level");
                    }
                    for segment in fs::read_dir(&level_path)? {
                        let segment = segment?;
                        let segment_path = segment.path();
                        regular(&segment_path)?;
                        let id = file_id(&segment_path, "tseg")?;
                        let prefix = read_prefix(&segment_path, 21)?;
                        let mut expected = crate::segments::format::SEGMENT_MAGIC
                            .to_le_bytes()
                            .to_vec();
                        expected.extend_from_slice(
                            &crate::segments::format::SEGMENT_VERSION.to_le_bytes(),
                        );
                        if prefix.len() < 21 {
                            if !stage
                                || (!expected.starts_with(&prefix)
                                    && !prefix.starts_with(&expected))
                            {
                                return corrupt(&segment_path, "incomplete segment role");
                            }
                        } else if prefix[..8] != expected
                            || u32::from_le_bytes(prefix[9..13].try_into().expect("level"))
                                != number
                            || u64::from_le_bytes(prefix[13..21].try_into().expect("id")) != id
                        {
                            return corrupt(&segment_path, "foreign or mismatched segment role");
                        }
                    }
                }
            }
            "values" | "wal" | "checkpoints" if kind.is_dir() => {
                for child in fs::read_dir(&path)? {
                    let child = child?;
                    let file = child.path();
                    regular(&file)?;
                    let extension = match name {
                        "values" => "tval",
                        "wal" => "wal",
                        _ => "chk",
                    };
                    let id = if name == "checkpoints" {
                        if stage && file.extension().is_some_and(|ext| ext == "tmp") {
                            checkpoint_id(&file.with_extension("chk"))?
                        } else {
                            checkpoint_id(&file)?
                        }
                    } else {
                        file_id(&file, extension)?
                    };
                    if name == "wal" {
                        let bytes = fs::read(&file)?;
                        if stage {
                            let expected = 0x5457_4146_u32.to_le_bytes();
                            if bytes.len() < 4 && !expected.starts_with(&bytes) {
                                return corrupt(&file, "unknown staged WAL prefix");
                            }
                            if bytes.len() >= 4
                                && ![0x5457_4146_u32, 0x5457_414c, 0x5457_4132]
                                    .iter()
                                    .any(|magic| bytes.starts_with(&magic.to_le_bytes()))
                            {
                                return corrupt(&file, "foreign staged WAL");
                            }
                        } else {
                            Wal::validate_backup_prefix(&bytes, &file, id, u64::MAX)?;
                        }
                    } else if name == "checkpoints" && !stage {
                        let _: crate::recovery::CheckpointFile =
                            serde_json::from_slice(&fs::read(&file)?)?;
                    }
                }
            }
            "tmp" if kind.is_dir() => {
                for child in fs::read_dir(&path)? {
                    let child = child?;
                    if child.file_type()?.is_symlink()
                        || !child.file_type()?.is_dir()
                        || !child
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.starts_with("backup-stage-"))
                    {
                        return corrupt(&child.path(), "unknown temporary copy role");
                    }
                    core_shape(&child.path(), false, true)?;
                }
            }
            _ => return corrupt(&path, "copy destination contains an unrelated role"),
        }
    }
    Ok(())
}

fn checkpoint_id(path: &Path) -> Result<u64> {
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse::<u64>().ok())
        .ok_or_else(|| error(path, "invalid checkpoint identity"))?;
    if path.file_name().and_then(|name| name.to_str()) != Some(format!("{name:020}.chk").as_str()) {
        return corrupt(path, "invalid checkpoint role");
    }
    Ok(name)
}
fn regular(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return corrupt(path, "copy role is not a regular file");
    }
    Ok(())
}
fn read_prefix(path: &Path, len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(len as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) struct Stage {
    root: PathBuf,
    remove_parent: bool,
}
impl Stage {
    pub(super) fn create(destination: &Path) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = destination.join("tmp");
        let remove_parent = !parent.exists();
        create_dir_all_durable(&parent)?;
        loop {
            let path = parent.join(format!(
                "backup-stage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    sync_parent_dir(&path)?;
                    return Ok(Self {
                        root: fs::canonicalize(path)?,
                        remove_parent,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = clear(&self.root, None);
        let _ = fs::remove_dir(&self.root);
        if self.remove_parent
            && let Some(parent) = self.root.parent()
            && fs::read_dir(parent).is_ok_and(|mut entries| entries.next().is_none())
        {
            let _ = fs::remove_dir(parent);
            let _ = sync_parent_dir(parent);
        }
    }
}

pub(super) fn publish(
    destination: &Path,
    stage: &Stage,
    staged: Staged,
    accelerator: &dyn Accelerator,
) -> Result<()> {
    Capture::new(stage.root(), staged.manifest.clone())?.validate(accelerator)?;
    phase(Phase::Staged)?;
    let marker = destination.join(INCOMPLETE);
    if !marker.exists() {
        let prepared = stage.root().join(PREPARED_MARKER);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&prepared)?;
        file.write_all(INCOMPLETE_BYTES)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&prepared, &marker)?;
    }
    // A prior attempt may have renamed the marker but failed its directory
    // sync. Every retry must reestablish marker-before-deletion ordering.
    fs::OpenOptions::new()
        .write(true)
        .open(&marker)?
        .sync_all()?;
    sync_parent_dir(&marker)?;
    let manifest = destination.join("MANIFEST");
    if manifest.exists() {
        fs::remove_file(&manifest)?;
        sync_parent_dir(&manifest)?;
    }
    phase(Phase::Invalidated)?;
    clear(destination, Some(stage.root()))?;
    phase(Phase::Cleared)?;
    for relative in staged.files {
        let target = destination.join(&relative);
        create_dir_all_durable(target.parent().expect("role parent"))?;
        fs::rename(stage.root().join(relative), &target)?;
        sync_parent_dir(&target)?;
    }
    ManifestStore::new(&manifest).save(&staged.manifest)?;
    phase(Phase::Published)?;
    Capture::from_bundle(destination)?.validate(accelerator)?;
    fs::remove_file(&marker)?;
    sync_parent_dir(&marker)?;
    Ok(())
}

fn clear(root: &Path, stage: Option<&Path>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_name() == crate::writer_lease::LOCK_FILE_NAME
            || entry.file_name() == INCOMPLETE
            || stage == Some(path.as_path())
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return corrupt(&path, "cleanup refuses an alias");
        }
        if kind.is_dir() {
            clear(&path, stage)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path)?;
                sync_parent_dir(&path)?;
            }
        } else {
            fs::remove_file(&path)?;
            sync_parent_dir(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod hooks {
    use super::*;
    use std::cell::RefCell;
    type Hook = Box<dyn FnMut(Phase) -> Result<()>>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = RefCell::new(None); }
    pub struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|hook| *hook.borrow_mut() = None);
        }
    }
    pub fn install(hook: impl FnMut(Phase) -> Result<()> + 'static) -> Reset {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Reset
    }
    pub fn invoke(point: Phase) -> Result<()> {
        HOOK.with(|hook| match hook.borrow_mut().as_mut() {
            Some(hook) => hook(point),
            None => Ok(()),
        })
    }
}
