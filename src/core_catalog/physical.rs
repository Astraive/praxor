//! Private, read-only physical evidence for a v4 catalog owner.
//!
//! Only the retired-bootstrap F=1/L=1, D=0 cut is admitted here. Every other
//! cut remains unsupported until its installed and replay relations are
//! proven. No public database owner is constructed from this evidence.
use super::codec::{Anchor, CatalogKey, CatalogValue, Head, anchor_digest, canonical_head_at_1};
use crate::accel::Accelerator;
use crate::config::{Compression, PraxisConfig};
use crate::core_records::codec::{Allocator, Key as RecordKey, Role, Row as RecordRow};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::segments::codec::decode_segment;
use crate::segments::{BloomFilter, bloom_key};
use crate::types::StoredValue;
use crate::wal::catalog_witness::{WalCut, WalFileWitness, recheck_v4_wals, scan_v4_wals};
use crate::writer_lease::WriterLease;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
// This first cut has four bootstrap rows. A later general inspector needs a
// streaming block iterator rather than decoding arbitrary segments.
const MAX_BOOTSTRAP_SEGMENT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        return Err(corrupt(
            path,
            "v4 installed file has an external hardlink alias",
        ));
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
        return Err(corrupt(
            path,
            "v4 installed file has an external hardlink alias",
        ));
    }
    let mut id = [0; 16];
    id[..8].copy_from_slice(&meta.ino().to_le_bytes());
    Ok(PhysicalId {
        volume: meta.dev(),
        file: id,
    })
}

#[cfg(not(any(unix, windows)))]
compile_error!("v4 installed witnesses require opened-handle physical identity");

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileWitness {
    path: PathBuf,
    identity: PhysicalId,
    len: u64,
    digest: blake3::Hash,
}

#[derive(Debug)]
pub(crate) struct CatalogOwnerProof {
    root: PathBuf,
    manifest: FileWitness,
    segment: FileWitness,
    pub(crate) cut: WalCut,
    pub(crate) recovered_sequence: u64,
    pub(crate) binding: ([u8; 16], u32),
    pub(crate) allocator: Allocator,
    pub(crate) head: Head,
    pub(crate) anchor: Anchor,
    pub(crate) wal_witnesses: Vec<WalFileWitness>,
}

impl CatalogOwnerProof {
    /// Recheck every source under the retained writer lease before a future
    /// in-process writer fence could consume this private candidate.
    pub(crate) fn recheck(&self, lease: &WriterLease) -> Result<()> {
        if lease.root() != self.root {
            return Err(corrupt(
                lease.root(),
                "v4 proof has a different writer root",
            ));
        }
        let paths = narrow_paths(&self.root)?;
        for expected in [&self.manifest, &self.segment] {
            let (_, current) = read_bound(&expected.path, expected.len.max(1))?;
            if &current != expected {
                return Err(corrupt(&expected.path, "v4 installed file changed"));
            }
        }
        if paths.manifest != self.manifest.path || paths.segment != self.segment.path {
            return Err(corrupt(&self.root, "v4 installed namespace changed"));
        }
        recheck_v4_wals(&self.root, self.cut, &self.wal_witnesses)
    }
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
            continue;
        }
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(
                ancestor,
                "v4 installed path crosses a symbolic link",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(
                    ancestor,
                    "v4 installed path crosses a reparse point",
                ));
            }
        }
    }
    Ok(())
}

fn read_bound(path: &Path, cap: u64) -> Result<(Vec<u8>, FileWitness)> {
    check_real(path)?;
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(corrupt(path, "v4 installed entry is not a regular file"));
    }
    let mut file = File::open(path)?;
    let identity = physical_id(&file, path)?;
    let len = file.metadata()?.len();
    if len > cap {
        return Err(corrupt(path, "v4 installed file exceeds this proof cap"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len as usize)
        .map_err(|_| corrupt(path, "v4 installed allocation failed"))?;
    file.by_ref().take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != len || file.metadata()?.len() != len {
        return Err(corrupt(path, "v4 installed file changed during read"));
    }
    let digest = blake3::hash(&bytes);
    file.seek(SeekFrom::Start(0))?;
    let mut second = blake3::Hasher::new();
    let mut chunk = [0; 64 * 1024];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        second.update(&chunk[..n]);
    }
    if second.finalize() != digest || file.metadata()?.len() != len {
        return Err(corrupt(
            path,
            "v4 installed file changed during verification",
        ));
    }
    check_real(path)?;
    let path_file = File::open(path)?;
    if physical_id(&path_file, path)? != identity || path_file.metadata()?.len() != len {
        return Err(corrupt(path, "v4 installed pathname changed"));
    }
    Ok((
        bytes,
        FileWitness {
            path: path.to_path_buf(),
            identity,
            len,
            digest,
        },
    ))
}

struct NarrowPaths {
    manifest: PathBuf,
    segment: PathBuf,
}

fn narrow_paths(root: &Path) -> Result<NarrowPaths> {
    let mut root_names = std::collections::BTreeSet::new();
    for item in fs::read_dir(root)? {
        let item = item?;
        let name = item.file_name();
        if ![
            "MANIFEST",
            "wal",
            "segments",
            crate::writer_lease::LOCK_FILE_NAME,
        ]
        .iter()
        .any(|allowed| name == *allowed)
        {
            return Err(corrupt(&item.path(), "unexpected v4 bootstrap root entry"));
        }
        root_names.insert(name);
    }
    if root_names.len() != 4 {
        return Err(corrupt(root, "v4 bootstrap root entries are incomplete"));
    }
    let segment_root = root.join("segments");
    let level_root = segment_root.join("0");
    let segment = level_root.join("00000000000000000001.tseg");
    for (dir, allowed) in [
        (&segment_root, "0"),
        (&level_root, "00000000000000000001.tseg"),
    ] {
        check_real(dir)?;
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(corrupt(dir, "v4 installed namespace is not a directory"));
        }
        let mut count = 0;
        for item in fs::read_dir(dir)? {
            let item = item?;
            if item.file_name() != allowed {
                return Err(corrupt(&item.path(), "unexpected v4 installed entry"));
            }
            count += 1;
        }
        if count != 1 {
            return Err(corrupt(dir, "v4 installed namespace is incomplete"));
        }
    }
    let value_root = root.join("values");
    if value_root.exists() {
        return Err(corrupt(
            &value_root,
            "this bootstrap cut has no external values",
        ));
    }
    Ok(NarrowPaths {
        manifest: root.join("MANIFEST"),
        segment,
    })
}

pub(crate) fn inspect_v4_owner(
    lease: &WriterLease,
    config: &PraxisConfig,
    accelerator: &dyn Accelerator,
) -> Result<CatalogOwnerProof> {
    config.validate()?;
    let root = lease.root();
    if fs::canonicalize(&config.data_dir)? != root {
        return Err(corrupt(root, "v4 config and writer lease roots differ"));
    }
    let paths = narrow_paths(root)?;
    let (manifest_bytes, manifest_witness) = read_bound(&paths.manifest, MAX_MANIFEST_BYTES)?;
    let manifest = Manifest::decode(&manifest_bytes, &paths.manifest)?;
    if manifest.format_version != 4 || manifest.effective_config != config.persisted() {
        return Err(corrupt(&paths.manifest, "v4 config or format mismatch"));
    }
    // This is the first physical proof slice, not a general F/L/R owner.
    if manifest.flushed_sequence != 1
        || manifest.last_sequence != 1
        || manifest.flushed_wal_id != 1
        || manifest.active_wal_id != 2
        || manifest.next_wal_id != 3
        || manifest.next_segment_id != 2
        || manifest.next_column_family_generation != 6
        || manifest.column_families.len() != 6
        || manifest.column_family_generations.len() != 6
        || manifest.segments.len() != 1
        || manifest.latest_checkpoint.is_some()
        || !manifest.compaction_jobs.is_empty()
        || !manifest.tier_migrations.is_empty()
        || manifest
            .record_authority
            .as_ref()
            .is_none_or(|r| r.index_descriptor_count != 0)
    {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond retired D0 bootstrap",
        });
    }
    let meta = &manifest.segments[0];
    if meta.id != 1
        || meta.level != 0
        || meta.path != paths.segment.to_string_lossy()
        || meta.partitioned_bloom_filter.is_some()
    {
        return Err(corrupt(
            &paths.manifest,
            "v4 bootstrap segment metadata mismatch",
        ));
    }
    check_real(&paths.segment)?;
    let (segment_bytes, segment_witness) = read_bound(&paths.segment, MAX_BOOTSTRAP_SEGMENT_BYTES)?;
    if meta.file_digest != segment_witness.digest.to_hex().to_string() {
        return Err(corrupt(
            &paths.segment,
            "v4 bootstrap segment digest mismatch",
        ));
    }
    if segment_bytes.get(8) != Some(&0) {
        return Err(corrupt(
            &paths.segment,
            "compressed v4 bootstrap segment is unsupported by this proof",
        ));
    }
    let decoded = decode_segment(&segment_bytes, &paths.segment, accelerator)?;
    if decoded.id != 1 || decoded.level != 0 || decoded.compression != Compression::None {
        return Err(corrupt(
            &paths.segment,
            "v4 bootstrap segment header mismatch",
        ));
    }
    let rows: Vec<_> = decoded.blocks.into_iter().flatten().collect();
    if rows.len() as u64 != meta.entries
        || rows.first().map(|raw| raw.entry.key.as_ref()) != Some(meta.min_key.as_slice())
        || rows.last().map(|raw| raw.entry.key.as_ref()) != Some(meta.max_key.as_slice())
    {
        return Err(corrupt(
            &paths.segment,
            "v4 bootstrap segment row metadata mismatch",
        ));
    }
    let mut bloom = BloomFilter::with_expected_items(rows.len());
    let mut previous: Option<(&str, &[u8])> = None;
    for raw in &rows {
        let current = (raw.entry.cf.0.as_str(), raw.entry.key.as_ref());
        if previous.is_some_and(|prior| prior >= current) {
            return Err(corrupt(
                &paths.segment,
                "v4 bootstrap rows are not strictly sorted",
            ));
        }
        previous = Some(current);
        bloom.insert(&bloom_key(current.0, current.1));
    }
    if bloom != meta.bloom_filter {
        return Err(corrupt(
            &paths.segment,
            "v4 bootstrap bloom metadata mismatch",
        ));
    }
    let id = manifest
        .record_authority
        .as_ref()
        .expect("checked above")
        .identity(&paths.manifest)?;
    let mut binding = None;
    let mut allocator = None;
    let mut head = None;
    let mut anchor = None;
    for raw in rows {
        let entry = raw.entry;
        if raw.blob_expiry.is_some() || entry.version.sequence != 1 {
            return Err(corrupt(
                &paths.segment,
                "invalid v4 installed bootstrap version",
            ));
        }
        let StoredValue::Put(value) = entry.version.value else {
            return Err(corrupt(
                &paths.segment,
                "v4 bootstrap row must be inline Put",
            ));
        };
        match entry.cf.0.as_str() {
            "__praxor_record_meta_v1" => {
                let key = RecordKey::decode(Role::Meta, &entry.key, &paths.segment)?;
                let row = RecordRow::decode(&key, &value, &paths.segment)?;
                match (key, row) {
                    (
                        RecordKey::Binding,
                        RecordRow::Binding {
                            database_id,
                            descriptor_count,
                        },
                    ) if database_id == id && descriptor_count == 0 && binding.is_none() => {
                        binding = Some((database_id, descriptor_count));
                    }
                    (RecordKey::Allocator, RecordRow::Allocator(found))
                        if found == Allocator::default() && allocator.is_none() =>
                    {
                        allocator = Some(found);
                    }
                    _ => {
                        return Err(corrupt(
                            &paths.segment,
                            "unexpected v4 record bootstrap row",
                        ));
                    }
                }
            }
            "__praxor_record_catalog_v1" => {
                let key = CatalogKey::decode(&entry.key, &paths.segment)?;
                let row = CatalogValue::decode(&key, &value, &paths.segment)?;
                match (key, row) {
                    (CatalogKey::Head, CatalogValue::Head(found))
                        if found.database_id == id
                            && found.revision == 1
                            && found.collection_count == 0
                            && value.as_slice() == canonical_head_at_1(id)?.as_slice()
                            && head.is_none() =>
                    {
                        head = Some(found);
                    }
                    (CatalogKey::Anchor, CatalogValue::Anchor(found))
                        if found.database_id == id
                            && found.head_at_1_digest == anchor_digest(id)?
                            && anchor.is_none() =>
                    {
                        anchor = Some(found);
                    }
                    _ => {
                        return Err(corrupt(
                            &paths.segment,
                            "unexpected v4 catalog bootstrap row",
                        ));
                    }
                }
            }
            _ => return Err(corrupt(&paths.segment, "unexpected v4 bootstrap family")),
        }
    }
    let binding = binding.ok_or_else(|| corrupt(&paths.segment, "missing record Binding@1"))?;
    let allocator =
        allocator.ok_or_else(|| corrupt(&paths.segment, "missing record Allocator@1"))?;
    let head = head.ok_or_else(|| corrupt(&paths.segment, "missing catalog Head@1"))?;
    let anchor = anchor.ok_or_else(|| corrupt(&paths.segment, "missing catalog Anchor@1"))?;
    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let wal_witnesses = scan_v4_wals(root, cut, |_, _, _, _| {
        Err(corrupt(
            root,
            "retired bootstrap cut has an unexpected WAL frame",
        ))
    })?;
    if wal_witnesses.len() != 1
        || wal_witnesses[0].id != 2
        || wal_witnesses[0].record_count != 0
        || wal_witnesses[0].torn_start.is_some()
        || wal_witnesses[0].full_len != 16
    {
        return Err(corrupt(
            root,
            "retired bootstrap requires header-only active WAL",
        ));
    }
    let proof = CatalogOwnerProof {
        root: root.to_path_buf(),
        manifest: manifest_witness,
        segment: segment_witness,
        cut,
        recovered_sequence: 1,
        binding,
        allocator,
        head,
        anchor,
        wal_witnesses,
    };
    proof.recheck(lease)?;
    Ok(proof)
}
