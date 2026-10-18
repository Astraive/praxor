//! Private, read-only physical evidence for a v4 catalog owner.
//!
//! Only the D=0 unflushed-bootstrap F=0/L=1 and retired-bootstrap F=1/L=1
//! cuts are admitted here. Every other cut remains unsupported until its
//! installed and replay relations are proven. No public owner is constructed.
use super::codec::{Anchor, CatalogKey, CatalogValue, Head, anchor_digest, canonical_head_at_1};
use super::control::CatalogControl;
use super::frame::{self, FrameContext, PriorCatalog, ValidatedCatalogFrame};
use crate::accel::Accelerator;
use crate::config::{Compression, PraxisConfig};
use crate::core_records::codec::{Allocator, Key as RecordKey, Role, Row as RecordRow};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::segments::codec::decode_segment;
use crate::segments::{BloomFilter, bloom_key};
use crate::transactions::BatchOp;
use crate::types::StoredValue;
use crate::wal::catalog_witness::{WalCut, WalFileWitness, recheck_v4_wals, scan_v4_wals};
use crate::wal::record::CoreWalRecord;
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
pub(crate) struct FileWitness {
    path: PathBuf,
    identity: PhysicalId,
    len: u64,
    digest: blake3::Hash,
}

/// One discardable, owned endpoint. It never borrows from the scanner's
/// temporary `CoreWalRecord` or publishes effects to the live engine.
#[derive(Debug)]
pub(crate) struct CatalogReplayState {
    source: PathBuf,
    database_id: [u8; 16],
    anchor: Anchor,
    pub(crate) head: Head,
    pub(crate) rows: CatalogReplayRows,
}

#[derive(Debug)]
struct OwnedCatalogRow {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl OwnedCatalogRow {
    fn new(
        key: &[u8],
        value: &[u8],
        key_cap: usize,
        value_cap: usize,
        source: &Path,
    ) -> Result<Self> {
        fn copy(bytes: &[u8], cap: usize, source: &Path) -> Result<Vec<u8>> {
            if bytes.len() > cap {
                return Err(corrupt(source, "v4 CREATE owned row exceeds catalog cap"));
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| corrupt(source, "cannot reserve v4 CREATE row"))?;
            owned.extend_from_slice(bytes);
            Ok(owned)
        }
        Ok(Self {
            key: copy(key, key_cap, source)?,
            value: copy(value, value_cap, source)?,
        })
    }
}

/// The admitted cut has two installed rows and, at most, three new keys.
/// Fixed slots make staging fallible only at explicit bounded byte copies.
#[derive(Debug)]
pub(crate) struct CatalogReplayRows {
    head: OwnedCatalogRow,
    anchor: OwnedCatalogRow,
    name: Option<OwnedCatalogRow>,
    schema: Option<OwnedCatalogRow>,
    namespace: Option<OwnedCatalogRow>,
}

impl CatalogReplayRows {
    pub(crate) fn len(&self) -> usize {
        2 + usize::from(self.name.is_some())
            + usize::from(self.schema.is_some())
            + usize::from(self.namespace.is_some())
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        [
            Some(&self.head),
            Some(&self.anchor),
            self.name.as_ref(),
            self.schema.as_ref(),
            self.namespace.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find(|row| row.key == key)
        .map(|row| &row.value)
    }
}

impl CatalogReplayState {
    fn from_head_anchor(head: Head, anchor: Anchor, source: &Path) -> Result<Self> {
        let rows = CatalogReplayRows {
            head: OwnedCatalogRow {
                key: CatalogKey::Head.encode()?,
                value: CatalogValue::Head(head).encode()?,
            },
            anchor: OwnedCatalogRow {
                key: CatalogKey::Anchor.encode()?,
                value: CatalogValue::Anchor(anchor).encode()?,
            },
            name: None,
            schema: None,
            namespace: None,
        };
        Ok(Self {
            source: source.to_path_buf(),
            database_id: head.database_id,
            anchor,
            head,
            rows,
        })
    }

    fn apply_create(&mut self, frame: ValidatedCatalogFrame<'_>) -> Result<()> {
        if frame.sequence() != 2 || self.head.revision != 1 || frame.ops().len() != 4 {
            return Err(corrupt(&self.source, "unsupported v4 CREATE replay cut"));
        }
        if self.rows.len() != 2 {
            return Err(corrupt(
                &self.source,
                "v4 CREATE endpoint is already extended",
            ));
        }
        // The validated frame's ordered effects are Head, Name, Schema,
        // Namespace. All four owned copies finish before publication.
        let caps = [(1, 48), (258, 12), (9, 33_947), (9, 16)];
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(4)
            .map_err(|_| corrupt(&self.source, "cannot reserve v4 CREATE effects"))?;
        for (op, (key_cap, value_cap)) in frame.ops().iter().zip(caps) {
            let BatchOp::Put { cf, key, value } = op else {
                return Err(corrupt(&self.source, "v4 CREATE replay requires plain Put"));
            };
            if cf.0 != super::authority::CATALOG_CF {
                return Err(corrupt(&self.source, "v4 CREATE replay family mismatch"));
            }
            staged.push(OwnedCatalogRow::new(
                key,
                value,
                key_cap,
                value_cap,
                &self.source,
            )?);
        }
        let [new_head, name, schema, namespace]: [OwnedCatalogRow; 4] = staged
            .try_into()
            .map_err(|_| corrupt(&self.source, "v4 CREATE effect count mismatch"))?;
        let new_head_value =
            self.validate_created_relation(&new_head, &name, &schema, &namespace)?;
        self.rows.head = new_head;
        self.rows.name = Some(name);
        self.rows.schema = Some(schema);
        self.rows.namespace = Some(namespace);
        self.head = new_head_value;
        Ok(())
    }

    fn validate_created_relation(
        &self,
        new_head: &OwnedCatalogRow,
        name: &OwnedCatalogRow,
        schema: &OwnedCatalogRow,
        namespace: &OwnedCatalogRow,
    ) -> Result<Head> {
        let key = CatalogKey::decode(&new_head.key, &self.source)?;
        let CatalogValue::Head(head) = CatalogValue::decode(&key, &new_head.value, &self.source)?
        else {
            return Err(corrupt(&self.source, "v4 CREATE effective Head mismatch"));
        };
        if key != CatalogKey::Head {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Head key mismatch",
            ));
        }
        let CatalogKey::Name(label) = CatalogKey::decode(&name.key, &self.source)? else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Name key mismatch",
            ));
        };
        let CatalogValue::Name(name_id) =
            CatalogValue::decode(&CatalogKey::Name(label), &name.value, &self.source)?
        else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Name row mismatch",
            ));
        };
        let CatalogKey::Schema(schema_id) = CatalogKey::decode(&schema.key, &self.source)? else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Schema key mismatch",
            ));
        };
        let CatalogValue::Schema(schema_row) =
            CatalogValue::decode(&CatalogKey::Schema(schema_id), &schema.value, &self.source)?
        else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Schema row mismatch",
            ));
        };
        let CatalogKey::Namespace(namespace_id) = CatalogKey::decode(&namespace.key, &self.source)?
        else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Namespace key mismatch",
            ));
        };
        let CatalogValue::Namespace(namespace_collection) = CatalogValue::decode(
            &CatalogKey::Namespace(namespace_id),
            &namespace.value,
            &self.source,
        )?
        else {
            return Err(corrupt(
                &self.source,
                "v4 CREATE effective Namespace row mismatch",
            ));
        };
        let CatalogValue::Anchor(anchor) =
            CatalogValue::decode(&CatalogKey::Anchor, &self.rows.anchor.value, &self.source)?
        else {
            return Err(corrupt(&self.source, "v4 CREATE effective Anchor mismatch"));
        };
        let expected_head = Head {
            database_id: self.database_id,
            revision: 2,
            collection_count: 1,
        };
        if head != expected_head
            || anchor != self.anchor
            || name_id.get() != 2
            || schema_id.get() != 2
            || schema_row.namespace_id.get() != 2
            || namespace_id.get() != 2
            || namespace_collection.get() != 2
            || label != schema_row.name
        {
            return Err(corrupt(&self.source, "v4 CREATE effective triple mismatch"));
        }
        Ok(expected_head)
    }
}

impl PriorCatalog for CatalogReplayState {
    fn head_and_name_presence(&mut self, exact_key: &[u8]) -> Result<(Head, bool)> {
        if !matches!(
            CatalogKey::decode(exact_key, &self.source)?,
            CatalogKey::Name(_)
        ) {
            return Err(corrupt(
                &self.source,
                "v4 prior endpoint queried a non-Name key",
            ));
        }
        Ok((self.head, self.rows.get(exact_key).is_some()))
    }
}

#[derive(Debug)]
pub(crate) enum InstalledEndpoint {
    Empty,
    FlushedBootstrap(Box<FlushedBootstrap>),
}

#[derive(Debug)]
pub(crate) struct FlushedBootstrap {
    segment: FileWitness,
    pub(crate) binding: ([u8; 16], u32),
    pub(crate) allocator: Allocator,
    pub(crate) head: Head,
    pub(crate) anchor: Anchor,
}

#[derive(Debug)]
pub(crate) struct BootstrapEffect {
    pub(crate) cf: &'static str,
    pub(crate) key: [u8; 1],
    pub(crate) value: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct BootstrapEffects {
    pub(crate) rows: [BootstrapEffect; 4],
}

struct StagedBootstrap {
    effects: BootstrapEffects,
    binding: ([u8; 16], u32),
    allocator: Allocator,
    head: Head,
    anchor: Anchor,
}

impl StagedBootstrap {
    fn from_validated(
        frame: ValidatedCatalogFrame<'_>,
        id: [u8; 16],
        source: &Path,
    ) -> Result<Self> {
        if frame.sequence() != 1 || frame.ops().len() != 4 {
            return Err(corrupt(source, "unsupported v4 bootstrap replay cut"));
        }
        let expected = [
            (Role::Meta.cf(), [0], 80),
            (Role::Meta.cf(), [1], 56),
            (super::authority::CATALOG_CF, [0], 48),
            (super::authority::CATALOG_CF, [4], 72),
        ];
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(4)
            .map_err(|_| corrupt(source, "cannot reserve v4 bootstrap effects"))?;
        for (op, (expected_cf, expected_key, value_len)) in frame.ops().iter().zip(expected) {
            let BatchOp::Put { cf, key, value } = op else {
                return Err(corrupt(source, "v4 bootstrap effect is not plain Put"));
            };
            if cf.0 != expected_cf || key.as_slice() != expected_key || value.len() != value_len {
                return Err(corrupt(source, "v4 bootstrap effect role/length mismatch"));
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(value_len)
                .map_err(|_| corrupt(source, "cannot reserve v4 bootstrap row"))?;
            owned.extend_from_slice(value);
            staged.push(BootstrapEffect {
                cf: expected_cf,
                key: expected_key,
                value: owned,
            });
        }
        let rows: [BootstrapEffect; 4] = staged
            .try_into()
            .map_err(|_| corrupt(source, "v4 bootstrap effect count mismatch"))?;
        let RecordRow::Binding {
            database_id,
            descriptor_count,
        } = RecordRow::decode(&RecordKey::Binding, &rows[0].value, source)?
        else {
            return Err(corrupt(source, "v4 bootstrap Binding role mismatch"));
        };
        let RecordRow::Allocator(allocator) =
            RecordRow::decode(&RecordKey::Allocator, &rows[1].value, source)?
        else {
            return Err(corrupt(source, "v4 bootstrap Allocator role mismatch"));
        };
        let CatalogValue::Head(head) =
            CatalogValue::decode(&CatalogKey::Head, &rows[2].value, source)?
        else {
            return Err(corrupt(source, "v4 bootstrap Head role mismatch"));
        };
        let CatalogValue::Anchor(anchor) =
            CatalogValue::decode(&CatalogKey::Anchor, &rows[3].value, source)?
        else {
            return Err(corrupt(source, "v4 bootstrap Anchor role mismatch"));
        };
        if database_id != id
            || descriptor_count != 0
            || allocator != Allocator::default()
            || head.database_id != id
            || head.revision != 1
            || head.collection_count != 0
            || rows[2].value != canonical_head_at_1(id)?
            || anchor.database_id != id
            || anchor.head_at_1_digest != anchor_digest(id)?
        {
            return Err(corrupt(source, "v4 bootstrap recovered relation mismatch"));
        }
        Ok(Self {
            effects: BootstrapEffects { rows },
            binding: (database_id, descriptor_count),
            allocator,
            head,
            anchor,
        })
    }
}

#[derive(Debug)]
pub(crate) struct CatalogOwnerProof {
    root: PathBuf,
    manifest: FileWitness,
    pub(crate) installed: InstalledEndpoint,
    pub(crate) cut: WalCut,
    pub(crate) recovered_sequence: u64,
    pub(crate) recovered_binding: ([u8; 16], u32),
    pub(crate) recovered_allocator: Allocator,
    pub(crate) bootstrap_effects: Option<BootstrapEffects>,
    pub(crate) effective: CatalogReplayState,
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
        let (_, current) = read_bound(&self.manifest.path, self.manifest.len.max(1))?;
        if current != self.manifest || self.manifest.path != self.root.join("MANIFEST") {
            return Err(corrupt(&self.manifest.path, "v4 MANIFEST changed"));
        }
        match &self.installed {
            InstalledEndpoint::Empty => empty_paths(&self.root)?,
            InstalledEndpoint::FlushedBootstrap(installed) => {
                let paths = narrow_paths(&self.root)?;
                let segment = &installed.segment;
                let (_, current) = read_bound(&segment.path, segment.len.max(1))?;
                if current != *segment || paths.segment != segment.path {
                    return Err(corrupt(&segment.path, "v4 installed segment changed"));
                }
            }
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

fn exact_named_children<const N: usize>(dir: &Path, expected: [&str; N]) -> Result<()> {
    check_real(dir)?;
    if !fs::symlink_metadata(dir)?.is_dir() {
        return Err(corrupt(dir, "v4 empty-installed role is not a directory"));
    }
    let mut seen = [false; N];
    for item in fs::read_dir(dir)? {
        let item = item?;
        let Some(index) = expected.iter().position(|name| item.file_name() == *name) else {
            return Err(corrupt(&item.path(), "unexpected v4 empty-installed entry"));
        };
        if seen[index] {
            return Err(corrupt(&item.path(), "duplicate v4 empty-installed entry"));
        }
        seen[index] = true;
        check_real(&item.path())?;
    }
    if !seen.into_iter().all(|present| present) {
        return Err(corrupt(dir, "v4 empty-installed role is incomplete"));
    }
    Ok(())
}

fn empty_paths(root: &Path) -> Result<()> {
    exact_named_children(
        root,
        [
            "MANIFEST",
            crate::writer_lease::LOCK_FILE_NAME,
            "wal",
            "segments",
            "values",
            "checkpoints",
            "tmp",
        ],
    )?;
    let manifest = root.join("MANIFEST");
    if !fs::symlink_metadata(&manifest)?.is_file() {
        return Err(corrupt(
            &manifest,
            "v4 empty-installed MANIFEST is not a file",
        ));
    }
    let lock = root.join(crate::writer_lease::LOCK_FILE_NAME);
    let lock_meta = fs::symlink_metadata(&lock)?;
    if !lock_meta.is_file() || lock_meta.len() != 0 {
        return Err(corrupt(&lock, "v4 empty-installed lock artifact changed"));
    }
    let wal = root.join("wal");
    exact_named_children(&wal, ["00000000000000000001.wal"])?;
    let wal_file = wal.join("00000000000000000001.wal");
    if !fs::symlink_metadata(&wal_file)?.is_file() {
        return Err(corrupt(&wal_file, "v4 empty-installed WAL is not a file"));
    }
    let segments = root.join("segments");
    exact_named_children(&segments, ["0", "1"])?;
    for level in ["0", "1"] {
        exact_named_children(&segments.join(level), [])?;
    }
    for role in ["values", "checkpoints", "tmp"] {
        exact_named_children(&root.join(role), [])?;
    }
    Ok(())
}

fn inspect_unflushed_bootstrap(
    lease: &WriterLease,
    manifest: &Manifest,
    manifest_witness: FileWitness,
) -> Result<CatalogOwnerProof> {
    let root = lease.root();
    empty_paths(root)?;
    let wal_path = root.join("wal/00000000000000000001.wal");
    let record_authority = manifest
        .record_authority
        .as_ref()
        .expect("validated v4 record authority");
    let catalog_authority = manifest
        .catalog_authority
        .as_ref()
        .expect("validated v4 catalog authority");
    let id = record_authority.identity(&manifest_witness.path)?;
    let context = FrameContext::new(record_authority, catalog_authority, &wal_path)?;
    let cut = WalCut {
        flushed_sequence: 0,
        last_sequence: 1,
        flushed_wal_id: 0,
        active_wal_id: 1,
        next_wal_id: 2,
    };
    let mut staged = None;
    let wal_witnesses = scan_v4_wals(root, cut, |wal_id, start, end, record| {
        if staged.is_some() || wal_id != 1 || start != 16 || end != 579 || record.sequence() != 1 {
            return Err(corrupt(
                &wal_path,
                "unexpected v4 unflushed bootstrap frame",
            ));
        }
        if !matches!(
            record,
            CoreWalRecord::Catalog {
                control: CatalogControl::Bootstrap { .. },
                ..
            }
        ) {
            return Err(corrupt(&wal_path, "unexpected v4 unflushed frame kind"));
        }
        let validated = frame::validate_bootstrap(record, &context)?;
        staged = Some(StagedBootstrap::from_validated(validated, id, &wal_path)?);
        Ok(())
    })?;
    if wal_witnesses.len() != 1
        || wal_witnesses[0].id != 1
        || wal_witnesses[0].record_count != 1
        || wal_witnesses[0].catalog_bootstraps != 1
        || wal_witnesses[0].catalog_creates != 0
        || wal_witnesses[0].first_sequence != Some(1)
        || wal_witnesses[0].last_sequence != Some(1)
        || wal_witnesses[0].full_len != 579
        || wal_witnesses[0].prefix_len != 579
        || wal_witnesses[0].torn_start.is_some()
    {
        return Err(corrupt(
            &wal_path,
            "v4 unflushed bootstrap WAL is incomplete or has an extra tail",
        ));
    }
    let staged =
        staged.ok_or_else(|| corrupt(&wal_path, "missing v4 unflushed bootstrap frame"))?;
    let effective = CatalogReplayState::from_head_anchor(staged.head, staged.anchor, &wal_path)?;
    let proof = CatalogOwnerProof {
        root: root.to_path_buf(),
        manifest: manifest_witness,
        installed: InstalledEndpoint::Empty,
        cut,
        recovered_sequence: 1,
        recovered_binding: staged.binding,
        recovered_allocator: staged.allocator,
        bootstrap_effects: Some(staged.effects),
        effective,
        wal_witnesses,
    };
    proof.recheck(lease)?;
    Ok(proof)
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
    let manifest_path = root.join("MANIFEST");
    let (manifest_bytes, manifest_witness) = read_bound(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest = Manifest::decode(&manifest_bytes, &manifest_path)?;
    if manifest.format_version != 4 || manifest.effective_config != config.persisted() {
        return Err(corrupt(&manifest_path, "v4 config or format mismatch"));
    }
    let common_invalid = manifest.next_column_family_generation != 6
        || manifest.column_families.len() != 6
        || manifest.column_family_generations.len() != 6
        || manifest.latest_checkpoint.is_some()
        || !manifest.compaction_jobs.is_empty()
        || !manifest.tier_migrations.is_empty()
        || manifest
            .record_authority
            .as_ref()
            .is_none_or(|r| r.index_descriptor_count != 0);
    let unflushed = manifest.flushed_sequence == 0
        && manifest.last_sequence == 1
        && manifest.flushed_wal_id == 0
        && manifest.active_wal_id == 1
        && manifest.next_wal_id == 2
        && manifest.next_segment_id == 1
        && manifest.segments.is_empty();
    let flushed = manifest.flushed_sequence == 1
        && manifest.last_sequence == 1
        && manifest.flushed_wal_id == 1
        && manifest.active_wal_id == 2
        && manifest.next_wal_id == 3
        && manifest.next_segment_id == 2
        && manifest.segments.len() == 1;
    if common_invalid || (!unflushed && !flushed) {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap",
        });
    }
    if unflushed {
        return inspect_unflushed_bootstrap(lease, &manifest, manifest_witness);
    }
    let paths = narrow_paths(root)?;
    if paths.manifest != manifest_path {
        return Err(corrupt(root, "v4 MANIFEST role changed"));
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
    let wal_path = root.join("wal/00000000000000000002.wal");
    let mut effective = CatalogReplayState::from_head_anchor(head, anchor, &wal_path)?;
    let context = FrameContext::new(
        manifest
            .record_authority
            .as_ref()
            .expect("validated v4 record authority"),
        manifest
            .catalog_authority
            .as_ref()
            .expect("validated v4 catalog authority"),
        &wal_path,
    )?;
    let mut saw_create = false;
    let wal_witnesses = scan_v4_wals(root, cut, |wal_id, start, _, record| {
        if saw_create || wal_id != 2 || start != 16 || record.sequence() != 2 {
            return Err(corrupt(
                &wal_path,
                "unexpected v4 WAL frame in retired bootstrap cut",
            ));
        }
        if !matches!(
            record,
            CoreWalRecord::Catalog {
                control: CatalogControl::Create { .. },
                ..
            }
        ) {
            return Err(corrupt(&wal_path, "unexpected v4 WAL frame kind"));
        }
        let validated = frame::validate_create(record, &context, &mut effective)?;
        effective.apply_create(validated)?;
        saw_create = true;
        Ok(())
    })?;
    if wal_witnesses.len() != 1
        || wal_witnesses[0].id != 2
        || wal_witnesses[0].torn_start.is_some()
        || wal_witnesses[0].full_len != wal_witnesses[0].prefix_len
        || (saw_create
            && (wal_witnesses[0].record_count != 1
                || wal_witnesses[0].catalog_creates != 1
                || wal_witnesses[0].first_sequence != Some(2)
                || wal_witnesses[0].last_sequence != Some(2)
                || wal_witnesses[0].full_len <= 16))
        || (!saw_create && (wal_witnesses[0].record_count != 0 || wal_witnesses[0].full_len != 16))
    {
        return Err(corrupt(
            root,
            "retired bootstrap WAL has an incomplete or extra tail",
        ));
    }
    let recovered_sequence = if saw_create { 2 } else { 1 };
    if recovered_sequence < cut.last_sequence {
        return Err(corrupt(root, "v4 replay ends below manifest last sequence"));
    }
    let proof = CatalogOwnerProof {
        root: root.to_path_buf(),
        manifest: manifest_witness,
        installed: InstalledEndpoint::FlushedBootstrap(Box::new(FlushedBootstrap {
            segment: segment_witness,
            binding,
            allocator,
            head,
            anchor,
        })),
        cut,
        recovered_sequence,
        recovered_binding: binding,
        recovered_allocator: allocator,
        bootstrap_effects: None,
        effective,
        wal_witnesses,
    };
    proof.recheck(lease)?;
    Ok(proof)
}
