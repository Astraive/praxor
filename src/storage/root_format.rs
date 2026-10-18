//! Read-only physical-format diagnosis. This module never initializes or repairs storage.
//!
//! Recognition establishes an owner, not payload validity, backup portability, or
//! a stable snapshot in the presence of a concurrent writer. Writable admission
//! must repeat inspection while retaining the owner's writer lease.

use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::store::StorageManifest;
use crate::writer_lease::LOCK_FILE_NAME as LOCK_FILE;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

const CORE_WAL_MAGIC: u32 = 0x5457_4146;
const CORE_RECORD_MAGICS: [u32; 2] = [0x5457_414c, 0x5457_4132];
const POINTER_WAL_MAGIC: u32 = 0x5453_574c;
const RECORD_MAGIC: u32 = 0x5452_4543;
const PAGE_MANIFEST_MAGIC: u32 = 0x5450_4d46;
const RID_DIRECTORY_MAGIC: u32 = 0x5452_4944;
const CATALOG_MAGIC: u32 = 0x5443_4154;
pub(crate) const CORE_COPY_INCOMPLETE: &str = "CORE_COPY_INCOMPLETE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionScope {
    EngineRoot,
    /// The caller supplies the actual `.praxis` namespace, not its parent.
    PageNamespace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionOptions {
    pub scope: InspectionScope,
    /// Cumulative bytes read from typed control files, including temporary files.
    pub max_control_bytes: usize,
    /// Cumulative directory entries and referenced control paths inspected.
    pub max_entries: usize,
    /// Cumulative bytes read from fixed-size physical header probes.
    pub max_header_bytes: usize,
}

impl Default for InspectionOptions {
    fn default() -> Self {
        Self {
            scope: InspectionScope::EngineRoot,
            max_control_bytes: 8 * 1024 * 1024,
            max_entries: 4096,
            max_header_bytes: 64 * 1024,
        }
    }
}

impl InspectionOptions {
    /// Admission preserves existing cardinality: reads and allocations are
    /// bounded by actual physical control bytes and enumerated directory entries.
    /// Public diagnostic inspection retains its explicit smaller default limits.
    pub(crate) fn for_admission() -> Self {
        Self {
            max_control_bytes: usize::MAX,
            max_entries: usize::MAX,
            max_header_bytes: usize::MAX,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RootOwner {
    Core,
    Pointer,
    Record,
    Page,
}

impl fmt::Display for RootOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Core => "core KV engine",
                Self::Pointer => "pointer storage engine",
                Self::Record => "standalone record store",
                Self::Page => "page namespace",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKind {
    Absent,
    Empty,
    CoreLegacy,
    CoreRecords,
    /// Structurally valid v4 manifest; physical catalog recovery is separate.
    CoreCatalog,
    PointerLegacy,
    /// Proven empty standalone primary prepared for its pointer owner.
    PointerScaffold,
    RecordLegacy,
    PageLegacy,
    PageScaffold,
    Mixed,
    Unknown,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticKind {
    MissingAuthority,
    DamagedControl,
    UnsupportedVersion { format: &'static str, version: u64 },
    ReservedIdentity,
    UnsafeAlias,
    UnexpectedEntry,
    InspectionLimit,
    Unstable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionDiagnostic {
    pub path: PathBuf,
    pub kind: DiagnosticKind,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatEvidence {
    pub path: PathBuf,
    pub owner: RootOwner,
    pub role: &'static str,
    pub version: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    Internal,
    Relative,
    OutsideRoot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathReference {
    pub source: PathBuf,
    pub path: PathBuf,
    /// Lexical only: external references and data payloads are never opened.
    pub kind: ReferenceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootInspection {
    pub requested_path: PathBuf,
    pub canonical_path: Option<PathBuf>,
    pub kind: RootKind,
    pub candidate_owner: Option<RootOwner>,
    pub evidence: Vec<FormatEvidence>,
    pub diagnostics: Vec<InspectionDiagnostic>,
    pub path_references: Vec<PathReference>,
    /// Opaque siblings under proven matching authority; never followed or owned.
    pub auxiliary_entries: Vec<PathBuf>,
}

impl RootInspection {
    /// Evaluate captured evidence only. This neither acquires a writer lease nor
    /// guarantees the root has remained unchanged since it was inspected.
    pub fn require_compatible(&self, expected: RootOwner) -> Result<()> {
        let evidence = || {
            self.evidence
                .iter()
                .map(|item| item.path.clone())
                .chain(self.diagnostics.iter().map(|item| item.path.clone()))
                .collect()
        };
        let reason = || {
            self.diagnostics
                .iter()
                .map(|item| format!("{}: {}", item.path.display(), item.reason))
                .collect::<Vec<_>>()
                .join("; ")
        };
        if self.diagnostics.iter().any(|item| {
            matches!(
                item.kind,
                DiagnosticKind::UnsupportedVersion { .. } | DiagnosticKind::ReservedIdentity
            )
        }) {
            return Err(PraxisError::StorageFormatUnsupported {
                path: self.requested_path.clone(),
                expected,
                reason: reason(),
                evidence: evidence(),
            });
        }
        let owner = match self.kind {
            RootKind::Absent | RootKind::Empty => return Ok(()),
            RootKind::CoreLegacy | RootKind::CoreRecords | RootKind::CoreCatalog => RootOwner::Core,
            RootKind::PointerLegacy | RootKind::PointerScaffold => RootOwner::Pointer,
            RootKind::RecordLegacy => RootOwner::Record,
            RootKind::PageLegacy | RootKind::PageScaffold => RootOwner::Page,
            RootKind::Mixed | RootKind::Unknown => {
                return Err(PraxisError::StorageFormatAmbiguous {
                    path: self.requested_path.clone(),
                    expected,
                    detected: self.kind,
                    reason: if self.diagnostics.is_empty() {
                        "multiple or unknown format anchors".into()
                    } else {
                        reason()
                    },
                    evidence: evidence(),
                });
            }
            RootKind::Incomplete => {
                return Err(PraxisError::StorageFormatIncomplete {
                    path: self.requested_path.clone(),
                    expected,
                    reason: reason(),
                    evidence: evidence(),
                });
            }
        };
        if owner == expected {
            Ok(())
        } else {
            Err(PraxisError::StorageFormatMismatch {
                path: self.requested_path.clone(),
                expected,
                detected: self.kind,
                evidence: evidence(),
            })
        }
    }

    /// Legacy core recovery and offline restore may inspect, but must never
    /// adopt a structurally recognized catalog owner.
    pub(crate) fn reject_catalog_for_legacy_core(&self) -> Result<()> {
        if let Some(manifest) = self.evidence.iter().find(|item| {
            item.owner == RootOwner::Core
                && item.role == "authoritative manifest"
                && item.version == Some(4)
        }) {
            return Err(unsupported_catalog_for_legacy_core(
                &self.requested_path,
                &manifest.path,
            ));
        }
        Ok(())
    }
}

pub(crate) fn unsupported_catalog_for_legacy_core(root: &Path, manifest: &Path) -> PraxisError {
    PraxisError::StorageFormatUnsupported {
        path: root.to_path_buf(),
        expected: RootOwner::Core,
        reason: "catalog format version 4 requires a validated catalog owner".into(),
        evidence: vec![manifest.to_path_buf()],
    }
}

type ProbeResult<T> = std::result::Result<T, InspectionDiagnostic>;

struct Inspector {
    entries_left: usize,
    controls_left: usize,
    headers_left: usize,
    lock_scopes: BTreeSet<PathBuf>,
    raw_root_entries: Vec<PathBuf>,
    report: RootInspection,
}

/// Diagnose an existing root using bounded reads, without acquiring a lock,
/// creating directories, replaying WALs, loading plugins, or opening engines.
pub fn inspect_storage_root(path: &Path, options: InspectionOptions) -> Result<RootInspection> {
    let mut inspector = Inspector {
        entries_left: options.max_entries,
        controls_left: options.max_control_bytes,
        headers_left: options.max_header_bytes,
        lock_scopes: BTreeSet::new(),
        raw_root_entries: Vec::new(),
        report: RootInspection {
            requested_path: path.to_path_buf(),
            canonical_path: None,
            kind: RootKind::Absent,
            candidate_owner: None,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            path_references: Vec::new(),
            auxiliary_entries: Vec::new(),
        },
    };
    match fs::metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // A dangling root alias is evidence, not an absent database.
            if fs::symlink_metadata(path).is_ok() {
                inspector.report.kind = RootKind::Incomplete;
                inspector.report.diagnostics.push(diagnostic(
                    path,
                    DiagnosticKind::UnsafeAlias,
                    "dangling root alias",
                ));
            }
            return Ok(inspector.report);
        }
        Err(err) => return Err(err.into()),
        Ok(meta) if !meta.is_dir() => {
            inspector.report.kind = RootKind::Unknown;
            inspector.report.diagnostics.push(diagnostic(
                path,
                DiagnosticKind::UnexpectedEntry,
                "storage root is not a directory",
            ));
            return Ok(inspector.report);
        }
        Ok(_) => {}
    }
    let root = fs::canonicalize(path)?;
    inspector.report.canonical_path = Some(root.clone());
    if options.scope == InspectionScope::EngineRoot {
        inspector.lock_scopes.insert(root.clone());
    }
    match inspector.inspect(&root, options.scope) {
        Ok(kind) => inspector.report.kind = kind,
        Err(problem) => {
            inspector.report.kind = RootKind::Incomplete;
            inspector.report.diagnostics.push(problem);
        }
    }
    if fs::symlink_metadata(root.join(CORE_COPY_INCOMPLETE)).is_ok() {
        if inspector.report.kind != RootKind::Mixed {
            inspector.report.kind = RootKind::Incomplete;
        }
        inspector.report.diagnostics.push(diagnostic(
            &root.join(CORE_COPY_INCOMPLETE),
            DiagnosticKind::MissingAuthority,
            "core copy publication is incomplete; explicit retry or discard is required",
        ));
    }
    Ok(inspector.report)
}

/// Check a page application's base without claiming its unrelated siblings.
///
/// The caller must retain the base's writer lease and invoke this before page
/// layout creation. Only exact foreign control names and bounded, shallow
/// physical-artifact probes are inspected at the base. Ordinary application
/// siblings, including empty directories, are not traversed. `options.scope` is
/// overridden to `PageNamespace` for the exact `base/.praxis` child. All supplied
/// byte/entry limits still apply; no lease or concurrency guarantee is supplied.
pub fn require_page_base_compatible(base: &Path, options: InspectionOptions) -> Result<()> {
    let metadata = match fs::metadata(base) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(base).is_ok() {
                return Err(page_base_ambiguous(
                    base,
                    "dangling application-base alias",
                    vec![base.to_path_buf()],
                ));
            }
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    if !metadata.is_dir() {
        return Err(page_base_ambiguous(
            base,
            "application base is not a directory",
            vec![base.to_path_buf()],
        ));
    }
    let base = fs::canonicalize(base)?;
    match fs::symlink_metadata(base.join(LOCK_FILE)) {
        Ok(meta) if is_alias(&meta) || !meta.is_file() => {
            return Err(page_base_ambiguous(
                &base,
                "base writer lock is not an exact regular artifact",
                vec![base.join(LOCK_FILE)],
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    for name in [
        CORE_COPY_INCOMPLETE,
        "PRAXOR_ROOT",
        "PRAXOR_ROOT.tmp",
        "MANIFEST",
        "MANIFEST.store",
        "MANIFEST.tmp",
        "indirection.tind",
        "indirection.tmp",
    ] {
        let path = base.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) if name.starts_with("PRAXOR_ROOT") => {
                return Err(PraxisError::StorageFormatUnsupported {
                    path: base.clone(),
                    expected: RootOwner::Page,
                    reason: "reserved future root identity prevents page initialization".into(),
                    evidence: vec![path],
                });
            }
            Ok(_) => {
                return Err(page_base_ambiguous(
                    &base,
                    "foreign or incomplete storage control at the page application base",
                    vec![path],
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    let mut remaining = options.max_entries;
    for directory in [
        "records",
        "primary",
        "primary/records",
        "wal",
        "segments",
        "values",
        "checkpoints",
    ] {
        let path = base.join(directory);
        match fs::symlink_metadata(&path) {
            Ok(meta) if is_alias(&meta) => {
                return Err(page_base_ambiguous(
                    &base,
                    "foreign-format probe would traverse an alias",
                    vec![path],
                ));
            }
            Ok(meta) if meta.is_dir() => {
                if directory == "primary" {
                    continue;
                }
                for item in fs::read_dir(&path)? {
                    let Some(next) = remaining.checked_sub(1) else {
                        return Err(PraxisError::StorageFormatIncomplete {
                            path: base.clone(),
                            expected: RootOwner::Page,
                            reason: "page-base foreign-artifact inspection budget exhausted".into(),
                            evidence: vec![path],
                        });
                    };
                    remaining = next;
                    let item = item?;
                    let name = item.file_name();
                    let name = name.to_string_lossy();
                    if directory == "segments" && name.parse::<u32>().is_ok() {
                        let metadata = fs::symlink_metadata(item.path())?;
                        if is_alias(&metadata) {
                            return Err(page_base_ambiguous(
                                &base,
                                "core segment-level probe would traverse an alias",
                                vec![item.path()],
                            ));
                        }
                        if metadata.is_dir() {
                            for segment in fs::read_dir(item.path())? {
                                remaining = remaining.checked_sub(1).ok_or_else(|| {
                                    PraxisError::StorageFormatIncomplete {
                                        path: base.clone(),
                                        expected: RootOwner::Page,
                                        reason:
                                            "page-base segment-entry inspection budget exhausted"
                                                .into(),
                                        evidence: vec![item.path()],
                                    }
                                })?;
                                let segment = segment?;
                                if decimal_file(
                                    &segment.file_name().to_string_lossy(),
                                    "",
                                    ".tseg",
                                    20,
                                )
                                .is_some()
                                {
                                    return Err(page_base_ambiguous(
                                        &base,
                                        "orphan core segment at the page application base",
                                        vec![segment.path()],
                                    ));
                                }
                            }
                        }
                    }
                    let suspect = if directory == "wal" {
                        name == "storage.wal"
                            || decimal_file(&name, "", ".wal", 20).is_some()
                            || decimal_file(&name, "storage.", ".swal", 20).is_some()
                    } else if directory == "values" {
                        decimal_file(&name, "", ".tval", 20).is_some()
                    } else if directory == "checkpoints" {
                        decimal_file(&name, "", ".chk", 20).is_some()
                    } else if directory == "segments" {
                        decimal_file(&name, "", ".tseg", 20).is_some()
                    } else {
                        hex_file(&name, ".trec", 8).is_some()
                    };
                    if suspect {
                        return Err(page_base_ambiguous(
                            &base,
                            "format-specific physical artifact at the page application base",
                            vec![item.path()],
                        ));
                    }
                }
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    let namespace = base.join(".praxis");
    match fs::symlink_metadata(&namespace) {
        Ok(meta) if is_alias(&meta) || !meta.is_dir() => {
            return Err(page_base_ambiguous(
                &base,
                "page namespace must be a real directory within its owned base",
                vec![namespace],
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let report = inspect_storage_root(
        &namespace,
        InspectionOptions {
            scope: InspectionScope::PageNamespace,
            max_entries: remaining,
            ..options
        },
    )?;
    report.require_compatible(RootOwner::Page)
}

fn page_base_ambiguous(base: &Path, reason: &str, evidence: Vec<PathBuf>) -> PraxisError {
    PraxisError::StorageFormatAmbiguous {
        path: base.to_path_buf(),
        expected: RootOwner::Page,
        detected: RootKind::Unknown,
        reason: reason.into(),
        evidence,
    }
}

pub(crate) fn require_primary_parent_compatible(
    parent: &Path,
    options: InspectionOptions,
) -> Result<()> {
    let report = inspect_storage_root(parent, options)?;
    if report.kind == RootKind::Incomplete && report.candidate_owner == Some(RootOwner::Pointer) {
        // An independently created standalone primary may be empty or keep its
        // own complete record authority. Inspecting the exact child separately
        // admits neither unrelated contents nor pointer adoption.
        let mut remaining = options.max_entries;
        let mut exact_container = true;
        for item in fs::read_dir(parent)? {
            let Some(next) = remaining.checked_sub(1) else {
                exact_container = false;
                break;
            };
            remaining = next;
            let item = item?;
            let name = item.file_name();
            let meta = fs::symlink_metadata(item.path())?;
            if !((name == LOCK_FILE && meta.is_file() && !is_alias(&meta))
                || (name == "primary" && meta.is_dir() && !is_alias(&meta)))
            {
                exact_container = false;
                break;
            }
        }
        if exact_container {
            let child = inspect_storage_root(
                &parent.join("primary"),
                InspectionOptions {
                    max_entries: remaining,
                    ..options
                },
            )?;
            if matches!(child.kind, RootKind::Empty | RootKind::RecordLegacy) {
                return child.require_compatible(RootOwner::Record);
            }
        }
    }
    report.require_compatible(RootOwner::Pointer)
}

impl Inspector {
    fn page(&mut self, root: &Path, entries: &BTreeMap<String, Metadata>) -> ProbeResult<RootKind> {
        self.root_directories(
            root,
            entries,
            &["catalog", "config", "runtime", "logs", "data"],
        )?;
        if self.unexpected(
            root,
            entries,
            &["catalog", "config", "runtime", "logs", "data"],
        ) {
            return Ok(RootKind::Unknown);
        }
        let manifest = root.join("catalog/page-layout.manifest");
        let mut authoritative = false;
        if entries.contains_key("catalog") {
            let catalog_root = root.join("catalog");
            for (name, meta) in self.list(&catalog_root)? {
                if let Some(shape) = catalog_shape(&name) {
                    if !meta.is_file() {
                        return Err(damaged(
                            &catalog_root.join(&name),
                            "catalog control is not a regular file",
                        ));
                    }
                    if meta.len() > 0 {
                        let path = catalog_root.join(name);
                        let bytes = self.control(&path)?;
                        validate_catalog(
                            envelope(&bytes, &path, CATALOG_MAGIC, "page catalog")?,
                            shape,
                            &path,
                        )?;
                        // A catalog file by itself does not establish a page root.
                        for required in ["catalog", "config", "runtime", "logs", "data"] {
                            if !entries.get(required).is_some_and(Metadata::is_dir) {
                                return Err(diagnostic(
                                    root,
                                    DiagnosticKind::MissingAuthority,
                                    "catalog control has no complete page namespace scaffold",
                                ));
                            }
                        }
                        self.evidence(path, RootOwner::Page, "typed page catalog", Some(1));
                        authoritative = true;
                    }
                }
            }
        }
        if manifest
            .try_exists()
            .map_err(|err| damaged(&manifest, &err.to_string()))?
        {
            let bytes = self.control(&manifest)?;
            let payload = envelope(&bytes, &manifest, PAGE_MANIFEST_MAGIC, "page manifest")?;
            validate_page_manifest(payload, &manifest)?;
            self.evidence(manifest, RootOwner::Page, "page layout manifest", Some(1));
            authoritative = true;
        }
        let data = root.join("data");
        let mut collections = Vec::new();
        if entries.contains_key("data") {
            for (name, meta) in self.list(&data)? {
                let collection = data.join(&name);
                if !page_id(&name) || !meta.is_dir() {
                    return Err(damaged(&collection, "unexpected page collection entry"));
                }
                // Check known namespace boundaries without visiting page bodies.
                let collection_entries = self.list(&collection)?;
                if [
                    "MANIFEST",
                    "MANIFEST.store",
                    "records",
                    "indirection.tind",
                    ".praxis",
                    "PRAXOR_ROOT",
                    "PRAXOR_ROOT.tmp",
                ]
                .iter()
                .any(|name| collection_entries.contains_key(*name))
                {
                    return Err(damaged(
                        &collection,
                        "foreign root anchor inside a page collection",
                    ));
                }
                for (parent, child) in [
                    (collection.clone(), "kv"),
                    (collection.join("kv"), "critical"),
                ] {
                    self.check_real_child(&parent.join(child))?;
                }
                let directory = collection.join("kv/critical/rid_to_slot.kv");
                if let Ok(meta) = fs::symlink_metadata(&directory) {
                    if is_alias(&meta) {
                        return Err(diagnostic(
                            &directory,
                            DiagnosticKind::UnsafeAlias,
                            "RID directory is an alias",
                        ));
                    }
                    if meta.len() > 0 {
                        let bytes = self.control(&directory)?;
                        validate_rid_directory(
                            envelope(&bytes, &directory, RID_DIRECTORY_MAGIC, "RID directory")?,
                            &directory,
                        )?;
                        self.evidence(
                            directory,
                            RootOwner::Page,
                            "collection RID directory",
                            Some(1),
                        );
                        authoritative = true;
                    }
                }
                collections.push(collection);
            }
        }
        if authoritative {
            // We inspect catalog names, not every tracked payload or entity page.
            let catalog = root.join("catalog");
            let catalog_entries = self.list(&catalog)?;
            for (name, meta) in catalog_entries {
                if !meta.is_file()
                    || !(PAGE_ROOT_FILES
                        .iter()
                        .any(|path| *path == format!("catalog/{name}"))
                        || matches!(
                            name.as_str(),
                            "page-layout.manifest"
                                | "page-layout.tmp"
                                | "fixed_attrs.cat"
                                | "dynamic_attrs.cat"
                        ))
                {
                    return Err(damaged(
                        &catalog.join(name),
                        "unexpected page catalog entry",
                    ));
                }
            }
            return Ok(RootKind::PageLegacy);
        }
        // Without durable control authority only the complete, exact current
        // empty scaffold is recognized. This exceptional walk remains bounded.
        let mut expected = BTreeMap::new();
        add_scaffold(&mut expected, root, PAGE_ROOT_DIRS, PAGE_ROOT_FILES);
        for collection in collections {
            expected.insert(collection.clone(), true);
            add_scaffold(
                &mut expected,
                &collection,
                PAGE_COLLECTION_DIRS,
                PAGE_COLLECTION_FILES,
            );
            let entities = collection.join("entities");
            for (name, meta) in self.list(&entities)? {
                let entity = entities.join(&name);
                if !page_id(&name) || !meta.is_dir() {
                    return Err(damaged(&entity, "unexpected page entity scaffold"));
                }
                expected.insert(entity.clone(), true);
                add_scaffold(&mut expected, &entity, PAGE_ENTITY_DIRS, PAGE_ENTITY_FILES);
            }
        }
        // A managed page owner may create its WAL before its first Put. The
        // exact header is optional on an otherwise complete empty scaffold;
        // record-bearing or malformed files do not establish authority here.
        let page_wal = root.join("logs/page.wal");
        let empty_page_wal = match fs::symlink_metadata(&page_wal) {
            Ok(meta) => {
                if is_alias(&meta) || !meta.is_file() || meta.len() != 16 {
                    return Err(damaged(
                        &page_wal,
                        "empty page WAL must be an exact v1 or v2 header",
                    ));
                }
                let bytes = self.control(&page_wal)?;
                if !crate::wal::page::is_empty_header(&bytes) {
                    return Err(damaged(&page_wal, "invalid empty page WAL header"));
                }
                expected.insert(page_wal.clone(), false);
                Some(page_wal)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(damaged(&page_wal, &err.to_string())),
        };
        self.scaffold_walk(root, &mut expected, 0, empty_page_wal.as_deref())?;
        if let Some(path) = expected.keys().next() {
            return Err(diagnostic(
                path,
                DiagnosticKind::MissingAuthority,
                "incomplete page scaffold has no durable authority",
            ));
        }
        self.evidence(
            root.to_path_buf(),
            RootOwner::Page,
            "exact empty page scaffold",
            None,
        );
        Ok(RootKind::PageScaffold)
    }

    fn check_real_child(&self, path: &Path) -> ProbeResult<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) if is_alias(&meta) || !meta.is_dir() => Err(diagnostic(
                path,
                DiagnosticKind::UnsafeAlias,
                "reserved namespace child is not a real directory",
            )),
            Ok(_) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(damaged(path, &err.to_string())),
        }
    }

    fn scaffold_walk(
        &mut self,
        root: &Path,
        expected: &mut BTreeMap<PathBuf, bool>,
        depth: usize,
        empty_page_wal: Option<&Path>,
    ) -> ProbeResult<()> {
        if depth > 32 {
            return Err(diagnostic(
                root,
                DiagnosticKind::InspectionLimit,
                "page scaffold depth budget exhausted",
            ));
        }
        for (name, meta) in self.list(root)? {
            let path = root.join(name);
            let Some(directory) = expected.remove(&path) else {
                return Err(diagnostic(
                    &path,
                    DiagnosticKind::UnexpectedEntry,
                    "entry is outside the exact empty page scaffold",
                ));
            };
            let validated_header = empty_page_wal == Some(path.as_path()) && meta.len() == 16;
            if directory != meta.is_dir() || (!directory && meta.len() != 0 && !validated_header) {
                return Err(diagnostic(
                    &path,
                    DiagnosticKind::MissingAuthority,
                    "nonempty or wrong-type scaffold entry has no durable page authority",
                ));
            }
            if directory {
                self.scaffold_walk(&path, expected, depth + 1, empty_page_wal)?;
            }
        }
        Ok(())
    }

    fn inspect(&mut self, root: &Path, scope: InspectionScope) -> ProbeResult<RootKind> {
        let entries = self.list(root)?;
        if entries.is_empty() {
            if !self.raw_root_entries.is_empty() {
                self.unexpected(root, &entries, &[]);
                return Ok(RootKind::Unknown);
            }
            return Ok(RootKind::Empty);
        }
        for name in ["PRAXOR_ROOT", "PRAXOR_ROOT.tmp"] {
            if entries.contains_key(name) {
                return Err(diagnostic(
                    &root.join(name),
                    DiagnosticKind::ReservedIdentity,
                    "reserved future root identity prevents legacy fallback",
                ));
            }
        }
        let mut owners = BTreeSet::new();
        let neutral_primary = entries.contains_key("MANIFEST")
            && !entries.contains_key("MANIFEST.store")
            && entries.get("primary").is_some_and(Metadata::is_dir)
            && self.lock_only_primary(&root.join("primary"))?;
        for (name, owner) in [
            ("MANIFEST", RootOwner::Core),
            ("MANIFEST.store", RootOwner::Pointer),
            ("primary", RootOwner::Pointer),
            ("indirection.tind", RootOwner::Record),
            ("records", RootOwner::Record),
            (".praxis", RootOwner::Page),
        ] {
            if name == "primary" && neutral_primary {
                continue;
            }
            if entries.contains_key(name) {
                owners.insert(owner);
                self.evidence(root.join(name), owner, "owner anchor", None);
            }
        }
        if scope == InspectionScope::PageNamespace
            && ["catalog", "config", "runtime", "logs", "data"]
                .iter()
                .any(|name| entries.contains_key(*name))
        {
            owners.insert(RootOwner::Page);
        }
        // A shared WAL directory is not ownership authority. Its actual header
        // can expose a foreign format even if another manifest is present.
        if entries.get("wal").is_some_and(Metadata::is_dir) {
            for (name, meta) in self.list(&root.join("wal"))? {
                if !meta.is_file() {
                    continue;
                }
                let path = root.join("wal").join(&name);
                let prefix = self.prefix(&path, 16)?;
                if let Some(magic) = u32_at(&prefix, 0) {
                    let owner = if magic == POINTER_WAL_MAGIC {
                        Some(RootOwner::Pointer)
                    } else if magic == CORE_WAL_MAGIC || CORE_RECORD_MAGICS.contains(&magic) {
                        Some(RootOwner::Core)
                    } else {
                        None
                    };
                    if let Some(owner) = owner {
                        owners.insert(owner);
                        self.evidence(path, owner, "WAL prefix", None);
                    }
                }
            }
        }
        if owners.len() > 1 {
            return Ok(RootKind::Mixed);
        }
        let owner = owners.first().copied();
        self.report.candidate_owner = owner;
        match owner {
            Some(RootOwner::Core) => self.core(root, &entries),
            Some(RootOwner::Pointer) => self.pointer(root, &entries),
            Some(RootOwner::Record) => self.record(root, &entries, false),
            Some(RootOwner::Page) => {
                if scope == InspectionScope::PageNamespace {
                    self.page(root, &entries)
                } else {
                    let namespace = root.join(".praxis");
                    let page_entries = self.list(&namespace)?;
                    let kind = self.page(&namespace, &page_entries)?;
                    if self.unexpected(root, &entries, &[".praxis"]) {
                        Ok(RootKind::Unknown)
                    } else {
                        Ok(kind)
                    }
                }
            }
            None => {
                if [
                    "MANIFEST.tmp",
                    "wal",
                    "segments",
                    "values",
                    "checkpoints",
                    "indexes",
                    "tmp",
                ]
                .iter()
                .any(|name| entries.contains_key(*name))
                {
                    Err(diagnostic(
                        root,
                        DiagnosticKind::MissingAuthority,
                        "layout or temporary artifacts have no authoritative owner metadata",
                    ))
                } else {
                    self.unexpected(root, &entries, &[]);
                    Ok(RootKind::Unknown)
                }
            }
        }
    }

    fn core(&mut self, root: &Path, entries: &BTreeMap<String, Metadata>) -> ProbeResult<RootKind> {
        let path = root.join("MANIFEST");
        if !entries.contains_key("MANIFEST") {
            return Err(diagnostic(
                &path,
                DiagnosticKind::MissingAuthority,
                "core WAL has no authoritative manifest",
            ));
        }
        let bytes = self.control(&path)?;
        #[derive(Deserialize)]
        struct Header {
            format_version: u32,
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| damaged(&path, "manifest is not UTF-8"))?;
        let header: Header = toml::from_str(text)
            .map_err(|err| damaged(&path, &format!("invalid typed manifest header: {err}")))?;
        if !matches!(header.format_version, 1..=4) {
            return Err(unsupported(
                &path,
                "core manifest",
                u64::from(header.format_version),
            ));
        }
        let manifest =
            Manifest::decode(&bytes, &path).map_err(|err| damaged(&path, &err.to_string()))?;
        self.evidence(
            path.clone(),
            RootOwner::Core,
            "authoritative manifest",
            Some(u64::from(header.format_version)),
        );
        for segment in manifest.segments {
            self.reference(&path, root, &segment.path);
        }
        if let Some(checkpoint) = manifest.latest_checkpoint {
            self.reference(&path, root, &checkpoint.path);
        }
        self.temporary(root, RootOwner::Core, entries)?;
        for level in ["0", "1"] {
            self.check_real_child(&root.join("segments").join(level))?;
        }
        if let Some(meta) = entries.get("wal") {
            if !meta.is_dir() {
                return Err(damaged(
                    &root.join("wal"),
                    "WAL namespace is not a directory",
                ));
            }
            for (name, meta) in self.list(&root.join("wal"))? {
                let path = root.join("wal").join(&name);
                let Some(id) = decimal_file(&name, "", ".wal", 20) else {
                    return Err(damaged(&path, "unexpected core WAL entry"));
                };
                if !meta.is_file() {
                    return Err(damaged(&path, "core WAL entry is not a regular file"));
                }
                self.core_wal(&path, id)?;
            }
        }
        self.root_directories(
            root,
            entries,
            &["wal", "segments", "values", "checkpoints", "tmp"],
        )?;
        self.auxiliaries(
            root,
            entries,
            &[
                "MANIFEST",
                "MANIFEST.tmp",
                "primary",
                "wal",
                "segments",
                "values",
                "checkpoints",
                "tmp",
            ],
        );
        Ok(match header.format_version {
            4 => RootKind::CoreCatalog,
            3 => RootKind::CoreRecords,
            _ => RootKind::CoreLegacy,
        })
    }

    fn pointer(
        &mut self,
        root: &Path,
        entries: &BTreeMap<String, Metadata>,
    ) -> ProbeResult<RootKind> {
        let path = root.join("MANIFEST.store");
        if !entries.contains_key("MANIFEST.store") {
            return self.pointer_scaffold(root, entries);
        }
        let bytes = self.control(&path)?;
        let manifest: StorageManifest =
            serde_json::from_slice(&bytes).map_err(|err| damaged(&path, &err.to_string()))?;
        self.evidence(
            path.clone(),
            RootOwner::Pointer,
            "authoritative manifest",
            None,
        );
        for reference in manifest
            .primary_segments
            .iter()
            .chain(manifest.index_files.values().flatten())
        {
            self.reference(&path, root, reference);
        }
        self.temporary(root, RootOwner::Pointer, entries)?;
        self.root_directories(root, entries, &["primary", "indexes", "wal"])?;
        let primary = root.join("primary");
        self.lock_scopes.insert(primary.clone());
        let primary_entries = self.list(&primary)?;
        let has_wal = entries.contains_key("wal");
        let wal_evidence = self.report.evidence.iter().any(|item| {
            item.owner == RootOwner::Pointer
                && item.role == "WAL prefix"
                && item.path.starts_with(root.join("wal"))
        });
        let primary_kind = self.record(&primary, &primary_entries, wal_evidence)?;
        if primary_kind == RootKind::Mixed {
            return Ok(RootKind::Mixed);
        }
        if primary_kind != RootKind::RecordLegacy {
            return Err(damaged(
                &primary,
                "pointer primary is not a recognized record component",
            ));
        }
        let wal_entries = if has_wal {
            self.list(&root.join("wal"))?
        } else {
            BTreeMap::new()
        };
        for (name, meta) in wal_entries {
            let path = root.join("wal").join(&name);
            if !meta.is_file()
                || !(name == "storage.wal"
                    || decimal_file(&name, "storage.", ".swal", 20).is_some())
            {
                return Err(damaged(&path, "unexpected pointer WAL entry"));
            }
            let prefix = self.prefix(&path, 5)?;
            let mut expected = POINTER_WAL_MAGIC.to_le_bytes().to_vec();
            expected.push(1);
            if prefix.len() < 5 && expected.starts_with(&prefix) {
                continue;
            }
            if u32_at(&prefix, 0) != Some(POINTER_WAL_MAGIC) {
                return Err(damaged(&path, "foreign or damaged pointer WAL header"));
            }
            if prefix[4] != 1 {
                return Err(unsupported(&path, "pointer WAL", u64::from(prefix[4])));
            }
        }
        self.auxiliaries(
            root,
            entries,
            &[
                "MANIFEST.store",
                "MANIFEST.tmp",
                "primary",
                "indexes",
                "wal",
            ],
        );
        Ok(RootKind::PointerLegacy)
    }

    fn lock_only_primary(&mut self, primary: &Path) -> ProbeResult<bool> {
        let mut count = 0;
        for entry in fs::read_dir(primary).map_err(|err| damaged(primary, &err.to_string()))? {
            self.entries_left = self.entries_left.checked_sub(1).ok_or_else(|| {
                diagnostic(
                    primary,
                    DiagnosticKind::InspectionLimit,
                    "primary lock-container inspection budget exhausted",
                )
            })?;
            let entry = entry.map_err(|err| damaged(primary, &err.to_string()))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|err| damaged(primary, &err.to_string()))?;
            if entry.file_name() != LOCK_FILE || !metadata.is_file() || is_alias(&metadata) {
                return Ok(false);
            }
            count += 1;
        }
        if count == 1 {
            self.lock_scopes.insert(primary.to_path_buf());
        }
        Ok(count == 1)
    }

    fn pointer_scaffold(
        &mut self,
        root: &Path,
        entries: &BTreeMap<String, Metadata>,
    ) -> ProbeResult<RootKind> {
        if self.unexpected(root, entries, &["primary", "indexes", "wal"]) {
            return Ok(RootKind::Unknown);
        }
        self.root_directories(root, entries, &["primary", "indexes", "wal"])?;
        let primary = root.join("primary");
        self.lock_scopes.insert(primary.clone());
        let primary_entries = self.list(&primary)?;
        let primary_kind = self.record(&primary, &primary_entries, false)?;
        if primary_kind == RootKind::Mixed {
            return Ok(RootKind::Mixed);
        }
        if primary_kind != RootKind::RecordLegacy {
            return Err(damaged(&primary, "unrecognized pointer scaffold primary"));
        }
        let segments = self.list(&primary.join("records"))?;
        if segments.len() != 1
            || segments
                .get("00000000.trec")
                .is_none_or(|meta| meta.len() != 9)
        {
            return Err(diagnostic(
                &primary,
                DiagnosticKind::MissingAuthority,
                "populated primary has no authoritative pointer manifest",
            ));
        }
        if primary_entries.contains_key("indirection.tind") {
            #[derive(Deserialize)]
            struct EmptyDirectory {
                next_rid: u64,
                next_segment_id: u32,
                entries: BTreeMap<u64, serde::de::IgnoredAny>,
            }
            let path = primary.join("indirection.tind");
            let directory: EmptyDirectory = serde_json::from_slice(&self.control(&path)?)
                .map_err(|err| damaged(&path, &err.to_string()))?;
            if directory.next_rid != 0
                || directory.next_segment_id != 0
                || !directory.entries.is_empty()
            {
                return Err(diagnostic(
                    &path,
                    DiagnosticKind::MissingAuthority,
                    "primary logical IDs exist without pointer authority",
                ));
            }
        }
        if entries.contains_key("indexes") && !self.list(&root.join("indexes"))?.is_empty() {
            return Err(diagnostic(
                &root.join("indexes"),
                DiagnosticKind::MissingAuthority,
                "index payloads have no pointer manifest",
            ));
        }
        if entries.contains_key("wal") {
            for (name, meta) in self.list(&root.join("wal"))? {
                let path = root.join("wal").join(&name);
                if !meta.is_file()
                    || meta.len() != 5
                    || !(name == "storage.wal"
                        || decimal_file(&name, "storage.", ".swal", 20) == Some(1))
                {
                    return Err(diagnostic(
                        &path,
                        DiagnosticKind::MissingAuthority,
                        "WAL payload has no pointer manifest",
                    ));
                }
                let bytes = self.prefix(&path, 5)?;
                if u32_at(&bytes, 0) != Some(POINTER_WAL_MAGIC) || bytes[4] != 1 {
                    return Err(damaged(&path, "invalid empty pointer scaffold WAL header"));
                }
            }
        }
        self.evidence(
            primary,
            RootOwner::Pointer,
            "proven empty pointer scaffold",
            None,
        );
        Ok(RootKind::PointerScaffold)
    }

    fn record(
        &mut self,
        root: &Path,
        entries: &BTreeMap<String, Metadata>,
        wal_recovery: bool,
    ) -> ProbeResult<RootKind> {
        for name in ["PRAXOR_ROOT", "PRAXOR_ROOT.tmp"] {
            if entries.contains_key(name) {
                return Err(diagnostic(
                    &root.join(name),
                    DiagnosticKind::ReservedIdentity,
                    "reserved identity inside a record component prevents legacy fallback",
                ));
            }
        }
        for (name, owner) in [
            ("MANIFEST", RootOwner::Core),
            ("MANIFEST.store", RootOwner::Pointer),
            ("MANIFEST.tmp", RootOwner::Pointer),
            ("primary", RootOwner::Pointer),
            (".praxis", RootOwner::Page),
        ] {
            if entries.contains_key(name) {
                self.evidence(root.join(name), owner, "foreign nested root anchor", None);
                return Ok(RootKind::Mixed);
            }
        }
        if entries.get("wal").is_some_and(Metadata::is_dir) {
            for (name, meta) in self.list(&root.join("wal"))? {
                let path = root.join("wal").join(name);
                if !meta.is_file() {
                    return Err(diagnostic(
                        &path,
                        DiagnosticKind::UnsafeAlias,
                        "WAL component entries must be regular files",
                    ));
                }
                let prefix = self.prefix(&path, 16)?;
                let owner = match u32_at(&prefix, 0) {
                    Some(POINTER_WAL_MAGIC) => Some(RootOwner::Pointer),
                    Some(CORE_WAL_MAGIC | 0x5457_414c | 0x5457_4132) => Some(RootOwner::Core),
                    Some(0x5450_5746) => Some(RootOwner::Page),
                    _ => None,
                };
                if let Some(owner) = owner {
                    self.evidence(path, owner, "foreign nested WAL prefix", None);
                    return Ok(RootKind::Mixed);
                }
            }
        }
        let records = root.join("records");
        let segments = self.list(&records)?;
        if segments.is_empty() {
            return Err(diagnostic(
                &records,
                DiagnosticKind::MissingAuthority,
                "record store has no initial segment",
            ));
        }
        let mut probe_names = BTreeSet::new();
        if entries.contains_key("indirection.tind") {
            let path = root.join("indirection.tind");
            #[derive(Deserialize)]
            struct Directory {
                next_rid: u64,
                next_segment_id: u32,
                entries: BTreeMap<u64, DirectoryEntry>,
            }
            #[derive(Deserialize)]
            struct DirectoryEntry {
                location: crate::store::PhysicalLocation,
                alive: bool,
            }
            let directory: Directory = serde_json::from_slice(&self.control(&path)?)
                .map_err(|err| damaged(&path, &format!("invalid record directory: {err}")))?;
            if directory
                .entries
                .keys()
                .any(|id| *id == 0 || *id > directory.next_rid)
            {
                return Err(damaged(
                    &path,
                    "record directory has invalid logical record counters",
                ));
            }
            let active = format!("{:08x}.trec", directory.next_segment_id);
            if !segments.contains_key(&active) {
                return Err(damaged(
                    &path,
                    "record directory references a missing active segment",
                ));
            }
            probe_names.insert(active);
            for entry in directory.entries.values().filter(|entry| entry.alive) {
                if !segments.contains_key(&format!("{:08x}.trec", entry.location.segment_id)) {
                    return Err(damaged(
                        &path,
                        "record directory references a missing live segment",
                    ));
                }
            }
            self.evidence(
                path,
                RootOwner::Record,
                "record indirection directory",
                None,
            );
        } else if !wal_recovery
            && (segments.len() != 1
                || segments
                    .get("00000000.trec")
                    .is_none_or(|meta| meta.len() != 9))
        {
            return Err(diagnostic(
                &records,
                DiagnosticKind::MissingAuthority,
                "only the header-only initial record segment is unambiguous without an indirection directory",
            ));
        }
        if let Some(name) = segments.keys().next() {
            probe_names.insert(name.clone());
        }
        // Fixed header probes only: record bodies remain the owner's responsibility.
        for (name, meta) in &segments {
            let path = records.join(name);
            let Some(id) = hex_file(name, ".trec", 8) else {
                return Err(damaged(&path, "unexpected record segment entry"));
            };
            if !meta.is_file() {
                return Err(damaged(&path, "record segment is not a regular file"));
            }
            if !probe_names.contains(name) {
                continue;
            }
            let prefix = self.prefix(&path, 9)?;
            if prefix.len() != 9 || u32_at(&prefix, 0) != Some(RECORD_MAGIC) {
                return Err(damaged(&path, "invalid record segment header"));
            }
            if prefix[4] != 1 {
                return Err(unsupported(&path, "record segment", u64::from(prefix[4])));
            }
            if u32_at(&prefix, 5) != Some(id) {
                return Err(damaged(
                    &path,
                    "record segment ID differs from its filename",
                ));
            }
        }
        self.evidence(
            records,
            RootOwner::Record,
            "record segment namespace",
            Some(1),
        );
        self.auxiliaries(
            root,
            entries,
            &["records", "indirection.tind", "indirection.tmp"],
        );
        Ok(RootKind::RecordLegacy)
    }

    fn core_wal(&mut self, path: &Path, id: u64) -> ProbeResult<()> {
        let prefix = self.prefix(path, 16)?;
        let mut expected = CORE_WAL_MAGIC.to_le_bytes().to_vec();
        expected.extend_from_slice(&1_u32.to_le_bytes());
        expected.extend_from_slice(&id.to_le_bytes());
        if prefix.len() < 16 && expected.starts_with(&prefix) {
            return Ok(());
        }
        if u32_at(&prefix, 0).is_some_and(|magic| CORE_RECORD_MAGICS.contains(&magic)) {
            return Ok(());
        }
        if prefix.len() < 4
            && CORE_RECORD_MAGICS
                .iter()
                .any(|magic| magic.to_le_bytes().starts_with(&prefix))
        {
            return Ok(());
        }
        if u32_at(&prefix, 0) != Some(CORE_WAL_MAGIC) {
            return Err(damaged(path, "foreign or damaged core WAL header"));
        }
        let Some(version) = u32_at(&prefix, 4) else {
            return Err(damaged(path, "damaged core WAL version prefix"));
        };
        if version != 1 {
            return Err(unsupported(path, "core WAL", u64::from(version)));
        }
        if prefix.len() != 16 || prefix[8..16] != id.to_le_bytes() {
            return Err(damaged(
                path,
                "core WAL header ID differs from its filename",
            ));
        }
        Ok(())
    }

    fn temporary(
        &mut self,
        root: &Path,
        owner: RootOwner,
        entries: &BTreeMap<String, Metadata>,
    ) -> ProbeResult<()> {
        if !entries.contains_key("MANIFEST.tmp") {
            return Ok(());
        }
        let path = root.join("MANIFEST.tmp");
        let bytes = self.control(&path)?;
        let first = bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace());
        // Own interrupted writes are recovery leftovers, not fresh authority.
        // The two live formats serialize different control languages.
        let foreign = match owner {
            RootOwner::Core => first == Some(b'{'),
            RootOwner::Pointer => {
                first != Some(b'{')
                    && std::str::from_utf8(&bytes)
                        .is_ok_and(|text| text.trim_start().starts_with("format_version"))
            }
            _ => false,
        };
        if foreign {
            return Err(damaged(
                &path,
                "temporary manifest contains a foreign owner's control format",
            ));
        }
        if owner == RootOwner::Core {
            #[derive(Deserialize)]
            struct Header {
                format_version: u32,
            }
            if let Ok(text) = std::str::from_utf8(&bytes)
                && let Ok(Header { format_version: 4 }) = toml::from_str::<Header>(text)
            {
                Manifest::decode(&bytes, &path).map_err(|err| damaged(&path, &err.to_string()))?;
                return Err(unsupported(&path, "core temporary manifest", 4));
            }
        }
        Ok(())
    }

    fn root_directories(
        &self,
        root: &Path,
        entries: &BTreeMap<String, Metadata>,
        names: &[&str],
    ) -> ProbeResult<()> {
        for name in names {
            if entries.get(*name).is_some_and(|meta| !meta.is_dir()) {
                return Err(damaged(
                    &root.join(name),
                    "owned namespace is not a directory",
                ));
            }
        }
        Ok(())
    }

    fn reference(&mut self, source: &Path, root: &Path, reference: &str) {
        let path = PathBuf::from(reference);
        let kind = if !path.is_absolute() {
            ReferenceKind::Relative
        } else if path.starts_with(root)
            && !path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            ReferenceKind::Internal
        } else {
            ReferenceKind::OutsideRoot
        };
        self.report.path_references.push(PathReference {
            source: source.to_path_buf(),
            path,
            kind,
        });
    }

    fn evidence(
        &mut self,
        path: PathBuf,
        owner: RootOwner,
        role: &'static str,
        version: Option<u64>,
    ) {
        self.report.evidence.push(FormatEvidence {
            path,
            owner,
            role,
            version,
        });
    }

    fn auxiliaries(&mut self, root: &Path, entries: &BTreeMap<String, Metadata>, allowed: &[&str]) {
        if self.report.canonical_path.as_deref() == Some(root) {
            self.report
                .auxiliary_entries
                .extend(self.raw_root_entries.iter().cloned());
        }
        for name in entries
            .keys()
            .filter(|name| !allowed.contains(&name.as_str()))
        {
            self.report.auxiliary_entries.push(root.join(name));
        }
    }

    fn unexpected(
        &mut self,
        root: &Path,
        entries: &BTreeMap<String, Metadata>,
        allowed: &[&str],
    ) -> bool {
        let mut found = false;
        if self.report.canonical_path.as_deref() == Some(root) {
            for path in &self.raw_root_entries {
                found = true;
                self.report.diagnostics.push(diagnostic(
                    path,
                    DiagnosticKind::UnexpectedEntry,
                    "unrecognized root entry has no authoritative owner",
                ));
            }
        }
        for name in entries
            .keys()
            .filter(|name| !allowed.contains(&name.as_str()))
        {
            found = true;
            self.report.diagnostics.push(diagnostic(
                &root.join(name),
                DiagnosticKind::UnexpectedEntry,
                "entry is outside the recognized owner's root layout",
            ));
        }
        found
    }

    fn list(&mut self, path: &Path) -> ProbeResult<BTreeMap<String, Metadata>> {
        let meta = fs::symlink_metadata(path).map_err(|err| damaged(path, &err.to_string()))?;
        if is_alias(&meta) || !meta.is_dir() {
            return Err(diagnostic(
                path,
                DiagnosticKind::UnsafeAlias,
                "expected a real owned directory, without a symlink or reparse point",
            ));
        }
        let mut entries = BTreeMap::new();
        for entry in fs::read_dir(path).map_err(|err| damaged(path, &err.to_string()))? {
            self.entries_left = self.entries_left.checked_sub(1).ok_or_else(|| {
                diagnostic(
                    path,
                    DiagnosticKind::InspectionLimit,
                    "directory entry inspection budget exhausted",
                )
            })?;
            let entry = entry.map_err(|err| damaged(path, &err.to_string()))?;
            let child = entry.path();
            let meta = fs::symlink_metadata(&child)
                .map_err(|err| diagnostic(&child, DiagnosticKind::Unstable, &err.to_string()))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                if self.report.canonical_path.as_deref() == Some(path) {
                    self.raw_root_entries.push(child);
                    continue;
                }
                return Err(diagnostic(
                    &child,
                    DiagnosticKind::UnexpectedEntry,
                    "non-UTF-8 entry is not a known format anchor",
                ));
            };
            if is_alias(&meta) && reserved_name(&name) {
                return Err(diagnostic(
                    &child,
                    DiagnosticKind::UnsafeAlias,
                    "reserved owner entry is a symlink or reparse point",
                ));
            }
            if name == LOCK_FILE && meta.is_file() && self.lock_scopes.contains(path) {
                continue;
            }
            if name == LOCK_FILE {
                return Err(diagnostic(
                    &child,
                    if meta.is_file() {
                        DiagnosticKind::UnexpectedEntry
                    } else {
                        DiagnosticKind::UnsafeAlias
                    },
                    if meta.is_file() {
                        "writer lock is outside a recognized ownership scope"
                    } else {
                        "permanent writer lock is not a regular file"
                    },
                ));
            }
            entries.insert(name, meta);
        }
        Ok(entries)
    }

    fn control(&mut self, path: &Path) -> ProbeResult<Vec<u8>> {
        let bytes = read_bounded(path, self.controls_left, false)?;
        self.controls_left -= bytes.len();
        Ok(bytes)
    }

    fn prefix(&mut self, path: &Path, count: usize) -> ProbeResult<Vec<u8>> {
        if self.headers_left < count {
            return Err(diagnostic(
                path,
                DiagnosticKind::InspectionLimit,
                "physical header probe budget exhausted",
            ));
        }
        let bytes = read_bounded(path, count, true)?;
        self.headers_left -= bytes.len();
        Ok(bytes)
    }
}

fn read_bounded(path: &Path, limit: usize, prefix_only: bool) -> ProbeResult<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|err| damaged(path, &err.to_string()))?;
    if is_alias(&before) || !before.is_file() {
        return Err(diagnostic(
            path,
            DiagnosticKind::UnsafeAlias,
            "control or header must be a regular file",
        ));
    }
    if !prefix_only && before.len() > limit as u64 {
        return Err(diagnostic(
            path,
            DiagnosticKind::InspectionLimit,
            "control-file byte inspection budget exhausted",
        ));
    }
    let file = File::open(path).map_err(|err| damaged(path, &err.to_string()))?;
    let physical_len = usize::try_from(if prefix_only {
        before.len().min(limit as u64)
    } else {
        before.len()
    })
    .map_err(|_| {
        diagnostic(
            path,
            DiagnosticKind::InspectionLimit,
            "physical control size does not fit this process address space",
        )
    })?;
    let requested = if prefix_only {
        limit.min(physical_len)
    } else {
        physical_len.checked_add(1).ok_or_else(|| {
            diagnostic(
                path,
                DiagnosticKind::InspectionLimit,
                "physical control size exceeds the inspection address space",
            )
        })?
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(requested).map_err(|_| {
        diagnostic(
            path,
            DiagnosticKind::InspectionLimit,
            "cannot reserve memory for actual physical control bytes",
        )
    })?;
    file.take(requested as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| damaged(path, &err.to_string()))?;
    let after = fs::symlink_metadata(path)
        .map_err(|err| diagnostic(path, DiagnosticKind::Unstable, &err.to_string()))?;
    if is_alias(&after)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || (!prefix_only && bytes.len() as u64 != before.len())
    {
        return Err(diagnostic(
            path,
            DiagnosticKind::Unstable,
            "control file changed during inspection",
        ));
    }
    if !prefix_only && bytes.len() > limit {
        return Err(diagnostic(
            path,
            DiagnosticKind::InspectionLimit,
            "control-file byte inspection budget exhausted",
        ));
    }
    Ok(bytes)
}

fn is_alias(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn reserved_name(name: &str) -> bool {
    matches!(
        name,
        LOCK_FILE
            | "PRAXOR_ROOT"
            | "PRAXOR_ROOT.tmp"
            | "MANIFEST"
            | "MANIFEST.store"
            | "MANIFEST.tmp"
            | "primary"
            | "records"
            | "indirection.tind"
            | "indirection.tmp"
            | "wal"
            | "segments"
            | "values"
            | "checkpoints"
            | "tmp"
            | "indexes"
            | ".praxis"
            | "catalog"
            | "config"
            | "runtime"
            | "logs"
            | "data"
    )
}

fn diagnostic(path: &Path, kind: DiagnosticKind, reason: &str) -> InspectionDiagnostic {
    InspectionDiagnostic {
        path: path.to_path_buf(),
        kind,
        reason: reason.to_owned(),
    }
}
fn damaged(path: &Path, reason: &str) -> InspectionDiagnostic {
    diagnostic(path, DiagnosticKind::DamagedControl, reason)
}
fn unsupported(path: &Path, format: &'static str, version: u64) -> InspectionDiagnostic {
    diagnostic(
        path,
        DiagnosticKind::UnsupportedVersion { format, version },
        &format!("{format} format version {version} is unsupported"),
    )
}
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}
fn decimal_file(name: &str, prefix: &str, suffix: &str, width: usize) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    (digits.len() == width && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}
fn hex_file(name: &str, suffix: &str, width: usize) -> Option<u32> {
    let digits = name.strip_suffix(suffix)?;
    (digits.len() == width && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(digits, 16).ok())
        .flatten()
}

fn page_id(name: &str) -> bool {
    u32::from_str_radix(name, 16).is_ok_and(|value| format!("{value:04x}") == name)
}

fn add_scaffold(
    expected: &mut BTreeMap<PathBuf, bool>,
    root: &Path,
    directories: &[&str],
    files: &[&str],
) {
    for (paths, is_dir) in [(directories, true), (files, false)] {
        for path in paths {
            let path = root.join(path);
            let mut parent = path.parent();
            while let Some(at) = parent.filter(|at| *at != root) {
                expected.insert(at.to_path_buf(), true);
                parent = at.parent();
            }
            expected.insert(path, is_dir);
        }
    }
}

fn envelope<'a>(
    bytes: &'a [u8],
    path: &Path,
    magic: u32,
    format: &'static str,
) -> ProbeResult<&'a [u8]> {
    if bytes.len() < 13 || u32_at(bytes, 0) != Some(magic) {
        return Err(damaged(path, "invalid binary control envelope"));
    }
    if bytes[4] != 1 {
        return Err(unsupported(path, format, u64::from(bytes[4])));
    }
    let len = u32_at(bytes, 5).expect("bounded envelope") as usize;
    let payload = bytes.get(13..).expect("bounded envelope");
    if len != payload.len() {
        return Err(damaged(
            path,
            "binary control length differs from remaining bytes",
        ));
    }
    if Some(crate::io::crc32_ieee(payload)) != u32_at(bytes, 9) {
        return Err(damaged(path, "binary control checksum mismatch"));
    }
    Ok(payload)
}

fn validate_rid_directory(bytes: &[u8], path: &Path) -> ProbeResult<()> {
    let Some(count) = u32_at(bytes, 16) else {
        return Err(damaged(path, "truncated RID directory counters"));
    };
    let remaining = bytes.len() - 20;
    if count as usize != remaining / 28 || !remaining.is_multiple_of(28) {
        return Err(damaged(
            path,
            "RID mapping count exceeds or differs from remaining fixed-size entries",
        ));
    }
    Ok(())
}

fn validate_page_manifest(bytes: &[u8], path: &Path) -> ProbeResult<()> {
    let Some(count) = u32_at(bytes, 0) else {
        return Err(damaged(path, "truncated page manifest count"));
    };
    if count as usize > (bytes.len() - 4) / 17 {
        return Err(damaged(
            path,
            "page manifest count exceeds remaining entries",
        ));
    }
    let mut cursor = 4_usize;
    for _ in 0..count {
        for field in 0..3 {
            let Some(len) = u32_at(bytes, cursor) else {
                return Err(damaged(path, "truncated page manifest field length"));
            };
            cursor += 4;
            let Some(end) = cursor.checked_add(len as usize) else {
                return Err(damaged(path, "page manifest field length overflow"));
            };
            let Some(text) = bytes.get(cursor..end) else {
                return Err(damaged(path, "page manifest field exceeds remaining bytes"));
            };
            if std::str::from_utf8(text).is_err() {
                return Err(damaged(path, "page manifest field is not UTF-8"));
            }
            cursor = end;
            if field == 1 {
                cursor = cursor
                    .checked_add(4)
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| damaged(path, "truncated tracked format version"))?;
            }
        }
        cursor = cursor
            .checked_add(1)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| damaged(path, "truncated recoverability flag"))?;
    }
    if cursor != bytes.len() {
        return Err(damaged(path, "trailing page manifest bytes"));
    }
    Ok(())
}

fn catalog_shape(name: &str) -> Option<&'static [u8]> {
    // Zero denotes a length-prefixed UTF-8 string; positive values are fixed
    // field widths. No existing decoder with count-based reserves is called.
    match name {
        "collections.cat" | "fulltext.cat" | "users.cat" => Some(&[4, 0, 0]),
        "entities.cat" => Some(&[4, 4, 0, 1, 0, 1]),
        "fixed_attrs.cat" | "dynamic_attrs.cat" => Some(&[4, 4, 0, 1, 1]),
        "indexes.cat" => Some(&[4, 4, 0, 0, 0]),
        "vector_models.cat" => Some(&[4, 0, 4, 0]),
        "graph.cat" => Some(&[4, 0, 1]),
        "shards.cat" => Some(&[4, 4, 0, 0]),
        _ => None,
    }
}

fn validate_catalog(bytes: &[u8], shape: &[u8], path: &Path) -> ProbeResult<()> {
    let Some(count) = u32_at(bytes, 0) else {
        return Err(damaged(path, "truncated catalog count"));
    };
    let minimum: usize = shape
        .iter()
        .map(|size| if *size == 0 { 4 } else { usize::from(*size) })
        .sum();
    if count as usize > (bytes.len() - 4) / minimum {
        return Err(damaged(path, "catalog count exceeds remaining entries"));
    }
    let mut cursor = 4_usize;
    for _ in 0..count {
        for width in shape {
            if *width == 0 {
                let Some(len) = u32_at(bytes, cursor) else {
                    return Err(damaged(path, "truncated catalog string length"));
                };
                cursor += 4;
                let end = cursor
                    .checked_add(len as usize)
                    .ok_or_else(|| damaged(path, "catalog string length overflow"))?;
                let text = bytes
                    .get(cursor..end)
                    .ok_or_else(|| damaged(path, "catalog string exceeds remaining bytes"))?;
                if std::str::from_utf8(text).is_err() {
                    return Err(damaged(path, "catalog string is not UTF-8"));
                }
                cursor = end;
            } else {
                cursor = cursor
                    .checked_add(usize::from(*width))
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| damaged(path, "truncated catalog fixed field"))?;
            }
        }
    }
    if cursor != bytes.len() {
        return Err(damaged(path, "trailing catalog bytes"));
    }
    Ok(())
}

const PAGE_ROOT_DIRS: &[&str] = &[
    "catalog",
    "config",
    "runtime/sockets",
    "runtime/locks",
    "runtime/sessions",
    "logs",
    "data",
];
const PAGE_ROOT_FILES: &[&str] = &[
    "config/engine.toml",
    "config/cache.toml",
    "config/compaction.toml",
    "config/wal.toml",
    "config/tiers.toml",
    "runtime/pid",
    "logs/engine.log",
    "logs/wal.log",
    "logs/compaction.log",
    "logs/query.log",
    "logs/recovery.log",
    "catalog/collections.cat",
    "catalog/entities.cat",
    "catalog/indexes.cat",
    "catalog/vector_models.cat",
    "catalog/fulltext.cat",
    "catalog/graph.cat",
    "catalog/shards.cat",
    "catalog/users.cat",
];
const PAGE_COLLECTION_DIRS: &[&str] = &[
    "meta",
    "wal/active",
    "wal/archived",
    "kv/levels/L0",
    "kv/levels/L1",
    "kv/levels/L2",
    "kv/levels/Ln",
    "kv/critical",
    "kv/secondary",
    "kv/cache",
    "entities",
    "pit/commits",
    "pit/branches",
    "pit/snapshots",
    "pit/timelines",
    "pit/gc",
    "pit/packfiles",
    "pit/recovery",
    "tiers/hot",
    "tiers/warm",
    "tiers/cold",
    "ops/transactions",
    "ops/checkpoints",
    "ops/recovery",
    "ops/metrics",
    "ops/planner",
    "ops/scheduler",
    "ops/telemetry",
    "tmp/compaction",
    "tmp/restore",
    "tmp/import",
    "tmp/rebuild",
];
const PAGE_COLLECTION_FILES: &[&str] = &[
    "meta/collection.meta",
    "meta/collection.stats",
    "meta/collection.config",
    "meta/retention.policy",
    "wal/wal.meta",
    "wal/checkpoint",
    "kv/manifest",
    "kv/memtable.wal",
    "kv/critical/rid_to_slot.kv",
    "kv/critical/rid_to_page.kv",
    "kv/critical/rid_to_entity.kv",
    "kv/critical/locks.kv",
    "kv/critical/commit_state.kv",
    "kv/critical/sequence.kv",
    "kv/secondary/value_to_rid.kv",
    "kv/secondary/edge_out.kv",
    "kv/secondary/edge_in.kv",
    "kv/secondary/text_lookup.kv",
    "kv/secondary/vector_lookup.kv",
    "kv/secondary/time_to_commit.kv",
    "kv/cache/bloom.filters",
    "kv/cache/hot.keys",
    "kv/cache/key.stats",
];
const PAGE_ENTITY_DIRS: &[&str] = &[
    "schema/sql",
    "schema/sql/fixed_attrs",
    "schema/nosql",
    "schema/nosql/dynamic_attrs",
    "pages/frames",
    "slots",
    "overflow/0001/0001/values",
    "overflow",
    "indexes/primary",
    "indexes/primary/btree",
    "indexes/primary/hash",
    "indexes/secondary",
    "indexes/secondary/range",
    "indexes/secondary/bitmap",
    "indexes/secondary/hash",
    "indexes/secondary/composite",
    "indexes/secondary/unique",
    "indexes/text",
    "indexes/vector",
    "indexes/vector/embeddings",
    "indexes/graph",
    "vectors",
    "vectors/models",
    "vectors/pages",
    "vectors/sparse",
    "vectors/quantized",
    "fulltext",
    "fulltext/pages",
    "fulltext/postings",
    "graph",
    "graph/nodes",
    "graph/relationships",
    "graph/adjacency",
    "graph/traversal",
    "graph/subgraphs",
    "graph/paths",
    "history",
    "history/commits",
    "history/snapshots",
    "history/branches",
    "history/deltas",
    "history/timelines",
    "history/gc",
    "compaction",
    "cache",
    "cache/hot",
    "cache/warm",
    "cache/cold",
    "cache/bloom",
    "cache/query",
    "cache/vectors",
    "analytics",
    "analytics/materialized",
    "analytics/rollups",
    "analytics/aggregates",
    "analytics/timeseries",
    "analytics/summaries",
];
const PAGE_ENTITY_FILES: &[&str] = &[
    "entity.meta",
    "entity.stats",
    "layout.bin",
    "rid.map",
    "page.map",
    "slot.map",
    "schema/schema.meta",
    "schema/schema.version",
    "schema/sql/columns.cat",
    "schema/sql/constraints.cat",
    "schema/sql/defaults.cat",
    "schema/sql/types.cat",
    "schema/sql/nullable.bitmap",
    "schema/sql/layout.idx",
    "schema/nosql/fields.cat",
    "schema/nosql/dynamic_keys.cat",
    "schema/nosql/codecs.cat",
    "schema/nosql/inferred_types.cat",
    "schema/nosql/validators.cat",
    "pages/page.catalog",
    "pages/free.pages",
    "pages/dirty.pages",
    "pages/hot.pages",
    "indexes/primary/primary.idx",
    "indexes/primary/primary.btree",
    "indexes/primary/primary.hash",
    "indexes/text/lexicon.idx",
    "indexes/text/gin.idx",
    "indexes/text/bm25.idx",
    "indexes/text/tokenizer.meta",
    "indexes/vector/hnsw.idx",
    "indexes/vector/ivf.idx",
    "indexes/vector/pq.codebook",
    "indexes/vector/quant.meta",
    "indexes/graph/edge_out.idx",
    "indexes/graph/edge_in.idx",
    "indexes/graph/degree.idx",
    "indexes/graph/traversal.idx",
    "indexes/graph/path.idx",
    "vectors/vector.meta",
    "fulltext/fts.meta",
    "fulltext/tokenizer.meta",
    "fulltext/stopwords.txt",
    "compaction/compact.plan",
    "compaction/relocation.log",
    "compaction/forwarding.idx",
    "compaction/tombstones.idx",
    "compaction/vacuum.queue",
    "compaction/rewrite.map",
];
