use praxis::catalog::CatalogStore;
use praxis::manifest::Manifest;
use praxis::record::PageRecordStore;
use praxis::storage::root_format::{
    DiagnosticKind, InspectionOptions, InspectionScope, ReferenceKind, RootInspection, RootKind,
    RootOwner, inspect_storage_root, require_page_base_compatible,
};
use praxis::store::{RecordStore, StorageEngine};
use praxis::{Aid, Cid, Eid, FieldId, PraxisConfig, PraxisEngine, PraxisError};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Alias(PathBuf),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        if !at.exists() {
            return;
        }
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let ty = entry.file_type().unwrap();
            let value = if ty.is_symlink() {
                Entry::Alias(fs::read_link(&path).unwrap())
            } else if ty.is_dir() {
                Entry::Directory
            } else {
                Entry::File(fs::read(&path).unwrap())
            };
            out.insert(path.strip_prefix(root).unwrap().to_path_buf(), value);
            if ty.is_dir() && !ty.is_symlink() {
                visit(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn inspect(root: &Path, options: InspectionOptions) -> RootInspection {
    let before = tree(root);
    let existed = root.exists();
    let report = inspect_storage_root(root, options).unwrap();
    assert_eq!(
        tree(root),
        before,
        "inspection changed file bytes or directory entries"
    );
    assert_eq!(root.exists(), existed, "inspection created the root");
    report
}

fn check(root: &Path, kind: RootKind) -> RootInspection {
    let report = inspect(root, InspectionOptions::default());
    assert_eq!(report.kind, kind, "{report:#?}");
    report
}

fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn core_manifest(root: &Path, version: u32) {
    let mut manifest = Manifest::fresh(&PraxisConfig::new(root));
    manifest.format_version = version;
    if version == 1 {
        manifest.column_family_generations.clear();
    }
    write(root, "MANIFEST", toml::to_string(&manifest).unwrap());
}

fn binary_control(magic: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = magic.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&praxis::io::crc32_ieee(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn absent_empty_and_exact_regular_lock_are_nonmutating_and_creatable() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing");
    check(&missing, RootKind::Absent)
        .require_compatible(RootOwner::Core)
        .unwrap();
    check(dir.path(), RootKind::Empty);
    write(dir.path(), ".praxor.writer.lock", b"opaque lock bytes");
    check(dir.path(), RootKind::Empty)
        .require_compatible(RootOwner::Pointer)
        .unwrap();
    write(dir.path(), ".hidden-data", b"do not ignore me");
    assert!(matches!(
        check(dir.path(), RootKind::Unknown).require_compatible(RootOwner::Core),
        Err(PraxisError::StorageFormatAmbiguous { .. })
    ));
}

#[test]
fn manifest_versions_and_unsigned_fields_are_typed_without_rewriting_v1() {
    for version in [1, 2] {
        let dir = tempdir().unwrap();
        core_manifest(dir.path(), version);
        let report = check(dir.path(), RootKind::CoreLegacy);
        report.require_compatible(RootOwner::Core).unwrap();
        assert!(matches!(
            report.require_compatible(RootOwner::Pointer),
            Err(PraxisError::StorageFormatMismatch { .. })
        ));
    }
    let dir = tempdir().unwrap();
    let mut manifest = Manifest::fresh(&PraxisConfig::new(dir.path()));
    manifest.column_families[0].options.ttl_seconds = Some(u64::MAX);
    write(dir.path(), "MANIFEST", toml::to_string(&manifest).unwrap());
    check(dir.path(), RootKind::CoreLegacy);
}

#[test]
fn real_core_pointer_and_record_roots_are_recognized() {
    let dir = tempdir().unwrap();
    drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
    check(dir.path(), RootKind::CoreLegacy);
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.put(b"acknowledged", &[]).unwrap();
    drop(pointer);
    check(dir.path(), RootKind::PointerLegacy);
    let dir = tempdir().unwrap();
    let mut record = RecordStore::open(dir.path()).unwrap();
    record.put(b"payload").unwrap();
    record.flush().unwrap();
    drop(record);
    check(dir.path(), RootKind::RecordLegacy);
}

#[test]
fn header_only_unwritten_record_store_is_supported_but_orphan_payload_is_not() {
    let dir = tempdir().unwrap();
    drop(RecordStore::open(dir.path()).unwrap());
    check(dir.path(), RootKind::RecordLegacy);
    let mut bytes = fs::read(dir.path().join("records/00000000.trec")).unwrap();
    bytes.push(42);
    write(dir.path(), "records/00000000.trec", bytes);
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn nested_pointer_primary_is_a_component_and_foreign_top_level_anchors_are_mixed() {
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.flush().unwrap();
    drop(pointer);
    check(dir.path(), RootKind::PointerLegacy);
    core_manifest(dir.path(), 2);
    check(dir.path(), RootKind::Mixed);
}

#[test]
fn pointer_primary_does_not_treat_foreign_authority_as_an_auxiliary() {
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.flush().unwrap();
    drop(pointer);
    core_manifest(&dir.path().join("primary"), 2);
    check(dir.path(), RootKind::Mixed);
}

#[test]
fn pointer_primary_does_not_treat_reserved_identity_as_an_auxiliary() {
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.flush().unwrap();
    drop(pointer);
    write(dir.path(), "primary/PRAXOR_ROOT", b"future identity");
    assert!(matches!(
        inspect(dir.path(), Default::default()).require_compatible(RootOwner::Pointer),
        Err(PraxisError::StorageFormatUnsupported { .. })
    ));
}

#[test]
fn core_accepts_only_an_exact_retained_primary_lock_container() {
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    write(
        dir.path(),
        "primary/.praxor.writer.lock",
        b"retained inode diagnostics",
    );
    check(dir.path(), RootKind::CoreLegacy);
    drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
    assert_eq!(
        fs::read(dir.path().join("primary/.praxor.writer.lock")).unwrap(),
        b"retained inode diagnostics"
    );
    write(
        dir.path(),
        "primary/unrelated-payload",
        b"not a lock-only container",
    );
    check(dir.path(), RootKind::Mixed);
}

#[test]
fn proven_core_pointer_and_record_authority_preserves_reported_opaque_auxiliaries() {
    for owner in [RootOwner::Core, RootOwner::Pointer, RootOwner::Record] {
        let dir = tempdir().unwrap();
        let expected = match owner {
            RootOwner::Core => {
                drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
                RootKind::CoreLegacy
            }
            RootOwner::Pointer => {
                let mut store = StorageEngine::open(dir.path(), 1024).unwrap();
                store.flush().unwrap();
                drop(store);
                RootKind::PointerLegacy
            }
            RootOwner::Record => {
                drop(RecordStore::open(dir.path()).unwrap());
                RootKind::RecordLegacy
            }
            RootOwner::Page => unreachable!(),
        };
        write(dir.path(), "README.md", b"application note");
        write(dir.path(), ".application-state", b"opaque state");
        write(
            dir.path(),
            "idx/MANIFEST",
            b"opaque index namespace, never traversed",
        );
        let report = check(dir.path(), expected);
        assert_eq!(report.auxiliary_entries.len(), 3);
        report.require_compatible(owner).unwrap();
        match owner {
            RootOwner::Core => drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap()),
            RootOwner::Pointer => drop(StorageEngine::open(dir.path(), 1024).unwrap()),
            RootOwner::Record => drop(RecordStore::open(dir.path()).unwrap()),
            RootOwner::Page => unreachable!(),
        }
        assert_eq!(
            fs::read(dir.path().join("idx/MANIFEST")).unwrap(),
            b"opaque index namespace, never traversed"
        );
    }
}

#[test]
fn pointer_legacy_wal_and_interrupted_own_temporary_manifest_keep_owner_recovery() {
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.put(b"acknowledged", &[]).unwrap();
    pointer.flush().unwrap();
    drop(pointer);
    fs::rename(
        dir.path().join("wal/storage.00000000000000000001.swal"),
        dir.path().join("wal/storage.wal"),
    )
    .unwrap();
    write(dir.path(), "MANIFEST.tmp", b"{\"version\":2,\"primary_seg");
    check(dir.path(), RootKind::PointerLegacy);
    let mut bytes = fs::read(dir.path().join("wal/storage.wal")).unwrap();
    bytes.extend_from_slice(b"torn tail");
    write(dir.path(), "wal/storage.wal", bytes);
    check(dir.path(), RootKind::PointerLegacy);
}

#[test]
fn assembled_pointer_manifest_and_complete_primary_can_initialize_missing_wal() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path().join("primary")).unwrap();
    store.put(b"offline assembled").unwrap();
    store.flush().unwrap();
    drop(store);
    write(
        dir.path(),
        "MANIFEST.store",
        serde_json::to_vec(&praxis::store::StorageManifest::default()).unwrap(),
    );
    check(dir.path(), RootKind::PointerLegacy);
    assert!(!dir.path().join("wal").exists());
}

#[test]
fn only_proven_empty_primary_can_be_adopted_as_a_pointer_scaffold() {
    let dir = tempdir().unwrap();
    drop(RecordStore::open(dir.path().join("primary")).unwrap());
    check(dir.path(), RootKind::PointerScaffold)
        .require_compatible(RootOwner::Pointer)
        .unwrap();
    let mut store = RecordStore::open(dir.path().join("primary")).unwrap();
    store.put(b"unowned primary payload").unwrap();
    store.flush().unwrap();
    drop(store);
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn record_header_ids_versions_and_control_corruption_are_diagnosed() {
    for bytes in [
        vec![],
        vec![0; 9],
        {
            let mut bytes = 0x5452_4543_u32.to_le_bytes().to_vec();
            bytes.push(99);
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes
        },
        {
            let mut bytes = 0x5452_4543_u32.to_le_bytes().to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&1_u32.to_le_bytes());
            bytes
        },
    ] {
        let dir = tempdir().unwrap();
        write(dir.path(), "records/00000000.trec", bytes);
        check(dir.path(), RootKind::Incomplete);
    }
    let dir = tempdir().unwrap();
    drop(RecordStore::open(dir.path()).unwrap());
    write(dir.path(), "indirection.tind", b"{not valid json");
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn own_manifest_temporary_crash_leftovers_do_not_steal_authority() {
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    for bytes in [
        b"".as_slice(),
        b"format_version = 2\ncolumn_famili".as_slice(),
    ] {
        write(dir.path(), "MANIFEST.tmp", bytes);
        check(dir.path(), RootKind::CoreLegacy);
    }
    write(dir.path(), "MANIFEST.tmp", b"{\"version\":1");
    check(dir.path(), RootKind::Incomplete);
    let dir = tempdir().unwrap();
    write(dir.path(), "MANIFEST.tmp", b"format_version = 2");
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn old_current_headerless_and_torn_core_wal_prefixes_keep_owner_recovery() {
    let mut prefixes = vec![
        vec![],
        vec![0x46],
        0x5457_414c_u32.to_le_bytes().to_vec(),
        0x5457_4132_u32.to_le_bytes().to_vec(),
    ];
    let mut header = 0x5457_4146_u32.to_le_bytes().to_vec();
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&1_u64.to_le_bytes());
    for count in 1..=16 {
        prefixes.push(header[..count].to_vec());
    }
    header.extend_from_slice(b"torn final append remains owner recovery");
    prefixes.push(header);
    for prefix in prefixes {
        let dir = tempdir().unwrap();
        core_manifest(dir.path(), 2);
        write(dir.path(), "wal/00000000000000000001.wal", prefix);
        check(dir.path(), RootKind::CoreLegacy);
    }
}

#[test]
fn header_versions_and_foreign_wals_are_reported_without_repair() {
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    let mut header = 0x5457_4146_u32.to_le_bytes().to_vec();
    header.extend_from_slice(&9_u32.to_le_bytes());
    header.extend_from_slice(&1_u64.to_le_bytes());
    write(dir.path(), "wal/00000000000000000001.wal", header);
    let report = check(dir.path(), RootKind::Incomplete);
    assert!(matches!(
        report.require_compatible(RootOwner::Core),
        Err(PraxisError::StorageFormatUnsupported { .. })
    ));
    write(
        dir.path(),
        "wal/storage.00000000000000000001.swal",
        [0x4c, 0x57, 0x53, 0x54, 1],
    );
    check(dir.path(), RootKind::Mixed);
}

#[test]
fn orphan_layouts_and_unknown_arbitrary_wal_never_become_empty() {
    for name in ["wal", "segments", "values", "tmp"] {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(name)).unwrap();
        check(dir.path(), RootKind::Incomplete);
    }
    let dir = tempdir().unwrap();
    write(dir.path(), "arbitrary.wal", b"unknown");
    check(dir.path(), RootKind::Unknown);
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "wal/00000000000000000001.wal",
        0x5457_4146_u32.to_le_bytes(),
    );
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn reserved_identity_and_temporaries_fail_closed_without_schema_activation() {
    for name in ["PRAXOR_ROOT", "PRAXOR_ROOT.tmp"] {
        for bytes in [
            b"".as_slice(),
            b"future marker or unknown schema".as_slice(),
        ] {
            let dir = tempdir().unwrap();
            core_manifest(dir.path(), 2);
            write(dir.path(), name, bytes);
            let report = check(dir.path(), RootKind::Incomplete);
            assert!(matches!(
                report.require_compatible(RootOwner::Core),
                Err(PraxisError::StorageFormatUnsupported { .. })
            ));
        }
    }
}

#[test]
fn corrupt_and_future_control_files_are_typed_diagnostics() {
    let dir = tempdir().unwrap();
    write(dir.path(), "MANIFEST", b"invalid [toml");
    assert!(matches!(
        check(dir.path(), RootKind::Incomplete).require_compatible(RootOwner::Core),
        Err(PraxisError::StorageFormatIncomplete { .. })
    ));
    core_manifest(dir.path(), 99);
    let report = check(dir.path(), RootKind::Incomplete);
    assert!(matches!(
        report.diagnostics[0].kind,
        DiagnosticKind::UnsupportedVersion { version: 99, .. }
    ));
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    pointer.flush().unwrap();
    drop(pointer);
    let manifest_path = dir.path().join("MANIFEST.store");
    let mut manifest: praxis::store::StorageManifest =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    // This field is a mutation revision, not a physical schema version.
    manifest.version = u64::MAX;
    fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    check(dir.path(), RootKind::PointerLegacy);
}

#[test]
fn configured_byte_entry_and_header_limits_refuse_instead_of_guessing() {
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    for options in [
        InspectionOptions {
            max_control_bytes: 4,
            ..Default::default()
        },
        InspectionOptions {
            max_entries: 0,
            ..Default::default()
        },
    ] {
        let report = inspect(dir.path(), options);
        assert_eq!(report.kind, RootKind::Incomplete);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|item| item.kind == DiagnosticKind::InspectionLimit)
        );
    }
    write(
        dir.path(),
        "wal/00000000000000000001.wal",
        0x5457_4146_u32.to_le_bytes(),
    );
    let report = inspect(
        dir.path(),
        InspectionOptions {
            max_header_bytes: 0,
            ..Default::default()
        },
    );
    assert_eq!(report.diagnostics[0].kind, DiagnosticKind::InspectionLimit);
}

#[test]
fn lock_named_directory_is_unsafe_and_nested_wrong_scope_lock_is_not_ignored() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join(".praxor.writer.lock")).unwrap();
    assert_eq!(
        check(dir.path(), RootKind::Incomplete).diagnostics[0].kind,
        DiagnosticKind::UnsafeAlias
    );
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    write(
        dir.path(),
        "wal/.praxor.writer.lock",
        b"not a WAL-root lease",
    );
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn exact_catalog_and_unwritten_entity_page_scaffolds_are_distinct_from_bare_namespaces() {
    let dir = tempdir().unwrap();
    drop(CatalogStore::open(dir.path()).unwrap());
    check(dir.path(), RootKind::PageScaffold);
    let dir = tempdir().unwrap();
    drop(PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap());
    check(dir.path(), RootKind::PageScaffold);
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join(".praxis")).unwrap();
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn catalog_save_reopen_is_supported_without_page_manifest_or_rid_directory() {
    use praxis::catalog::{CatalogSnapshot, CollectionCatalogEntry};
    for populated in [false, true] {
        let dir = tempdir().unwrap();
        let catalog = CatalogStore::open(dir.path()).unwrap();
        let mut snapshot = CatalogSnapshot::default();
        if populated {
            snapshot.collections.push(CollectionCatalogEntry {
                cid: Cid(1),
                name: "records".into(),
                retention_policy: Some("forever".into()),
            });
        }
        catalog.save(&snapshot).unwrap();
        drop(catalog);
        let reopened = CatalogStore::open(dir.path()).unwrap();
        assert_eq!(reopened.load().unwrap(), snapshot);
        drop(reopened);
        assert!(
            !dir.path()
                .join(".praxis/catalog/page-layout.manifest")
                .exists()
        );
        check(dir.path(), RootKind::PageLegacy);
    }
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        ".praxis/catalog/collections.cat",
        binary_control(0x5443_4154, &0_u32.to_le_bytes()),
    );
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn page_namespace_and_collection_have_no_independent_writer_lock_exemption() {
    for relative in [
        ".praxis/.praxor.writer.lock",
        ".praxis/data/0001/.praxor.writer.lock",
    ] {
        let dir = tempdir().unwrap();
        drop(PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap());
        write(dir.path(), relative, b"unrelated artifact");
        check(dir.path(), RootKind::Incomplete);
    }
    let dir = tempdir().unwrap();
    drop(CatalogStore::open(dir.path()).unwrap());
    write(dir.path(), ".praxor.writer.lock", b"base lease");
    check(dir.path(), RootKind::PageScaffold);
}

fn page_base_check(root: &Path, options: InspectionOptions) -> praxis::Result<()> {
    let before = tree(root);
    let existed = root.exists();
    let result = require_page_base_compatible(root, options);
    assert_eq!(tree(root), before);
    assert_eq!(root.exists(), existed);
    result
}

#[test]
fn page_base_helper_preserves_application_siblings_and_inspects_exact_namespace() {
    let dir = tempdir().unwrap();
    let absent = dir.path().join("absent");
    page_base_check(&absent, Default::default()).unwrap();
    write(dir.path(), "README.md", b"application");
    for name in [
        "tmp",
        "logs",
        "data",
        "records",
        "primary",
        "other-directory",
    ] {
        fs::create_dir(dir.path().join(name)).unwrap();
    }
    page_base_check(dir.path(), Default::default()).unwrap();
    assert!(!dir.path().join(".praxis").exists());
    drop(CatalogStore::open(dir.path()).unwrap());
    page_base_check(dir.path(), Default::default()).unwrap();
    let engine_root = inspect(dir.path(), InspectionOptions::default());
    assert!(engine_root.require_compatible(RootOwner::Core).is_err());
    write(dir.path(), ".praxis/PRAXOR_ROOT", b"future identity");
    assert!(matches!(
        page_base_check(dir.path(), Default::default()),
        Err(PraxisError::StorageFormatUnsupported { .. })
    ));
}

#[test]
fn page_base_helper_refuses_foreign_controls_and_suspect_physical_artifacts() {
    for name in [
        "MANIFEST",
        "MANIFEST.store",
        "MANIFEST.tmp",
        "indirection.tind",
        "records/00000000.trec",
        "primary/records/00000000.trec",
        "wal/00000000000000000001.wal",
        "wal/storage.00000000000000000001.swal",
    ] {
        let dir = tempdir().unwrap();
        write(dir.path(), name, b"unknown or interrupted format");
        assert!(
            matches!(
                page_base_check(dir.path(), Default::default()),
                Err(PraxisError::StorageFormatAmbiguous { .. })
            ),
            "{name}"
        );
    }
    for name in ["PRAXOR_ROOT", "PRAXOR_ROOT.tmp"] {
        let dir = tempdir().unwrap();
        drop(CatalogStore::open(dir.path()).unwrap());
        write(dir.path(), name, []);
        assert!(matches!(
            page_base_check(dir.path(), Default::default()),
            Err(PraxisError::StorageFormatUnsupported { .. })
        ));
    }
    let dir = tempdir().unwrap();
    write(dir.path(), "records/README.md", b"application file");
    assert!(matches!(
        page_base_check(
            dir.path(),
            InspectionOptions {
                max_entries: 0,
                ..Default::default()
            }
        ),
        Err(PraxisError::StorageFormatIncomplete { .. })
    ));
}

#[test]
fn page_base_refuses_orphan_core_segment() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "segments/0/00000000000000000001.tseg",
        [0x47, 0x45, 0x53, 0x54, 2, 0, 0, 0],
    );
    assert!(page_base_check(dir.path(), Default::default()).is_err());
}

#[test]
fn page_base_refuses_orphan_core_value_log() {
    let dir = tempdir().unwrap();
    let mut log = praxis::values::ValueLog::open({
        let path = dir.path().join("values/00000000000000000001.tval");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    })
    .unwrap();
    log.append(b"orphan value").unwrap();
    drop(log);
    assert!(page_base_check(dir.path(), Default::default()).is_err());
}

#[test]
fn page_base_refuses_orphan_core_checkpoint() {
    let source = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(source.path())).unwrap();
    let checkpoint = engine.checkpoint().unwrap();
    drop(engine);
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "checkpoints/00000000000000000000.chk",
        fs::read(checkpoint.path).unwrap(),
    );
    assert!(page_base_check(dir.path(), Default::default()).is_err());
}

#[cfg(any(windows, unix))]
#[test]
fn page_base_must_not_follow_a_namespace_alias() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let outside = tempdir().unwrap();
    drop(CatalogStore::open(outside.path()).unwrap());
    let before = tree(outside.path());
    let dir = tempdir().unwrap();
    symlink_dir(outside.path().join(".praxis"), dir.path().join(".praxis")).unwrap();
    assert!(page_base_check(dir.path(), Default::default()).is_err());
    assert_eq!(tree(outside.path()), before);
}

#[test]
fn populated_page_namespace_and_application_base_have_explicit_scopes() {
    let dir = tempdir().unwrap();
    let mut page = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    page.put(&[(FieldId::Fixed(Aid(1)), b"payload")]).unwrap();
    drop(page);
    check(dir.path(), RootKind::PageLegacy);
    write(dir.path(), "application.json", b"user application file");
    check(dir.path(), RootKind::Unknown);
    let report = inspect(
        &dir.path().join(".praxis"),
        InspectionOptions {
            scope: InspectionScope::PageNamespace,
            ..Default::default()
        },
    );
    assert_eq!(report.kind, RootKind::PageLegacy, "{report:#?}");
    report.require_compatible(RootOwner::Page).unwrap();
}

#[test]
fn malicious_page_control_counts_and_lengths_are_bounded_before_allocation() {
    for payload in [
        u32::MAX.to_le_bytes().to_vec(),
        vec![
            1, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ] {
        let dir = tempdir().unwrap();
        drop(CatalogStore::open(dir.path()).unwrap());
        write(
            dir.path(),
            ".praxis/catalog/page-layout.manifest",
            binary_control(0x5450_4d46, &payload),
        );
        check(dir.path(), RootKind::Incomplete);
    }
    let dir = tempdir().unwrap();
    drop(PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap());
    let mut payload = vec![0; 16];
    payload.extend_from_slice(&u32::MAX.to_le_bytes());
    write(
        dir.path(),
        ".praxis/data/0001/kv/critical/rid_to_slot.kv",
        binary_control(0x5452_4944, &payload),
    );
    check(dir.path(), RootKind::Incomplete);
}

#[test]
fn persisted_path_references_are_diagnosed_without_opening_external_data() {
    let dir = tempdir().unwrap();
    let mut manifest = Manifest::fresh(&PraxisConfig::new(dir.path()));
    manifest.latest_checkpoint = Some(praxis::manifest::CheckpointMetadata {
        id: 1,
        path: "relative/checkpoint.chk".into(),
        sequence: 0,
        segment_count: 0,
        file_digest: String::new(),
    });
    write(dir.path(), "MANIFEST", toml::to_string(&manifest).unwrap());
    let report = check(dir.path(), RootKind::CoreLegacy);
    assert_eq!(report.path_references[0].kind, ReferenceKind::Relative);
}

#[cfg(unix)]
#[test]
fn child_aliases_and_non_utf8_names_are_never_followed_or_ignored() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let outside = tempdir().unwrap();
    let dir = tempdir().unwrap();
    symlink(outside.path(), dir.path().join("wal")).unwrap();
    check(dir.path(), RootKind::Incomplete);
    let dir = tempdir().unwrap();
    symlink(outside.path(), dir.path().join(".praxor.writer.lock")).unwrap();
    check(dir.path(), RootKind::Incomplete);
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join(std::ffi::OsString::from_vec(vec![0xff])),
        b"unknown",
    )
    .unwrap();
    check(dir.path(), RootKind::Unknown);
    core_manifest(dir.path(), 2);
    let report = check(dir.path(), RootKind::CoreLegacy);
    assert!(
        report.auxiliary_entries.contains(
            &fs::canonicalize(dir.path())
                .unwrap()
                .join(std::ffi::OsString::from_vec(vec![0xff]))
        )
    );
    drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
}

#[cfg(any(windows, unix))]
#[test]
fn opaque_auxiliary_aliases_are_reported_without_traversing_their_targets() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let outside = tempdir().unwrap();
    write(outside.path(), "MANIFEST", b"unrelated external data");
    let before = tree(outside.path());
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    symlink_dir(outside.path(), dir.path().join("auxiliary-link")).unwrap();
    let report = check(dir.path(), RootKind::CoreLegacy);
    assert_eq!(report.auxiliary_entries.len(), 1);
    drop(PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap());
    assert_eq!(tree(outside.path()), before);
    assert!(!outside.path().join(".praxor.writer.lock").exists());
}

#[cfg(windows)]
#[test]
fn windows_root_alias_is_diagnosed_but_reserved_child_aliases_are_refused() {
    use std::os::windows::fs::symlink_dir;
    let outside = tempdir().unwrap();
    core_manifest(outside.path(), 2);
    let dir = tempdir().unwrap();
    let alias = dir.path().join("root-alias");
    symlink_dir(outside.path(), &alias).unwrap();
    let report = check(&alias, RootKind::CoreLegacy);
    assert_eq!(report.requested_path, alias);
    assert_eq!(
        report.canonical_path.unwrap(),
        fs::canonicalize(outside.path()).unwrap()
    );
    let dir = tempdir().unwrap();
    symlink_dir(outside.path(), dir.path().join("wal")).unwrap();
    assert_eq!(
        check(dir.path(), RootKind::Incomplete).diagnostics[0].kind,
        DiagnosticKind::UnsafeAlias
    );
    let dir = tempdir().unwrap();
    symlink_dir(outside.path(), dir.path().join(".praxor.writer.lock")).unwrap();
    assert_eq!(
        check(dir.path(), RootKind::Incomplete).diagnostics[0].kind,
        DiagnosticKind::UnsafeAlias
    );
    let dir = tempdir().unwrap();
    core_manifest(dir.path(), 2);
    fs::create_dir(dir.path().join("segments")).unwrap();
    symlink_dir(outside.path(), dir.path().join("segments/0")).unwrap();
    assert_eq!(
        check(dir.path(), RootKind::Incomplete).diagnostics[0].kind,
        DiagnosticKind::UnsafeAlias
    );
}
