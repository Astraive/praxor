use praxis::manifest::{CompactionJobState, CompactionJobStatus, Manifest, ManifestStore};
use praxis::store::StorageEngine;
use praxis::{
    CatalogDatabase, CoreDatabase, MappingDescriptor, PraxisConfig, PraxisEngine, PraxisError,
    RecordAuthorityOptions,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    LockedFile(u64),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, at: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        for item in std::fs::read_dir(at).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = item.file_type().unwrap();
            assert!(!kind.is_symlink(), "fixture contains an alias: {path:?}");
            if kind.is_dir() {
                entries.insert(relative, Entry::Directory);
                walk(root, &path, entries);
            } else {
                assert!(
                    kind.is_file(),
                    "fixture contains an unknown entry: {path:?}"
                );
                let entry = match std::fs::read(&path) {
                    Ok(bytes) => Entry::File(bytes),
                    Err(error)
                        if relative == Path::new(".praxor.writer.lock")
                            && error.raw_os_error() == Some(33) =>
                    {
                        // Windows prevents reading a lock held by this owner.
                        // The test seeds and verifies its exact bytes after drop.
                        Entry::LockedFile(item.metadata().unwrap().len())
                    }
                    Err(error) => panic!("cannot snapshot {path:?}: {error}"),
                };
                entries.insert(relative, entry);
            }
        }
    }
    let mut entries = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut entries);
    }
    entries
}

#[test]
fn catalog_open_refuses_existing_v3_without_touching_control_files_or_lock() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    drop(CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions::default()).unwrap());
    std::fs::write(
        root.path().join(".praxor.writer.lock"),
        b"existing lease bytes",
    )
    .unwrap();
    let before = tree(root.path());

    let result = CatalogDatabase::open_catalog(config);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, .. })
                if reason.contains('3')
        ),
        "v3 catalog admission must identify the observed format"
    );
    assert_eq!(
        tree(root.path()),
        before,
        "refusal altered the complete root"
    );
}

#[test]
fn catalog_open_does_not_reconcile_an_unfinished_v3_job() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    drop(CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions::default()).unwrap());
    let manifest_path = root.path().join("MANIFEST");
    let mut manifest: Manifest =
        toml::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest.compaction_jobs.push(CompactionJobState {
        id: 1,
        strategy: praxis::CompactionStrategy::Leveled,
        status: CompactionJobStatus::Running,
        source_segment_ids: vec![],
        output_segment_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
    });
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(config),
        Err(PraxisError::StorageFormatUnsupported { ref reason, .. }) if reason.contains('3')
    ));
    assert_eq!(
        tree(root.path()),
        before,
        "catalog refusal reconciled a v3 job"
    );
}

#[test]
fn catalog_open_refuses_existing_v2_with_its_raw_version() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    let before = tree(root.path());

    assert!(matches!(
        CatalogDatabase::open_catalog(config),
        Err(PraxisError::StorageFormatUnsupported { ref reason, .. }) if reason.contains('2')
    ));
    assert_eq!(tree(root.path()), before);
}

#[test]
fn catalog_open_reports_raw_v1_before_legacy_manifest_upgrade() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    let manifest_path = root.path().join("MANIFEST");
    let mut manifest: Manifest =
        toml::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest.format_version = 1;
    manifest.column_family_generations.clear();
    manifest.next_column_family_generation = 1;
    let encoded = toml::to_string_pretty(&manifest)
        .unwrap()
        .replace("next_column_family_generation = 1\n", "")
        .replace("[column_family_generations]\n", "");
    std::fs::write(&manifest_path, encoded).unwrap();
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(config),
        Err(PraxisError::StorageFormatUnsupported { ref reason, .. }) if reason.contains("version 1")
    ));
    assert_eq!(tree(root.path()), before);
}

#[test]
fn catalog_open_requires_an_existing_owner() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(config),
        Err(PraxisError::StorageFormatIncomplete { .. })
    ));
    let mut allowed = before;
    allowed.insert(
        PathBuf::from(".praxor.writer.lock"),
        Entry::File(Vec::new()),
    );
    assert_eq!(tree(root.path()), allowed);
}

#[test]
fn catalog_open_on_absent_root_creates_only_root_and_permanent_lock() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("absent");
    assert!(!root.exists());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(&root)),
        Err(PraxisError::StorageFormatIncomplete { .. })
    ));
    assert_eq!(
        tree(&root),
        BTreeMap::from([(
            PathBuf::from(".praxor.writer.lock"),
            Entry::File(Vec::new())
        )])
    );
}

#[test]
fn catalog_open_preserves_an_unsupported_future_manifest_version() {
    let root = tempfile::tempdir().unwrap();
    drop(PraxisEngine::open(PraxisConfig::new(root.path())).unwrap());
    let manifest_path = root.path().join("MANIFEST");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest.contains("format_version = 2"));
    std::fs::write(
        &manifest_path,
        manifest.replace("format_version = 2", "format_version = 99"),
    )
    .unwrap();
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(root.path())),
        Err(PraxisError::StorageFormatUnsupported { .. })
    ));
    assert_eq!(tree(root.path()), before);
}

#[test]
fn catalog_create_refuses_an_existing_v3_owner_without_modification() {
    let root = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(root.path());
    drop(CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions::default()).unwrap());
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(config, RecordAuthorityOptions::default()),
        Err(PraxisError::StorageFormatUnsupported { .. })
    ));
    assert_eq!(tree(root.path()), before);
}

#[test]
fn catalog_create_on_empty_root_stays_unavailable_and_creates_only_a_lock() {
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(
            PraxisConfig::new(root.path()),
            RecordAuthorityOptions::default()
        ),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(
        tree(root.path()),
        BTreeMap::from([(
            PathBuf::from(".praxor.writer.lock"),
            Entry::File(Vec::new())
        )])
    );
}

#[test]
fn invalid_catalog_config_and_record_options_leave_absent_roots_absent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("invalid-config");
    let mut config = PraxisConfig::new(&root);
    config.page_size = 100;
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(config.clone(), RecordAuthorityOptions::default()),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert!(matches!(
        CatalogDatabase::open_catalog(config),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert!(!root.exists());

    let root = temporary.path().join("invalid-record-options");
    let options = RecordAuthorityOptions {
        indexes: vec![MappingDescriptor {
            name: String::new(),
            namespace: "invalid".into(),
        }],
    };
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(PraxisConfig::new(&root), options),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert!(!root.exists());
}

#[test]
fn catalog_refuses_foreign_and_unknown_nonempty_roots_without_repair() {
    let foreign = tempfile::tempdir().unwrap();
    drop(StorageEngine::open(foreign.path(), 1024).unwrap());
    let before = tree(foreign.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(foreign.path())),
        Err(PraxisError::StorageFormatMismatch { .. })
    ));
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(
            PraxisConfig::new(foreign.path()),
            RecordAuthorityOptions::default()
        ),
        Err(PraxisError::StorageFormatMismatch { .. })
    ));
    assert_eq!(tree(foreign.path()), before);

    let unknown = tempfile::tempdir().unwrap();
    std::fs::write(unknown.path().join("unrelated-control"), b"keep me").unwrap();
    let before = tree(unknown.path());
    assert!(matches!(
        CatalogDatabase::create_fresh_v4(
            PraxisConfig::new(unknown.path()),
            RecordAuthorityOptions::default()
        ),
        Err(PraxisError::StorageFormatAmbiguous { .. })
    ));
    let mut allowed = before;
    allowed.insert(
        PathBuf::from(".praxor.writer.lock"),
        Entry::File(Vec::new()),
    );
    assert_eq!(tree(unknown.path()), allowed);
}

#[test]
fn catalog_open_preserves_mixed_and_damaged_core_controls() {
    let mixed = tempfile::tempdir().unwrap();
    drop(PraxisEngine::open(PraxisConfig::new(mixed.path())).unwrap());
    std::fs::write(mixed.path().join("MANIFEST.store"), b"foreign owner").unwrap();
    let before = tree(mixed.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(mixed.path())),
        Err(PraxisError::StorageFormatAmbiguous { .. })
    ));
    assert_eq!(tree(mixed.path()), before);

    let damaged = tempfile::tempdir().unwrap();
    drop(PraxisEngine::open(PraxisConfig::new(damaged.path())).unwrap());
    std::fs::write(damaged.path().join("MANIFEST"), b"broken TOML").unwrap();
    let before = tree(damaged.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(damaged.path())),
        Err(PraxisError::StorageFormatIncomplete { .. })
    ));
    assert_eq!(tree(damaged.path()), before);
}

#[test]
fn already_open_writer_blocks_catalog_before_inspection() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".praxor.writer.lock"), b"held lease bytes").unwrap();
    let owner = CoreDatabase::create_fresh(
        PraxisConfig::new(root.path()),
        RecordAuthorityOptions::default(),
    )
    .unwrap();
    let before = tree(root.path());
    assert!(matches!(
        CatalogDatabase::open_catalog(PraxisConfig::new(root.path())),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(tree(root.path()), before);
    drop(owner);
    assert_eq!(
        std::fs::read(root.path().join(".praxor.writer.lock")).unwrap(),
        b"held lease bytes"
    );
}
