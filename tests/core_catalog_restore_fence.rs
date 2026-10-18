use praxis::core_catalog::{CatalogAuthorityV1, CatalogBindingV1};
use praxis::manifest::{
    ColumnFamilyDescriptor, ColumnFamilyGeneration, ColumnFamilyOptions, CompactionJobState,
    CompactionJobStatus, ManifestStore,
};
use praxis::storage::root_format::{InspectionOptions, RootKind, RootOwner, inspect_storage_root};
use praxis::{
    CatalogDatabase, CoreDatabase, PraxisConfig, PraxisEngine, PraxisError, RecordAuthorityOptions,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const RETRY_MARKER: &[u8] = b"praxor core copy incomplete v1\n";

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Alias(PathBuf),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for item in std::fs::read_dir(at).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = item.file_type().unwrap();
            if kind.is_symlink() {
                out.insert(relative, Entry::Alias(std::fs::read_link(&path).unwrap()));
            } else if kind.is_dir() {
                out.insert(relative, Entry::Directory);
                visit(root, &path, out);
            } else {
                assert!(kind.is_file(), "unknown entry at {path:?}");
                out.insert(relative, Entry::File(std::fs::read(&path).unwrap()));
            }
        }
    }

    let mut out = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut out);
    }
    out
}

fn strict_v4_from_v3(root: &Path) -> Vec<u8> {
    let path = root.join("MANIFEST");
    let mut manifest = ManifestStore::new(&path)
        .load_or_create(&PraxisConfig::new(root))
        .unwrap();
    assert_eq!(manifest.format_version, 3);
    let database_id = manifest
        .record_authority
        .as_ref()
        .unwrap()
        .database_id
        .clone();
    manifest.format_version = 4;
    manifest.next_column_family_generation = 6;
    manifest.catalog_authority = Some(CatalogAuthorityV1 {
        kind: "core_catalog".into(),
        schema_version: 1,
        codec_version: 1,
        database_id,
        epoch: 1,
        bootstrap_sequence: 1,
        binding: CatalogBindingV1 {
            role: "catalog".into(),
            column_family: "__praxor_record_catalog_v1".into(),
            generation: 5,
        },
    });
    manifest.column_families.push(ColumnFamilyDescriptor {
        name: "__praxor_record_catalog_v1".into(),
        write_buffer_size_bytes: manifest.effective_config.memtable_flush_threshold_bytes,
        large_value_threshold_bytes: manifest.effective_config.large_value_threshold,
        bloom_enabled: true,
        options: ColumnFamilyOptions {
            memtable_kind: manifest.effective_config.default_memtable_kind,
            compaction_strategy: manifest.effective_config.default_compaction_strategy,
            ..ColumnFamilyOptions::default()
        },
    });
    manifest.column_family_generations.insert(
        "__praxor_record_catalog_v1".into(),
        ColumnFamilyGeneration {
            id: 5,
            visible_after_sequence: 0,
        },
    );
    toml::to_string_pretty(&manifest).unwrap().into_bytes()
}

fn bundle(base: &Path) -> PathBuf {
    let source = base.join("source");
    let engine = PraxisEngine::open(PraxisConfig::new(&source)).unwrap();
    engine.put("source-row", "keep").unwrap();
    let bundle = base.join("bundle");
    engine.backup_to(&bundle).unwrap();
    bundle
}

fn v3_shell(root: &Path) {
    drop(
        CoreDatabase::create_fresh(PraxisConfig::new(root), RecordAuthorityOptions::default())
            .unwrap(),
    );
    std::fs::write(root.join(".praxor.writer.lock"), b"existing lock bytes").unwrap();
}

fn running_job(root: &Path) {
    let path = root.join("MANIFEST");
    let mut manifest = ManifestStore::new(&path)
        .load_or_create(&PraxisConfig::new(root))
        .unwrap();
    manifest.compaction_jobs.push(CompactionJobState {
        id: 1,
        strategy: praxis::CompactionStrategy::Leveled,
        status: CompactionJobStatus::Running,
        source_segment_ids: vec![],
        output_segment_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
    });
    ManifestStore::new(path).save(&manifest).unwrap();
}

#[test]
fn v3_old_open_refuses_complete_v4_temporary_control_before_job_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("owner");
    v3_shell(&root);
    let v4 = strict_v4_from_v3(&root);
    running_job(&root);
    std::fs::write(root.join("MANIFEST.tmp"), v4).unwrap();
    let before = tree(&root);
    let canonical = root.canonicalize().unwrap();

    let error = match CoreDatabase::open(PraxisConfig::new(&root)) {
        Ok(database) => {
            drop(database);
            None
        }
        Err(error) => Some(error),
    };
    let after = tree(&root);
    assert!(
        matches!(error, Some(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST.tmp"))),
        "old open did not identify the v4 temporary control: {error:?}; tree changed={}",
        after != before
    );
    assert_eq!(
        after, before,
        "old open changed control, WAL, or lock bytes"
    );
}

#[test]
fn v2_generic_open_refuses_complete_v4_temporary_control_before_job_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("legacy-owner");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    engine.put("legacy-row", "keep").unwrap();
    drop(engine);
    std::fs::write(root.join(".praxor.writer.lock"), b"existing lock bytes").unwrap();
    let fixture = dir.path().join("v3-fixture");
    v3_shell(&fixture);
    let v4 = strict_v4_from_v3(&fixture);
    running_job(&root);
    std::fs::write(root.join("MANIFEST.tmp"), v4).unwrap();
    let before = tree(&root);
    let canonical = root.canonicalize().unwrap();

    let error = match PraxisEngine::open(PraxisConfig::new(&root)) {
        Ok(engine) => {
            drop(engine);
            None
        }
        Err(error) => Some(error),
    };
    let after = tree(&root);
    assert!(
        matches!(error, Some(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST.tmp"))),
        "generic open did not identify the v4 temporary control: {error:?}; tree changed={}",
        after != before
    );
    assert_eq!(
        after, before,
        "generic open changed control, WAL, or lock bytes"
    );
}

#[test]
fn strict_v4_manifest_is_classified_as_a_core_catalog_shell() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("owner");
    v3_shell(&root);
    std::fs::write(root.join("MANIFEST"), strict_v4_from_v3(&root)).unwrap();
    let before = tree(&root);

    let report = inspect_storage_root(&root, InspectionOptions::default()).unwrap();
    assert_eq!(report.kind, RootKind::CoreCatalog, "{report:#?}");
    assert!(
        report.evidence.iter().any(|item| {
            item.owner == RootOwner::Core
                && item.role == "authoritative manifest"
                && item.version == Some(4)
        }),
        "v4 format evidence was lost: {report:#?}"
    );
    report.require_compatible(RootOwner::Core).unwrap();
    assert_eq!(tree(&root), before, "classification changed the root");
}

#[test]
fn strict_v4_shell_cannot_enter_catalog_or_old_writable_open() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("owner");
    v3_shell(&root);
    std::fs::write(root.join("MANIFEST"), strict_v4_from_v3(&root)).unwrap();
    let before = tree(&root);
    let canonical = root.canonicalize().unwrap();

    let catalog = CatalogDatabase::open_catalog(PraxisConfig::new(&root));
    assert!(
        matches!(catalog, Err(PraxisError::UnsupportedCatalogFeature { .. })),
        "catalog open should stay unavailable until physical v4 validation exists"
    );
    assert_eq!(
        tree(&root),
        before,
        "catalog open modified a structural shell"
    );

    let create = CatalogDatabase::create_fresh_v4(
        PraxisConfig::new(&root),
        RecordAuthorityOptions::default(),
    );
    assert!(
        matches!(create, Err(PraxisError::StorageFormatUnsupported { .. })),
        "fresh catalog create accepted an existing shell"
    );
    assert_eq!(
        tree(&root),
        before,
        "catalog create modified an existing shell"
    );

    let generic = PraxisEngine::open(PraxisConfig::new(&root));
    assert!(
        matches!(generic, Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST"))),
        "generic open did not identify format 4"
    );
    assert_eq!(tree(&root), before, "generic open modified a v4 shell");

    let records = CoreDatabase::open(PraxisConfig::new(&root));
    assert!(
        matches!(records, Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST"))),
        "v3 record open did not identify format 4"
    );
    assert_eq!(tree(&root), before, "v3 record open modified a v4 shell");
}

#[test]
fn strict_v4_backup_source_refuses_before_creating_a_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    v3_shell(&source);
    std::fs::write(source.join("MANIFEST"), strict_v4_from_v3(&source)).unwrap();
    let before = tree(&source);
    let canonical = source.canonicalize().unwrap();
    let target = dir.path().join("absent-target");
    assert!(!target.exists());

    let result = PraxisEngine::restore_from_backup(&source, &target);
    assert!(
        matches!(result, Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST"))),
        "restore source did not identify format 4: {result:?}"
    );
    assert!(
        !target.exists(),
        "restore created the target before source admission"
    );
    assert_eq!(tree(&source), before, "restore altered the source tree");
}

#[test]
fn strict_v4_temporary_backup_source_refuses_before_creating_a_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    v3_shell(&source);
    std::fs::write(source.join("MANIFEST.tmp"), strict_v4_from_v3(&source)).unwrap();
    let before = tree(&source);
    let canonical = source.canonicalize().unwrap();
    let target = dir.path().join("absent-target");

    let result = PraxisEngine::restore_from_backup(&source, &target);
    assert!(
        matches!(result, Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
            if reason.contains('4') && evidence.contains(&canonical.join("MANIFEST.tmp"))),
        "restore source did not identify the v4 temporary control: {result:?}"
    );
    assert!(
        !target.exists(),
        "restore created the target before source admission"
    );
    assert_eq!(tree(&source), before, "restore altered the source tree");
}

#[test]
fn malformed_v4_temporary_control_keeps_old_open_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("owner");
    v3_shell(&root);
    std::fs::write(
        root.join("MANIFEST.tmp"),
        b"format_version = 4\n[catalog_authority]\n",
    )
    .unwrap();
    let before = tree(&root);
    let result = CoreDatabase::open(PraxisConfig::new(&root));
    assert!(
        matches!(result, Err(PraxisError::StorageFormatIncomplete { .. })),
        "malformed v4 temporary control changed refusal family"
    );
    assert_eq!(tree(&root), before);
}

#[test]
fn aliased_temporary_control_keeps_old_open_incomplete_without_following_target() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("owner");
    v3_shell(&root);
    let outside = dir.path().join("outside-v4-control");
    std::fs::write(&outside, strict_v4_from_v3(&root)).unwrap();
    file_alias(&outside, &root.join("MANIFEST.tmp"));
    let before = tree(&root);
    let outside_before = std::fs::read(&outside).unwrap();

    let result = CoreDatabase::open(PraxisConfig::new(&root));
    assert!(
        matches!(result, Err(PraxisError::StorageFormatIncomplete { .. })),
        "aliased temporary control changed refusal family"
    );
    assert_eq!(tree(&root), before);
    assert_eq!(std::fs::read(&outside).unwrap(), outside_before);
}

#[test]
fn ordinary_old_temporary_controls_still_allow_old_open() {
    let dir = tempfile::tempdir().unwrap();
    let records_root = dir.path().join("records");
    v3_shell(&records_root);
    std::fs::copy(
        records_root.join("MANIFEST"),
        records_root.join("MANIFEST.tmp"),
    )
    .unwrap();
    let records = CoreDatabase::open(PraxisConfig::new(&records_root)).unwrap();
    assert_eq!(records.kv().snapshot().sequence, 1);
    drop(records);

    let legacy_root = dir.path().join("legacy");
    let legacy = PraxisEngine::open(PraxisConfig::new(&legacy_root)).unwrap();
    legacy.put("legacy-row", "keep").unwrap();
    drop(legacy);
    std::fs::copy(
        legacy_root.join("MANIFEST"),
        legacy_root.join("MANIFEST.tmp"),
    )
    .unwrap();
    let reopened = PraxisEngine::open(PraxisConfig::new(&legacy_root)).unwrap();
    assert_eq!(
        reopened.get("legacy-row").unwrap().unwrap().as_ref(),
        b"keep"
    );
}

#[test]
fn complete_v4_temporary_manifest_cannot_be_replaced_during_retry() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    std::fs::write(
        destination.join("MANIFEST.tmp"),
        strict_v4_from_v3(&destination),
    )
    .unwrap();
    assert_eq!(
        ManifestStore::new(destination.join("MANIFEST.tmp"))
            .load_or_create(&PraxisConfig::new(&destination))
            .unwrap()
            .format_version,
        4,
    );
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    let source_before = tree(&source);
    let destination_before = tree(&destination);
    let canonical_destination = destination.canonicalize().unwrap();

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                if reason.contains('4')
                    && evidence.contains(&canonical_destination.join("MANIFEST.tmp"))
        ),
        "v4 temporary manifest must refuse restore: {result:?}"
    );
    assert_eq!(tree(&source), source_before, "source bundle changed");
    assert_eq!(
        tree(&destination),
        destination_before,
        "destination changed"
    );
}

#[test]
fn complete_v4_temporary_manifest_without_main_manifest_cannot_be_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    let v4 = strict_v4_from_v3(&destination);
    std::fs::remove_file(destination.join("MANIFEST")).unwrap();
    std::fs::write(destination.join("MANIFEST.tmp"), v4).unwrap();
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    let source_before = tree(&source);
    let destination_before = tree(&destination);
    let canonical_destination = destination.canonicalize().unwrap();

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                if reason.contains('4')
                    && evidence.contains(&canonical_destination.join("MANIFEST.tmp"))
        ),
        "v4 temporary manifest without main manifest must refuse restore: {result:?}"
    );
    assert_eq!(tree(&source), source_before, "source bundle changed");
    assert_eq!(
        tree(&destination),
        destination_before,
        "destination changed"
    );
}

fn assert_minimal_v4_temporary_root_is_preserved(neutral_primary: bool) {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let fixture = dir.path().join("v3-fixture");
    v3_shell(&fixture);
    let v4 = strict_v4_from_v3(&fixture);
    let destination = dir.path().join("destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(
        destination.join(".praxor.writer.lock"),
        b"existing lock bytes",
    )
    .unwrap();
    std::fs::write(destination.join("MANIFEST.tmp"), v4).unwrap();
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    if neutral_primary {
        std::fs::create_dir(destination.join("primary")).unwrap();
        std::fs::write(
            destination.join("primary/.praxor.writer.lock"),
            b"primary lock bytes",
        )
        .unwrap();
    }
    let source_before = tree(&source);
    let destination_before = tree(&destination);
    let canonical_destination = destination.canonicalize().unwrap();

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                if reason.contains('4')
                    && evidence.contains(&canonical_destination.join("MANIFEST.tmp"))
        ),
        "v4 temporary manifest without core anchor must refuse restore (neutral primary={neutral_primary}): {result:?}"
    );
    assert_eq!(tree(&source), source_before, "source bundle changed");
    assert_eq!(
        tree(&destination),
        destination_before,
        "destination changed"
    );
}

#[test]
fn v4_temporary_manifest_without_any_owner_anchor_cannot_be_replaced() {
    assert_minimal_v4_temporary_root_is_preserved(false);
}

#[test]
fn v4_temporary_manifest_with_only_neutral_primary_cannot_be_replaced() {
    assert_minimal_v4_temporary_root_is_preserved(true);
}

fn assert_old_stage_v4_control_is_preserved(control: &str) {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    let v4 = strict_v4_from_v3(&destination);
    let old_stage = destination.join("tmp/backup-stage-old");
    std::fs::create_dir_all(&old_stage).unwrap();
    std::fs::write(old_stage.join(control), v4).unwrap();
    let source_before = tree(&source);
    let destination_before = tree(&destination);
    let canonical_destination = destination.canonicalize().unwrap();

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                if reason.contains('4')
                    && evidence.contains(&canonical_destination.join("tmp/backup-stage-old").join(control))
        ),
        "v4 {control} inside an old stage must refuse restore: {result:?}"
    );
    assert_eq!(tree(&source), source_before, "source bundle changed");
    assert_eq!(
        tree(&destination),
        destination_before,
        "destination changed"
    );
}

#[test]
fn v4_manifest_in_old_stage_cannot_be_cleared_by_restore() {
    assert_old_stage_v4_control_is_preserved("MANIFEST");
}

#[test]
fn v4_temporary_manifest_in_old_stage_cannot_be_cleared_by_restore() {
    assert_old_stage_v4_control_is_preserved("MANIFEST.tmp");
}

#[test]
fn authoritative_v4_manifest_refuses_restore_with_and_without_retry_marker() {
    for retry in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let source = bundle(dir.path());
        let destination = dir.path().join("destination");
        v3_shell(&destination);
        std::fs::write(
            destination.join("MANIFEST"),
            strict_v4_from_v3(&destination),
        )
        .unwrap();
        if retry {
            std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
        }
        let source_before = tree(&source);
        let destination_before = tree(&destination);
        let canonical_destination = destination.canonicalize().unwrap();

        let result = PraxisEngine::restore_from_backup(&source, &destination);
        assert!(
            matches!(
                result,
                Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                    if reason.contains('4')
                        && evidence.contains(&canonical_destination.join("MANIFEST"))
            ),
            "v4 authoritative manifest must refuse restore (retry={retry}): {result:?}"
        );
        assert_eq!(tree(&source), source_before, "source bundle changed");
        assert_eq!(
            tree(&destination),
            destination_before,
            "destination changed"
        );
    }
}

#[test]
fn malformed_v4_temporary_control_keeps_existing_corrupt_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    std::fs::write(
        destination.join("MANIFEST.tmp"),
        b"format_version = 4\n[catalog_authority]\n",
    )
    .unwrap();
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    let source_before = tree(&source);
    let destination_before = tree(&destination);

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::Corrupt { .. } | PraxisError::StorageFormatIncomplete { .. })
        ),
        "malformed temporary control changed diagnostic family: {result:?}"
    );
    assert_eq!(tree(&source), source_before);
    assert_eq!(tree(&destination), destination_before);
}

#[cfg(windows)]
fn file_alias(target: &Path, alias: &Path) {
    std::os::windows::fs::symlink_file(target, alias).unwrap();
}

#[cfg(unix)]
fn file_alias(target: &Path, alias: &Path) {
    std::os::unix::fs::symlink(target, alias).unwrap();
}

#[test]
fn temporary_manifest_alias_refuses_without_reading_or_changing_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    let outside = dir.path().join("outside-v4-control");
    std::fs::write(&outside, strict_v4_from_v3(&destination)).unwrap();
    file_alias(&outside, &destination.join("MANIFEST.tmp"));
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    let source_before = tree(&source);
    let destination_before = tree(&destination);
    let outside_before = std::fs::read(&outside).unwrap();

    let result = PraxisEngine::restore_from_backup(&source, &destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::Corrupt { .. } | PraxisError::StorageFormatIncomplete { .. })
        ),
        "aliased temporary control changed diagnostic family: {result:?}"
    );
    assert_eq!(tree(&source), source_before);
    assert_eq!(tree(&destination), destination_before);
    assert_eq!(std::fs::read(&outside).unwrap(), outside_before);
}

#[test]
fn alias_and_nonfile_temporary_controls_precede_v4_main_manifest() {
    for alias in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let source = bundle(dir.path());
        let destination = dir.path().join("destination");
        v3_shell(&destination);
        std::fs::write(
            destination.join("MANIFEST"),
            strict_v4_from_v3(&destination),
        )
        .unwrap();
        let outside = dir.path().join("outside-control");
        std::fs::write(&outside, b"external bytes").unwrap();
        if alias {
            file_alias(&outside, &destination.join("MANIFEST.tmp"));
        } else {
            std::fs::create_dir(destination.join("MANIFEST.tmp")).unwrap();
        }
        std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
        let source_before = tree(&source);
        let destination_before = tree(&destination);
        let outside_before = std::fs::read(&outside).unwrap();

        let result = PraxisEngine::restore_from_backup(&source, &destination);
        assert!(
            matches!(
                result,
                Err(PraxisError::Corrupt { .. } | PraxisError::StorageFormatIncomplete { .. })
            ),
            "alias/nonfile control must retain its refusal (alias={alias}): {result:?}"
        );
        assert_eq!(tree(&source), source_before);
        assert_eq!(tree(&destination), destination_before);
        assert_eq!(std::fs::read(&outside).unwrap(), outside_before);
    }
}

#[test]
fn backup_to_uses_the_same_v4_destination_fence() {
    let dir = tempfile::tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    source.put("source-row", "keep").unwrap();
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    std::fs::write(
        destination.join("MANIFEST.tmp"),
        strict_v4_from_v3(&destination),
    )
    .unwrap();
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();
    let before = tree(&destination);
    let canonical_destination = destination.canonicalize().unwrap();

    let result = source.backup_to(&destination);
    assert!(
        matches!(
            result,
            Err(PraxisError::StorageFormatUnsupported { ref reason, ref evidence, .. })
                if reason.contains('4')
                    && evidence.contains(&canonical_destination.join("MANIFEST.tmp"))
        ),
        "backup_to must refuse v4 destination control: {result:?}"
    );
    assert_eq!(tree(&destination), before);
}

#[test]
fn ordinary_v3_temporary_control_allows_v2_restore() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    std::fs::copy(
        destination.join("MANIFEST"),
        destination.join("MANIFEST.tmp"),
    )
    .unwrap();

    PraxisEngine::restore_from_backup(&source, &destination).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
    assert_eq!(
        restored.get("source-row").unwrap().unwrap().as_ref(),
        b"keep"
    );
}

#[test]
fn exact_private_v2_partial_retry_remains_replaceable() {
    let dir = tempfile::tempdir().unwrap();
    let source = bundle(dir.path());
    let destination = dir.path().join("destination");
    v3_shell(&destination);
    std::fs::remove_file(destination.join("MANIFEST")).unwrap();
    std::fs::write(destination.join("MANIFEST.tmp"), b"format_version = 2").unwrap();
    std::fs::write(destination.join("CORE_COPY_INCOMPLETE"), RETRY_MARKER).unwrap();

    PraxisEngine::restore_from_backup(&source, &destination).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
    assert_eq!(
        restored.get("source-row").unwrap().unwrap().as_ref(),
        b"keep"
    );
}
