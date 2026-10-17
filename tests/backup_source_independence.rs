use bytes::Bytes;
use praxis::manifest::ColumnFamilyDescriptor;
use praxis::types::ColumnFamily;
use praxis::{Compression, PraxisConfig, PraxisEngine, WriteBatch};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn config(root: &Path, external: bool) -> PraxisConfig {
    let mut config = PraxisConfig::new(root);
    if external {
        config.large_value_threshold = 8;
    }
    config
}

fn restored_database_survives_source_unavailability(external: bool) {
    let temporary = tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("live");
    let hidden_source = root.join("unavailable-live");
    let backup = root.join("backup");
    let target = root.join("restored");
    let value = if external {
        Bytes::from(vec![0xa5; 16 * 1024])
    } else {
        Bytes::from_static(b"inline record")
    };
    let engine = PraxisEngine::open(config(&source, external)).unwrap();
    engine.put("record", value.clone()).unwrap();
    engine.flush().unwrap();
    engine.backup_to(&backup).unwrap();
    PraxisEngine::restore_from_backup(&backup, &target).unwrap();

    // A source-available control must not be mistaken for independence proof.
    {
        let control = PraxisEngine::open(config(&target, external)).unwrap();
        assert_eq!(control.get("record").unwrap(), Some(value.clone()));
    }
    drop(engine);
    let source = source.canonicalize().unwrap();
    assert!(source.starts_with(&root));
    assert!(hidden_source.starts_with(&root));
    assert!(!hidden_source.exists());
    std::fs::rename(&source, &hidden_source).unwrap();

    let reopened = PraxisEngine::open(config(&target, external));
    assert!(
        reopened.is_ok(),
        "restored open still requires the unavailable source: {:?}",
        reopened.err()
    );
    let reopened = reopened.unwrap();
    assert_eq!(reopened.get("record").unwrap(), Some(value));
    reopened.verify().unwrap();
}

#[test]
fn inline_backup_reopens_with_its_source_unavailable() {
    restored_database_survives_source_unavailability(false);
}

#[test]
fn external_value_backup_reopens_with_its_source_unavailable() {
    restored_database_survives_source_unavailability(true);
}

fn local_primary_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                pending.push(entry.path());
            } else if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "tseg" || extension == "tval")
            {
                files.push(entry.path());
            }
        }
    }
    files
}

#[test]
fn restored_gc_retains_its_local_segment_and_value_files() {
    let temporary = tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("live");
    let backup = root.join("backup");
    let target = root.join("restored");
    let value = Bytes::from(vec![0xa5; 16 * 1024]);
    let engine = PraxisEngine::open(config(&source, true)).unwrap();
    engine.put("record", value.clone()).unwrap();
    engine.flush().unwrap();
    engine.backup_to(&backup).unwrap();
    PraxisEngine::restore_from_backup(&backup, &target).unwrap();
    let restored = PraxisEngine::open(config(&target, true)).unwrap();
    assert_eq!(restored.get("record").unwrap(), Some(value.clone()));
    let files = local_primary_files(&target);
    assert!(files.iter().any(|path| path.extension().unwrap() == "tseg"));
    assert!(files.iter().any(|path| path.extension().unwrap() == "tval"));

    restored.garbage_collect().unwrap();
    for file in files {
        assert!(
            file.exists(),
            "restore GC deleted its copied primary file: {file:?}"
        );
    }
    assert_eq!(restored.get("record").unwrap(), Some(value.clone()));
    assert_eq!(engine.get("record").unwrap(), Some(value));
}

#[test]
fn backup_itself_opens_without_access_to_the_live_source() {
    let temporary = tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("live");
    let hidden = root.join("unavailable-live");
    let backup = root.join("backup");
    let engine = PraxisEngine::open(config(&source, true)).unwrap();
    let value = Bytes::from(vec![0x3c; 16 * 1024]);
    engine.put("record", value.clone()).unwrap();
    engine.backup_to(&backup).unwrap();
    drop(engine);
    assert!(source.canonicalize().unwrap().starts_with(&root));
    assert!(hidden.starts_with(&root));
    std::fs::rename(&source, hidden).unwrap();
    let archived = PraxisEngine::open(config(&backup, true)).unwrap();
    assert_eq!(archived.get("record").unwrap(), Some(value));
    archived.verify().unwrap();
}

fn relocated_history_and_expiry(compression: Compression) {
    let temporary = tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("live");
    let hidden_source = root.join("unavailable-live");
    let backup = root.join("backup");
    let moved_backup = root.join("moved-backup");
    let target = root.join("restored");
    let hidden_backup = root.join("unavailable-backup");
    let mut source_config = config(&source, true);
    source_config.compression = compression;
    let engine = PraxisEngine::open(source_config.clone()).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "tenant".into(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let tenant = ColumnFamily("tenant".into());
    let old = Bytes::from(vec![0x31; 16 * 1024]);
    let new = Bytes::from(vec![0x32; 20 * 1024]);
    let expiring = Bytes::from(vec![0x45; 18 * 1024]);
    let mut first = WriteBatch::new();
    first.put(tenant.clone(), "history", old.clone());
    first.put(tenant.clone(), "deleted", "visible before delete");
    first.put(tenant.clone(), "merged", "base");
    first.put_with_expiry(tenant.clone(), "expiring", expiring.clone(), u64::MAX - 1);
    engine.write_batch(first).unwrap();
    engine.flush().unwrap();
    let pin = engine.pin_snapshot();
    let historical = pin.snapshot();
    let mut second = WriteBatch::new();
    second.put(tenant.clone(), "history", new.clone());
    second.delete(tenant.clone(), "deleted");
    second.merge(tenant.clone(), "merged", ":first");
    second.merge(tenant.clone(), "merged", ":second");
    engine.write_batch(second).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();
    // Prove the source actually retained the history/operand order under test.
    assert_eq!(
        engine.get_cf(&tenant, b"history", historical).unwrap(),
        Some(old.clone())
    );
    assert_eq!(
        engine
            .get_cf(&tenant, b"merged", engine.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"base:first:second"))
    );
    engine.backup_to(&backup).unwrap();
    drop(pin);
    drop(engine);
    for path in [&source, &backup] {
        assert!(path.canonicalize().unwrap().starts_with(&root));
    }
    for path in [&hidden_source, &moved_backup, &hidden_backup] {
        assert!(path.starts_with(&root));
        assert!(!path.exists());
    }
    std::fs::rename(&source, hidden_source).unwrap();
    std::fs::rename(&backup, &moved_backup).unwrap();
    PraxisEngine::restore_from_backup(&moved_backup, &target).unwrap();
    std::fs::rename(&moved_backup, hidden_backup).unwrap();
    source_config.data_dir = target;
    let restored = PraxisEngine::open(source_config.clone()).unwrap();
    assert_eq!(
        restored.get_cf(&tenant, b"history", historical).unwrap(),
        Some(old)
    );
    assert_eq!(
        restored
            .get_cf(&tenant, b"history", restored.snapshot())
            .unwrap(),
        Some(new)
    );
    assert!(
        restored
            .get_cf(&tenant, b"deleted", restored.snapshot())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restored.get_cf(&tenant, b"deleted", historical).unwrap(),
        Some(Bytes::from_static(b"visible before delete"))
    );
    assert_eq!(
        restored
            .get_cf(&tenant, b"merged", restored.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"base:first:second"))
    );
    assert_eq!(
        restored
            .get_cf(&tenant, b"expiring", restored.snapshot())
            .unwrap(),
        Some(expiring)
    );
    restored.verify().unwrap();
    restored.garbage_collect().unwrap();
    drop(restored);
    PraxisEngine::open(source_config).unwrap().verify().unwrap();
}

#[test]
fn moved_backup_retains_history_and_large_expiry_values_without_compression() {
    relocated_history_and_expiry(Compression::None);
}

#[test]
fn moved_backup_retains_history_and_large_expiry_values_with_lz4() {
    relocated_history_and_expiry(Compression::Lz4);
}

#[test]
fn moved_backup_retains_history_and_large_expiry_values_with_zstd() {
    relocated_history_and_expiry(Compression::Zstd);
}

#[test]
fn supplied_destination_volume_survives_source_removal_and_reopen() {
    let source_area = tempdir().unwrap();
    let destination_parent = std::env::var_os("PRAXOR_BACKUP_TEST_VOLUME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let destination_area = tempfile::Builder::new()
        .prefix("praxor-backup-test-")
        .tempdir_in(destination_parent)
        .unwrap();
    let source_root = source_area.path().canonicalize().unwrap();
    let destination_root = destination_area.path().canonicalize().unwrap();
    #[cfg(windows)]
    if std::env::var_os("PRAXOR_BACKUP_TEST_VOLUME").is_some() {
        assert_ne!(
            source_root.components().next(),
            destination_root.components().next(),
            "supplied destination must be a different volume for this gate"
        );
    }
    eprintln!("backup volume gate: source={source_root:?} destination={destination_root:?}");
    let source = source_root.join("live");
    let bundle = destination_root.join("bundle");
    let target = destination_root.join("target");
    let engine = PraxisEngine::open(config(&source, true)).unwrap();
    let value = Bytes::from(vec![b'V'; 16384]);
    engine.put("value", value.clone()).unwrap();
    engine.flush().unwrap();
    engine.backup_to(&bundle).unwrap();
    drop(engine);
    std::fs::rename(&source, source_root.join("hidden-live")).unwrap();
    PraxisEngine::restore_from_backup(&bundle, &target).unwrap();
    std::fs::rename(&bundle, destination_root.join("hidden-bundle")).unwrap();
    let restored = PraxisEngine::open(config(&target, true)).unwrap();
    assert_eq!(restored.get("value").unwrap(), Some(value));
    restored.verify().unwrap();
}
