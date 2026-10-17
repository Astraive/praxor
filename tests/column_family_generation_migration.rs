use bytes::Bytes;
use praxis::manifest::ColumnFamilyDescriptor;
use praxis::{PraxisConfig, PraxisEngine, WalSyncPolicy, WriteBatch};
use tempfile::tempdir;

fn create(engine: &PraxisEngine, name: &str) {
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: name.into(),
            ..Default::default()
        })
        .unwrap();
}

fn read_manifest(dir: &std::path::Path) -> praxis::manifest::Manifest {
    toml::from_str(&std::fs::read_to_string(dir.join("MANIFEST")).unwrap()).unwrap()
}

fn write_legacy_manifest(dir: &std::path::Path, empty_families: bool) {
    let mut raw = read_manifest(dir);
    raw.format_version = 1;
    raw.column_family_generations.clear();
    raw.next_column_family_generation = 1;
    if empty_families {
        raw.column_families.clear();
    }
    let encoded = toml::to_string_pretty(&raw)
        .unwrap()
        .replace("next_column_family_generation = 1\n", "")
        .replace("[column_family_generations]\n", "");
    std::fs::write(dir.join("MANIFEST"), encoded).unwrap();
}

#[test]
fn legacy_active_families_keep_data_and_gain_explicit_zero_generations() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    create(&engine, "legacy");
    let mut batch = WriteBatch::new();
    batch.put("legacy", "key", "old");
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    drop(engine);
    write_legacy_manifest(dir.path(), false);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(
        engine
            .get_cf(&"legacy".into(), b"key", engine.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"old"))
    );
    let metadata = &engine.stats()["manifest"]["column_family_generations"];
    assert_eq!(metadata["legacy"]["id"].as_u64(), Some(0));
    assert_eq!(
        metadata["legacy"]["visible_after_sequence"].as_u64(),
        Some(0)
    );
    assert_eq!(read_manifest(dir.path()).format_version, 1);
    create(&engine, "fresh");
    let persisted = read_manifest(dir.path());
    assert_eq!(persisted.format_version, 2);
    assert_eq!(persisted.column_family_generations["fresh"].id, 1);
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine
            .get_cf(&"legacy".into(), b"key", engine.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"old"))
    );
}

#[test]
fn legacy_empty_family_list_repairs_before_coverage_validation() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    write_legacy_manifest(dir.path(), true);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.list_column_families().len(), 1);
    assert_eq!(
        engine.stats()["manifest"]["column_family_generations"]["default"]["id"].as_u64(),
        Some(0)
    );
    engine.put("legacy-default", "value").unwrap();
    engine.flush().unwrap();
    assert_eq!(read_manifest(dir.path()).format_version, 2);
}

#[test]
fn fully_filtered_wal_record_still_advances_global_sequence() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    let mut wal = praxis::wal::Wal::open(
        dir.path().join("wal/00000000000000000001.wal"),
        1,
        WalSyncPolicy::EveryBatch,
    )
    .unwrap();
    let mut batch = WriteBatch::new();
    batch.put("retired", "key", "old");
    wal.append(&praxis::wal::WalRecord {
        sequence: 73,
        batch,
    })
    .unwrap();
    drop(wal);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.snapshot().sequence, 73);
    create(&engine, "retired");
    assert!(
        engine
            .get_cf(&"retired".into(), b"key", engine.snapshot())
            .unwrap()
            .is_none()
    );
    assert_eq!(engine.stats()["manifest"]["column_family_generations"]["retired"]["visible_after_sequence"].as_u64(),Some(73));
    let mut batch = WriteBatch::new();
    batch.put("retired", "fresh", "new");
    assert_eq!(engine.write_batch(batch).unwrap(), 74);
    engine.flush().unwrap();
    engine.garbage_collect().unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.snapshot().sequence, 74);
    assert!(
        engine
            .get_cf(&"retired".into(), b"key", engine.snapshot())
            .unwrap()
            .is_none()
    );
}

#[test]
fn checkpoints_and_backup_manifest_carry_active_incarnation_metadata() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config).unwrap();
    create(&engine, "tenant");
    let mut batch = WriteBatch::new();
    batch.put("tenant", "old", "retired");
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    engine.drop_column_family("tenant").unwrap();
    create(&engine, "tenant");
    let checkpoint = engine.checkpoint().unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checkpoint.path).unwrap()).unwrap();
    let manifest = engine.stats()["manifest"].clone();
    assert_eq!(
        raw["column_family_generations"],
        manifest["column_family_generations"]
    );
    assert_eq!(
        raw["next_column_family_generation"],
        manifest["next_column_family_generation"]
    );
    let backup = tempdir().unwrap();
    let destination = backup.path().join("copy");
    engine.backup_to(&destination).unwrap();
    let copied: praxis::manifest::Manifest =
        toml::from_str(&std::fs::read_to_string(destination.join("MANIFEST")).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(copied.column_family_generations).unwrap(),
        manifest["column_family_generations"]
    );
    assert_eq!(
        serde_json::json!(copied.next_column_family_generation),
        manifest["next_column_family_generation"]
    );
}

#[test]
fn pin_does_not_retain_access_to_a_dropped_or_recreated_family() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    create(&engine, "tenant");
    let mut batch = WriteBatch::new();
    batch.put("tenant", "key", "retired");
    engine.write_batch(batch).unwrap();
    let pin = engine.pin_snapshot();
    engine.drop_column_family("tenant").unwrap();
    assert!(matches!(
        engine.get_cf(&"tenant".into(), b"key", pin.snapshot()),
        Err(praxis::PraxisError::UnknownColumnFamily(_))
    ));
    create(&engine, "tenant");
    let mut batch = WriteBatch::new();
    batch.put("tenant", "key", "fresh");
    engine.write_batch(batch).unwrap();
    assert!(
        engine
            .get_cf(&"tenant".into(), b"key", pin.snapshot())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine
            .get_cf(&"tenant".into(), b"key", engine.snapshot())
            .unwrap(),
        Some(Bytes::from_static(b"fresh"))
    );
}
