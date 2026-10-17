use super::engine::PraxisEngine;
use crate::config::{PraxisConfig, WalSyncPolicy};

fn engine() -> (tempfile::TempDir, PraxisConfig, PraxisEngine) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::GroupCommit;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    (dir, config, engine)
}

#[test]
fn cf_validation_errors_leave_handle_writable() {
    use crate::errors::PraxisError;
    let (_dir, _config, engine) = engine();
    let descriptor = crate::manifest::ColumnFamilyDescriptor {
        name: "registered".to_string(),
        ..Default::default()
    };
    engine.create_column_family(descriptor.clone()).unwrap();
    assert!(matches!(
        engine.create_column_family(descriptor),
        Err(PraxisError::ColumnFamilyExists(_))
    ));
    assert!(matches!(
        engine.drop_column_family("missing"),
        Err(PraxisError::UnknownColumnFamily(_))
    ));
    assert!(matches!(
        engine.drop_column_family("default"),
        Err(PraxisError::CannotDropDefaultColumnFamily)
    ));
    assert!(engine.put("still-writable", "value").is_ok());
}

#[test]
fn failed_cf_create_keeps_previous_manifest_and_requires_recovery() {
    let (dir, config, engine) = engine();
    let before = engine.list_column_families();
    let before_generations = engine
        .inner
        .manifest
        .lock()
        .column_family_generations
        .clone();
    let before_next = engine.inner.manifest.lock().next_column_family_generation;
    let manifest = std::fs::read(dir.path().join("MANIFEST")).unwrap();
    std::fs::create_dir(dir.path().join("MANIFEST.tmp")).unwrap();
    assert!(
        engine
            .create_column_family(crate::manifest::ColumnFamilyDescriptor {
                name: "unregistered".to_string(),
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(engine.list_column_families(), before);
    assert_eq!(
        engine.inner.manifest.lock().column_family_generations,
        before_generations
    );
    assert_eq!(
        engine.inner.manifest.lock().next_column_family_generation,
        before_next
    );
    assert_eq!(
        std::fs::read(dir.path().join("MANIFEST")).unwrap(),
        manifest
    );
    assert!(matches!(
        engine.put("later", "x"),
        Err(crate::errors::PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        engine.garbage_collect(),
        Err(crate::errors::PraxisError::RecoveryRequired)
    ));
    std::fs::remove_dir(dir.path().join("MANIFEST.tmp")).unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.list_column_families(), before);
    assert_eq!(
        engine.inner.manifest.lock().column_family_generations,
        before_generations
    );
    assert_eq!(
        engine.inner.manifest.lock().next_column_family_generation,
        before_next
    );
    assert!(engine.put("recovered", "x").is_ok());
}

#[test]
fn failed_cf_drop_keeps_previous_manifest_and_readable_data() {
    let (dir, config, engine) = engine();
    engine
        .create_column_family(crate::manifest::ColumnFamilyDescriptor {
            name: "registered".to_string(),
            ..Default::default()
        })
        .unwrap();
    let mut batch = crate::transactions::WriteBatch::new();
    batch.put("registered", "key", "value");
    engine.write_batch(batch).unwrap();
    let before = engine.list_column_families();
    let before_generations = engine
        .inner
        .manifest
        .lock()
        .column_family_generations
        .clone();
    let before_next = engine.inner.manifest.lock().next_column_family_generation;
    let manifest = std::fs::read(dir.path().join("MANIFEST")).unwrap();
    std::fs::create_dir(dir.path().join("MANIFEST.tmp")).unwrap();
    assert!(engine.drop_column_family("registered").is_err());
    assert_eq!(engine.list_column_families(), before);
    assert_eq!(
        engine.inner.manifest.lock().column_family_generations,
        before_generations
    );
    assert_eq!(
        engine.inner.manifest.lock().next_column_family_generation,
        before_next
    );
    assert_eq!(
        std::fs::read(dir.path().join("MANIFEST")).unwrap(),
        manifest
    );
    assert_eq!(
        engine
            .get_cf(&"registered".into(), b"key", engine.snapshot())
            .unwrap()
            .unwrap()
            .as_ref(),
        b"value"
    );
    assert!(matches!(
        engine.flush(),
        Err(crate::errors::PraxisError::RecoveryRequired)
    ));
    assert!(matches!(
        engine.checkpoint(),
        Err(crate::errors::PraxisError::RecoveryRequired)
    ));
    std::fs::remove_dir(dir.path().join("MANIFEST.tmp")).unwrap();
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.list_column_families(), before);
    assert_eq!(
        engine.inner.manifest.lock().column_family_generations,
        before_generations
    );
    assert_eq!(
        engine.inner.manifest.lock().next_column_family_generation,
        before_next
    );
    assert_eq!(
        engine
            .get_cf(&"registered".into(), b"key", engine.snapshot())
            .unwrap()
            .unwrap()
            .as_ref(),
        b"value"
    );
}
