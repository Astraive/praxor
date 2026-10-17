use bytes::Bytes;
use praxis::{PraxisConfig, PraxisEngine};
use tempfile::tempdir;

#[test]
fn durable_writes_leave_checkpoint_manifest_unchanged_until_maintenance() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let manifest = dir.path().join("MANIFEST");
    let before = std::fs::read(&manifest).unwrap();
    for index in 0..16 {
        engine
            .put(Bytes::from(format!("key/{index}")), "value")
            .unwrap();
    }
    assert!(
        std::fs::read(&manifest).unwrap() == before,
        "durable WAL appends must not rewrite checkpoint metadata"
    );
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.snapshot().sequence, 16);
    for index in 0..16 {
        assert_eq!(
            engine.get(format!("key/{index}")).unwrap(),
            Some(Bytes::from_static(b"value"))
        );
    }
}

#[test]
fn wal_only_write_does_not_depend_on_a_manifest_temporary_file() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let blocked = dir.path().join("MANIFEST.tmp");
    std::fs::create_dir(&blocked).unwrap();
    let result = engine.put("key", "value");
    std::fs::remove_dir(&blocked).unwrap();
    assert!(
        result.is_ok(),
        "a WAL-only commit should not write the manifest: {result:?}"
    );
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"value"))
    );
}

#[test]
fn recovered_wal_watermark_survives_flush_and_a_second_reopen() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.put("key", "value").unwrap(), 1);
    drop(engine);

    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.snapshot().sequence, 1);
    engine.flush().unwrap();
    drop(engine);

    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(engine.snapshot().sequence, 1);
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"value"))
    );
    assert_eq!(engine.put("second", "new").unwrap(), 2);
    drop(engine);

    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(engine.snapshot().sequence, 2);
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"value"))
    );
    assert_eq!(
        engine.get("second").unwrap(),
        Some(Bytes::from_static(b"new"))
    );
}
