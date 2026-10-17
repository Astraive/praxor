use bytes::Bytes;
use praxis::manifest::ColumnFamilyDescriptor;
use praxis::types::ColumnFamily;
use praxis::{PraxisConfig, PraxisEngine, WriteBatch};
use tempfile::tempdir;

fn create_tenant(engine: &PraxisEngine) {
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "tenant".into(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
}

fn put_tenant(engine: &PraxisEngine, key: &str, value: &str) -> u64 {
    let mut batch = WriteBatch::new();
    batch.put(
        "tenant",
        Bytes::copy_from_slice(key.as_bytes()),
        Bytes::copy_from_slice(value.as_bytes()),
    );
    engine.write_batch(batch).unwrap()
}

fn read_tenant(engine: &PraxisEngine, key: &str) -> Option<Bytes> {
    engine
        .get_cf(
            &ColumnFamily("tenant".into()),
            key.as_bytes(),
            engine.snapshot(),
        )
        .unwrap()
}

#[test]
fn dropped_family_wal_does_not_reappear_when_name_is_recreated_after_reopen() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    create_tenant(&engine);
    let old_sequence = put_tenant(&engine, "retired", "old");
    engine.put("keep", "default value").unwrap();
    engine.drop_column_family("tenant").unwrap();
    drop(engine);

    let engine = PraxisEngine::open(config.clone()).unwrap();
    create_tenant(&engine);
    assert_eq!(read_tenant(&engine, "retired"), None);
    assert!(put_tenant(&engine, "fresh", "new") > old_sequence);
    drop(engine);

    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(read_tenant(&engine, "retired"), None);
    assert_eq!(
        read_tenant(&engine, "fresh"),
        Some(Bytes::from_static(b"new"))
    );
    assert_eq!(
        engine.get("keep").unwrap(),
        Some(Bytes::from_static(b"default value"))
    );
}

#[test]
fn replacement_family_ignores_old_flushed_versions_through_maintenance_and_reopen() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    create_tenant(&engine);
    put_tenant(&engine, "retired", "old");
    put_tenant(&engine, "changed", "old");
    engine.put("keep", "default value").unwrap();
    engine.flush().unwrap();
    engine.drop_column_family("tenant").unwrap();
    create_tenant(&engine);
    put_tenant(&engine, "changed", "new");
    drop(engine);

    for _ in 0..3 {
        let engine = PraxisEngine::open(config.clone()).unwrap();
        assert_eq!(read_tenant(&engine, "retired"), None);
        assert_eq!(
            read_tenant(&engine, "changed"),
            Some(Bytes::from_static(b"new"))
        );
        assert_eq!(
            engine.get("keep").unwrap(),
            Some(Bytes::from_static(b"default value"))
        );
        engine.flush().unwrap();
        engine.compact().unwrap();
        engine.garbage_collect().unwrap();
    }
}

#[test]
fn replacement_merge_chain_does_not_use_a_base_from_the_dropped_family() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    create_tenant(&engine);
    put_tenant(&engine, "key", "retired-base");
    engine.flush().unwrap();
    engine.drop_column_family("tenant").unwrap();
    create_tenant(&engine);
    let mut batch = WriteBatch::new();
    batch.merge("tenant", "key", "new-generation");
    engine.write_batch(batch).unwrap();
    assert_eq!(
        read_tenant(&engine, "key"),
        Some(Bytes::from_static(b"new-generation"))
    );
    drop(engine);

    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        read_tenant(&engine, "key"),
        Some(Bytes::from_static(b"new-generation"))
    );
}

fn persisted_manifest(dir: &std::path::Path) -> toml::Value {
    toml::from_str(&std::fs::read_to_string(dir.join("MANIFEST")).unwrap()).unwrap()
}

fn save_manifest(dir: &std::path::Path, value: &toml::Value) {
    std::fs::write(dir.join("MANIFEST"), toml::to_string_pretty(value).unwrap()).unwrap();
}

fn generation(id: i64, floor: i64) -> toml::Value {
    let mut value = toml::Table::new();
    value.insert("id".into(), id.into());
    value.insert("visible_after_sequence".into(), floor.into());
    value.into()
}

#[test]
fn recreations_without_writes_consume_distinct_persisted_generation_ids() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    create_tenant(&engine);
    let first = persisted_manifest(dir.path())["column_family_generations"]["tenant"]["id"]
        .as_integer()
        .unwrap();
    assert!(first > 0);
    engine.drop_column_family("tenant").unwrap();
    create_tenant(&engine);
    let second = persisted_manifest(dir.path())["column_family_generations"]["tenant"]["id"]
        .as_integer()
        .unwrap();
    assert!(second > first);
    assert_eq!(engine.snapshot().sequence, 0);
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine.stats()["manifest"]["column_family_generations"]["tenant"]["id"].as_u64(),
        Some(second as u64)
    );
}

#[test]
fn malformed_v2_generation_metadata_is_rejected() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    let mut valid = persisted_manifest(dir.path());
    valid["format_version"] = 2.into();
    valid.as_table_mut().unwrap().insert(
        "column_family_generations".into(),
        toml::Table::from_iter([("default".into(), generation(0, 0))]).into(),
    );
    valid
        .as_table_mut()
        .unwrap()
        .insert("next_column_family_generation".into(), 1.into());
    let descriptor = valid["column_families"][0].clone();
    let mut cases = Vec::new();
    for version in [0, 3] {
        let mut value = valid.clone();
        value["format_version"] = version.into();
        cases.push((format!("unsupported version {version}"), value));
    }
    for field in ["column_family_generations", "next_column_family_generation"] {
        let mut value = valid.clone();
        value.as_table_mut().unwrap().remove(field);
        cases.push((format!("missing {field}"), value));
    }
    let mut value = valid.clone();
    value["column_family_generations"] = toml::Table::new().into();
    cases.push(("missing active default".into(), value));
    let mut value = valid.clone();
    value["column_family_generations"]
        .as_table_mut()
        .unwrap()
        .insert("ghost".into(), generation(1, 0));
    value["next_column_family_generation"] = 2.into();
    cases.push(("extra inactive family".into(), value));
    let mut value = valid.clone();
    value["column_families"]
        .as_array_mut()
        .unwrap()
        .push(descriptor.clone());
    cases.push(("duplicate family names".into(), value));
    let mut value = valid.clone();
    value["column_family_generations"]["default"] = generation(1, 0);
    value["next_column_family_generation"] = 2.into();
    cases.push(("nonlegacy default".into(), value));
    let mut value = valid.clone();
    value["column_family_generations"]["default"] = generation(0, 1);
    value["last_sequence"] = 1.into();
    cases.push(("legacy nonzero floor".into(), value));
    let mut tenant = descriptor.clone();
    tenant["name"] = "tenant".into();
    let mut with_tenant = valid.clone();
    with_tenant["column_families"]
        .as_array_mut()
        .unwrap()
        .push(tenant.clone());
    with_tenant["column_family_generations"]
        .as_table_mut()
        .unwrap()
        .insert("tenant".into(), generation(1, 0));
    with_tenant["next_column_family_generation"] = 2.into();
    let mut value = with_tenant.clone();
    value["column_family_generations"]["tenant"] = generation(1, 2);
    value["last_sequence"] = 1.into();
    cases.push(("floor beyond durable watermark".into(), value));
    let mut value = with_tenant.clone();
    tenant["name"] = "other".into();
    value["column_families"]
        .as_array_mut()
        .unwrap()
        .push(tenant);
    value["column_family_generations"]
        .as_table_mut()
        .unwrap()
        .insert("other".into(), generation(1, 0));
    cases.push(("duplicate nonzero IDs".into(), value));
    for counter in [0, 1] {
        let mut value = with_tenant.clone();
        value["next_column_family_generation"] = counter.into();
        cases.push((format!("invalid counter {counter}"), value));
    }
    for field in ["id", "visible_after_sequence"] {
        let mut value = with_tenant.clone();
        value["column_family_generations"]["tenant"]
            .as_table_mut()
            .unwrap()
            .remove(field);
        cases.push((format!("missing generation field {field}"), value));
    }
    let mut value = valid.clone();
    value["column_families"] = Vec::<toml::Value>::new().into();
    value["column_family_generations"] = toml::Table::new().into();
    cases.push(("empty v2 active metadata".into(), value));
    let mut accepted = Vec::new();
    for (name, value) in cases {
        save_manifest(dir.path(), &value);
        if PraxisEngine::open(config.clone()).is_ok() {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted malformed manifests: {accepted:?}"
    );
}

#[test]
fn legacy_v1_zero_sequence_wal_data_migrates_without_disappearing() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    let mut legacy = persisted_manifest(dir.path());
    legacy["format_version"] = 1.into();
    legacy
        .as_table_mut()
        .unwrap()
        .remove("column_family_generations");
    legacy
        .as_table_mut()
        .unwrap()
        .remove("next_column_family_generation");
    save_manifest(dir.path(), &legacy);
    let mut batch = WriteBatch::new();
    batch.put_default("zero", "legacy");
    let mut wal = praxis::wal::Wal::open(
        dir.path().join("wal/00000000000000000001.wal"),
        1,
        praxis::WalSyncPolicy::EveryBatch,
    )
    .unwrap();
    wal.append(&praxis::wal::WalRecord { sequence: 0, batch })
        .unwrap();
    drop(wal);
    let engine = PraxisEngine::open(config.clone()).unwrap();
    assert_eq!(
        engine.get("zero").unwrap(),
        Some(Bytes::from_static(b"legacy"))
    );
    engine.flush().unwrap();
    drop(engine);
    let upgraded: praxis::manifest::Manifest =
        toml::from_str(&std::fs::read_to_string(dir.path().join("MANIFEST")).unwrap()).unwrap();
    assert_eq!(upgraded.format_version, 2);
    assert_eq!(
        upgraded.column_family_generations["default"],
        praxis::manifest::ColumnFamilyGeneration::default()
    );
    let engine = PraxisEngine::open(config).unwrap();
    assert_eq!(
        engine.get("zero").unwrap(),
        Some(Bytes::from_static(b"legacy"))
    );
}
