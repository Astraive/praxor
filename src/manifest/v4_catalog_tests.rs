use super::*;
use crate::core_catalog::{CatalogAuthorityV1, CatalogBindingV1};
use crate::core_records::RecordAuthority;

fn valid_v4_with_config(config: &PraxisConfig) -> Manifest {
    let mut manifest = Manifest::fresh_records(config, RecordAuthority::new([0x11; 16], 0));
    manifest.format_version = 4;
    manifest.next_column_family_generation = 6;
    manifest.catalog_authority = Some(CatalogAuthorityV1 {
        kind: "core_catalog".into(),
        schema_version: 1,
        codec_version: 1,
        database_id: "11111111111111111111111111111111".into(),
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
    manifest
}

fn valid_v4() -> Manifest {
    valid_v4_with_config(&PraxisConfig::default())
}

fn wire_value() -> toml::Value {
    toml::Value::try_from(valid_v4()).unwrap()
}

fn assert_raw_refused(raw: &[u8]) {
    let direct = Manifest::decode(raw, Path::new("direct-v4"));
    assert!(
        matches!(
            direct,
            Err(PraxisError::Corrupt { .. } | PraxisError::TomlDe(_))
        ),
        "direct decode accepted malformed v4: {direct:?}"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST");
    std::fs::write(&path, raw).unwrap();
    let store = crate::manifest::ManifestStore::new(&path);
    let loaded = store.load_or_create(&PraxisConfig::new(dir.path()));
    assert!(
        matches!(
            loaded,
            Err(PraxisError::Corrupt { .. } | PraxisError::TomlDe(_))
        ),
        "stored decode accepted malformed v4: {loaded:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    assert!(!path.with_extension("tmp").exists());
}

fn assert_value_refused(value: toml::Value) {
    assert_raw_refused(toml::to_string(&value).unwrap().as_bytes());
}

fn assert_typed_refused(manifest: Manifest) {
    assert_raw_refused(toml::to_string(&manifest).unwrap().as_bytes());
}

fn synthetic_v4_wire() -> String {
    let manifest = Manifest::fresh_records(
        &PraxisConfig::default(),
        RecordAuthority::new([0x11; 16], 0),
    );
    let mut wire = toml::Value::try_from(&manifest).unwrap();
    let root = wire.as_table_mut().unwrap();
    root.insert("format_version".into(), toml::Value::Integer(4));
    root.insert(
        "next_column_family_generation".into(),
        toml::Value::Integer(6),
    );
    root.insert(
        "catalog_authority".into(),
        toml::toml! {
            kind = "core_catalog"
            schema_version = 1
            codec_version = 1
            database_id = "11111111111111111111111111111111"
            epoch = 1
            bootstrap_sequence = 1
            [binding]
            role = "catalog"
            column_family = "__praxor_record_catalog_v1"
            generation = 5
        }
        .into(),
    );
    root.get_mut("column_families")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(
            toml::Value::try_from(ColumnFamilyDescriptor {
                name: "__praxor_record_catalog_v1".into(),
                write_buffer_size_bytes: manifest.effective_config.memtable_flush_threshold_bytes,
                large_value_threshold_bytes: manifest.effective_config.large_value_threshold,
                bloom_enabled: true,
                options: ColumnFamilyOptions {
                    memtable_kind: manifest.effective_config.default_memtable_kind,
                    compaction_strategy: manifest.effective_config.default_compaction_strategy,
                    ..ColumnFamilyOptions::default()
                },
            })
            .unwrap(),
        );
    root.get_mut("column_family_generations")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "__praxor_record_catalog_v1".into(),
            toml::Value::try_from(ColumnFamilyGeneration {
                id: 5,
                visible_after_sequence: 0,
            })
            .unwrap(),
        );
    toml::to_string(&wire).unwrap()
}

#[test]
fn synthetic_v4_manifest_decodes_with_five_bound_families() {
    let decoded = Manifest::decode(synthetic_v4_wire().as_bytes(), Path::new("v4-synthetic"))
        .expect("strict structural v4 manifest should decode");
    assert_eq!(decoded.format_version, 4);
    assert_eq!(decoded.column_families.len(), 6);
    assert_eq!(decoded.column_family_generations.len(), 6);
    assert_eq!(decoded.last_sequence, 1);
}

#[test]
fn v4_typed_roundtrip_preserves_complete_authorities_and_high_u64() {
    let mut manifest = valid_v4();
    manifest.last_sequence = u64::MAX;
    manifest.next_column_family_generation = u64::MAX;
    manifest.record_authority.as_mut().unwrap().roles.swap(0, 3);
    let raw = toml::to_string_pretty(&manifest).unwrap();
    assert_eq!(
        Manifest::decode(raw.as_bytes(), Path::new("v4-high-u64")).unwrap(),
        manifest
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST");
    let store = crate::manifest::ManifestStore::new(&path);
    store.save(&manifest).unwrap();
    assert_eq!(
        store
            .load_or_create(&PraxisConfig::new(dir.path()))
            .unwrap(),
        manifest
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), raw);
}

#[test]
fn v4_catalog_descriptor_follows_nondefault_effective_config() {
    let mut config = PraxisConfig::default();
    config.memtable_flush_threshold_bytes += 4096;
    config.large_value_threshold += 512;
    config.default_memtable_kind = MemTableKind::Art;
    config.default_compaction_strategy = CompactionStrategy::Tiered;
    let manifest = valid_v4_with_config(&config);
    assert_eq!(
        Manifest::decode(
            toml::to_string(&manifest).unwrap().as_bytes(),
            Path::new("nondefault")
        )
        .unwrap(),
        manifest
    );
    assert_ne!(
        manifest.column_families[0].write_buffer_size_bytes,
        manifest.column_families[5].write_buffer_size_bytes
    );
}

#[test]
fn v4_authority_wire_requires_exact_members_and_types() {
    for field in [
        "kind",
        "schema_version",
        "codec_version",
        "database_id",
        "epoch",
        "bootstrap_sequence",
        "binding",
    ] {
        let mut wire = wire_value();
        wire["catalog_authority"]
            .as_table_mut()
            .unwrap()
            .remove(field);
        assert_value_refused(wire);
    }
    for field in ["role", "column_family", "generation"] {
        let mut wire = wire_value();
        wire["catalog_authority"]["binding"]
            .as_table_mut()
            .unwrap()
            .remove(field);
        assert_value_refused(wire);
    }
    for field in [
        "kind",
        "schema_version",
        "codec_version",
        "database_id",
        "epoch",
        "bootstrap_sequence",
        "binding",
    ] {
        let mut wire = wire_value();
        wire["catalog_authority"][field] = toml::Value::Boolean(false);
        assert_value_refused(wire);
    }
    for field in ["role", "column_family", "generation"] {
        let mut wire = wire_value();
        wire["catalog_authority"]["binding"][field] = toml::Value::Boolean(false);
        assert_value_refused(wire);
    }
    for replacement in [
        toml::Value::Boolean(false),
        toml::Value::Table(Default::default()),
    ] {
        let mut wire = wire_value();
        wire["catalog_authority"] = replacement;
        assert_value_refused(wire);
    }
    let mut wire = wire_value();
    wire["catalog_authority"]["binding"] = toml::Value::Table(Default::default());
    assert_value_refused(wire);
    for path in [false, true] {
        let mut wire = wire_value();
        let target = if path {
            &mut wire["catalog_authority"]["binding"]
        } else {
            &mut wire["catalog_authority"]
        };
        target
            .as_table_mut()
            .unwrap()
            .insert("future_member".into(), toml::Value::Integer(1));
        assert_value_refused(wire);
    }
    let raw = toml::to_string(&valid_v4()).unwrap();
    assert_raw_refused(
        raw.replace(
            "kind = \"core_catalog\"",
            "kind = \"core_catalog\"\nkind = \"core_catalog\"",
        )
        .as_bytes(),
    );
    assert_raw_refused(
        raw.replace(
            "role = \"catalog\"",
            "role = \"catalog\"\nrole = \"catalog\"",
        )
        .as_bytes(),
    );
    assert_raw_refused(format!("{raw}\n[catalog_authority]\n").as_bytes());
}

#[test]
fn v4_authority_literals_and_cross_identity_are_enforced() {
    for mutate in [
        (|a: &mut CatalogAuthorityV1| a.kind = "other".into()) as fn(&mut CatalogAuthorityV1),
        |a| a.schema_version = 0,
        |a| a.schema_version = 2,
        |a| a.codec_version = 0,
        |a| a.codec_version = 2,
        |a| a.epoch = 0,
        |a| a.epoch = 2,
        |a| a.bootstrap_sequence = 0,
        |a| a.bootstrap_sequence = 2,
        |a| a.binding.role = "other".into(),
        |a| a.binding.column_family = "default".into(),
        |a| a.binding.generation = 4,
        |a| a.binding.generation = 6,
    ] {
        let mut manifest = valid_v4();
        mutate(manifest.catalog_authority.as_mut().unwrap());
        assert_typed_refused(manifest);
    }
    for id in [
        "0".repeat(32),
        "A".repeat(32),
        "1".repeat(31),
        "g".repeat(32),
        "2".repeat(32),
    ] {
        let mut manifest = valid_v4();
        manifest.catalog_authority.as_mut().unwrap().database_id = id;
        assert_typed_refused(manifest);
    }
    for record_id in ["2".repeat(32), "A".repeat(32)] {
        let mut manifest = valid_v4();
        manifest.record_authority.as_mut().unwrap().database_id = record_id;
        assert_typed_refused(manifest);
    }
}

#[test]
fn v4_record_binding_and_authority_remain_strictly_four_role() {
    let mut manifest = valid_v4();
    manifest.record_authority = None;
    assert_typed_refused(manifest);
    for mutate in [
        (|a: &mut RecordAuthority| a.kind = "other".into()) as fn(&mut RecordAuthority),
        |a| a.roles[0].role = "catalog".into(),
        |a| a.roles[0].column_family = "default".into(),
        |a| a.roles[0].generation = 5,
        |a| a.roles[1] = a.roles[0].clone(),
    ] {
        let mut manifest = valid_v4();
        mutate(manifest.record_authority.as_mut().unwrap());
        assert_typed_refused(manifest);
    }
    let mut wire = wire_value();
    wire.as_table_mut().unwrap().remove("record_authority");
    assert_value_refused(wire);
}

#[test]
fn v4_all_protected_descriptors_and_generations_are_immutable() {
    for index in 1..=5 {
        let mutations: [fn(&mut ColumnFamilyDescriptor); 12] = [
            |cf| cf.name.push('x'),
            |cf| cf.write_buffer_size_bytes += 1,
            |cf| cf.large_value_threshold_bytes += 1,
            |cf| cf.bloom_enabled = false,
            |cf| cf.options.memtable_kind = MemTableKind::Art,
            |cf| cf.options.compaction_strategy = CompactionStrategy::Tiered,
            |cf| cf.options.compression_override = Some(Compression::None),
            |cf| cf.options.ttl_seconds = Some(1),
            |cf| cf.options.prefix_extractor_len = Some(1),
            |cf| cf.options.cache_partition_percent = Some(1),
            |cf| cf.options.merge_operator = Some("concat".into()),
            |cf| cf.options.merge_operator = Some(String::new()),
        ];
        for mutate in mutations {
            let mut manifest = valid_v4();
            mutate(&mut manifest.column_families[index]);
            assert_typed_refused(manifest);
        }
        for (id, floor) in [(0, 0), (index as u64, 1), (9, 0)] {
            let mut manifest = valid_v4();
            manifest.next_column_family_generation = 10;
            let name = manifest.column_families[index].name.clone();
            let generation = manifest.column_family_generations.get_mut(&name).unwrap();
            generation.id = id;
            generation.visible_after_sequence = floor;
            assert_typed_refused(manifest);
        }
        let mut manifest = valid_v4();
        manifest.column_families.remove(index);
        assert_typed_refused(manifest);
        let mut manifest = valid_v4();
        let name = manifest.column_families[index].name.clone();
        manifest.column_family_generations.remove(&name);
        assert_typed_refused(manifest);
    }
    for id in [4, 6] {
        let mut manifest = valid_v4();
        manifest.next_column_family_generation = 7;
        manifest
            .column_family_generations
            .get_mut("__praxor_record_catalog_v1")
            .unwrap()
            .id = id;
        assert_typed_refused(manifest);
    }
    let mut manifest = valid_v4();
    manifest
        .column_families
        .push(manifest.column_families[5].clone());
    assert_typed_refused(manifest);
    let mut manifest = valid_v4();
    manifest.column_families.push(ColumnFamilyDescriptor {
        name: "__praxor_record_extra_v1".into(),
        ..ColumnFamilyDescriptor::default()
    });
    manifest.column_family_generations.insert(
        "__praxor_record_extra_v1".into(),
        ColumnFamilyGeneration {
            id: 6,
            visible_after_sequence: 1,
        },
    );
    manifest.next_column_family_generation = 7;
    assert_typed_refused(manifest);
    let mut manifest = valid_v4();
    manifest
        .column_family_generations
        .get_mut("default")
        .unwrap()
        .id = 6;
    manifest.next_column_family_generation = 7;
    assert_typed_refused(manifest);
}

#[test]
fn v4_user_family_floor_ids_and_counter_start_after_catalog() {
    let mut user = valid_v4();
    user.column_families.push(ColumnFamilyDescriptor {
        name: "user".into(),
        ..ColumnFamilyDescriptor::default()
    });
    user.column_family_generations.insert(
        "user".into(),
        ColumnFamilyGeneration {
            id: 6,
            visible_after_sequence: 1,
        },
    );
    user.next_column_family_generation = 7;
    assert_eq!(
        Manifest::decode(
            toml::to_string(&user).unwrap().as_bytes(),
            Path::new("v4-user")
        )
        .unwrap(),
        user
    );
    for (id, floor, next) in [
        (0, 0, 7),
        (1, 1, 7),
        (2, 1, 7),
        (3, 1, 7),
        (4, 1, 7),
        (5, 1, 7),
        (6, 0, 7),
        (6, 2, 7),
        (6, 1, 6),
        (6, 1, 5),
    ] {
        let mut manifest = user.clone();
        let generation = manifest.column_family_generations.get_mut("user").unwrap();
        generation.id = id;
        generation.visible_after_sequence = floor;
        manifest.next_column_family_generation = next;
        assert_typed_refused(manifest);
    }
    let mut manifest = valid_v4();
    manifest.next_column_family_generation = 5;
    assert_typed_refused(manifest);
}

#[test]
fn v4_strict_wire_rejects_unknown_nested_metadata_missing_generation_and_invalid_utf8() {
    for version in [0, 5] {
        let mut wire = wire_value();
        wire["format_version"] = toml::Value::Integer(version);
        assert_value_refused(wire);
    }
    for target in ["descriptor", "options", "generation"] {
        let mut wire = wire_value();
        let target = match target {
            "descriptor" => &mut wire["column_families"][5],
            "options" => &mut wire["column_families"][5]["options"],
            _ => &mut wire["column_family_generations"]["__praxor_record_catalog_v1"],
        };
        target
            .as_table_mut()
            .unwrap()
            .insert("future_catalog_metadata".into(), toml::Value::Boolean(true));
        assert_value_refused(wire);
    }
    for field in [
        "column_family_generations",
        "next_column_family_generation",
        "catalog_authority",
    ] {
        let mut wire = wire_value();
        wire.as_table_mut().unwrap().remove(field);
        assert_value_refused(wire);
    }
    for field in ["memtable_kind", "compaction_strategy"] {
        let mut wire = wire_value();
        wire["column_families"][5]["options"]
            .as_table_mut()
            .unwrap()
            .remove(field);
        assert_value_refused(wire);
    }
    let raw = toml::to_string(&valid_v4()).unwrap();
    assert_raw_refused(format!("unknown_v4_root = true\n{raw}").as_bytes());
    assert_raw_refused(
        raw.replace(
            "format_version = 4",
            "format_version = 4\nformat_version = 4",
        )
        .as_bytes(),
    );
    let mut invalid_comment = raw.into_bytes();
    invalid_comment.extend_from_slice(b"\n# bad UTF-8: ");
    invalid_comment.push(0xff);
    assert_raw_refused(&invalid_comment);
}

#[test]
fn v4_sequence_claims_must_include_bootstrap_and_not_overflush() {
    let mut manifest = valid_v4();
    manifest.last_sequence = 0;
    assert_typed_refused(manifest);
    let mut manifest = valid_v4();
    manifest.flushed_sequence = 2;
    assert_typed_refused(manifest);
}

#[test]
fn catalog_authority_save_refusal_precedes_temp_file_for_v4_and_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST");
    let store = crate::manifest::ManifestStore::new(&path);
    let valid = valid_v4();
    store.save(&valid).unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut absent = valid.clone();
    absent.catalog_authority = None;
    let mut wrong_binding = valid.clone();
    wrong_binding
        .catalog_authority
        .as_mut()
        .unwrap()
        .binding
        .generation = 6;
    let mut wrong_descriptor = valid.clone();
    wrong_descriptor.column_families[5].bloom_enabled = false;
    for malformed in [absent, wrong_binding, wrong_descriptor] {
        assert!(matches!(
            store.save(&malformed),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!path.with_extension("tmp").exists());
    }
    for version in [1, 2, 3] {
        let mut legacy = if version == 3 {
            Manifest::fresh_records(
                &PraxisConfig::default(),
                RecordAuthority::new([0x11; 16], 0),
            )
        } else {
            Manifest::fresh(&PraxisConfig::default())
        };
        legacy.format_version = version;
        legacy.catalog_authority = valid.catalog_authority.clone();
        assert!(matches!(
            store.save(&legacy),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!path.with_extension("tmp").exists());
    }
}

#[test]
fn v3_reserved_catalog_name_still_refused_and_v2_user_name_still_allowed() {
    let mut v3 = valid_v4();
    v3.format_version = 3;
    v3.catalog_authority = None;
    assert_typed_refused(v3);
    let mut v2 = Manifest::fresh(&PraxisConfig::default());
    v2.last_sequence = 1;
    v2.next_column_family_generation = 2;
    v2.column_families.push(ColumnFamilyDescriptor {
        name: "__praxor_record_catalog_v1".into(),
        ..ColumnFamilyDescriptor::default()
    });
    v2.column_family_generations.insert(
        "__praxor_record_catalog_v1".into(),
        ColumnFamilyGeneration {
            id: 1,
            visible_after_sequence: 1,
        },
    );
    assert_eq!(
        Manifest::decode(
            toml::to_string(&v2).unwrap().as_bytes(),
            Path::new("v2-catalog-name")
        )
        .unwrap(),
        v2
    );
}
