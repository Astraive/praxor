use super::*;
use crate::core_records::RecordAuthority;

fn valid() -> Manifest {
    Manifest::fresh_records(
        &PraxisConfig::default(),
        RecordAuthority::new([0x11; 16], 2),
    )
}
fn decode(manifest: &Manifest) -> Result<Manifest> {
    Manifest::decode(
        toml::to_string(manifest).unwrap().as_bytes(),
        Path::new("manifest-v3"),
    )
}

#[test]
fn v3_round_trip_requires_every_authority_field_and_exact_role_fields() {
    let manifest = valid();
    assert_eq!(decode(&manifest).unwrap(), manifest);
    let value = toml::Value::try_from(&manifest).unwrap();
    for field in [
        "kind",
        "schema_version",
        "database_id",
        "epoch",
        "bootstrap_sequence",
        "index_descriptor_count",
        "roles",
    ] {
        let mut value = value.clone();
        value["record_authority"]
            .as_table_mut()
            .unwrap()
            .remove(field);
        assert!(
            Manifest::decode(
                toml::to_string(&value).unwrap().as_bytes(),
                Path::new("missing-field")
            )
            .is_err(),
            "{field}"
        );
    }
    for field in ["role", "column_family", "generation"] {
        let mut value = value.clone();
        value["record_authority"]["roles"][0]
            .as_table_mut()
            .unwrap()
            .remove(field);
        assert!(
            Manifest::decode(
                toml::to_string(&value).unwrap().as_bytes(),
                Path::new("missing-role-field")
            )
            .is_err()
        );
    }
    for target in [None, Some(0)] {
        let mut value = value.clone();
        let table = if let Some(index) = target {
            value["record_authority"]["roles"][index]
                .as_table_mut()
                .unwrap()
        } else {
            value["record_authority"].as_table_mut().unwrap()
        };
        table.insert("future_feature".into(), toml::Value::Boolean(false));
        assert!(
            Manifest::decode(
                toml::to_string(&value).unwrap().as_bytes(),
                Path::new("unknown-field")
            )
            .is_err()
        );
    }
}

#[test]
fn v3_rejects_all_role_policy_and_generation_mutations() {
    for index in 1..=4 {
        let mutations: Vec<fn(&mut ColumnFamilyDescriptor)> = vec![
            |cf| cf.name.push('x'),
            |cf| cf.write_buffer_size_bytes += 1,
            |cf| cf.large_value_threshold_bytes += 1,
            |cf| cf.bloom_enabled = false,
            |cf| cf.options.ttl_seconds = Some(0),
            |cf| cf.options.merge_operator = Some("concat".into()),
            |cf| cf.options.compression_override = Some(Compression::None),
            |cf| cf.options.prefix_extractor_len = Some(1),
            |cf| cf.options.cache_partition_percent = Some(0),
            |cf| cf.options.memtable_kind = crate::config::MemTableKind::Art,
            |cf| cf.options.compaction_strategy = crate::config::CompactionStrategy::Tiered,
        ];
        for mutate in mutations {
            let mut manifest = valid();
            mutate(&mut manifest.column_families[index]);
            assert!(decode(&manifest).is_err());
        }
        let mut manifest = valid();
        let name = manifest.column_families[index].name.clone();
        manifest
            .column_family_generations
            .get_mut(&name)
            .unwrap()
            .visible_after_sequence = 1;
        assert!(decode(&manifest).is_err());
        let mut manifest = valid();
        manifest
            .column_family_generations
            .get_mut(&name)
            .unwrap()
            .id = 9;
        manifest.next_column_family_generation = 10;
        assert!(decode(&manifest).is_err());
    }
    let mut manifest = valid();
    manifest.record_authority.as_mut().unwrap().roles.swap(0, 1);
    assert!(
        decode(&manifest).is_ok(),
        "TOML role order is not binary role order"
    );
    manifest.record_authority.as_mut().unwrap().roles[0] =
        manifest.record_authority.as_ref().unwrap().roles[1].clone();
    assert!(decode(&manifest).is_err());
}

#[test]
fn v3_identity_features_presence_and_u64_values_are_strict() {
    for identity in [
        "0".repeat(32),
        "A".repeat(32),
        "1".repeat(31),
        "g".repeat(32),
    ] {
        let mut manifest = valid();
        manifest.record_authority.as_mut().unwrap().database_id = identity;
        assert!(decode(&manifest).is_err());
    }
    for mutate in [
        (|a: &mut RecordAuthority| a.kind = "other".into()) as fn(&mut RecordAuthority),
        |a| a.schema_version = 2,
        |a| a.epoch = 2,
        |a| a.bootstrap_sequence = 0,
        |a| a.roles[0].generation = 2,
        |a| a.roles[0].column_family = "default".into(),
        |a| a.roles[0].role = "unknown".into(),
    ] {
        let mut manifest = valid();
        mutate(manifest.record_authority.as_mut().unwrap());
        assert!(decode(&manifest).is_err());
    }
    let mut manifest = valid();
    manifest.record_authority = None;
    assert!(decode(&manifest).is_err());
    for version in [1, 2] {
        let mut manifest = valid();
        manifest.format_version = version;
        assert!(decode(&manifest).is_err());
    }
    let mut manifest = valid();
    manifest.last_sequence = u64::MAX;
    manifest.next_column_family_generation = u64::MAX;
    assert_eq!(decode(&manifest).unwrap(), manifest);
}

fn user_manifest(generation: u64, floor: u64) -> Manifest {
    let mut manifest = valid();
    manifest.next_column_family_generation = 6;
    manifest.column_families.push(ColumnFamilyDescriptor {
        name: "user".into(),
        ..ColumnFamilyDescriptor::default()
    });
    manifest.column_family_generations.insert(
        "user".into(),
        ColumnFamilyGeneration {
            id: generation,
            visible_after_sequence: floor,
        },
    );
    manifest
}

#[test]
fn review_v3_user_family_cannot_have_a_legacy_zero_incarnation() {
    assert!(decode(&user_manifest(0, 0)).is_err());
}

#[test]
fn review_v3_user_family_cannot_precede_the_authority_bootstrap_floor() {
    assert!(decode(&user_manifest(5, 0)).is_err());
}

#[test]
fn v3_later_user_family_and_legacy_zero_or_zero_floor_families_remain_supported() {
    assert!(decode(&user_manifest(5, 1)).is_ok());
    for generation in [0, 5] {
        let mut manifest = user_manifest(generation, 0);
        manifest.format_version = 2;
        manifest.record_authority = None;
        assert!(decode(&manifest).is_ok());
    }
}

fn legacy_header_fixture(version: u32) -> String {
    let mut manifest = if version == 3 {
        valid()
    } else {
        Manifest::fresh(&PraxisConfig::default())
    };
    manifest.format_version = version;
    let mut wire = toml::Value::try_from(&manifest).unwrap();
    if version == 1 {
        // A genuine v1 file has neither generation field on disk. Its
        // in-memory upgrade to v2 happens only after the header is checked.
        let fields = wire.as_table_mut().unwrap();
        fields.remove("column_family_generations");
        fields.remove("next_column_family_generation");
    }
    let bytes = toml::to_string(&wire).unwrap();
    let decoded = Manifest::decode(bytes.as_bytes(), Path::new("legacy-fixture")).unwrap();
    assert_eq!(
        decoded.format_version,
        if version == 1 { 2 } else { version }
    );
    bytes
}

fn assert_legacy_catalog_field_is_rejected(version: u32) {
    let fixture = legacy_header_fixture(version);
    let forms = [
        format!("catalog_authority = false\n{fixture}"),
        format!("{fixture}\n[catalog_authority]\n"),
        format!("{fixture}\n[catalog_authority]\nkind = \"core_catalog\"\nschema_version = 1\n"),
    ];
    for (index, bytes) in forms.iter().enumerate() {
        assert!(
            matches!(
                Manifest::decode(bytes.as_bytes(), Path::new("legacy-catalog-field")),
                Err(PraxisError::Corrupt { .. })
            ),
            "v{version} accepted catalog_authority form {index}"
        );
    }
}

#[test]
fn legacy_catalog_authority_v1_presence_is_rejected() {
    assert_legacy_catalog_field_is_rejected(1);
}

#[test]
fn legacy_catalog_authority_v2_presence_is_rejected() {
    assert_legacy_catalog_field_is_rejected(2);
}

#[test]
fn legacy_catalog_authority_v3_presence_is_rejected() {
    assert_legacy_catalog_field_is_rejected(3);
}

#[test]
fn legacy_unknown_top_level_field_remains_permitted() {
    for version in 1..=3 {
        let bytes = format!(
            "unrelated_future_field = true\n{}",
            legacy_header_fixture(version)
        );
        let decoded = Manifest::decode(bytes.as_bytes(), Path::new("legacy-future-field")).unwrap();
        assert_eq!(
            decoded.format_version,
            if version == 1 { 2 } else { version }
        );
    }
}

#[test]
fn v2_generic_owner_reopens_with_unrelated_top_level_field() {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = crate::PraxisEngine::open(config.clone()).unwrap();
    engine.put("legacy-key", "legacy-value").unwrap();
    drop(engine);

    let path = dir.path().join("MANIFEST");
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("unrelated_future_field = true\n{original}")).unwrap();

    let reopened = crate::PraxisEngine::open(config).unwrap();
    assert_eq!(
        reopened.get("legacy-key").unwrap(),
        Some(bytes::Bytes::from_static(b"legacy-value"))
    );
}
