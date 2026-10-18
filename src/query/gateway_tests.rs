use super::*;
use crate::catalog::schema::{
    AttributeSchema, AttributeType, CollectionSchema, ComputedField, IntegerType, SchemaMode,
};
use crate::query::fixture_v1::FixtureDecodeReason;
use crate::query::fixture_v1::encode_document;
use crate::query::{CompileInput, CompiledStatement, QueryCompileError, compile};
use serde_json::{Number, Value, json};
use std::collections::BTreeMap;

fn db() -> (tempfile::TempDir, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(
        crate::PraxisConfig::new(dir.path()),
        crate::RecordAuthorityOptions::default(),
    )
    .unwrap();
    (dir, db)
}

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("docs").with_attribute(AttributeSchema::new(
                "n",
                AttributeType::Integer(IntegerType::Uint8),
            )),
        )
        .unwrap();
    catalog
}

fn with_schema(schema: CollectionSchema) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.create_collection(schema).unwrap();
    catalog
}

fn catalog_code(db: &CoreDatabase, catalog: Catalog) -> &'static str {
    match QueryGateway::attach_fixture_v1(db, catalog) {
        Err(QueryReadError::FixtureCatalog { code }) => code,
        Ok(_) => panic!("expected fixture catalog refusal, got success"),
        Err(other) => panic!("expected fixture catalog refusal, got {other:?}"),
    }
}

fn put(db: &CoreDatabase, collection: &str, key: &str, value: Value) -> crate::store::RecordId {
    let attributes = BTreeMap::from([("n".to_owned(), value)]);
    let frame = encode_document(collection, key, &attributes).unwrap();
    db.records().put(&frame, &[]).unwrap()
}

#[test]
fn gateway_selects_one_retained_complete_collection_with_typed_parameter() {
    let (_dir, db) = db();
    put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    put(&db, "docs", "second", Value::Number(Number::from(8_u64)));
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let params = TypedParameters {
        positional: vec![super::super::ParameterValue::U64(7)],
        ..TypedParameters::default()
    };
    let QueryResult::Rows(rows) = gateway
        .query(&view, "SELECT n FROM docs WHERE n = $1", &params)
        .unwrap()
    else {
        panic!("expected rows")
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].id.collection.as_str(), rows[0].id.key.as_str()),
        ("docs", "first")
    );
    assert_eq!(
        rows[0].fields,
        vec![("n".into(), Value::Number(Number::from(7_u64)))]
    );
}

#[test]
fn gateway_rejects_a_view_from_another_gateway_over_the_same_database() {
    let (_dir, db) = db();
    let first = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let second = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let foreign = first.begin_read().unwrap();
    assert!(matches!(
        second.query(&foreign, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::ForeignGateway)
    ));
}

#[test]
fn gateway_refuses_a_deserialized_outer_catalog_key_before_rekeying() {
    let (_dir, db) = db();
    let schema = CollectionSchema::new("docs");
    let malformed: Catalog = serde_json::from_value(json!({
        "collections": { "shadow": schema }
    }))
    .unwrap();
    assert!(matches!(
        QueryGateway::attach_fixture_v1(&db, malformed),
        Err(QueryReadError::FixtureCatalog {
            code: "collection_key"
        })
    ));
}

#[test]
fn gateway_catalog_admission_checks_count_keys_modes_and_declarations() {
    let (_dir, db) = db();
    let mut too_many = Catalog::new();
    for index in 0..17 {
        too_many
            .create_collection(CollectionSchema::new(format!("c{index}")))
            .unwrap();
    }
    assert_eq!(catalog_code(&db, too_many), "collection_count");

    // Global count wins over a later malformed map key.
    let mut entries = serde_json::Map::new();
    for index in 0..17 {
        entries.insert(format!("c{index}"), json!(CollectionSchema::new("wrong")));
    }
    let simultaneous: Catalog = serde_json::from_value(Value::Object(serde_json::Map::from_iter(
        [("collections".into(), Value::Object(entries))],
    )))
    .unwrap();
    assert_eq!(catalog_code(&db, simultaneous), "collection_count");

    let duplicate = serde_json::from_value(json!({ "collections": {
        "docs": CollectionSchema::new("docs"),
        "shadow": CollectionSchema::new("docs")
    }}))
    .unwrap();
    assert_eq!(catalog_code(&db, duplicate), "collection_key");

    let mut wrong_attribute_key = catalog().collection("docs").unwrap().clone();
    let attribute = wrong_attribute_key.attributes.remove("n").unwrap();
    wrong_attribute_key
        .attributes
        .insert("shadow".into(), attribute);
    assert_eq!(
        catalog_code(&db, with_schema(wrong_attribute_key)),
        "attribute_key"
    );

    let mut strict = catalog().collection("docs").unwrap().clone();
    strict.mode = SchemaMode::Strict;
    assert_eq!(catalog_code(&db, with_schema(strict)), "schema_mode");
    let mut mixed = catalog().collection("docs").unwrap().clone();
    mixed.mode = SchemaMode::Mixed;
    assert_eq!(catalog_code(&db, with_schema(mixed)), "schema_mode");

    let mut version = catalog().collection("docs").unwrap().clone();
    version.version = 2;
    assert_eq!(catalog_code(&db, with_schema(version)), "schema_version");

    let mut history = catalog().collection("docs").unwrap().clone();
    history.migrate("historical", Vec::new());
    history.version = 1;
    assert_eq!(catalog_code(&db, with_schema(history)), "schema_history");

    let computed = catalog()
        .collection("docs")
        .unwrap()
        .clone()
        .with_computed(ComputedField {
            name: "derived".into(),
            expression: "n".into(),
            result_type: AttributeType::Text,
        });
    assert_eq!(catalog_code(&db, with_schema(computed)), "computed_fields");

    let mut indexed = catalog().collection("docs").unwrap().clone();
    indexed.attributes.get_mut("n").unwrap().indexed = true;
    assert_eq!(catalog_code(&db, with_schema(indexed)), "indexed_attribute");

    let unsupported = CollectionSchema::new("docs")
        .with_attribute(AttributeSchema::new("n", AttributeType::Json));
    assert_eq!(
        catalog_code(&db, with_schema(unsupported)),
        "attribute_type"
    );
}

#[test]
fn gateway_catalog_name_and_aggregate_boundaries_have_stable_precedence() {
    let (_dir, db) = db();
    assert_eq!(
        catalog_code(&db, with_schema(CollectionSchema::new(""))),
        "collection_name"
    );
    assert_eq!(
        catalog_code(&db, with_schema(CollectionSchema::new("x".repeat(256)))),
        "collection_name"
    );
    assert_eq!(
        catalog_code(&db, with_schema(CollectionSchema::new("bad\nname"))),
        "collection_name"
    );
    assert!(
        QueryGateway::attach_fixture_v1(&db, with_schema(CollectionSchema::new("x".repeat(255))))
            .is_ok()
    );
    let mut max_collections = Catalog::new();
    for index in 0..16 {
        max_collections
            .create_collection(CollectionSchema::new(format!(
                "{index:02}{}",
                "x".repeat(253)
            )))
            .unwrap();
    }
    // 16 * 255 = 4,080, so the 4 KiB aggregate guard is unreachable today.
    assert!(QueryGateway::attach_fixture_v1(&db, max_collections).is_ok());

    let empty_attribute =
        CollectionSchema::new("docs").with_attribute(AttributeSchema::new("", AttributeType::Text));
    assert_eq!(
        catalog_code(&db, with_schema(empty_attribute)),
        "attribute_name"
    );
    let oversized_attribute = CollectionSchema::new("docs")
        .with_attribute(AttributeSchema::new("x".repeat(129), AttributeType::Text));
    assert_eq!(
        catalog_code(&db, with_schema(oversized_attribute)),
        "attribute_name"
    );
    let control_attribute = CollectionSchema::new("docs")
        .with_attribute(AttributeSchema::new("bad\u{0085}", AttributeType::Text));
    assert_eq!(
        catalog_code(&db, with_schema(control_attribute)),
        "attribute_name"
    );
    let max_attribute_name = CollectionSchema::new("docs")
        .with_attribute(AttributeSchema::new("x".repeat(128), AttributeType::Text));
    assert!(QueryGateway::attach_fixture_v1(&db, with_schema(max_attribute_name)).is_ok());

    let mut max_count = CollectionSchema::new("docs");
    for index in 0..256 {
        max_count = max_count.with_attribute(AttributeSchema::new(
            format!("a{index:03}"),
            AttributeType::Text,
        ));
    }
    assert!(QueryGateway::attach_fixture_v1(&db, with_schema(max_count)).is_ok());

    let mut many = CollectionSchema::new("docs");
    for index in 0..257 {
        many = many.with_attribute(AttributeSchema::new(
            format!("a{index:03}"),
            AttributeType::Text,
        ));
    }
    assert_eq!(catalog_code(&db, with_schema(many)), "attribute_count");

    let mut exact_aggregate = CollectionSchema::new("docs");
    for index in 0..128 {
        exact_aggregate = exact_aggregate.with_attribute(AttributeSchema::new(
            format!("{index:03}{}", "x".repeat(125)),
            AttributeType::Text,
        ));
    }
    assert!(QueryGateway::attach_fixture_v1(&db, with_schema(exact_aggregate.clone())).is_ok());
    let long_names = exact_aggregate.with_attribute(AttributeSchema::new(
        format!("{:03}{}", 128, "x".repeat(125)),
        AttributeType::Text,
    ));
    assert_eq!(
        catalog_code(&db, with_schema(long_names)),
        "attribute_name_bytes"
    );
}

#[test]
fn gateway_cloned_view_keeps_one_pin_and_explain_does_not_scan() {
    let (_dir, db) = db();
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
    let view = gateway.begin_read().unwrap();
    let clone = view.clone();
    assert!(Arc::ptr_eq(&view.read_identity, &clone.read_identity));
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    let QueryResult::Explain(explain) = gateway
        .query(
            &clone,
            "EXPLAIN SELECT n FROM docs",
            &TypedParameters::default(),
        )
        .unwrap()
    else {
        panic!("expected explain")
    };
    assert_eq!(explain.projection, ["n"]);
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    drop(view);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
    drop(clone);
    assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
}

#[test]
fn gateway_rejects_foreign_and_stale_capabilities_before_scan() {
    let (_dir, db) = db();
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let foreign = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let foreign_view = foreign.begin_read().unwrap();
    let CompiledStatement::Select(foreign_bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &foreign_view.catalog,
    )
    .unwrap() else {
        panic!("expected SELECT")
    };
    assert!(matches!(
        gateway.execute_bound(&view, &foreign_bound),
        Err(QueryReadError::Compile(QueryCompileError::ForeignCatalog))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let CompiledStatement::Select(bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &view.catalog,
    )
    .unwrap() else {
        panic!("expected SELECT")
    };
    assert!(matches!(
        gateway.execute_bound(&foreign_view, &bound),
        Err(QueryReadError::ForeignGateway)
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let mut other_core = view.clone();
    let (_other_dir, other_db) = self::db();
    other_core.core = other_db.records().pin_snapshot().unwrap();
    assert!(matches!(
        gateway.execute_bound(&other_core, &bound),
        Err(QueryReadError::Storage(
            PraxisError::ForeignRecordSnapshot { .. }
        ))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    gateway.catalog.drop_collection("docs").unwrap();
    assert!(matches!(
        gateway.execute_bound(&view, &bound),
        Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
    ));
    assert!(matches!(
        gateway.query(
            &view,
            "EXPLAIN SELECT n FROM docs",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn gateway_direct_bound_helper_refuses_a_stale_bound_with_a_fresh_view() {
    let (_dir, db) = db();
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let old_view = gateway.begin_read().unwrap();
    let CompiledStatement::Select(old_bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &old_view.catalog,
    )
    .unwrap() else {
        panic!("expected SELECT")
    };
    gateway
        .catalog
        .replace_collection(catalog().collection("docs").unwrap().clone())
        .unwrap();
    let fresh_view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.execute_bound(&fresh_view, &old_bound),
        Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn gateway_preserves_recovery_required_before_scan() {
    let (_dir, db) = db();
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    db.kv()
        .inner
        .group_commit
        .poison("test uncertain write".into());
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn gateway_final_owner_and_catalog_validation_prevents_partial_success() {
    for explain in [false, true] {
        let (_dir, db) = db();
        put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
        let gateway = Arc::new(QueryGateway::attach_fixture_v1(&db, catalog()).unwrap());
        let view = gateway.begin_read().unwrap();
        let weak = Arc::downgrade(&gateway);
        *gateway.test_hooks.before_final.lock() = Some(Arc::new(move || {
            if let Some(gateway) = weak.upgrade() {
                let _ = gateway.catalog.drop_collection("docs");
            }
        }));
        let sql = if explain {
            "EXPLAIN SELECT n FROM docs"
        } else {
            "SELECT n FROM docs"
        };
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
        ));
        assert_eq!(
            gateway
                .test_hooks
                .scan_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            usize::from(!explain)
        );
    }
}

#[test]
fn gateway_final_storage_validation_refuses_rows_and_explain_after_owner_poison() {
    for explain in [false, true] {
        let (_dir, db) = db();
        put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
        let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
        let view = gateway.begin_read().unwrap();
        let engine = db.kv();
        *gateway.test_hooks.before_final.lock() = Some(Arc::new(move || {
            engine
                .inner
                .group_commit
                .poison("test final owner fault".into());
        }));
        let sql = if explain {
            "EXPLAIN SELECT n FROM docs"
        } else {
            "SELECT n FROM docs"
        };
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
        ));
        assert_eq!(
            gateway
                .test_hooks
                .scan_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            usize::from(!explain)
        );
    }
}

#[test]
fn gateway_decodes_foreign_envelopes_and_rejects_late_malformed_or_duplicate_rows() {
    let (_dir, db) = db();
    put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    put(&db, "foreign", "opaque", Value::Number(Number::from(1_u64)));
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let QueryResult::Rows(rows) = gateway
        .query(&view, "SELECT n FROM docs", &TypedParameters::default())
        .unwrap()
    else {
        panic!("expected rows")
    };
    assert_eq!(rows.len(), 1);
    drop(view);

    let mut invalid = encode_document("foreign", "bad", &BTreeMap::new()).unwrap();
    invalid[0] ^= 1;
    let bad_rid = db.records().put(&invalid, &[]).unwrap();
    let view = gateway.begin_read().unwrap();
    assert!(
        matches!(gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Document { core_rid, reason: FixtureDecodeReason::InvalidMagic }) if core_rid == bad_rid)
    );
    drop(view);

    let (_dir2, db2) = self::db();
    put(&db2, "docs", "first", Value::Number(Number::from(7_u64)));
    let later = put(&db2, "docs", "first", Value::Number(Number::from(8_u64)));
    let gateway2 = QueryGateway::attach_fixture_v1(&db2, catalog()).unwrap();
    let view2 = gateway2.begin_read().unwrap();
    assert!(
        matches!(gateway2.query(&view2, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::DuplicateLogicalId { core_rid }) if core_rid == later)
    );
}

#[test]
fn gateway_preserves_distinct_colon_pairs_utf8_and_empty_keys() {
    // Full frames are independent v1 wire literals, not written by the codec.
    const A: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x03a:b\x00\x01c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
    const B: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x01a\x00\x03b:c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
    const C: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x19\x00\x01u\x00\x02\xc3\xa9\x00\x00";
    const D: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x17\x00\x01u\x00\x00\x00\x00";
    let (_dir, db) = db();
    for wire in [A, B, C, D] {
        db.records().put(wire, &[]).unwrap();
    }
    let mut catalog = Catalog::new();
    for name in ["a:b", "a", "u"] {
        catalog
            .create_collection(
                CollectionSchema::new(name).with_attribute(AttributeSchema::new(
                    "v",
                    AttributeType::Integer(IntegerType::Uint8),
                )),
            )
            .unwrap();
    }
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog).unwrap();
    let view = gateway.begin_read().unwrap();
    for (sql, collection, key) in [
        ("SELECT v FROM \"a:b\"", "a:b", "c"),
        ("SELECT v FROM a", "a", "b:c"),
    ] {
        let QueryResult::Rows(rows) = gateway
            .query(&view, sql, &TypedParameters::default())
            .unwrap()
        else {
            panic!("expected rows")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].id.collection.as_str(), rows[0].id.key.as_str()),
            (collection, key)
        );
        assert_eq!(
            rows[0].fields,
            vec![("v".into(), Value::Number(Number::from(7_u64)))]
        );
    }
    let QueryResult::Rows(rows) = gateway
        .query(&view, "SELECT v FROM u", &TypedParameters::default())
        .unwrap()
    else {
        panic!("expected rows")
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .map(|row| row.id.key.as_str())
            .collect::<Vec<_>>(),
        ["é", ""]
    );
    assert!(
        rows.iter()
            .all(|row| row.fields == [("v".into(), Value::Null)])
    );
}

#[test]
fn gateway_maps_first_middle_and_last_invalid_envelope_to_its_physical_rid() {
    for bad_at in 0..3 {
        let (_dir, db) = db();
        let mut invalid = encode_document("foreign", "bad", &BTreeMap::new()).unwrap();
        invalid[0] ^= 1;
        let mut bad_rid = crate::store::RecordId::NULL;
        for index in 0..3 {
            if index == bad_at {
                bad_rid = db.records().put(&invalid, &[]).unwrap();
            } else {
                put(
                    &db,
                    "docs",
                    &format!("valid{index}"),
                    Value::Number(Number::from(index as u64)),
                );
            }
        }
        let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
        let view = gateway.begin_read().unwrap();
        assert!(
            matches!(gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
            Err(QueryReadError::Document { core_rid, reason: FixtureDecodeReason::InvalidMagic }) if core_rid == bad_rid)
        );
    }
}

#[test]
fn gateway_preserves_frame_count_and_budget_error_precedence() {
    let (_dir, db) = db();
    put(&db, "foreign", "one", Value::Number(Number::from(1_u64)));
    let mut bad_count = encode_document(
        "docs",
        "bad-count",
        &BTreeMap::from([("n".into(), Value::Number(Number::from(7_u64)))]),
    )
    .unwrap();
    let count_at = 16 + 2 + "docs".len() + 2 + "bad-count".len();
    bad_count[count_at..count_at + 2].copy_from_slice(&257_u16.to_be_bytes());
    let bad_rid = db.records().put(&bad_count, &[]).unwrap();
    let mut gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    gateway.limits.decoded_attribute_entries = 1;
    let view = gateway.begin_read().unwrap();
    assert!(
        matches!(gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Document { core_rid, reason: FixtureDecodeReason::InvalidAttributeCount }) if core_rid == bad_rid)
    );
    drop(view);

    let (_dir2, db2) = self::db();
    put(&db2, "foreign", "one", Value::Number(Number::from(1_u64)));
    let mut bad_entry = encode_document(
        "docs",
        "bad-entry",
        &BTreeMap::from([("n".into(), Value::Number(Number::from(7_u64)))]),
    )
    .unwrap();
    let tag_at = bad_entry.len() - 9;
    bad_entry[tag_at] = 255;
    let bad_rid = db2.records().put(&bad_entry, &[]).unwrap();
    let mut gateway2 = QueryGateway::attach_fixture_v1(&db2, catalog()).unwrap();
    gateway2.limits.decoded_attribute_entries = 1;
    let view2 = gateway2.begin_read().unwrap();
    assert!(matches!(
        gateway2.query(&view2, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::ResourceLimit {
            code: "attribute_entries"
        })
    ));
    gateway2.limits.decoded_attribute_entries = 2;
    assert!(
        matches!(gateway2.query(&view2, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Document { core_rid, reason: FixtureDecodeReason::UnknownValueTag }) if core_rid == bad_rid)
    );
}

#[test]
fn gateway_rejects_filtered_out_referenced_wrong_type_and_unsupported_sql() {
    let (_dir, db) = db();
    put(&db, "docs", "good", Value::Number(Number::from(7_u64)));
    put(&db, "docs", "wrong", Value::String("text".into()));
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(
            &view,
            "SELECT n FROM docs WHERE n = 7",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Compile(QueryCompileError::DataContract {
            code: "wrong_type"
        }))
    ));
    let scans = gateway
        .test_hooks
        .scan_calls
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        gateway.query(
            &view,
            "SELECT n FROM docs ORDER BY n",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Compile(
            QueryCompileError::UnsupportedFeature { .. }
        ))
    ));
    assert_eq!(
        gateway
            .test_hooks
            .scan_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        scans
    );
}

#[test]
fn gateway_does_not_claim_whole_schema_validation_for_unreferenced_fields() {
    let (_dir, db) = db();
    let attributes = BTreeMap::from([
        ("n".to_owned(), Value::Number(Number::from(7_u64))),
        (
            "other".to_owned(),
            Value::String("text despite integer declaration".into()),
        ),
    ]);
    let frame = encode_document("docs", "one", &attributes).unwrap();
    db.records().put(&frame, &[]).unwrap();
    let mut schema = catalog().collection("docs").unwrap().clone();
    schema = schema.with_attribute(AttributeSchema::new(
        "other",
        AttributeType::Integer(IntegerType::Uint8),
    ));
    let gateway = QueryGateway::attach_fixture_v1(&db, with_schema(schema)).unwrap();
    let view = gateway.begin_read().unwrap();
    let QueryResult::Rows(rows) = gateway
        .query(&view, "SELECT n FROM docs", &TypedParameters::default())
        .unwrap()
    else {
        panic!("expected rows")
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].fields,
        vec![("n".into(), Value::Number(Number::from(7_u64)))]
    );
}

#[test]
fn gateway_debug_paths_do_not_echo_row_or_sql_parameter_values() {
    let row = ProjectedRow {
        id: crate::document::RecordId::new("secret_collection", "secret_key"),
        fields: vec![("secret_field".into(), Value::String("secret_value".into()))],
    };
    let debug = format!("{:?}", QueryResult::Rows(vec![row]));
    assert_eq!(debug, "Rows(1)");
    let error = QueryReadError::Document {
        core_rid: crate::store::RecordId(17),
        reason: FixtureDecodeReason::InvalidMagic,
    };
    let rendered = format!("{error:?} {error}");
    for secret in [
        "secret_collection",
        "secret_key",
        "secret_field",
        "secret_value",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn gateway_checks_cumulative_foreign_attributes_and_preclone_output_for_named_and_wildcard() {
    let (_dir, db) = db();
    let first = put(&db, "foreign", "one", Value::Number(Number::from(1_u64)));
    let second = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    assert_ne!(first, second);
    let mut gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    gateway.limits.decoded_attribute_entries = 1;
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::ResourceLimit {
            code: "attribute_entries"
        })
    ));
    gateway.limits.decoded_attribute_entries = 2;
    // The foreign frame contributes to the pinned payload total; one requested
    // logical pair is 7 bytes and one projected field contributes 129 bytes.
    let exact = 44 + 41 + 7 + 129;
    for sql in ["SELECT n FROM docs", "SELECT * FROM docs"] {
        gateway.limits.logical_output_bytes = exact - 1;
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Err(QueryReadError::ResourceLimit {
                code: "logical_output_bytes"
            })
        ));
        gateway.limits.logical_output_bytes = exact;
        let QueryResult::Rows(rows) = gateway
            .query(&view, sql, &TypedParameters::default())
            .unwrap()
        else {
            panic!("expected rows")
        };
        assert_eq!(rows.len(), 1);
    }
}
