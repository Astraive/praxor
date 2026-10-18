//! External public gateway oracle for a controlled v1 fixture root.

#[path = "support/query_fixture_v1.rs"]
mod fixture;

use fixture::Scalar;
use praxis::catalog::IntegerType;
use praxis::store::BatchRecord;
use praxis::{
    AttributeSchema, AttributeType, Catalog, CollectionSchema, CompactionStrategy, CoreDatabase,
    ParameterValue, PraxisConfig, PraxisError, ProjectedRow, QueryCompileError,
    QueryDocumentReason, QueryGateway, QueryReadError, QueryReadView, QueryResult,
    RecordAuthorityOptions, RecordId, TypedParameters,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const A: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x03a:b\x00\x01c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
const B: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x01a\x00\x03b:c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
const C: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x19\x00\x01u\x00\x02\xc3\xa9\x00\x00";
const D: &[u8] =
    b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x17\x00\x01u\x00\x00\x00\x00";

#[test]
fn independent_writer_matches_frozen_identity_literals() {
    let actual = [
        fixture::frame(
            "a:b",
            "c",
            &[("n", Scalar::Null), ("v", Scalar::Unsigned(7))],
        )
        .unwrap(),
        fixture::frame(
            "a",
            "b:c",
            &[("n", Scalar::Null), ("v", Scalar::Unsigned(7))],
        )
        .unwrap(),
        fixture::frame("u", "é", &[]).unwrap(),
        fixture::frame("u", "", &[]).unwrap(),
    ];
    for (written, literal) in actual.iter().zip([A, B, C, D]) {
        assert_eq!(written, literal);
    }
}

#[test]
fn independent_writer_matches_signed_unsigned_boolean_and_hostile_text_bytes() {
    let negative = fixture::frame("x", "y", &[("n", Scalar::Negative(-3))]).unwrap();
    assert_eq!(negative.len(), 36);
    assert_eq!(&negative[12..16], &[0, 0, 0, 36]);
    assert_eq!(
        &negative[27..36],
        &[3, 255, 255, 255, 255, 255, 255, 255, 253]
    );

    let maximum = fixture::frame("x", "y", &[("n", Scalar::Unsigned(u64::MAX))]).unwrap();
    assert_eq!(maximum.len(), 36);
    assert_eq!(
        &maximum[27..36],
        &[4, 255, 255, 255, 255, 255, 255, 255, 255]
    );

    let false_frame = fixture::frame("x", "y", &[("n", Scalar::Bool(false))]).unwrap();
    let true_frame = fixture::frame("x", "y", &[("n", Scalar::Bool(true))]).unwrap();
    assert_eq!(false_frame.len(), 28);
    assert_eq!(true_frame.len(), 28);
    assert_eq!(false_frame[27], 1);
    assert_eq!(true_frame[27], 2);

    let hostile = fixture::frame("x", "y", &[("n", Scalar::Text("x' OR TRUE --"))]).unwrap();
    assert_eq!(hostile.len(), 45);
    assert_eq!(hostile[27], 5);
    assert_eq!(&hostile[28..32], &[0, 0, 0, 13]);
    assert_eq!(&hostile[32..45], b"x' OR TRUE --");
}

#[test]
fn independent_writer_sorts_attribute_names_without_dropping_duplicates() {
    let ordered = fixture::frame("x", "y", &[("a", Scalar::Null), ("z", Scalar::Null)]).unwrap();
    let unsorted = fixture::frame("x", "y", &[("z", Scalar::Null), ("a", Scalar::Null)]).unwrap();
    assert_eq!(unsorted, ordered);
    assert_eq!(&ordered[24..30], &[0, 1, b'a', 0, 0, 1]);
    assert!(fixture::frame("x", "y", &[("a", Scalar::Null), ("a", Scalar::Null)],).is_err());
}

fn users_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("users")
                .with_attribute(AttributeSchema::new(
                    "age",
                    AttributeType::Integer(IntegerType::Int8),
                ))
                .with_attribute(AttributeSchema::new(
                    "visits",
                    AttributeType::Integer(IntegerType::Uint8),
                ))
                .with_attribute(AttributeSchema::new("name", AttributeType::Text))
                .with_attribute(AttributeSchema::new("active", AttributeType::Boolean)),
        )
        .unwrap();
    catalog
        .create_collection(
            CollectionSchema::new("teams")
                .with_attribute(AttributeSchema::new("label", AttributeType::Text)),
        )
        .unwrap();
    catalog
}

fn seeded_users() -> (tempfile::TempDir, CoreDatabase, QueryGateway, Vec<RecordId>) {
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(
        PraxisConfig::new(dir.path()),
        RecordAuthorityOptions::default(),
    )
    .unwrap();
    let frames = [
        fixture::frame(
            "users",
            "u_neg",
            &[
                ("age", Scalar::Negative(-3)),
                ("visits", Scalar::Unsigned(0)),
                ("name", Scalar::Text("Ana")),
                ("active", Scalar::Bool(true)),
            ],
        )
        .unwrap(),
        fixture::frame(
            "users",
            "u_max",
            &[
                ("age", Scalar::Unsigned(5)),
                ("visits", Scalar::Unsigned(u64::MAX)),
                ("name", Scalar::Text("x' OR TRUE --")),
                ("active", Scalar::Bool(false)),
            ],
        )
        .unwrap(),
        fixture::frame(
            "users",
            "u_null",
            &[
                ("age", Scalar::Null),
                ("visits", Scalar::Unsigned(7)),
                ("name", Scalar::Text("Null")),
                ("active", Scalar::Bool(true)),
            ],
        )
        .unwrap(),
        fixture::frame("teams", "t_blue", &[("label", Scalar::Text("blue"))]).unwrap(),
    ];
    let batch = frames
        .iter()
        .map(|frame| BatchRecord::new(frame, &[]))
        .collect::<Vec<_>>();
    let rids = db.records().put_batch(&batch).unwrap();
    assert_eq!(rids.len(), 4);
    let gateway = QueryGateway::attach_fixture_v1(&db, users_catalog()).unwrap();
    (dir, db, gateway, rids)
}

type LiteralRow = (String, String, Vec<(String, Value)>);

fn literal_rows(result: QueryResult) -> Vec<LiteralRow> {
    let QueryResult::Rows(rows) = result else {
        panic!("expected Rows")
    };
    let mut literal = rows
        .into_iter()
        .map(|ProjectedRow { id, fields }| (id.collection, id.key, fields))
        .collect::<Vec<_>>();
    literal.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    literal
}

fn select(
    gateway: &QueryGateway,
    view: &QueryReadView,
    sql: &str,
    params: &TypedParameters,
) -> Vec<LiteralRow> {
    literal_rows(gateway.query(view, sql, params).unwrap())
}

#[test]
fn public_fixture_queries_match_hand_written_multiset_oracles() {
    let (_dir, _db, gateway, _rids) = seeded_users();
    let view = gateway.begin_read().unwrap();

    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT age, name FROM users WHERE age < $1",
            &TypedParameters {
                positional: vec![ParameterValue::I64(0)],
                ..TypedParameters::default()
            },
        ),
        vec![(
            "users".into(),
            "u_neg".into(),
            vec![("age".into(), json!(-3)), ("name".into(), json!("Ana"))]
        )]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT name, visits FROM users WHERE visits = :v",
            &TypedParameters {
                named: BTreeMap::from([("v".into(), ParameterValue::U64(u64::MAX))]),
                ..TypedParameters::default()
            },
        ),
        vec![(
            "users".into(),
            "u_max".into(),
            vec![
                ("name".into(), json!("x' OR TRUE --")),
                ("visits".into(), json!(u64::MAX))
            ]
        )]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT name FROM users WHERE age IS NULL",
            &TypedParameters::default()
        ),
        vec![(
            "users".into(),
            "u_null".into(),
            vec![("name".into(), json!("Null"))]
        )]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT name FROM users WHERE name = :needle",
            &TypedParameters {
                named: BTreeMap::from([(
                    "needle".into(),
                    ParameterValue::Text("x' OR TRUE --".into())
                )]),
                ..TypedParameters::default()
            },
        ),
        vec![(
            "users".into(),
            "u_max".into(),
            vec![("name".into(), json!("x' OR TRUE --"))]
        )]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT label FROM teams WHERE label = 'blue'",
            &TypedParameters::default()
        ),
        vec![(
            "teams".into(),
            "t_blue".into(),
            vec![("label".into(), json!("blue"))]
        )]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT name FROM users WHERE visits IS NULL",
            &TypedParameters::default()
        ),
        Vec::<LiteralRow>::new()
    );
}

#[test]
fn public_wildcard_boolean_compound_and_null_oracle_is_hand_written() {
    let (_dir, _db, gateway, _rids) = seeded_users();
    let view = gateway.begin_read().unwrap();
    let rows = select(
        &gateway,
        &view,
        "SELECT * FROM users WHERE active = :flag AND (age IS NULL OR age < $1)",
        &TypedParameters {
            positional: vec![ParameterValue::I64(0)],
            named: BTreeMap::from([("flag".into(), ParameterValue::Bool(true))]),
        },
    );
    assert_eq!(
        rows,
        vec![
            (
                "users".into(),
                "u_neg".into(),
                vec![
                    ("active".into(), json!(true)),
                    ("age".into(), json!(-3)),
                    ("name".into(), json!("Ana")),
                    ("visits".into(), json!(0)),
                ],
            ),
            (
                "users".into(),
                "u_null".into(),
                vec![
                    ("active".into(), json!(true)),
                    ("age".into(), Value::Null),
                    ("name".into(), json!("Null")),
                    ("visits".into(), json!(7)),
                ],
            ),
        ]
    );
}

#[test]
fn public_gateway_preserves_delimiters_utf8_and_empty_logical_keys() {
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(
        PraxisConfig::new(dir.path()),
        RecordAuthorityOptions::default(),
    )
    .unwrap();
    let frames = [A, B, C, D];
    db.records()
        .put_batch(
            &frames
                .iter()
                .map(|bytes| BatchRecord::new(bytes, &[]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
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
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT v FROM \"a:b\"",
            &TypedParameters::default()
        ),
        vec![("a:b".into(), "c".into(), vec![("v".into(), json!(7))])]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT v FROM a",
            &TypedParameters::default()
        ),
        vec![("a".into(), "b:c".into(), vec![("v".into(), json!(7))])]
    );
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT v FROM u",
            &TypedParameters::default()
        ),
        vec![
            ("u".into(), "".into(), vec![("v".into(), Value::Null)]),
            ("u".into(), "é".into(), vec![("v".into(), Value::Null)]),
        ]
    );
}

#[test]
fn public_explain_is_literal_redacted_shape_and_does_not_decode_rows() {
    let (_dir, db, gateway, _rids) = seeded_users();
    let mut invalid = fixture::frame("users", "broken", &[("age", Scalar::Unsigned(1))]).unwrap();
    invalid[0] ^= 1;
    let bad_rid = db.records().put(&invalid, &[]).unwrap();
    let view = gateway.begin_read().unwrap();
    let params = TypedParameters {
        positional: vec![ParameterValue::I64(0)],
        ..TypedParameters::default()
    };
    let QueryResult::Explain(explain) = gateway
        .query(
            &view,
            "EXPLAIN SELECT age, name FROM users WHERE age < $1",
            &params,
        )
        .unwrap()
    else {
        panic!("expected Explain")
    };
    assert_eq!(
        serde_json::to_value(explain).unwrap(),
        json!({
            "version": 1,
            "catalog_scope": "process",
            "revision": 1,
            "collection": "users",
            "projection": ["age", "name"],
            "predicate_shape": [{"kind": "compare", "field": "age", "operator": "<"}],
            "required_capabilities": ["collection_scan"],
            "execution": "not_executed"
        })
    );
    assert!(matches!(
        gateway.query(&view, "SELECT age, name FROM users WHERE age < $1", &params),
        Err(QueryReadError::Document { core_rid, reason: QueryDocumentReason::InvalidMagic }) if core_rid == bad_rid
    ));
}

#[test]
fn public_compile_failures_are_typed_and_never_empty_rows() {
    let (_dir, _db, gateway, _rids) = seeded_users();
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT name FROM missing", &TypedParameters::default()),
        Err(QueryReadError::Compile(QueryCompileError::UnknownCollection { name, .. })) if name == "missing"
    ));
    for sql in [
        "SELECT name FROM users AS OF 1",
        "SELECT name FROM users GROUP BY name",
        "DELETE FROM users",
        "SELECT COUNT(*) FROM users",
    ] {
        assert!(
            matches!(
                gateway.query(&view, sql, &TypedParameters::default()),
                Err(QueryReadError::Compile(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn public_foreign_frame_must_decode_fully_and_reports_physical_rid() {
    let (_dir, db, gateway, _rids) = seeded_users();
    let mut invalid = fixture::frame("teams", "bad", &[("label", Scalar::Text("bad"))]).unwrap();
    invalid[0] ^= 1;
    let bad_rid = db.records().put(&invalid, &[]).unwrap();
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT name FROM users", &TypedParameters::default()),
        Err(QueryReadError::Document { core_rid, reason: QueryDocumentReason::InvalidMagic }) if core_rid == bad_rid
    ));
}

fn public_malformed_envelope_at(bad_at: usize) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.memtable_flush_threshold_bytes = usize::MAX;
    let db = CoreDatabase::create_fresh(config, RecordAuthorityOptions::default()).unwrap();
    let records = db.records();
    let mut frames = [
        fixture::frame("users", "first", &[("name", Scalar::Text("first"))]).unwrap(),
        fixture::frame("users", "middle", &[("name", Scalar::Text("middle"))]).unwrap(),
        fixture::frame("users", "last", &[("name", Scalar::Text("last"))]).unwrap(),
    ];
    // The independent writer provides valid neighbours. Change only the magic
    // byte of one complete envelope, leaving its core State/Payload valid.
    frames[bad_at][0] ^= 1;
    let rids = frames.map(|frame| records.put(&frame, &[]).unwrap());
    assert_eq!(rids, [RecordId(1), RecordId(2), RecordId(3)]);
    records.flush().unwrap();

    let gateway = QueryGateway::attach_fixture_v1(&db, name_catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    match gateway.query(&view, "SELECT name FROM users", &TypedParameters::default()) {
        Err(QueryReadError::Document { core_rid, reason }) => {
            assert_eq!(
                core_rid, rids[bad_at],
                "malformed physical ordinal {bad_at}"
            );
            assert_eq!(reason, QueryDocumentReason::InvalidMagic);
        }
        other => panic!("ordinal {bad_at} returned partial Rows or wrong error: {other:?}"),
    }
}

#[test]
fn public_malformed_envelope_first_reports_physical_rid() {
    public_malformed_envelope_at(0);
}

#[test]
fn public_malformed_envelope_middle_reports_physical_rid() {
    public_malformed_envelope_at(1);
}

#[test]
fn public_malformed_envelope_last_reports_physical_rid() {
    public_malformed_envelope_at(2);
}

#[test]
fn public_duplicate_logical_id_reports_the_second_physical_rid() {
    let (_dir, db, gateway, _rids) = seeded_users();
    let duplicate = fixture::frame("users", "u_neg", &[("name", Scalar::Text("again"))]).unwrap();
    let second = db.records().put(&duplicate, &[]).unwrap();
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT name FROM users", &TypedParameters::default()),
        Err(QueryReadError::DuplicateLogicalId { core_rid }) if core_rid == second
    ));
}

#[test]
fn public_filtered_out_referenced_wrong_type_remains_a_data_contract_error() {
    let (_dir, db, gateway, _rids) = seeded_users();
    let wrong = fixture::frame(
        "users",
        "u_wrong",
        &[
            ("age", Scalar::Text("wrong")),
            ("name", Scalar::Text("bad")),
        ],
    )
    .unwrap();
    db.records().put(&wrong, &[]).unwrap();
    let view = gateway.begin_read().unwrap();
    assert_eq!(
        select(
            &gateway,
            &view,
            "SELECT name FROM users WHERE name = 'bad'",
            &TypedParameters::default(),
        ),
        vec![(
            "users".into(),
            "u_wrong".into(),
            vec![("name".into(), json!("bad"))]
        )]
    );
    assert!(matches!(
        gateway.query(
            &view,
            "SELECT age FROM users WHERE age < $1",
            &TypedParameters {
                positional: vec![ParameterValue::I64(0)],
                ..TypedParameters::default()
            }
        ),
        Err(QueryReadError::Compile(QueryCompileError::DataContract {
            code: "wrong_type"
        }))
    ));
}

fn name_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("users")
                .with_attribute(AttributeSchema::new("name", AttributeType::Text)),
        )
        .unwrap();
    catalog
}

#[test]
fn public_retained_view_stays_old_across_each_compaction_reclaim_and_gc_strategy() {
    for strategy in [
        CompactionStrategy::Leveled,
        CompactionStrategy::Tiered,
        CompactionStrategy::Universal,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PraxisConfig::new(dir.path());
        config.default_compaction_strategy = strategy;
        config.memtable_flush_threshold_bytes = usize::MAX;
        let db = CoreDatabase::create_fresh(config, RecordAuthorityOptions::default()).unwrap();
        let records = db.records();
        let old = fixture::frame("users", "u1", &[("name", Scalar::Text("old"))]).unwrap();
        let steady =
            fixture::frame("users", "steady", &[("name", Scalar::Text("steady"))]).unwrap();
        let old_rid = records.put(&old, &[]).unwrap();
        records.put(&steady, &[]).unwrap();
        records.flush().unwrap();
        let gateway = QueryGateway::attach_fixture_v1(&db, name_catalog()).unwrap();
        let old_view = gateway.begin_read().unwrap();
        let clone = old_view.clone();

        records.delete_record(old_rid).unwrap();
        let new = fixture::frame("users", "u1", &[("name", Scalar::Text("new"))]).unwrap();
        records.put(&new, &[]).unwrap();
        records.flush().unwrap();
        let compacted = db.kv().compact_with_strategy(strategy).unwrap();
        assert!(compacted > 0, "{strategy:?} must perform compaction");
        records.reclaim_snapshot_history().unwrap();
        db.kv().garbage_collect().unwrap();

        let old_expected = vec![
            (
                "users".into(),
                "steady".into(),
                vec![("name".into(), json!("steady"))],
            ),
            (
                "users".into(),
                "u1".into(),
                vec![("name".into(), json!("old"))],
            ),
        ];
        assert_eq!(
            select(
                &gateway,
                &old_view,
                "SELECT name FROM users",
                &TypedParameters::default()
            ),
            old_expected,
            "{strategy:?} original"
        );
        assert_eq!(
            select(
                &gateway,
                &clone,
                "SELECT name FROM users",
                &TypedParameters::default()
            ),
            old_expected,
            "{strategy:?} clone"
        );
        let current = gateway.begin_read().unwrap();
        assert_eq!(
            select(
                &gateway,
                &current,
                "SELECT name FROM users",
                &TypedParameters::default()
            ),
            vec![
                (
                    "users".into(),
                    "steady".into(),
                    vec![("name".into(), json!("steady"))]
                ),
                (
                    "users".into(),
                    "u1".into(),
                    vec![("name".into(), json!("new"))]
                ),
            ],
            "{strategy:?} current"
        );
    }
}

#[test]
fn public_last_view_clone_retains_writer_lease_until_drop() {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions::default()).unwrap();
    let records = db.records();
    let engine = db.kv();
    let gateway = QueryGateway::attach_fixture_v1(&db, name_catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let last_view = view.clone();
    drop(view);
    drop(gateway);
    drop(engine);
    drop(records);
    drop(db);
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    drop(last_view);
    let reopened = CoreDatabase::open(config).unwrap();
    let gateway = QueryGateway::attach_fixture_v1(&reopened, name_catalog()).unwrap();
    let current = gateway.begin_read().unwrap();
    assert_eq!(
        select(
            &gateway,
            &current,
            "SELECT name FROM users",
            &TypedParameters::default()
        ),
        Vec::<LiteralRow>::new()
    );
}

#[test]
fn public_view_pin_protects_deleted_history_until_all_clones_drop() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.default_compaction_strategy = CompactionStrategy::Tiered;
    config.memtable_flush_threshold_bytes = usize::MAX;
    config.large_value_threshold = usize::MAX;
    let db = CoreDatabase::create_fresh(config, RecordAuthorityOptions::default()).unwrap();
    let records = db.records();
    let old = fixture::frame("users", "u1", &[("name", Scalar::Text("old"))]).unwrap();
    let old_rid = records.put(&old, &[]).unwrap();
    records.flush().unwrap();
    assert!(
        records
            .reclaim_snapshot_history()
            .unwrap()
            .rewrite_performed
    );
    let gateway = QueryGateway::attach_fixture_v1(&db, name_catalog()).unwrap();
    let view = gateway.begin_read().unwrap();
    let clone = view.clone();
    records.delete_record(old_rid).unwrap();
    records.flush().unwrap();

    let pinned = records.reclaim_snapshot_history().unwrap();
    assert_eq!(pinned.protected_versions_removed, 0);
    assert_eq!(
        select(
            &gateway,
            &clone,
            "SELECT name FROM users",
            &TypedParameters::default()
        ),
        vec![(
            "users".into(),
            "u1".into(),
            vec![("name".into(), json!("old"))]
        )]
    );
    drop(view);
    drop(clone);
    let retired = records.reclaim_snapshot_history().unwrap();
    assert!(retired.protected_versions_removed >= 1, "{retired:?}");
    let current = gateway.begin_read().unwrap();
    assert_eq!(
        select(
            &gateway,
            &current,
            "SELECT name FROM users",
            &TypedParameters::default()
        ),
        Vec::<LiteralRow>::new()
    );
}
