//! Literal, fixed-record execution cases from the independent Q1 oracle.
use super::QueryCompileError;
use super::binder::{BoundPredicateOp, ParameterValue, TypedParameters, bind_sql};
use super::catalog::QueryCatalogAuthority;
use super::evaluator::{ProjectedRow, execute_in_memory};
use crate::catalog::schema::{
    AttributeSchema, AttributeType, Catalog, CollectionSchema, IntegerType, ScalarType,
};
use crate::document::{Record, RecordId};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn authority(name: &str, fields: &[(&str, AttributeType, bool)]) -> QueryCatalogAuthority {
    let mut schema = CollectionSchema::new(name);
    for (field, kind, nullable) in fields {
        let declared = AttributeSchema::new(*field, kind.clone());
        schema = schema.with_attribute(if *nullable {
            declared
        } else {
            declared.required()
        });
    }
    let mut catalog = Catalog::new();
    catalog.create_collection(schema).unwrap();
    QueryCatalogAuthority::new(catalog)
}

fn row(collection: &str, key: &str, fields: &[(&str, Value)]) -> Record {
    fields
        .iter()
        .fold(Record::new(collection, key), |record, (name, value)| {
            record.with_attribute(*name, value.clone())
        })
}

fn projected(collection: &str, key: &str, fields: &[(&str, Value)]) -> ProjectedRow {
    ProjectedRow {
        id: RecordId::new(collection, key),
        fields: fields
            .iter()
            .map(|(name, value)| ((*name).into(), value.clone()))
            .collect(),
    }
}

fn run(
    owner: &QueryCatalogAuthority,
    sql: &str,
    params: &TypedParameters,
    rows: &[Record],
) -> Result<Vec<ProjectedRow>, QueryCompileError> {
    let select = bind_sql(sql, params, &owner.view())?;
    execute_in_memory(owner, &select, rows)
}

fn users_owner() -> QueryCatalogAuthority {
    authority(
        "users",
        &[
            ("age", AttributeType::Integer(IntegerType::Int4), true),
            ("active", AttributeType::Boolean, false),
            ("name", AttributeType::Text, false),
        ],
    )
}

fn users() -> Vec<Record> {
    vec![
        row(
            "users",
            "u16",
            &[
                ("age", json!(16)),
                ("active", json!(true)),
                ("name", json!("Sela")),
            ],
        ),
        row(
            "users",
            "u21",
            &[
                ("age", json!(21)),
                ("active", json!(true)),
                ("name", json!("Ada")),
            ],
        ),
        row(
            "users",
            "u34",
            &[
                ("age", json!(34)),
                ("active", json!(false)),
                ("name", json!("Béla")),
            ],
        ),
        row(
            "users",
            "u55",
            &[
                ("age", json!(55)),
                ("active", json!(true)),
                ("name", json!("Xena")),
            ],
        ),
        row(
            "users",
            "u_null",
            &[
                ("age", Value::Null),
                ("active", json!(false)),
                ("name", json!("Nia")),
            ],
        ),
        row(
            "users",
            "u_missing",
            &[("active", json!(true)), ("name", json!("Mira"))],
        ),
    ]
}

#[test]
fn fixed_users_oracle_preserves_ids_input_order_projection_and_boolean_precedence() {
    let owner = users_owner();
    let rows = users();
    let params = TypedParameters {
        positional: vec![ParameterValue::I64(18)],
        named: BTreeMap::from([
            ("n".into(), ParameterValue::Text("Ada".into())),
            ("n2".into(), ParameterValue::Text("Béla".into())),
        ]),
    };
    assert_eq!(
        run(
            &owner,
            "SELECT name, age FROM users WHERE age >= $1 AND (name = :n OR name = @n2)",
            &params,
            &rows
        )
        .unwrap(),
        vec![
            projected(
                "users",
                "u21",
                &[("name", json!("Ada")), ("age", json!(21))]
            ),
            projected(
                "users",
                "u34",
                &[("name", json!("Béla")), ("age", json!(34))]
            ),
        ]
    );
    for (sql, expected) in [
        (
            "SELECT name FROM users WHERE age IS NULL",
            vec![
                projected("users", "u_null", &[("name", json!("Nia"))]),
                projected("users", "u_missing", &[("name", json!("Mira"))]),
            ],
        ),
        (
            "SELECT name FROM users WHERE age = NULL OR age = 21",
            vec![projected("users", "u21", &[("name", json!("Ada"))])],
        ),
        ("SELECT name FROM users WHERE NOT (age = NULL)", vec![]),
        (
            "SELECT name FROM users WHERE age = 21 OR age = 34 AND active = TRUE",
            vec![projected("users", "u21", &[("name", json!("Ada"))])],
        ),
        (
            "SELECT name FROM users WHERE (age = 21 OR age = 34) AND active = FALSE",
            vec![projected("users", "u34", &[("name", json!("Béla"))])],
        ),
        (
            "SELECT * FROM users WHERE age = 21",
            vec![projected(
                "users",
                "u21",
                &[
                    ("active", json!(true)),
                    ("age", json!(21)),
                    ("name", json!("Ada")),
                ],
            )],
        ),
        (
            "SELECT age FROM users WHERE name = 'Mira'",
            vec![projected("users", "u_missing", &[("age", Value::Null)])],
        ),
    ] {
        assert_eq!(
            run(&owner, sql, &TypedParameters::default(), &rows).unwrap(),
            expected,
            "{sql}"
        );
    }
}

#[test]
fn referenced_fields_are_validated_even_when_predicate_would_skip_a_row() {
    let owner = users_owner();
    let missing_projected_name = row(
        "users",
        "bad",
        &[("age", json!(16)), ("active", json!(true))],
    );
    assert!(matches!(
        run(
            &owner,
            "SELECT name FROM users WHERE age = 21",
            &TypedParameters::default(),
            &[missing_projected_name]
        ),
        Err(QueryCompileError::DataContract {
            code: "missing_required"
        })
    ));
    let wrong_predicate_age = row(
        "users",
        "bad",
        &[
            ("age", json!("21")),
            ("active", json!(true)),
            ("name", json!("Ada")),
        ],
    );
    assert!(matches!(
        run(
            &owner,
            "SELECT name FROM users WHERE active = TRUE OR age = 21",
            &TypedParameters::default(),
            &[wrong_predicate_age]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let unreferenced_bad_age = row(
        "users",
        "fine",
        &[
            ("age", json!("21")),
            ("active", json!(true)),
            ("name", json!("Ada")),
        ],
    );
    assert_eq!(
        run(
            &owner,
            "SELECT name FROM users",
            &TypedParameters::default(),
            &[unreferenced_bad_age.clone()]
        )
        .unwrap(),
        vec![projected("users", "fine", &[("name", json!("Ada"))])]
    );
    assert!(matches!(
        run(
            &owner,
            "SELECT * FROM users",
            &TypedParameters::default(),
            &[unreferenced_bad_age]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let foreign = row(
        "orders",
        "bad",
        &[("active", json!(true)), ("name", json!("Ada"))],
    );
    assert!(matches!(
        run(
            &owner,
            "SELECT name FROM users WHERE active = FALSE",
            &TypedParameters::default(),
            &[foreign]
        ),
        Err(QueryCompileError::DataContract {
            code: "wrong_collection"
        })
    ));
}

#[test]
fn stale_foreign_and_explain_plans_are_refused_before_row_validation() {
    let owner = users_owner();
    let malformed = row("orders", "bad", &[]);
    let select = bind_sql(
        "SELECT name FROM users",
        &TypedParameters::default(),
        &owner.view(),
    )
    .unwrap();
    let foreign = users_owner();
    assert!(matches!(
        execute_in_memory(&foreign, &select, &[malformed.clone()]),
        Err(QueryCompileError::ForeignCatalog)
    ));
    owner
        .replace_collection(
            CollectionSchema::new("users")
                .with_attribute(AttributeSchema::new("name", AttributeType::Text).required()),
        )
        .unwrap();
    assert!(matches!(
        execute_in_memory(&owner, &select, &[malformed.clone()]),
        Err(QueryCompileError::StaleCatalog)
    ));
    assert!(matches!(
        execute_in_memory(&owner, &select, &[]),
        Err(QueryCompileError::StaleCatalog)
    ));
    let explain = bind_sql(
        "EXPLAIN SELECT name FROM users",
        &TypedParameters::default(),
        &owner.view(),
    )
    .unwrap();
    assert!(matches!(
        execute_in_memory(&owner, &explain, &[malformed]),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "explain_execution",
            span: None
        })
    ));
}

#[test]
fn an_invalid_internal_predicate_returns_a_typed_error_instead_of_panicking() {
    let owner = users_owner();
    let mut select = bind_sql(
        "SELECT name FROM users",
        &TypedParameters::default(),
        &owner.view(),
    )
    .unwrap();
    select.predicate = Some(vec![BoundPredicateOp::And]);
    assert!(matches!(
        execute_in_memory(&owner, &select, &users()),
        Err(QueryCompileError::InvalidBoundPlan {
            code: "predicate_stack"
        })
    ));
}

#[test]
fn thousand_flat_or_terms_execute_iteratively() {
    let owner = authority(
        "ints",
        &[("s2", AttributeType::Integer(IntegerType::Int2), false)],
    );
    let sql = format!(
        "SELECT s2 FROM ints WHERE {}",
        (0..1_000)
            .map(|_| "s2 = 1")
            .collect::<Vec<_>>()
            .join(" OR ")
    );
    let rows = [
        row("ints", "zero", &[("s2", json!(0))]),
        row("ints", "one", &[("s2", json!(1))]),
    ];
    assert_eq!(
        run(&owner, &sql, &TypedParameters::default(), &rows).unwrap(),
        vec![projected("ints", "one", &[("s2", json!(1))])]
    );
}

#[test]
fn integer_rows_compare_in_exact_signed_and_unsigned_domains() {
    let owner = authority(
        "ints",
        &[
            ("s2", AttributeType::Integer(IntegerType::Int2), false),
            ("s4", AttributeType::Integer(IntegerType::Int4), false),
            ("s8", AttributeType::Integer(IntegerType::Int8), false),
            ("scalar", AttributeType::Scalar(ScalarType::Integer), false),
            ("u8", AttributeType::Integer(IntegerType::Uint8), false),
        ],
    );
    let rows = [
        row(
            "ints",
            "n_min",
            &[
                ("s2", json!(-32768)),
                ("s4", json!(-2147483648_i64)),
                ("s8", json!(i64::MIN)),
                ("scalar", json!(i64::MIN)),
                ("u8", json!(0)),
            ],
        ),
        row(
            "ints",
            "n_max",
            &[
                ("s2", json!(32767)),
                ("s4", json!(2147483647_i64)),
                ("s8", json!(i64::MAX)),
                ("scalar", json!(i64::MAX)),
                ("u8", json!(u64::MAX)),
            ],
        ),
        row(
            "ints",
            "n_one",
            &[
                ("s2", json!(1)),
                ("s4", json!(1)),
                ("s8", json!(1)),
                ("scalar", json!(1)),
                ("u8", json!(1)),
            ],
        ),
    ];
    for (sql, key, field, value) in [
        (
            "SELECT s2 FROM ints WHERE s2 = -32768",
            "n_min",
            "s2",
            json!(-32768),
        ),
        (
            "SELECT s2 FROM ints WHERE s2 = 32767",
            "n_max",
            "s2",
            json!(32767),
        ),
        (
            "SELECT s4 FROM ints WHERE s4 = -2147483648",
            "n_min",
            "s4",
            json!(-2147483648_i64),
        ),
        (
            "SELECT s4 FROM ints WHERE s4 = 2147483647",
            "n_max",
            "s4",
            json!(2147483647_i64),
        ),
        (
            "SELECT s8 FROM ints WHERE s8 = -9223372036854775808",
            "n_min",
            "s8",
            json!(i64::MIN),
        ),
        (
            "SELECT s8 FROM ints WHERE s8 = 9223372036854775807",
            "n_max",
            "s8",
            json!(i64::MAX),
        ),
        (
            "SELECT scalar FROM ints WHERE scalar = -9223372036854775808",
            "n_min",
            "scalar",
            json!(i64::MIN),
        ),
        (
            "SELECT scalar FROM ints WHERE scalar = 9223372036854775807",
            "n_max",
            "scalar",
            json!(i64::MAX),
        ),
        ("SELECT u8 FROM ints WHERE u8 = 0", "n_min", "u8", json!(0)),
        (
            "SELECT u8 FROM ints WHERE u8 = 18446744073709551615",
            "n_max",
            "u8",
            json!(u64::MAX),
        ),
    ] {
        assert_eq!(
            run(&owner, sql, &TypedParameters::default(), &rows).unwrap(),
            vec![projected("ints", key, &[(field, value)])],
            "{sql}"
        );
    }
    assert_eq!(
        run(
            &owner,
            "SELECT s2 FROM ints WHERE s2 > 0",
            &TypedParameters::default(),
            &rows
        )
        .unwrap(),
        vec![
            projected("ints", "n_max", &[("s2", json!(32767))]),
            projected("ints", "n_one", &[("s2", json!(1))])
        ]
    );
    for (sql, expected_keys) in [
        ("SELECT s2 FROM ints WHERE s2 < 1", vec!["n_min"]),
        ("SELECT s2 FROM ints WHERE s2 <= 1", vec!["n_min", "n_one"]),
        ("SELECT s2 FROM ints WHERE s2 > 1", vec!["n_max"]),
        ("SELECT s2 FROM ints WHERE s2 >= 1", vec!["n_max", "n_one"]),
        ("SELECT s2 FROM ints WHERE s2 <> 1", vec!["n_min", "n_max"]),
        ("SELECT s2 FROM ints WHERE s2 != 1", vec!["n_min", "n_max"]),
    ] {
        let actual = run(&owner, sql, &TypedParameters::default(), &rows).unwrap();
        assert_eq!(
            actual
                .iter()
                .map(|row| row.id.key.as_str())
                .collect::<Vec<_>>(),
            expected_keys,
            "{sql}"
        );
    }
    assert_eq!(
        run(
            &owner,
            "SELECT s2 FROM ints WHERE s2 = $1",
            &TypedParameters {
                positional: vec![ParameterValue::I64(-32768)],
                named: BTreeMap::new()
            },
            &rows
        )
        .unwrap(),
        vec![projected("ints", "n_min", &[("s2", json!(-32768))])]
    );
    assert_eq!(
        run(
            &owner,
            "SELECT u8 FROM ints WHERE u8 = $1",
            &TypedParameters {
                positional: vec![ParameterValue::U64(u64::MAX)],
                named: BTreeMap::new()
            },
            &rows
        )
        .unwrap(),
        vec![projected("ints", "n_max", &[("u8", json!(u64::MAX))])]
    );
    assert_eq!(
        run(
            &owner,
            "SELECT s2 FROM ints WHERE s2 = NULL",
            &TypedParameters::default(),
            &rows
        )
        .unwrap(),
        vec![]
    );

    let bad_signed = row("ints", "bad", &[("s8", json!(u64::MAX))]);
    assert!(matches!(
        run(
            &owner,
            "SELECT s8 FROM ints",
            &TypedParameters::default(),
            &[bad_signed]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let bad_narrow = row("ints", "bad", &[("s2", json!(32768))]);
    assert!(matches!(
        run(
            &owner,
            "SELECT s2 FROM ints",
            &TypedParameters::default(),
            &[bad_narrow]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let bad_float = row("ints", "bad", &[("s2", json!(1.0))]);
    assert!(matches!(
        run(
            &owner,
            "SELECT s2 FROM ints",
            &TypedParameters::default(),
            &[bad_float]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let negative_unsigned = row("ints", "bad", &[("u8", json!(-1))]);
    assert!(matches!(
        run(
            &owner,
            "SELECT u8 FROM ints",
            &TypedParameters::default(),
            &[negative_unsigned]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
}

#[test]
fn hostile_text_quoted_identifiers_scalar_types_and_unqueried_json_stay_typed() {
    let tokens_owner = authority(
        "tokens",
        &[
            ("@name", AttributeType::Text, false),
            ("name", AttributeType::Text, false),
        ],
    );
    let tokens = [
        row(
            "tokens",
            "t_attack",
            &[("@name", json!("raw")), ("name", json!("x' OR TRUE --"))],
        ),
        row(
            "tokens",
            "t_literal",
            &[("@name", json!("quoted")), ("name", json!("$1 :n @n"))],
        ),
    ];
    let hostile = TypedParameters {
        positional: vec![],
        named: BTreeMap::from([(
            "needle".into(),
            ParameterValue::Text("x' OR TRUE --".into()),
        )]),
    };
    let expected = vec![projected(
        "tokens",
        "t_attack",
        &[("name", json!("x' OR TRUE --"))],
    )];
    for sql in [
        "SELECT name FROM tokens WHERE name = :needle",
        "SELECT name FROM tokens WHERE name = :needle OR name = @needle",
    ] {
        assert_eq!(
            run(&tokens_owner, sql, &hostile, &tokens).unwrap(),
            expected,
            "{sql}"
        );
    }
    assert_eq!(
        run(
            &tokens_owner,
            "SELECT name FROM tokens WHERE name = 'x'' OR TRUE --'",
            &TypedParameters::default(),
            &tokens
        )
        .unwrap(),
        expected
    );
    assert_eq!(
        run(
            &tokens_owner,
            "SELECT \"@name\" FROM tokens WHERE name = '$1 :n @n'",
            &TypedParameters::default(),
            &tokens
        )
        .unwrap(),
        vec![projected(
            "tokens",
            "t_literal",
            &[("@name", json!("quoted"))]
        )]
    );

    let scalar_owner = authority(
        "scalars",
        &[
            ("flag", AttributeType::Scalar(ScalarType::Boolean), false),
            ("label", AttributeType::Scalar(ScalarType::Text), false),
        ],
    );
    let scalars = [
        row(
            "scalars",
            "s_true",
            &[("flag", json!(true)), ("label", json!("Ž"))],
        ),
        row(
            "scalars",
            "s_false",
            &[("flag", json!(false)), ("label", json!("é"))],
        ),
    ];
    assert_eq!(
        run(
            &scalar_owner,
            "SELECT label FROM scalars WHERE flag = TRUE",
            &TypedParameters::default(),
            &scalars
        )
        .unwrap(),
        vec![projected("scalars", "s_true", &[("label", json!("Ž"))])]
    );
    assert_eq!(
        run(
            &scalar_owner,
            "SELECT label FROM scalars WHERE label < 'Ž'",
            &TypedParameters::default(),
            &scalars
        )
        .unwrap(),
        vec![projected("scalars", "s_false", &[("label", json!("é"))])]
    );
    assert_eq!(
        run(
            &scalar_owner,
            "SELECT label FROM scalars WHERE flag = $1",
            &TypedParameters {
                positional: vec![ParameterValue::Bool(true)],
                named: BTreeMap::new()
            },
            &scalars
        )
        .unwrap(),
        vec![projected("scalars", "s_true", &[("label", json!("Ž"))])]
    );
    let docs_owner = authority(
        "docs",
        &[
            ("payload", AttributeType::Json, true),
            ("title", AttributeType::Text, false),
        ],
    );
    let docs = [row(
        "docs",
        "d1",
        &[
            ("payload", json!({"tag": "unqueried"})),
            ("title", json!("Doc")),
        ],
    )];
    assert_eq!(
        run(
            &docs_owner,
            "SELECT title FROM docs",
            &TypedParameters::default(),
            &docs
        )
        .unwrap(),
        vec![projected("docs", "d1", &[("title", json!("Doc"))])]
    );
    let wrong_boolean = row(
        "scalars",
        "bad",
        &[("flag", json!("true")), ("label", json!("Ž"))],
    );
    assert!(matches!(
        run(
            &scalar_owner,
            "SELECT label FROM scalars WHERE flag = TRUE",
            &TypedParameters::default(),
            &[wrong_boolean]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
    let wrong_text = row(
        "scalars",
        "bad",
        &[("flag", json!(true)), ("label", json!(3))],
    );
    assert!(matches!(
        run(
            &scalar_owner,
            "SELECT label FROM scalars",
            &TypedParameters::default(),
            &[wrong_text]
        ),
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    ));
}

#[test]
fn three_valued_logic_preserves_unknown_and_is_not_null_is_boolean() {
    let owner = users_owner();
    let rows = users();
    for (sql, expected_keys) in [
        (
            "SELECT name FROM users WHERE active = TRUE OR age = NULL",
            vec!["u16", "u21", "u55", "u_missing"],
        ),
        (
            "SELECT name FROM users WHERE active = TRUE AND age = NULL",
            vec![],
        ),
        (
            "SELECT name FROM users WHERE active = FALSE AND age = NULL",
            vec![],
        ),
        (
            "SELECT name FROM users WHERE age IS NOT NULL",
            vec!["u16", "u21", "u34", "u55"],
        ),
        (
            "SELECT name FROM users WHERE NOT (age = NULL OR active = FALSE)",
            vec![],
        ),
    ] {
        let actual = run(&owner, sql, &TypedParameters::default(), &rows).unwrap();
        assert_eq!(
            actual
                .iter()
                .map(|row| row.id.key.as_str())
                .collect::<Vec<_>>(),
            expected_keys,
            "{sql}"
        );
    }
}

#[test]
fn required_missing_and_explicit_null_fail_without_partial_results() {
    let orders = authority(
        "orders",
        &[("qty", AttributeType::Integer(IntegerType::Int4), false)],
    );
    assert!(matches!(
        run(
            &orders,
            "SELECT qty FROM orders",
            &TypedParameters::default(),
            &[row("orders", "o_missing", &[])]
        ),
        Err(QueryCompileError::DataContract {
            code: "missing_required"
        })
    ));
    assert!(matches!(
        run(
            &orders,
            "SELECT qty FROM orders",
            &TypedParameters::default(),
            &[row("orders", "o_null", &[("qty", Value::Null)])]
        ),
        Err(QueryCompileError::DataContract {
            code: "null_required"
        })
    ));
    assert!(matches!(
        run(
            &orders,
            "SELECT qty FROM orders",
            &TypedParameters::default(),
            &[
                row("orders", "good", &[("qty", json!(1))]),
                row("orders", "bad", &[])
            ]
        ),
        Err(QueryCompileError::DataContract {
            code: "missing_required"
        })
    ));
}
