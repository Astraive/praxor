//! Public Q1 compiler contract. Inputs and expected JSON are literal client fixtures.
use praxis::catalog::schema::ComputedField;
use praxis::document::RecordId;
use praxis::query::{
    AsOfClause, DdlPlan, FullTextClause, JoinClause, MutationPlan, OrderClause, QueryParams,
    TraversalClause, VectorClause, WindowFunction,
};
use praxis::{
    AttributeSchema, AttributeType, Catalog, CollectionSchema, CompileInput, CompiledStatement,
    LogicalPlan, ParameterValue, QueryCatalogAuthority, QueryCompileError, QueryLanguage,
    QueryOperation, Record, TypedParameters, compile, execute_in_memory,
};
use serde_json::json;
use std::collections::BTreeMap;

fn tokens() -> QueryCatalogAuthority {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("tokens")
                .with_attribute(AttributeSchema::new("name", AttributeType::Text).required()),
        )
        .unwrap();
    QueryCatalogAuthority::new(catalog)
}

fn authority_with_value_bearing_schema() -> QueryCatalogAuthority {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("computed").with_computed(ComputedField {
                name: "derived".into(),
                expression: "'schema-expression-secret'".into(),
                result_type: AttributeType::Text,
            }),
        )
        .unwrap();
    QueryCatalogAuthority::new(catalog)
}

fn select_legacy() -> LogicalPlan {
    LogicalPlan {
        language: QueryLanguage::Sql,
        operation: QueryOperation::Select,
        collection: "tokens".into(),
        filter: None,
        filter_expression: None,
        joins: vec![],
        full_text: None,
        vector: None,
        traversal: None,
        rank_by: None,
        order_by: None,
        limit: None,
        offset: None,
        distinct: false,
        group_by: None,
        having: None,
        as_of: None,
        mutation: None,
        ddl: None,
        explain_analyze: false,
        ctes: vec![],
        window_functions: vec![],
        params: QueryParams::default(),
    }
}

#[test]
fn public_select_uses_document_ids_and_typed_text_without_source_substitution() {
    let authority = tokens();
    let values = TypedParameters {
        positional: vec![],
        named: BTreeMap::from([(
            "needle".into(),
            ParameterValue::Text("x' OR TRUE --".into()),
        )]),
    };
    let compiled = compile(
        CompileInput::Sql("SELECT name FROM tokens WHERE name = :needle"),
        &values,
        &authority.view(),
    )
    .unwrap();
    assert!(!format!("{compiled:?}").contains("x' OR TRUE --"));
    let CompiledStatement::Select(select) = compiled else {
        panic!("SELECT must produce only an executable Select variant")
    };
    let rows = [
        Record::new("tokens", "t_attack").with_attribute("name", json!("x' OR TRUE --")),
        Record::new("tokens", "t_other").with_attribute("name", json!("plain")),
    ];
    let result = execute_in_memory(&authority, &select, &rows).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, RecordId::new("tokens", "t_attack"));
    assert_eq!(
        result[0].fields,
        vec![("name".into(), json!("x' OR TRUE --"))]
    );
}

#[test]
fn explain_is_a_distinct_versioned_redacted_nonexecuting_artifact() {
    let authority = tokens();
    let values = TypedParameters {
        positional: vec![],
        named: BTreeMap::from([(
            "needle".into(),
            ParameterValue::Text("x' OR TRUE --".into()),
        )]),
    };
    let compiled = compile(
        CompileInput::Sql("EXPLAIN SELECT name FROM tokens WHERE name = :needle"),
        &values,
        &authority.view(),
    )
    .unwrap();
    let CompiledStatement::Explain(explain) = compiled else {
        panic!("EXPLAIN must never yield an executable Select variant")
    };
    let json_value = serde_json::to_value(&explain).unwrap();
    assert_eq!(
        json_value,
        json!({
            "version": 1,
            "catalog_scope": "process",
            "revision": 1,
            "collection": "tokens",
            "projection": ["name"],
            "predicate_shape": [{"kind": "compare", "field": "name", "operator": "="}],
            "required_capabilities": ["collection_scan"],
            "execution": "not_executed"
        })
    );
    assert!(!json_value.to_string().contains("x' OR TRUE --"));
    assert!(matches!(
        compile(
            CompileInput::Sql("EXPLAIN ANALYZE SELECT name FROM tokens"),
            &TypedParameters::default(),
            &authority.view(),
        ),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "explain_analyze",
            span: Some(_)
        })
    ));
}

#[test]
fn explain_uses_the_same_binding_checks_and_never_serializes_literal_values() {
    let authority = tokens();
    let view = authority.view();
    assert!(matches!(
        compile(
            CompileInput::Sql("EXPLAIN SELECT unknown FROM tokens"),
            &TypedParameters::default(),
            &view,
        ),
        Err(QueryCompileError::UnknownField { .. })
    ));
    assert!(matches!(
        compile(
            CompileInput::Sql("EXPLAIN SELECT name FROM tokens WHERE name = :missing"),
            &TypedParameters::default(),
            &view,
        ),
        Err(QueryCompileError::Parameter {
            code: "missing",
            ..
        })
    ));
    assert!(matches!(
        compile(
            CompileInput::Sql("EXPLAIN SELECT name FROM tokens GROUP BY name"),
            &TypedParameters::default(),
            &view,
        ),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "group_by",
            span: Some(_)
        })
    ));
    let CompiledStatement::Explain(no_predicate) = compile(
        CompileInput::Sql("EXPLAIN SELECT name FROM tokens"),
        &TypedParameters::default(),
        &view,
    )
    .unwrap() else {
        panic!("EXPLAIN variant")
    };
    assert_eq!(
        serde_json::to_value(no_predicate).unwrap()["predicate_shape"],
        json!(null)
    );

    let CompiledStatement::Explain(inline_value) = compile(
        CompileInput::Sql("EXPLAIN SELECT name FROM tokens WHERE name = 'redact this literal'"),
        &TypedParameters::default(),
        &view,
    )
    .unwrap() else {
        panic!("EXPLAIN variant")
    };
    assert!(
        !serde_json::to_string(&inline_value)
            .unwrap()
            .contains("redact this literal")
    );

    authority
        .replace_collection(
            CollectionSchema::new("tokens")
                .with_attribute(AttributeSchema::new("name", AttributeType::Text).required()),
        )
        .unwrap();
    assert!(matches!(
        compile(
            CompileInput::Sql("EXPLAIN SELECT name FROM tokens"),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::StaleCatalog)
    ));
}

#[test]
fn explain_postfix_shape_and_projection_order_are_exact_and_value_free() {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("things")
                .with_attribute(AttributeSchema::new("b", AttributeType::Text).required())
                .with_attribute(AttributeSchema::new("a", AttributeType::Text).required()),
        )
        .unwrap();
    let authority = QueryCatalogAuthority::new(catalog);
    let CompiledStatement::Explain(named) = compile(
        CompileInput::Sql("EXPLAIN SELECT b, a FROM things WHERE a = 'secret' OR NOT (b IS NULL)"),
        &TypedParameters::default(),
        &authority.view(),
    )
    .unwrap() else {
        panic!("EXPLAIN variant")
    };
    assert_eq!(named.projection, ["b", "a"]);
    assert_eq!(
        serde_json::to_value(&named).unwrap()["predicate_shape"],
        json!([
            {"kind": "compare", "field": "a", "operator": "="},
            {"kind": "is_null", "field": "b", "negated": false},
            {"kind": "not"},
            {"kind": "or"}
        ])
    );
    assert!(!serde_json::to_string(&named).unwrap().contains("secret"));
    let CompiledStatement::Explain(all) = compile(
        CompileInput::Sql("EXPLAIN SELECT * FROM things"),
        &TypedParameters::default(),
        &authority.view(),
    )
    .unwrap() else {
        panic!("EXPLAIN variant")
    };
    assert_eq!(all.projection, ["a", "b"]);
}

#[test]
fn a_client_cannot_reuse_stale_or_foreign_compiled_selects() {
    let authority = tokens();
    let compiled = compile(
        CompileInput::Sql("SELECT name FROM tokens"),
        &TypedParameters::default(),
        &authority.view(),
    )
    .unwrap();
    let CompiledStatement::Select(select) = compiled else {
        panic!("SELECT variant")
    };
    let foreign = tokens();
    let bad_row = Record::new("other", "bad");
    assert!(matches!(
        execute_in_memory(&foreign, &select, std::slice::from_ref(&bad_row)),
        Err(QueryCompileError::ForeignCatalog)
    ));
    authority
        .replace_collection(
            CollectionSchema::new("tokens")
                .with_attribute(AttributeSchema::new("name", AttributeType::Text).required()),
        )
        .unwrap();
    assert!(matches!(
        execute_in_memory(&authority, &select, &[bad_row]),
        Err(QueryCompileError::StaleCatalog)
    ));
}

#[test]
fn every_required_legacy_feature_is_refused_before_unbound_fallback() {
    let authority = tokens();
    let view = authority.view();
    let base = select_legacy();
    assert!(matches!(
        compile(
            CompileInput::LegacyPlan(&base),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::LegacyPlanUnbound)
    ));
    type LegacyFeatureCase = (&'static str, fn(&mut LogicalPlan));
    let cases: [LegacyFeatureCase; 20] = [
        ("operation", |plan| plan.operation = QueryOperation::Watch),
        ("join", |plan| {
            plan.joins.push(JoinClause {
                collection: "other".into(),
                left_attribute: "id".into(),
                right_attribute: "id".into(),
            })
        }),
        ("full_text", |plan| {
            plan.full_text = Some(FullTextClause {
                attribute: "name".into(),
                query: "x".into(),
                top: None,
            })
        }),
        ("vector", |plan| {
            plan.vector = Some(VectorClause {
                target: "vec".into(),
                top: 1,
                threshold: None,
            })
        }),
        ("traversal", |plan| {
            plan.traversal = Some(TraversalClause {
                target: "x".into(),
                hops: 1,
                edge_label: None,
            })
        }),
        ("rank", |plan| plan.rank_by = Some("score".into())),
        ("order_by", |plan| {
            plan.order_by = Some(OrderClause {
                attribute: "name".into(),
                descending: false,
            })
        }),
        ("limit", |plan| plan.limit = Some(0)),
        ("offset", |plan| plan.offset = Some(0)),
        ("distinct", |plan| plan.distinct = true),
        ("group_by", |plan| plan.group_by = Some(vec!["name".into()])),
        ("having", |plan| {
            plan.having = Some(praxis::query::BooleanExpression::Predicate(
                praxis::query::Predicate {
                    attribute: "name".into(),
                    operator: "=".into(),
                    value: "x".into(),
                },
            ))
        }),
        ("as_of", |plan| {
            plan.as_of = Some(AsOfClause::Commit("c1".into()))
        }),
        ("mutation", |plan| {
            plan.mutation = Some(MutationPlan::Delete { key: "k".into() })
        }),
        ("ddl", |plan| {
            plan.ddl = Some(DdlPlan::DropCollection {
                name: "tokens".into(),
            })
        }),
        ("cte", |plan| {
            plan.ctes.push(praxis::query::CteDefinition {
                name: "q".into(),
                query: Box::new(select_legacy()),
                recursive: false,
            })
        }),
        ("window", |plan| {
            plan.window_functions.push(WindowFunction {
                function: "ROW_NUMBER".into(),
                args: vec![],
                partition_by: vec![],
                order_by: vec![],
                alias: "n".into(),
            })
        }),
        ("explain_analyze", |plan| plan.explain_analyze = true),
        ("legacy_parameters", |plan| {
            plan.params.positional.push("x".into())
        }),
        ("legacy_parameters", |plan| {
            plan.params.named.insert("needle".into(), "x".into());
        }),
    ];
    for (feature, change) in cases {
        let mut plan = base.clone();
        change(&mut plan);
        assert!(
            matches!(
                compile(CompileInput::LegacyPlan(&plan), &TypedParameters::default(), &view),
                Err(QueryCompileError::UnsupportedFeature { feature: actual, span: None }) if actual == feature
            ),
            "{feature}"
        );
    }
    let mut both = base.clone();
    both.group_by = Some(vec!["name".into()]);
    both.as_of = Some(AsOfClause::Commit("c1".into()));
    assert!(matches!(
        compile(
            CompileInput::LegacyPlan(&both),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "group_by",
            span: None
        })
    ));
}

#[test]
fn a_deserialized_q0_logical_fixture_cannot_be_promoted_to_a_q1_capability() {
    let plan: LogicalPlan =
        serde_json::from_str(include_str!("fixtures/query-q0/logical-select.json")).unwrap();
    let authority = tokens();
    assert!(matches!(
        compile(
            CompileInput::LegacyPlan(&plan),
            &TypedParameters::default(),
            &authority.view()
        ),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "order_by",
            span: None
        })
    ));
}

#[test]
fn public_compile_enforces_q1_caps_and_never_accepts_untyped_legacy_filters() {
    let authority = tokens();
    let view = authority.view();
    let mut filtered = select_legacy();
    filtered.filter = Some(praxis::query::Predicate {
        attribute: "name".into(),
        operator: "=".into(),
        value: "x".into(),
    });
    assert!(matches!(
        compile(
            CompileInput::LegacyPlan(&filtered),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::LegacyPlanUnbound)
    ));
    assert!(matches!(
        compile(
            CompileInput::Sql("SELECT * FROM tokens GROUP BY name"),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::UnsupportedFeature {
            feature: "group_by",
            span: Some(_)
        })
    ));
    assert!(matches!(
        compile(
            CompileInput::Sql("SELECT name FROM tokens WHERE name = $1"),
            &TypedParameters {
                positional: vec![ParameterValue::Text("x".into()); 257],
                named: BTreeMap::new()
            },
            &view
        ),
        Err(QueryCompileError::LimitExceeded {
            code: "positional_parameters",
            span: None
        })
    ));
    let oversized = format!("SELECT name FROM tokens{}", " ".repeat(65_537));
    assert!(matches!(
        compile(
            CompileInput::Sql(&oversized),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::LimitExceeded {
            code: "input_bytes",
            span: Some(_)
        })
    ));
    let too_many_tokens = format!(
        "SELECT name FROM tokens WHERE {}",
        (0..2_050)
            .map(|_| "name = 'x'")
            .collect::<Vec<_>>()
            .join(" OR ")
    );
    assert!(matches!(
        compile(
            CompileInput::Sql(&too_many_tokens),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::LimitExceeded {
            code: "tokens",
            span: Some(_)
        })
    ));
    let too_deep = format!(
        "SELECT name FROM tokens WHERE {}name = 'x'{}",
        "(".repeat(65),
        ")".repeat(65)
    );
    assert!(matches!(
        compile(
            CompileInput::Sql(&too_deep),
            &TypedParameters::default(),
            &view
        ),
        Err(QueryCompileError::LimitExceeded {
            code: "nesting",
            span: Some(_)
        })
    ));
}

#[test]
fn sql_compile_input_debug_redacts_source_text() {
    let sql = "SELECT name FROM tokens WHERE name = 'x'' OR TRUE --'";
    let formatted = format!("{:?}", CompileInput::Sql(sql));
    assert!(!formatted.contains("x'' OR TRUE --"), "{formatted}");
    assert!(!formatted.contains(sql), "{formatted}");
}

#[test]
fn legacy_compile_input_debug_redacts_plan_values() {
    let mut plan = select_legacy();
    plan.filter = Some(praxis::query::Predicate {
        attribute: "name".into(),
        operator: "=".into(),
        value: "x' OR TRUE --".into(),
    });
    let formatted = format!("{:?}", CompileInput::LegacyPlan(&plan));
    assert!(!formatted.contains("x' OR TRUE --"), "{formatted}");
}

#[test]
fn parameter_value_debug_redacts_all_payload_kinds() {
    for (value, secret) in [
        (
            ParameterValue::Text("x' OR TRUE --".into()),
            "x' OR TRUE --",
        ),
        (ParameterValue::Bool(true), "true"),
        (ParameterValue::I64(-123456789), "-123456789"),
        (ParameterValue::U64(987654321), "987654321"),
    ] {
        let formatted = format!("{value:?}");
        assert!(!formatted.contains(secret), "{formatted}");
    }
}

#[test]
fn typed_parameters_debug_redacts_nested_bindings() {
    let values = TypedParameters {
        positional: vec![ParameterValue::Text("x' OR TRUE --".into())],
        named: BTreeMap::from([(
            "needle".into(),
            ParameterValue::Text("nested-secret".into()),
        )]),
    };
    let formatted = format!("{values:?}");
    assert!(!formatted.contains("x' OR TRUE --"), "{formatted}");
    assert!(!formatted.contains("nested-secret"), "{formatted}");
}

#[test]
fn catalog_authority_debug_redacts_schema_expressions() {
    let authority = authority_with_value_bearing_schema();
    let formatted = format!("{authority:?}");
    assert!(
        !formatted.contains("schema-expression-secret"),
        "{formatted}"
    );
}

#[test]
fn catalog_view_debug_redacts_schema_expressions() {
    let authority = authority_with_value_bearing_schema();
    let formatted = format!("{:?}", authority.view());
    assert!(
        !formatted.contains("schema-expression-secret"),
        "{formatted}"
    );
}
