//! Literal wire observations for experimental models, not a stability upgrade.
use praxis::api::graphql::{GraphQLError, GraphQLRequest, GraphQLResponse};
use praxis::planner::{AggregateExpr, CostedOperator, CostedPlan};
use praxis::query::{
    AlterAction, AttributeDdl, CteDefinition, JoinClause, OrderClause, QueryParams, WindowFunction,
};
use praxis::{
    AsOfClause, BooleanExpression, Catalog, DdlPlan, FullTextClause, LogicalPlan, MutationPlan,
    PhysicalOperator, PhysicalPlan, Planner, PlannerStats, Predicate, QueryLanguage,
    QueryOperation, QueryParser, TraversalClause, VectorClause,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Debug;

const SELECT: &str = "SELECT * FROM users WHERE age >= 18 ORDER BY age DESC LIMIT 2 OFFSET 1;";
fn age() -> Predicate {
    Predicate {
        attribute: "age".into(),
        operator: ">=".into(),
        value: "18".into(),
    }
}
fn order() -> OrderClause {
    OrderClause {
        attribute: "age".into(),
        descending: true,
    }
}
fn logical() -> LogicalPlan {
    LogicalPlan {
        language: QueryLanguage::Sql,
        operation: QueryOperation::Select,
        collection: "users".into(),
        filter: Some(age()),
        filter_expression: Some(BooleanExpression::Predicate(age())),
        joins: vec![],
        full_text: None,
        vector: None,
        traversal: None,
        rank_by: None,
        order_by: Some(order()),
        limit: Some(2),
        offset: Some(1),
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
fn check<T: Serialize + DeserializeOwned + PartialEq + Debug>(literal: Value, expected: T) {
    assert_eq!(
        serde_json::from_value::<T>(literal.clone()).unwrap(),
        expected
    );
    assert_eq!(serde_json::to_value(expected).unwrap(), literal);
}

#[test]
fn literal_logical_and_physical_select_match_independent_constructions() {
    let literal: Value =
        serde_json::from_str(include_str!("fixtures/query-q0/logical-select.json")).unwrap();
    check(literal.clone(), logical());
    assert_eq!(QueryParser::parse(SELECT).unwrap(), logical());
    let physical = PhysicalPlan {
        collection: "users".into(),
        operators: vec![
            PhysicalOperator::FilterExpression(BooleanExpression::Predicate(age())),
            PhysicalOperator::Order(order()),
            PhysicalOperator::Offset(1),
            PhysicalOperator::Limit(2),
        ],
    };
    check(
        serde_json::from_str(include_str!("fixtures/query-q0/physical-select.json")).unwrap(),
        physical.clone(),
    );
    assert_eq!(Planner.plan(&logical()).unwrap(), physical);
    let mut absent_optional = literal.clone();
    absent_optional.as_object_mut().unwrap().remove("as_of");
    assert_eq!(
        serde_json::from_value::<LogicalPlan>(absent_optional)
            .unwrap()
            .as_of,
        None
    );
    let mut absent_required = literal;
    absent_required.as_object_mut().unwrap().remove("params");
    assert!(serde_json::from_value::<LogicalPlan>(absent_required).is_err());
}

#[test]
fn literal_query_variants_clauses_and_boxed_cte_keep_current_serde_shapes() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/query-q0/query-variants.json")).unwrap();
    check(
        fixture["QueryLanguage"].clone(),
        vec![QueryLanguage::Sql, QueryLanguage::Pql],
    );
    check(
        fixture["QueryOperation"].clone(),
        vec![
            QueryOperation::Select,
            QueryOperation::Insert,
            QueryOperation::Update,
            QueryOperation::Delete,
            QueryOperation::Watch,
            QueryOperation::Explain,
            QueryOperation::CreateCollection,
            QueryOperation::AlterCollection,
            QueryOperation::DropCollection,
            QueryOperation::ShowCollections,
            QueryOperation::ListRoles,
            QueryOperation::ListBranches,
            QueryOperation::CreateBranch,
            QueryOperation::DropBranch,
        ],
    );
    check(
        fixture["AsOfClause"].clone(),
        vec![
            AsOfClause::Commit("c1".into()),
            AsOfClause::Branch("main".into()),
            AsOfClause::Timestamp("2026-10-18T00:00:00Z".into()),
        ],
    );
    check(
        fixture["MutationPlan"].clone(),
        vec![
            MutationPlan::Insert {
                key: "u1".into(),
                attributes: BTreeMap::from([
                    ("active".into(), json!(true)),
                    ("age".into(), json!(18)),
                    ("name".into(), json!("Ada")),
                    ("nullable".into(), Value::Null),
                ]),
            },
            MutationPlan::Update {
                key: "u1".into(),
                attributes: BTreeMap::from([("age".into(), json!(19))]),
            },
            MutationPlan::Delete { key: "u1".into() },
        ],
    );
    check(
        fixture["DdlPlan"].clone(),
        vec![
            DdlPlan::CreateCollection {
                name: "users".into(),
                attributes: vec![AttributeDdl {
                    name: "age".into(),
                    type_name: "int".into(),
                    nullable: false,
                }],
            },
            DdlPlan::AlterCollection {
                name: "users".into(),
                actions: vec![
                    AlterAction::AddAttribute {
                        name: "name".into(),
                        type_name: "text".into(),
                        nullable: true,
                    },
                    AlterAction::DropAttribute { name: "old".into() },
                ],
            },
            DdlPlan::DropCollection {
                name: "users".into(),
            },
        ],
    );
    check(
        fixture["BooleanExpression"].clone(),
        BooleanExpression::And(
            Box::new(BooleanExpression::Predicate(age())),
            Box::new(BooleanExpression::Or(
                Box::new(BooleanExpression::Predicate(Predicate {
                    attribute: "active".into(),
                    operator: "=".into(),
                    value: "true".into(),
                })),
                Box::new(BooleanExpression::Predicate(Predicate {
                    attribute: "name".into(),
                    operator: "=".into(),
                    value: "Ada".into(),
                })),
            )),
        ),
    );
    check(
        fixture["JoinClause"].clone(),
        JoinClause {
            collection: "teams".into(),
            left_attribute: "users.team".into(),
            right_attribute: "teams.id".into(),
        },
    );
    check(
        fixture["FullTextClause"].clone(),
        FullTextClause {
            attribute: "bio".into(),
            query: "rust".into(),
            top: Some(3),
        },
    );
    check(
        fixture["VectorClause"].clone(),
        VectorClause {
            target: "seed".into(),
            top: 2,
            threshold: Some("0.8".into()),
        },
    );
    check(
        fixture["TraversalClause"].clone(),
        TraversalClause {
            target: "seed".into(),
            hops: 2,
            edge_label: Some("follows".into()),
        },
    );
    check(fixture["OrderClause"].clone(), order());
    check(
        fixture["QueryParams"].clone(),
        QueryParams {
            positional: vec!["18".into()],
            named: BTreeMap::from([
                ("active".into(), "true".into()),
                ("name".into(), "'Ada'".into()),
            ]),
        },
    );
    check(
        fixture["WindowFunction"].clone(),
        WindowFunction {
            function: "LAG".into(),
            args: vec!["age".into()],
            partition_by: vec!["team".into()],
            order_by: vec![order()],
            alias: "prev_age".into(),
        },
    );
    check(fixture["Catalog"].clone(), Catalog::new());
    check(
        serde_json::from_str(include_str!("fixtures/query-q0/cte.json")).unwrap(),
        CteDefinition {
            name: "adults".into(),
            query: Box::new(logical()),
            recursive: false,
        },
    );
}

#[test]
fn literal_physical_variants_are_serde_cases_not_a_synthetic_execution_claim() {
    let manual = PhysicalPlan {
        collection: "users".into(),
        operators: vec![
            PhysicalOperator::AsOf,
            PhysicalOperator::Filter(age()),
            PhysicalOperator::Join(JoinClause {
                collection: "teams".into(),
                left_attribute: "team".into(),
                right_attribute: "id".into(),
            }),
            PhysicalOperator::FullText(FullTextClause {
                attribute: "bio".into(),
                query: "rust".into(),
                top: Some(3),
            }),
            PhysicalOperator::Similarity(VectorClause {
                target: "seed".into(),
                top: 2,
                threshold: Some("0.8".into()),
            }),
            PhysicalOperator::Traverse(TraversalClause {
                target: "seed".into(),
                hops: 2,
                edge_label: Some("follows".into()),
            }),
            PhysicalOperator::Rank("text".into()),
            PhysicalOperator::GroupBy(vec!["team".into()]),
            PhysicalOperator::Distinct,
            PhysicalOperator::Aggregate(AggregateExpr {
                function: "COUNT".into(),
                attribute: "age".into(),
                alias: "n".into(),
            }),
            PhysicalOperator::Order(order()),
            PhysicalOperator::Offset(1),
            PhysicalOperator::Limit(2),
        ],
    };
    check(
        serde_json::from_str(include_str!("fixtures/query-q0/physical-variants.json")).unwrap(),
        manual,
    );
}

#[test]
fn cost_fields_roundtrip_with_diagnostic_reason_and_bounded_planner_estimates() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/query-q0/costed.json")).unwrap();
    let stats = PlannerStats {
        collection_cardinality: 10,
        filter_selectivity: 0.5,
        vector_fanout: 4,
        graph_average_degree: 2.0,
        graph_depth: 1,
        full_text_posting_hits: 3,
        scalar_index_density: 0.25,
    };
    check(fixture["PlannerStats"].clone(), stats.clone());
    let physical = PhysicalPlan {
        collection: "users".into(),
        operators: vec![PhysicalOperator::Limit(2)],
    };
    // This reason is literal diagnostic data in a manually constructed value;
    // planner/explain prose may change in a reviewed later implementation.
    check(
        fixture["CostedPlan"].clone(),
        CostedPlan {
            physical: physical.clone(),
            operators: vec![CostedOperator {
                operator: PhysicalOperator::Limit(2),
                estimated_rows: 2,
                estimated_cost: 1.0,
                reason: "limit caps rows".into(),
            }],
            total_cost: 1.0,
        },
    );
    let mut limited = logical();
    limited.filter = None;
    limited.filter_expression = None;
    limited.order_by = None;
    limited.offset = None;
    let actual = Planner.plan_with_stats(&limited, &stats).unwrap();
    assert_eq!(actual.physical, physical);
    assert_eq!(actual.operators.len(), 1);
    assert_eq!(actual.operators[0].estimated_rows, 2);
    assert!(actual.total_cost.is_finite() && (0.0..=10.0).contains(&actual.total_cost));
    assert!(
        actual.operators[0].estimated_cost.is_finite()
            && (0.0..=10.0).contains(&actual.operators[0].estimated_cost)
    );
}

#[test]
fn graphql_request_rename_defaults_and_response_omissions_remain_observable() {
    let request: GraphQLRequest =
        serde_json::from_value(json!({"query":"{ users { age } }"})).unwrap();
    assert!(request.variables.is_empty());
    assert_eq!(request.operation_name, None);
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        json!({"query":"{ users { age } }","variables":{},"operationName":null})
    );
    let response = GraphQLResponse {
        data: Some(json!({"records":[]})),
        errors: vec![],
    };
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({"data":{"records":[]}})
    );
    let error: GraphQLError =
        serde_json::from_value(json!({"message":"bad","path":["users"]})).unwrap();
    assert_eq!(error.path.as_deref(), Some(["users".to_owned()].as_slice()));
    assert_eq!(
        serde_json::to_value(GraphQLError::new("bad")).unwrap(),
        json!({"message":"bad"})
    );
}
