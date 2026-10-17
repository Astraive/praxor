//! Current readiness observations. `known_gap_*` cases intentionally describe
//! accepted-but-ignored behavior for #61 to replace in a reviewed behavior fix.
//! No storage provider, retained snapshot, DDL writer or runtime is supplied.
use praxis::api::graphql::{GraphQLRequest, execute_graphql};
use praxis::document::{Record, RecordId};
use praxis::execution::RecordProvider;
use praxis::query::{QueryParams, substitute_params, tokenize};
use praxis::{
    AsOfClause, Executor, PhysicalOperator, Planner, PraxisError, Predicate, QueryParser,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

struct MemoryProvider {
    records: Vec<Record>,
    scalar_acceleration: bool,
}
impl MemoryProvider {
    fn new(scalar_acceleration: bool) -> Self {
        let mut records: Vec<_> = [("u16", 16), ("u21", 21), ("u34", 34), ("u55", 55)]
            .into_iter()
            .map(|(id, age)| Record::new("users", id).with_attribute("age", json!(age)))
            .collect();
        records.push(Record::new("users", "u_null").with_attribute("age", Value::Null));
        records.push(Record::new("users", "u_missing"));
        Self {
            records,
            scalar_acceleration,
        }
    }
}
impl RecordProvider for MemoryProvider {
    fn collection(&self, name: &str) -> Vec<Record> {
        self.records
            .iter()
            .filter(|record| record.id.collection == name)
            .cloned()
            .collect()
    }
    fn get(&self, id: &RecordId) -> Option<Record> {
        self.records.iter().find(|record| &record.id == id).cloned()
    }
    fn scalar_filter(&self, collection: &str, predicate: &Predicate) -> Option<Vec<Record>> {
        if !self.scalar_acceleration
            || predicate.attribute != "age"
            || predicate.operator != ">="
            || predicate.value != "18"
        {
            return None;
        }
        // Independent literal index result for this one bounded predicate.
        Some(
            self.collection(collection)
                .into_iter()
                .filter(|record| ["u21", "u34", "u55"].contains(&record.id.key.as_str()))
                .collect(),
        )
    }
    fn full_text_search(&self, _: &str, _: &str, _: &str, _: Option<usize>) -> Option<Vec<Record>> {
        None
    }
    fn vector_similarity(&self, _: &str, _: &str, _: usize) -> Option<Vec<Record>> {
        None
    }
    fn graph_connected_to(&self, _: &str, _: &str, _: usize, _: Option<&str>) -> Vec<Record> {
        vec![]
    }
}
fn execute(input: &str, provider: &MemoryProvider) -> Vec<String> {
    let logical = QueryParser::parse(input).unwrap();
    let physical = Planner.plan(&logical).unwrap();
    let execute: fn(
        &Executor,
        &MemoryProvider,
        &praxis::PhysicalPlan,
    ) -> praxis::Result<Vec<Record>> = Executor::execute::<MemoryProvider>;
    execute(&Executor, provider, &physical)
        .unwrap()
        .into_iter()
        .map(|record| record.id.key)
        .collect()
}
fn query_error<T: std::fmt::Debug>(result: praxis::Result<T>, expected: &str) {
    match result {
        Err(PraxisError::Query(message)) => assert_eq!(message, expected),
        other => panic!("expected Query({expected:?}), got {other:?}"),
    }
}

#[test]
fn bounded_select_executes_filter_order_offset_limit_with_and_without_scalar_index() {
    for accelerated in [false, true] {
        assert_eq!(
            execute(
                "SELECT * FROM users WHERE age >= 18 ORDER BY age DESC LIMIT 2 OFFSET 1;",
                &MemoryProvider::new(accelerated)
            ),
            ["u34", "u21"]
        );
    }
    assert_eq!(
        execute(
            "SELECT * FROM users WHERE age >= 21 AND age < 55 OR age = 16",
            &MemoryProvider::new(false)
        ),
        ["u16", "u21", "u34"]
    );
}

#[test]
fn known_gap_projection_is_absent_and_is_null_is_not_sql_null_execution() {
    assert_eq!(
        QueryParser::parse("SELECT age FROM users").unwrap(),
        QueryParser::parse("SELECT * FROM users").unwrap()
    );
    let logical = QueryParser::parse("SELECT * FROM users WHERE age IS NULL").unwrap();
    assert_eq!(logical.filter.unwrap().operator, "is_null");
    assert!(
        execute(
            "SELECT * FROM users WHERE age IS NULL",
            &MemoryProvider::new(false)
        )
        .is_empty()
    );
}

#[test]
fn known_gap_as_of_and_group_by_are_plan_metadata_without_execution() {
    let provider = MemoryProvider::new(false);
    let all = ["u16", "u21", "u34", "u55", "u_null", "u_missing"];
    let logical = QueryParser::parse("FIND users AS OF COMMIT c1").unwrap();
    assert_eq!(logical.as_of, Some(AsOfClause::Commit("c1".into())));
    assert_eq!(
        Planner.plan(&logical).unwrap().operators,
        [PhysicalOperator::AsOf]
    );
    assert_eq!(execute("FIND users AS OF COMMIT c1", &provider), all);
    let grouped = QueryParser::parse("SELECT * FROM users GROUP BY team").unwrap();
    assert_eq!(
        Planner.plan(&grouped).unwrap().operators,
        [PhysicalOperator::GroupBy(vec!["team".into()])]
    );
    assert_eq!(execute("SELECT * FROM users GROUP BY team", &provider), all);
}

#[test]
fn known_gap_parameter_metadata_loss_and_with_exception_are_not_binding() {
    let supplied = QueryParams {
        positional: vec!["18".into()],
        named: BTreeMap::from([("name".into(), "'Ada'".into())]),
    };
    assert_eq!(
        QueryParser::parse_with_params("SELECT * FROM users", &supplied)
            .unwrap()
            .params,
        QueryParams::default()
    );
    let with = QueryParser::parse_with_params(
        "WITH a AS (SELECT * FROM users) SELECT * FROM a",
        &supplied,
    )
    .unwrap();
    assert_eq!(with.params, supplied);
    assert_eq!(with.ctes.len(), 1);
    assert_eq!(with.ctes[0].query.params, QueryParams::default());
}

#[test]
fn parameter_tokens_are_rejected_before_binding_and_raw_helper_replaces_text() {
    for (token, expected) in [
        ("$1", "unsupported query character '$'"),
        (":age", "unsupported query character ':'"),
        ("@age", "unsupported query character '@'"),
    ] {
        query_error(
            QueryParser::parse(&format!("SELECT * FROM users WHERE age = {token}")),
            expected,
        );
    }
    let params = QueryParams {
        positional: vec!["7".into()],
        named: BTreeMap::from([("x".into(), "9".into())]),
    };
    assert_eq!(
        substitute_params("SELECT $1, $10, :x, @x, '$1'", &params),
        "SELECT 7, 70, 9, 9, '7'"
    );
}

#[test]
fn known_gap_trailing_tokens_are_accepted_separately_from_real_parse_errors() {
    assert_eq!(
        QueryParser::parse("SELECT * FROM users WHERE age >= 18 GARBAGE").unwrap(),
        QueryParser::parse("SELECT * FROM users WHERE age >= 18").unwrap()
    );
    query_error(
        QueryParser::parse("BOGUS users"),
        "expected SQL SELECT, DDL, PQL FIND, SHOW, or LIST statement",
    );
    query_error(
        QueryParser::parse("SHOW USERS"),
        "unsupported SHOW target: USERS",
    );
    query_error(tokenize("'open"), "unterminated string literal");
}

#[test]
fn known_gap_public_graphql_response_contains_a_plan_instead_of_executed_rows() {
    let request = GraphQLRequest {
        query: "{ users { age } }".into(),
        variables: BTreeMap::new(),
        operation_name: None,
    };
    let response = execute_graphql(&request);
    assert!(response.errors.is_empty());
    let data = response.data.unwrap();
    assert_eq!(
        data["records"],
        json!([{"collection":"users","operators":[]} ])
    );
}
