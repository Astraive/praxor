//! Legacy query entrypoints must reject the two operators they used to ignore.
use praxis::document::{Record, RecordId};
use praxis::execution::RecordProvider;
use praxis::{
    Executor, PhysicalOperator, PhysicalPlan, Planner, PraxisError, Predicate, QueryParser,
};
use std::cell::Cell;

#[derive(Default)]
struct CountingProvider {
    calls: Cell<usize>,
}

impl CountingProvider {
    fn read(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

impl RecordProvider for CountingProvider {
    fn collection(&self, _: &str) -> Vec<Record> {
        self.read();
        vec![Record::new("users", "current")]
    }
    fn get(&self, _: &RecordId) -> Option<Record> {
        self.read();
        None
    }
    fn scalar_filter(&self, _: &str, _: &Predicate) -> Option<Vec<Record>> {
        self.read();
        None
    }
    fn full_text_search(&self, _: &str, _: &str, _: &str, _: Option<usize>) -> Option<Vec<Record>> {
        self.read();
        None
    }
    fn vector_similarity(&self, _: &str, _: &str, _: usize) -> Option<Vec<Record>> {
        self.read();
        None
    }
    fn graph_connected_to(&self, _: &str, _: &str, _: usize, _: Option<&str>) -> Vec<Record> {
        self.read();
        Vec::new()
    }
}

fn assert_unsupported<T: std::fmt::Debug>(result: praxis::Result<T>, feature: &str) {
    match result {
        Err(PraxisError::Query(code)) => {
            assert_eq!(code, format!("unsupported query feature: {feature}"))
        }
        other => panic!("expected unsupported {feature}, got {other:?}"),
    }
}

#[test]
fn planner_refuses_as_of_and_group_by_instead_of_emitting_ignored_operators() {
    for (sql, feature) in [
        ("FIND users AS OF COMMIT c1", "as_of"),
        ("SELECT * FROM users GROUP BY team", "group_by"),
    ] {
        let logical = QueryParser::parse(sql).unwrap();
        assert_unsupported(Planner.plan(&logical), feature);
        assert_unsupported(Planner.explain(&logical), feature);
    }
}

#[test]
fn manually_constructed_ignored_operators_refuse_before_any_provider_read() {
    for (operator, feature) in [
        (PhysicalOperator::AsOf, "as_of"),
        (PhysicalOperator::GroupBy(vec!["team".into()]), "group_by"),
    ] {
        let provider = CountingProvider::default();
        let plan = PhysicalPlan {
            collection: "users".into(),
            operators: vec![
                PhysicalOperator::Filter(Predicate {
                    attribute: "age".into(),
                    operator: ">=".into(),
                    value: "18".into(),
                }),
                operator,
            ],
        };
        assert_unsupported(Executor.execute(&provider, &plan), feature);
        assert_eq!(
            provider.calls.get(),
            0,
            "provider read before {feature} refusal"
        );
    }
}
