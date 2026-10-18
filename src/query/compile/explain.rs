//! Stable, redacted shape for the process-local Q1 compiler. No row evaluation.
use super::binder::{BoundPredicateOp, BoundSelect};
use super::syntax::CompareOp;
use serde::Serialize;

/// Version 1 process-local explanation. It contains no bound values or row data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExplainV1 {
    pub version: u8,
    pub catalog_scope: &'static str,
    pub revision: u64,
    pub collection: String,
    pub projection: Vec<String>,
    /// Postfix operations preserve the exact predicate shape without recursive JSON.
    pub predicate_shape: Option<Vec<PredicateShapeOp>>,
    pub required_capabilities: Vec<&'static str>,
    pub execution: &'static str,
}

/// Value-free postfix predicate operation used by `ExplainV1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PredicateShapeOp {
    Compare {
        field: String,
        operator: &'static str,
    },
    IsNull {
        field: String,
        negated: bool,
    },
    Not,
    And,
    Or,
}

fn comparison_symbol(operator: CompareOp) -> &'static str {
    match operator {
        CompareOp::Eq => "=",
        CompareOp::NotEq => "<>",
        CompareOp::Lt => "<",
        CompareOp::Lte => "<=",
        CompareOp::Gt => ">",
        CompareOp::Gte => ">=",
    }
}

impl ExplainV1 {
    pub(super) fn from_bound(select: &BoundSelect) -> Self {
        let predicate_shape = select.predicate.as_ref().map(|operations| {
            operations
                .iter()
                .map(|operation| match operation {
                    BoundPredicateOp::Compare {
                        field, operator, ..
                    } => PredicateShapeOp::Compare {
                        field: field.name.clone(),
                        operator: comparison_symbol(*operator),
                    },
                    BoundPredicateOp::IsNull { field, negated } => PredicateShapeOp::IsNull {
                        field: field.name.clone(),
                        negated: *negated,
                    },
                    BoundPredicateOp::Not => PredicateShapeOp::Not,
                    BoundPredicateOp::And => PredicateShapeOp::And,
                    BoundPredicateOp::Or => PredicateShapeOp::Or,
                })
                .collect()
        });
        Self {
            version: 1,
            catalog_scope: "process",
            revision: select.revision,
            collection: select.collection.clone(),
            projection: select
                .projection
                .iter()
                .map(|field| field.name.clone())
                .collect(),
            predicate_shape,
            required_capabilities: vec!["collection_scan"],
            execution: "not_executed",
        }
    }
}
