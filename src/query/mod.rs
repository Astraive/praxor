//! Query layer for praxis: SQL/PQL parser, logical plans, and query model definitions.
//!
//! The parser supports:
//! - SQL: SELECT, INSERT, UPDATE, DELETE, CREATE/ALTER/DROP COLLECTION, EXPLAIN
//! - PQL: FIND, WATCH, SIMILAR TO, TRAVERSE, RANK BY, AS OF

mod compile;
pub mod graph;
pub mod hybrid;
pub mod kv;
pub mod parser;
pub mod search;
pub mod sql;
pub mod tokenizer;
pub mod vector;

// Re-export parser types for convenience
pub use parser::{
    AlterAction, AsOfClause, AttributeDdl, BooleanExpression, CteDefinition, DdlPlan,
    FullTextClause, JoinClause, LogicalPlan, MutationPlan, OrderClause, Predicate, QueryLanguage,
    QueryOperation, QueryParams, QueryParser, TraversalClause, VectorClause, WindowFunction,
    parse_window_functions, substitute_params,
};
pub use tokenizer::{Token, tokenize};

// Legacy query model types (used by other praxis modules)
use crate::kernel::ExecutionMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryModel {
    Kv,
    Sql,
    Graph,
    Vector,
    Search,
    Hybrid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlan {
    pub model: QueryModel,
    pub execution_mode: ExecutionMode,
    pub index: &'static str,
    pub cursor: &'static str,
    pub cost_units: u64,
}

pub fn plan(model: QueryModel) -> QueryPlan {
    match model {
        QueryModel::Kv => QueryPlan {
            model,
            execution_mode: ExecutionMode::Specialized,
            index: "lsm",
            cursor: "kv_point_or_range",
            cost_units: 10,
        },
        QueryModel::Sql => QueryPlan {
            model,
            execution_mode: ExecutionMode::Specialized,
            index: "btree",
            cursor: "relational_scan",
            cost_units: 35,
        },
        QueryModel::Graph => QueryPlan {
            model,
            execution_mode: ExecutionMode::Specialized,
            index: "adjacency",
            cursor: "graph_traversal",
            cost_units: 45,
        },
        QueryModel::Vector => QueryPlan {
            model,
            execution_mode: ExecutionMode::Specialized,
            index: "hnsw_or_ivf",
            cursor: "ann_hits",
            cost_units: 55,
        },
        QueryModel::Search => QueryPlan {
            model,
            execution_mode: ExecutionMode::Specialized,
            index: "inverted",
            cursor: "postings",
            cost_units: 30,
        },
        QueryModel::Hybrid => QueryPlan {
            model,
            execution_mode: ExecutionMode::Hybrid,
            index: "multi_index",
            cursor: "hybrid_bitmap_join",
            cost_units: 100,
        },
    }
}
