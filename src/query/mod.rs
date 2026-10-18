//! Query layer for praxis: the bounded Q1 compiler and experimental legacy plans.
//!
//! `compile` accepts one read-only SQL SELECT or EXPLAIN SELECT over one collection,
//! with scalar projection and typed boolean predicates. It uses a detached,
//! process-local catalog view; `execute_in_memory` scans only caller-supplied
//! immutable document records. It does not provide a persisted catalog generation,
//! a row/catalog read snapshot, a storage provider, or a product query route.
//! Q2 needs a joint row/catalog view and Q3 needs a persisted catalog protocol.
//!
//! The older `QueryParser`, `Planner`, and `Executor` surfaces remain experimental.
//! Their broader SQL/PQL syntax is not a Q1 execution capability; only their
//! previously ignored AS OF and GROUP BY operators have targeted preflight refusal.

mod compile;
mod fixture_v1;
pub mod graph;
pub mod hybrid;
pub mod kv;
pub mod parser;
pub mod search;
pub mod sql;
pub mod tokenizer;
pub mod vector;

pub use compile::{
    BoundSelect, ByteSpan, CompileInput, CompiledStatement, ExplainV1, ParameterValue,
    PredicateShapeOp, ProjectedRow, QueryCatalogAuthority, QueryCatalogView, QueryCompileError,
    TypedParameters, compile, execute_in_memory,
};

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
