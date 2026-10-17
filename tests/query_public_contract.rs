//! Public reachability checks for the current experimental query surface.
//! These imports do not promote these modules to stable API.
use praxis::api::graphql::{GraphQLError, GraphQLRequest, GraphQLResponse, execute_graphql};
use praxis::api::server::{RestServerConfig, serve_rest};
use praxis::catalog::CatalogStore;
use praxis::document::RecordId as DocumentRecordId;
use praxis::execution::{
    RecordProvider, RecordStore, matches_boolean_expression, matches_predicate,
};
use praxis::planner::{AggregateExpr, CostedOperator, CostedPlan};
use praxis::query::sql::{SqlCostMetadata, SqlIndexKind, SqlIndexSpec, SqlQuery};
use praxis::query::{
    AlterAction, AttributeDdl, CteDefinition, JoinClause, OrderClause, QueryModel, QueryParams,
    QueryPlan, Token, WindowFunction, parse_window_functions, plan, substitute_params, tokenize,
};
use praxis::{
    AsOfClause, AttributeSchema, AttributeType, BooleanExpression, Catalog, CollectionSchema,
    DdlPlan, DistanceMetric, Executor, FullTextClause, LogicalPlan, MutationPlan, PhysicalOperator,
    PhysicalPlan, Planner, PlannerStats, PraxisConfig, PraxisEngine, Predicate, QueryLanguage,
    QueryOperation, QueryParser, RecordId as CoreRecordId, StorageClass, TraversalClause,
    VectorClause,
};
use serde::{Serialize, de::DeserializeOwned};
use std::any::TypeId;

#[test]
fn current_root_submodule_exports_and_function_signatures_are_reachable() {
    macro_rules! same_type {
        ($root:ty, $module:ty) => {
            assert_eq!(TypeId::of::<$root>(), TypeId::of::<$module>());
        };
    }
    same_type!(LogicalPlan, praxis::query::parser::LogicalPlan);
    same_type!(QueryParser, praxis::query::QueryParser);
    same_type!(PhysicalPlan, praxis::planner::plan::PhysicalPlan);
    same_type!(Planner, praxis::planner::Planner);
    same_type!(Executor, praxis::execution::executor::Executor);
    same_type!(Catalog, praxis::catalog::schema::Catalog);
    let _: fn(&str) -> praxis::Result<LogicalPlan> = QueryParser::parse;
    let _: fn(&str, &QueryParams) -> praxis::Result<LogicalPlan> = QueryParser::parse_with_params;
    let _: fn(&Planner, &LogicalPlan) -> praxis::Result<PhysicalPlan> = Planner::plan;
    let _: fn(&Planner, &LogicalPlan) -> praxis::Result<String> = Planner::explain;
    let _: fn(&Planner, &LogicalPlan, &PlannerStats) -> praxis::Result<CostedPlan> =
        Planner::plan_with_stats;
    let _: fn(&str) -> praxis::Result<Vec<Token>> = tokenize;
    let _: fn(&[Token]) -> Vec<WindowFunction> = parse_window_functions;
    let _: fn(&str, &QueryParams) -> String = substitute_params;
    let _: fn(QueryModel) -> QueryPlan = plan;
    let _: fn(&praxis::Record, &Predicate) -> bool = matches_predicate;
    let _: fn(&praxis::Record, &BooleanExpression) -> bool = matches_boolean_expression;
    let _: fn(&mut Catalog, &str, &[AlterAction]) -> praxis::Result<()> = Catalog::alter_collection;
    let _: fn(&GraphQLRequest) -> GraphQLResponse = execute_graphql;
    let _: Option<&dyn RecordProvider> = None;
    let _: Option<&dyn RecordStore> = None;
    let _: Option<(PraxisConfig, PraxisEngine, RestServerConfig)> = None;
    let _public_rest_entrypoint = serve_rest;
    // Legacy helpers remain reachable without acquiring a new serde contract.
    let _: Option<(SqlQuery, SqlIndexKind, SqlIndexSpec, SqlCostMetadata)> = None;
}

#[test]
fn current_serde_models_are_public_without_requiring_serde_on_legacy_helpers() {
    fn model<T: Serialize + DeserializeOwned>() {}
    macro_rules! models { ($($kind:ty),* $(,)?) => { $(model::<$kind>();)* }; }
    models!(
        LogicalPlan,
        QueryLanguage,
        QueryOperation,
        Predicate,
        BooleanExpression,
        AsOfClause,
        MutationPlan,
        DdlPlan,
        FullTextClause,
        VectorClause,
        TraversalClause,
        AlterAction,
        AttributeDdl,
        CteDefinition,
        JoinClause,
        OrderClause,
        QueryParams,
        WindowFunction,
        PhysicalPlan,
        PhysicalOperator,
        AggregateExpr,
        CostedOperator,
        CostedPlan,
        PlannerStats,
        Catalog,
        CollectionSchema,
        AttributeSchema,
        AttributeType,
        DistanceMetric,
        StorageClass,
        GraphQLRequest,
        GraphQLResponse,
        GraphQLError,
    );
}

#[test]
fn document_core_and_page_identifiers_and_catalog_owners_are_distinct() {
    let document = DocumentRecordId::new("users", "u1");
    let core = CoreRecordId(1);
    let page = praxis::identity::Rid(1);
    assert_eq!(document.collection, "users");
    assert_eq!(core.0, 1);
    assert_eq!(page.0, 1);
    assert_ne!(
        TypeId::of::<DocumentRecordId>(),
        TypeId::of::<CoreRecordId>()
    );
    assert_ne!(
        TypeId::of::<CoreRecordId>(),
        TypeId::of::<praxis::identity::Rid>()
    );
    assert_ne!(
        TypeId::of::<DocumentRecordId>(),
        TypeId::of::<praxis::identity::Rid>()
    );
    assert_ne!(TypeId::of::<Catalog>(), TypeId::of::<CatalogStore>());
}
