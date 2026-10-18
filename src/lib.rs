//! praxis: primitive-first universal storage kernel with a single-copy guarantee.
//!
//! Every piece of data is stored exactly once in the primary data store.
//! All indexes (LSM, B-tree, Adjacency, HNSW) hold only pointer-to-RecordId mappings.
//!
//! The stable storage-kernel surface is `config`, `errors`, `kernel`, `store`, `index`,
//! `storage`, `transactions`, `api`, `sdk`, and `slog`. Other public modules are still
//! exported for the current beta/test harness and should be treated as experimental
//! internals until the compatibility layer is retired.

pub mod accel;
pub mod api;
pub mod bench;
pub mod bench_advanced;
pub mod cache;
pub mod catalog;
pub mod cli;
pub mod config;
pub mod core_records;
pub mod datatype;
pub mod disk;
pub mod document;
pub mod engine;
pub mod errors;
pub mod events;
pub mod execution;
pub mod formats;
pub mod identity;
pub mod index;
pub mod io;
pub mod kernel;
pub mod layout;
pub mod maintenance;
pub mod manifest;
pub mod memory;
pub mod metrics;
pub mod page;
pub mod planner;
pub mod query;
pub mod record;
pub mod recovery;
pub mod replication;
pub mod sdk;
pub mod segments;
pub mod server;
pub mod slog;
pub mod storage;
pub mod store;
pub mod transactions;
pub mod types;
pub mod values;
pub mod wal;
mod writer_lease;

pub use catalog::schema::{
    AttributeSchema, AttributeType, Catalog, CollectionSchema, DistanceMetric, StorageClass,
};
pub use config::{CompactionStrategy, Compression, PraxisConfig, WalSyncPolicy};
pub use core_records::{
    CoreDatabase, CoreRecordSnapshot, CoreRecordStore, MappingDescriptor, RecordAuthorityOptions,
    RecordHistoryReclaimReport,
};
pub use document::{Edge, Record, RecordDirectory};
pub use engine::PraxisEngine;
pub use engine::r#async::AsyncPraxisEngine;
pub use errors::{PraxisError, Result};
pub use execution::Executor;
pub use identity::{Aid, Cid, Did, Eid, Fid, FieldId, Pid, RelativeVid, Rid, Sid, Vid, VidContext};
pub use index::{
    AdjacencyIndex, BTreeIndex, BitmapIndex, BoundingBox, HnswIndex, InvertedIndex, IvfFlatIndex,
    PackedRTreeIndex, TimePartition,
};
pub use index::{
    Bm25Index, GraphIndex, HybridWeights, RetrievalEngine, ScalarIndex, VectorIndex, VectorStrategy,
};
pub use index::{IndexPlugin, IndexSnapshotCapability};
pub use maintenance::{JobPriority, MaintenanceRuntimeConfig, RuntimeLaneConfig};
pub use planner::{PhysicalOperator, PhysicalPlan, Planner, PlannerStats};
pub use query::{
    AsOfClause, BooleanExpression, DdlPlan, FullTextClause, LogicalPlan, MutationPlan, Predicate,
    QueryLanguage, QueryOperation, QueryParser, TraversalClause, VectorClause,
};
pub use query::{
    BoundSelect, ByteSpan, CompileInput, CompiledStatement, ExplainV1, ParameterValue,
    PredicateShapeOp, ProjectedRow, QueryCatalogAuthority, QueryCatalogView, QueryCompileError,
    TypedParameters, compile, execute_in_memory,
};
pub use storage::lsm::LsmIndex;
pub use store::RecordId;
pub use transactions::WriteBatch;
pub use types::ColumnFamily;
