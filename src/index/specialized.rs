use crate::kernel::{
    DurableFormatDescriptor, EngineCapability, PhysicalEngine, PhysicalEngineKind,
    StorageOperationMetrics,
};
use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq)]
pub struct SpecializedEngineContract {
    pub engine: PhysicalEngine,
    pub format: DurableFormatDescriptor,
    pub manifest_tracked: bool,
    pub metrics: StorageOperationMetrics,
}

impl SpecializedEngineContract {
    pub fn pointer_engine(
        name: impl Into<String>,
        kind: PhysicalEngineKind,
        capabilities: Vec<EngineCapability>,
        structure: &'static str,
    ) -> Self {
        Self {
            engine: PhysicalEngine::pointer_index(name, kind, capabilities),
            format: DurableFormatDescriptor {
                structure,
                format_version: 1,
                checksum: Cow::Borrowed("crc32c"),
                forward_compatible: true,
                independently_recoverable: true,
            },
            manifest_tracked: true,
            metrics: StorageOperationMetrics::default(),
        }
    }

    pub fn shipping_defaults() -> Vec<Self> {
        vec![
            Self::pointer_engine(
                "art",
                PhysicalEngineKind::Art,
                vec![EngineCapability::PointLookup, EngineCapability::PrefixScan],
                "art_index",
            ),
            Self::pointer_engine(
                "hash",
                PhysicalEngineKind::Hash,
                vec![EngineCapability::PointLookup],
                "hash_index",
            ),
            Self::pointer_engine(
                "search",
                PhysicalEngineKind::Inverted,
                vec![
                    EngineCapability::FullTextSearch,
                    EngineCapability::FilteredScan,
                ],
                "inverted_segments",
            ),
            Self::pointer_engine(
                "graph",
                PhysicalEngineKind::GraphAdjacency,
                vec![EngineCapability::GraphTraversal],
                "graph_adjacency_pages",
            ),
            Self::pointer_engine(
                "vector",
                PhysicalEngineKind::Hnsw,
                vec![
                    EngineCapability::VectorSearch,
                    EngineCapability::FilteredScan,
                ],
                "vector_graph",
            ),
            Self::pointer_engine(
                "columnar",
                PhysicalEngineKind::ColumnarProjection,
                vec![
                    EngineCapability::ColumnarScan,
                    EngineCapability::FilteredScan,
                ],
                "columnar_projection",
            ),
            Self::pointer_engine(
                "wide_column",
                PhysicalEngineKind::WideColumn,
                vec![EngineCapability::RangeScan, EngineCapability::PrefixScan],
                "wide_column_sstable",
            ),
            Self::pointer_engine(
                "time_series",
                PhysicalEngineKind::TimeSeries,
                vec![EngineCapability::RangeScan, EngineCapability::ColumnarScan],
                "time_series_partition",
            ),
            Self::pointer_engine(
                "log_stream",
                PhysicalEngineKind::LogStream,
                vec![EngineCapability::AppendOnlyLog],
                "log_stream_segment",
            ),
        ]
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpecializedEngineRegistry {
    contracts: Vec<SpecializedEngineContract>,
}

impl SpecializedEngineRegistry {
    pub fn shipping_defaults() -> Self {
        Self {
            contracts: SpecializedEngineContract::shipping_defaults(),
        }
    }

    pub fn contracts(&self) -> &[SpecializedEngineContract] {
        &self.contracts
    }

    pub fn all_pointer_oriented(&self) -> bool {
        self.contracts
            .iter()
            .all(|contract| contract.engine.pointer_oriented && contract.manifest_tracked)
    }
}
