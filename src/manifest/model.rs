use crate::config::{
    CompactionStrategy, Compression, DEFAULT_LARGE_VALUE_THRESHOLD,
    DEFAULT_MEMTABLE_FLUSH_THRESHOLD_BYTES, MemTableKind, PersistedEngineConfig, PraxisConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    #[serde(default)]
    pub effective_config: PersistedEngineConfig,
    #[serde(default = "default_active_wal_id")]
    pub active_wal_id: u64,
    #[serde(default = "default_next_wal_id")]
    pub next_wal_id: u64,
    pub last_sequence: u64,
    /// WAL records through this sequence are covered by installed segments.
    #[serde(default)]
    pub flushed_sequence: u64,
    /// Only WAL files through this id may be reclaimed after installation.
    #[serde(default)]
    pub flushed_wal_id: u64,
    pub next_segment_id: u64,
    pub latest_checkpoint: Option<CheckpointMetadata>,
    #[serde(default)]
    pub compaction_jobs: Vec<CompactionJobState>,
    #[serde(default)]
    pub tier_migrations: Vec<crate::storage::TierMigrationRecord>,
    pub column_families: Vec<ColumnFamilyDescriptor>,
    pub segments: Vec<SegmentMetadata>,
}

impl Manifest {
    pub fn fresh(config: &PraxisConfig) -> Self {
        Self {
            format_version: 1,
            effective_config: config.persisted(),
            active_wal_id: 1,
            next_wal_id: 2,
            last_sequence: 0,
            flushed_sequence: 0,
            flushed_wal_id: 0,
            next_segment_id: 1,
            latest_checkpoint: None,
            compaction_jobs: Vec::new(),
            tier_migrations: Vec::new(),
            column_families: vec![ColumnFamilyDescriptor {
                options: ColumnFamilyOptions {
                    memtable_kind: config.default_memtable_kind,
                    compaction_strategy: config.default_compaction_strategy,
                    ..ColumnFamilyOptions::default()
                },
                ..ColumnFamilyDescriptor::default()
            }],
            segments: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactionJobState {
    pub id: u64,
    pub strategy: CompactionStrategy,
    pub status: CompactionJobStatus,
    pub source_segment_ids: Vec<u64>,
    pub output_segment_id: Option<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompactionJobStatus {
    Planned,
    Running,
    Installed,
    Aborted,
}

fn default_active_wal_id() -> u64 {
    1
}

fn default_next_wal_id() -> u64 {
    2
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SegmentMetadata {
    pub id: u64,
    pub level: u32,
    pub path: String,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub entries: u64,
    pub bloom_filter: crate::segments::BloomFilter,
    #[serde(default)]
    pub partitioned_bloom_filter: Option<crate::segments::PartitionedBloomFilter>,
    pub file_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    pub id: u64,
    pub path: String,
    pub sequence: u64,
    pub segment_count: u64,
    pub file_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ColumnFamilyDescriptor {
    pub name: String,
    pub write_buffer_size_bytes: usize,
    pub large_value_threshold_bytes: usize,
    pub bloom_enabled: bool,
    #[serde(default)]
    pub options: ColumnFamilyOptions,
}

impl Default for ColumnFamilyDescriptor {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            write_buffer_size_bytes: DEFAULT_MEMTABLE_FLUSH_THRESHOLD_BYTES,
            large_value_threshold_bytes: DEFAULT_LARGE_VALUE_THRESHOLD,
            bloom_enabled: true,
            options: ColumnFamilyOptions::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ColumnFamilyOptions {
    pub memtable_kind: MemTableKind,
    pub compaction_strategy: CompactionStrategy,
    pub compression_override: Option<Compression>,
    pub ttl_seconds: Option<u64>,
    pub prefix_extractor_len: Option<usize>,
    pub cache_partition_percent: Option<u8>,
    pub merge_operator: Option<String>,
}

impl Default for ColumnFamilyOptions {
    fn default() -> Self {
        Self {
            memtable_kind: MemTableKind::SkipList,
            compaction_strategy: CompactionStrategy::Leveled,
            compression_override: None,
            ttl_seconds: None,
            prefix_extractor_len: None,
            cache_partition_percent: None,
            merge_operator: None,
        }
    }
}
