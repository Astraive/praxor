use crate::config::{
    CompactionStrategy, Compression, DEFAULT_LARGE_VALUE_THRESHOLD,
    DEFAULT_MEMTABLE_FLUSH_THRESHOLD_BYTES, MemTableKind, PersistedEngineConfig, PraxisConfig,
};
use crate::errors::{PraxisError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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
    #[serde(default)]
    pub column_family_generations: BTreeMap<String, ColumnFamilyGeneration>,
    #[serde(default = "default_next_column_family_generation")]
    pub next_column_family_generation: u64,
    pub segments: Vec<SegmentMetadata>,
}

impl Manifest {
    pub fn fresh(config: &PraxisConfig) -> Self {
        Self {
            format_version: 2,
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
            column_family_generations: BTreeMap::from([(
                "default".to_string(),
                ColumnFamilyGeneration::default(),
            )]),
            next_column_family_generation: 1,
            segments: Vec::new(),
        }
    }

    pub(crate) fn decode(bytes: &[u8], source: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Header {
            format_version: u32,
            column_family_generations: Option<serde::de::IgnoredAny>,
            next_column_family_generation: Option<serde::de::IgnoredAny>,
        }
        // A generic toml::Value would incorrectly reject u64 Bloom bits and
        // configurations above i64::MAX. Keep the complete model typed.
        let text = String::from_utf8_lossy(bytes);
        let header: Header = toml::from_str(&text)?;
        let corrupt = |reason: &str| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: reason.to_string(),
        };
        if !matches!(header.format_version, 1 | 2) {
            return Err(corrupt("unsupported manifest format version"));
        }
        // Defaults exist solely for v1; every v2 file carries complete metadata.
        if header.format_version == 2
            && (header.column_family_generations.is_none()
                || header.next_column_family_generation.is_none())
        {
            return Err(corrupt(
                "v2 manifest is missing column-family generation metadata",
            ));
        }
        let mut manifest: Self = toml::from_str(&text)?;
        manifest.validate_and_upgrade(source)?;
        Ok(manifest)
    }

    pub(crate) fn validate_and_upgrade(&mut self, source: &Path) -> Result<()> {
        let corrupt = |reason: &str| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: reason.to_string(),
        };
        if !matches!(self.format_version, 1 | 2) {
            return Err(corrupt("unsupported manifest format version"));
        }
        if self.format_version == 1 {
            if !self.column_family_generations.is_empty() || self.next_column_family_generation != 1
            {
                return Err(corrupt(
                    "v1 manifest unexpectedly contains incarnation metadata",
                ));
            }
            if self.column_families.is_empty() {
                self.column_families.push(ColumnFamilyDescriptor::default());
            }
            self.column_family_generations = self
                .column_families
                .iter()
                .map(|family| (family.name.clone(), ColumnFamilyGeneration::default()))
                .collect();
            self.format_version = 2;
        }
        let mut names = BTreeSet::new();
        for family in &self.column_families {
            if !names.insert(family.name.as_str()) {
                return Err(corrupt("duplicate column-family name"));
            }
        }
        if !names.contains("default") {
            return Err(corrupt("manifest is missing the default column family"));
        }
        if names.len() != self.column_family_generations.len()
            || self
                .column_family_generations
                .keys()
                .any(|name| !names.contains(name.as_str()))
        {
            return Err(corrupt(
                "column-family generation coverage does not match active families",
            ));
        }
        let mut nonzero_ids = BTreeSet::new();
        let watermark = self.last_sequence.max(self.flushed_sequence);
        for (name, generation) in &self.column_family_generations {
            if name == "default" && *generation != ColumnFamilyGeneration::default() {
                return Err(corrupt(
                    "default column family must retain legacy generation zero",
                ));
            }
            if generation.id == 0 && generation.visible_after_sequence != 0 {
                return Err(corrupt("legacy generation must have a zero sequence floor"));
            }
            if generation.visible_after_sequence > watermark {
                return Err(corrupt(
                    "column-family floor exceeds persisted sequence watermark",
                ));
            }
            if generation.id != 0 && !nonzero_ids.insert(generation.id) {
                return Err(corrupt("duplicate column-family incarnation ID"));
            }
            if generation.id >= self.next_column_family_generation {
                return Err(corrupt(
                    "column-family generation counter does not exceed allocated IDs",
                ));
            }
        }
        if self.next_column_family_generation == 0 {
            return Err(corrupt("column-family generation counter must be positive"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ColumnFamilyGeneration {
    pub id: u64,
    pub visible_after_sequence: u64,
}

impl ColumnFamilyGeneration {
    pub(crate) fn includes(&self, sequence: u64) -> bool {
        self.id == 0 || sequence > self.visible_after_sequence
    }
}

pub(crate) fn default_next_column_family_generation() -> u64 {
    1
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
