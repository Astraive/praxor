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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_authority: Option<crate::core_records::RecordAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_authority: Option<crate::core_catalog::CatalogAuthorityV1>,
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
            record_authority: None,
            catalog_authority: None,
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
            record_authority: Option<serde::de::IgnoredAny>,
            catalog_authority: Option<serde::de::IgnoredAny>,
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
        if header.format_version == 4 {
            let strict_text = std::str::from_utf8(bytes)
                .map_err(|_| corrupt("v4 manifest contains invalid UTF-8"))?;
            let wire: V4ManifestWire = toml::from_str(strict_text)?;
            let mut manifest: Self = wire.into();
            manifest.validate_and_upgrade(source)?;
            return Ok(manifest);
        }
        if !matches!(header.format_version, 1..=3) {
            return Err(corrupt("unsupported manifest format version"));
        }
        if header.catalog_authority.is_some() {
            return Err(corrupt(
                "legacy manifest contains catalog authority metadata",
            ));
        }
        if header.format_version < 3 && header.record_authority.is_some() {
            return Err(corrupt(
                "legacy manifest contains record authority metadata",
            ));
        }
        if header.format_version == 3 && header.record_authority.is_none() {
            return Err(corrupt("v3 manifest is missing record authority metadata"));
        }
        // Defaults exist solely for v1; later files carry complete metadata.
        if header.format_version >= 2
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
        if !matches!(self.format_version, 1..=4) {
            return Err(corrupt("unsupported manifest format version"));
        }
        if self.format_version < 4 && self.catalog_authority.is_some() {
            return Err(corrupt(
                "legacy manifest contains catalog authority metadata",
            ));
        }
        match (self.format_version, &self.record_authority) {
            (1 | 2, Some(_)) => {
                return Err(corrupt(
                    "legacy manifest contains record authority metadata",
                ));
            }
            (3, None) => return Err(corrupt("v3 manifest is missing record authority metadata")),
            (4, None) => return Err(corrupt("v4 manifest is missing record authority metadata")),
            _ => {}
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
        match self.format_version {
            3 => self
                .record_authority
                .as_ref()
                .expect("checked above")
                .validate(self, source)?,
            4 => self.validate_v4(source)?,
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn validate_v4(&self, source: &Path) -> Result<()> {
        let corrupt = |reason: &str| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: reason.to_string(),
        };
        let record = self
            .record_authority
            .as_ref()
            .ok_or_else(|| corrupt("v4 manifest is missing record authority metadata"))?;
        let catalog = self
            .catalog_authority
            .as_ref()
            .ok_or_else(|| corrupt("v4 manifest is missing catalog authority metadata"))?;
        record.validate_binding(source)?;
        catalog.validate(record, source)?;
        if self.last_sequence < record.bootstrap_sequence
            || self.flushed_sequence > self.last_sequence
            || self.next_column_family_generation < 6
        {
            return Err(corrupt(
                "v4 manifest has inconsistent sequence or generation counters",
            ));
        }
        for binding in &record.roles {
            // validate_binding has already checked the exact four generations.
            let index = usize::try_from(binding.generation - 1)
                .map_err(|_| corrupt("invalid record binding generation"))?;
            let expected = record.descriptor(index, self);
            if self
                .column_families
                .iter()
                .find(|cf| cf.name == binding.column_family)
                != Some(&expected)
                || self.column_family_generations.get(&binding.column_family)
                    != Some(&ColumnFamilyGeneration {
                        id: binding.generation,
                        visible_after_sequence: 0,
                    })
            {
                return Err(corrupt("record role descriptor/incarnation mismatch"));
            }
        }
        let catalog_name = &catalog.binding.column_family;
        if self
            .column_families
            .iter()
            .find(|cf| cf.name == *catalog_name)
            != Some(&crate::core_catalog::CatalogAuthorityV1::descriptor(self))
            || self.column_family_generations.get(catalog_name)
                != Some(&ColumnFamilyGeneration {
                    id: 5,
                    visible_after_sequence: 0,
                })
        {
            return Err(corrupt("catalog descriptor/incarnation mismatch"));
        }
        for family in &self.column_families {
            if family.name == "default"
                || family.name == *catalog_name
                || record
                    .roles
                    .iter()
                    .any(|binding| binding.column_family == family.name)
            {
                continue;
            }
            if family.name.starts_with("__praxor_record_") {
                return Err(corrupt("unbound reserved record column family"));
            }
            let generation = self
                .column_family_generations
                .get(&family.name)
                .ok_or_else(|| corrupt("v4 user family lacks generation metadata"))?;
            if generation.id < 6 || generation.visible_after_sequence < 1 {
                return Err(corrupt("v4 user family predates catalog authority"));
            }
        }
        Ok(())
    }

    pub(crate) fn fresh_records(
        config: &PraxisConfig,
        authority: crate::core_records::RecordAuthority,
    ) -> Self {
        let mut manifest = Self::fresh(config);
        manifest.format_version = 3;
        manifest.last_sequence = 1;
        manifest.next_column_family_generation = 5;
        for index in 0..4 {
            let descriptor = authority.descriptor(index, &manifest);
            manifest.column_family_generations.insert(
                descriptor.name.clone(),
                ColumnFamilyGeneration {
                    id: index as u64 + 1,
                    visible_after_sequence: 0,
                },
            );
            manifest.column_families.push(descriptor);
        }
        manifest.record_authority = Some(authority);
        manifest
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

// Format 4 is a separate wire vocabulary. The shared public model retains
// the legacy parser's tolerance; this wire rejects unknown v4 metadata at
// every manifest, descriptor, options and generation level.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V4ManifestWire {
    format_version: u32,
    record_authority: crate::core_records::RecordAuthority,
    catalog_authority: crate::core_catalog::CatalogAuthorityV1,
    #[serde(default)]
    effective_config: PersistedEngineConfig,
    #[serde(default = "default_active_wal_id")]
    active_wal_id: u64,
    #[serde(default = "default_next_wal_id")]
    next_wal_id: u64,
    last_sequence: u64,
    #[serde(default)]
    flushed_sequence: u64,
    #[serde(default)]
    flushed_wal_id: u64,
    next_segment_id: u64,
    latest_checkpoint: Option<CheckpointMetadata>,
    #[serde(default)]
    compaction_jobs: Vec<CompactionJobState>,
    #[serde(default)]
    tier_migrations: Vec<crate::storage::TierMigrationRecord>,
    column_families: Vec<V4DescriptorWire>,
    column_family_generations: BTreeMap<String, V4GenerationWire>,
    next_column_family_generation: u64,
    segments: Vec<SegmentMetadata>,
}

impl From<V4ManifestWire> for Manifest {
    fn from(wire: V4ManifestWire) -> Self {
        Self {
            format_version: wire.format_version,
            record_authority: Some(wire.record_authority),
            catalog_authority: Some(wire.catalog_authority),
            effective_config: wire.effective_config,
            active_wal_id: wire.active_wal_id,
            next_wal_id: wire.next_wal_id,
            last_sequence: wire.last_sequence,
            flushed_sequence: wire.flushed_sequence,
            flushed_wal_id: wire.flushed_wal_id,
            next_segment_id: wire.next_segment_id,
            latest_checkpoint: wire.latest_checkpoint,
            compaction_jobs: wire.compaction_jobs,
            tier_migrations: wire.tier_migrations,
            column_families: wire.column_families.into_iter().map(Into::into).collect(),
            column_family_generations: wire
                .column_family_generations
                .into_iter()
                .map(|(name, generation)| (name, generation.into()))
                .collect(),
            next_column_family_generation: wire.next_column_family_generation,
            segments: wire.segments,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DescriptorWire {
    name: String,
    write_buffer_size_bytes: usize,
    large_value_threshold_bytes: usize,
    bloom_enabled: bool,
    #[serde(default)]
    options: Option<V4OptionsWire>,
}

impl From<V4DescriptorWire> for ColumnFamilyDescriptor {
    fn from(wire: V4DescriptorWire) -> Self {
        Self {
            name: wire.name,
            write_buffer_size_bytes: wire.write_buffer_size_bytes,
            large_value_threshold_bytes: wire.large_value_threshold_bytes,
            bloom_enabled: wire.bloom_enabled,
            options: wire.options.map(Into::into).unwrap_or_default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V4OptionsWire {
    memtable_kind: MemTableKind,
    compaction_strategy: CompactionStrategy,
    compression_override: Option<Compression>,
    ttl_seconds: Option<u64>,
    prefix_extractor_len: Option<usize>,
    cache_partition_percent: Option<u8>,
    merge_operator: Option<String>,
}

impl From<V4OptionsWire> for ColumnFamilyOptions {
    fn from(wire: V4OptionsWire) -> Self {
        Self {
            memtable_kind: wire.memtable_kind,
            compaction_strategy: wire.compaction_strategy,
            compression_override: wire.compression_override,
            ttl_seconds: wire.ttl_seconds,
            prefix_extractor_len: wire.prefix_extractor_len,
            cache_partition_percent: wire.cache_partition_percent,
            merge_operator: wire.merge_operator,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GenerationWire {
    id: u64,
    visible_after_sequence: u64,
}

impl From<V4GenerationWire> for ColumnFamilyGeneration {
    fn from(wire: V4GenerationWire) -> Self {
        Self {
            id: wire.id,
            visible_after_sequence: wire.visible_after_sequence,
        }
    }
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

#[cfg(test)]
#[path = "record_authority_tests.rs"]
mod record_authority_tests;

#[cfg(test)]
#[path = "v4_catalog_tests.rs"]
mod v4_catalog_tests;
