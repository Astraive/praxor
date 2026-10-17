use crate::errors::{PraxisError, Result};
use crate::index::IndexStorageLayout;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelInvariant {
    CanonicalValuesSingleCopy,
    PointerOrientedIndexes,
    WalBeforeVisibility,
    DurableStructuresVersionedChecksummedRecoverable,
    ReadsDoNotBlockWrites,
    DeterministicCrashRecovery,
    ForwardCompatibleFormats,
    SnapshotSafeCompaction,
    ExplicitMemoryOwnership,
    ManifestTrackedDurability,
    MeasurableStorageOperations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalValuePolicy {
    pub canonical_values_single_copy: bool,
    pub allow_replicas: bool,
    pub allow_snapshots: bool,
    pub allow_backups: bool,
    pub allow_erasure_redundancy: bool,
    pub allow_lossy_summaries: bool,
}

impl CanonicalValuePolicy {
    pub const STRICT: Self = Self {
        canonical_values_single_copy: true,
        allow_replicas: true,
        allow_snapshots: true,
        allow_backups: true,
        allow_erasure_redundancy: true,
        allow_lossy_summaries: true,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFormatDescriptor {
    pub structure: &'static str,
    pub format_version: u16,
    pub checksum: Cow<'static, str>,
    pub forward_compatible: bool,
    pub independently_recoverable: bool,
}

impl DurableFormatDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.format_version == 0 {
            return Err(PraxisError::InvalidConfig(format!(
                "{} has no durable format version",
                self.structure
            )));
        }
        if self.checksum.is_empty() {
            return Err(PraxisError::InvalidConfig(format!(
                "{} has no durable checksum",
                self.structure
            )));
        }
        if !self.independently_recoverable {
            return Err(PraxisError::InvalidConfig(format!(
                "{} is not independently recoverable",
                self.structure
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct StorageOperationMetrics {
    pub latency_us: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub io_ops: u64,
    pub memory_bytes: u64,
    pub cpu_units: u64,
    pub read_amplification: f64,
    pub write_amplification: f64,
    pub space_amplification: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryOwnership {
    Arena,
    Slab,
    Epoch,
    RefCount,
    PageLifetime,
    Borrowed,
    Owned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestTracked {
    pub logical_name: String,
    pub path: PathBuf,
    pub format_version: u16,
}

impl ManifestTracked {
    pub fn new(
        logical_name: impl Into<String>,
        path: impl Into<PathBuf>,
        format_version: u16,
    ) -> Self {
        Self {
            logical_name: logical_name.into(),
            path: path.into(),
            format_version,
        }
    }
}

pub trait RecoverableStructure {
    fn durable_format(&self) -> DurableFormatDescriptor;
    fn manifest_path(&self) -> &Path;

    fn validate_recovery_contract(&self) -> Result<()> {
        self.durable_format().validate()?;
        if self.manifest_path().as_os_str().is_empty() {
            return Err(PraxisError::InvalidConfig(
                "recoverable structure has no manifest path".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableArtifactKind {
    WalSegment,
    Manifest,
    RecordDirectory,
    ValueSegment,
    IndexSegment,
    Sstable,
    BTreePageFile,
    Checkpoint,
    TieredObject,
    ReplicationLog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableArtifactState {
    Created,
    Installed,
    Replaced,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableArtifactDescriptor {
    pub logical_name: String,
    pub path: PathBuf,
    pub kind: DurableArtifactKind,
    pub state: DurableArtifactState,
    pub format: DurableFormatDescriptor,
}

impl DurableArtifactDescriptor {
    pub fn validate(&self) -> Result<()> {
        self.format.validate()?;
        if self.logical_name.is_empty() {
            return Err(PraxisError::InvalidConfig(
                "durable artifact has no logical name".to_string(),
            ));
        }
        if self.path.as_os_str().is_empty() {
            return Err(PraxisError::InvalidConfig(format!(
                "durable artifact {} has no manifest path",
                self.logical_name
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KernelInvariantReport {
    pub checked: Vec<KernelInvariant>,
}

pub struct KernelInvariantValidator;

impl KernelInvariantValidator {
    pub fn validate_engine_open(
        artifacts: &[DurableArtifactDescriptor],
    ) -> Result<KernelInvariantReport> {
        Self::validate_durable_artifacts(artifacts)?;
        Ok(KernelInvariantReport {
            checked: vec![
                KernelInvariant::DurableStructuresVersionedChecksummedRecoverable,
                KernelInvariant::ManifestTrackedDurability,
                KernelInvariant::DeterministicCrashRecovery,
            ],
        })
    }

    pub fn validate_write(
        wal_durable: bool,
        visibility_applied: bool,
        metrics: StorageOperationMetrics,
    ) -> Result<KernelInvariantReport> {
        if visibility_applied && !wal_durable {
            return Err(PraxisError::InvalidConfig(
                "write visibility cannot precede WAL durability".to_string(),
            ));
        }
        if metrics.latency_us == 0 && metrics.bytes_written == 0 && metrics.io_ops == 0 {
            return Err(PraxisError::InvalidConfig(
                "storage write completed without measurable operation metrics".to_string(),
            ));
        }
        Ok(KernelInvariantReport {
            checked: vec![
                KernelInvariant::WalBeforeVisibility,
                KernelInvariant::MeasurableStorageOperations,
            ],
        })
    }

    pub fn validate_index_registration(
        index_name: &str,
        layout: IndexStorageLayout,
    ) -> Result<KernelInvariantReport> {
        layout.validate_default_kernel_policy(index_name)?;
        Ok(KernelInvariantReport {
            checked: vec![
                KernelInvariant::CanonicalValuesSingleCopy,
                KernelInvariant::PointerOrientedIndexes,
            ],
        })
    }

    pub fn validate_durable_artifacts(
        artifacts: &[DurableArtifactDescriptor],
    ) -> Result<KernelInvariantReport> {
        for artifact in artifacts {
            artifact.validate()?;
        }
        Ok(KernelInvariantReport {
            checked: vec![
                KernelInvariant::DurableStructuresVersionedChecksummedRecoverable,
                KernelInvariant::ManifestTrackedDurability,
            ],
        })
    }

    pub fn validate_recovery_plan(steps: &[&str]) -> Result<KernelInvariantReport> {
        const EXPECTED: [&str; 6] = [
            "wal_replay",
            "manifest_reconcile",
            "record_directory_repair",
            "index_replay",
            "compaction_cleanup",
            "tier_migration_cleanup",
        ];
        if steps != EXPECTED {
            return Err(PraxisError::InvalidConfig(format!(
                "recovery plan must be deterministic and ordered as {}",
                EXPECTED.join(" -> ")
            )));
        }
        Ok(KernelInvariantReport {
            checked: vec![KernelInvariant::DeterministicCrashRecovery],
        })
    }
}
