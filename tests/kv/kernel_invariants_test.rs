use praxis::errors::Result;
use praxis::index::{IndexPlugin, IndexStats, IndexStorageLayout};
use praxis::kernel::{
    CanonicalValuePolicy, DurableArtifactDescriptor, DurableArtifactKind, DurableArtifactState,
    DurableFormatDescriptor, EngineCapability, KernelInvariant, KernelInvariantValidator,
    PhysicalEngine, PhysicalEngineKind, StorageOperationMetrics,
};
use praxis::store::{RecordId, StorageEngine};

struct FullValueIndex;

impl IndexPlugin for FullValueIndex {
    fn name(&self) -> &str {
        "full_value"
    }

    fn put(&mut self, _key: &[u8], _rid: RecordId) -> Result<()> {
        Ok(())
    }

    fn get(&self, _key: &[u8]) -> Option<RecordId> {
        None
    }

    fn delete(&mut self, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn stats(&self) -> IndexStats {
        IndexStats::default()
    }

    fn storage_layout(&self) -> IndexStorageLayout {
        IndexStorageLayout {
            stores_full_values: true,
            stores_record_ids: true,
            stores_lossy_summaries: false,
        }
    }
}

#[test]
fn strict_canonical_policy_allows_only_declared_redundancy() {
    let policy = CanonicalValuePolicy::STRICT;
    assert!(policy.canonical_values_single_copy);
    assert!(policy.allow_replicas);
    assert!(policy.allow_snapshots);
    assert!(policy.allow_backups);
    assert!(policy.allow_erasure_redundancy);
    assert!(policy.allow_lossy_summaries);
}

#[test]
fn durable_format_descriptor_requires_version_checksum_and_recovery() {
    let descriptor = DurableFormatDescriptor {
        structure: "sstable",
        format_version: 1,
        checksum: "crc32c".into(),
        forward_compatible: true,
        independently_recoverable: true,
    };

    assert!(descriptor.validate().is_ok());
}

#[test]
fn kernel_validator_rejects_unmeasured_visible_writes() {
    let err =
        KernelInvariantValidator::validate_write(false, true, StorageOperationMetrics::default())
            .unwrap_err();

    assert!(err.to_string().contains("WAL durability"));
}

#[test]
fn kernel_validator_accepts_manifest_tracked_artifacts() {
    let artifact = DurableArtifactDescriptor {
        logical_name: "wal_segment:0001".to_string(),
        path: "wal/storage.00000000000000000001.swal".into(),
        kind: DurableArtifactKind::WalSegment,
        state: DurableArtifactState::Installed,
        format: DurableFormatDescriptor {
            structure: "wal_segment",
            format_version: 1,
            checksum: "record_crc32".into(),
            forward_compatible: true,
            independently_recoverable: true,
        },
    };

    let report = KernelInvariantValidator::validate_engine_open(&[artifact]).unwrap();
    assert!(
        report
            .checked
            .contains(&KernelInvariant::ManifestTrackedDurability)
    );
}

#[test]
fn kernel_validator_requires_deterministic_recovery_order() {
    let report = KernelInvariantValidator::validate_recovery_plan(&[
        "wal_replay",
        "manifest_reconcile",
        "record_directory_repair",
        "index_replay",
        "compaction_cleanup",
        "tier_migration_cleanup",
    ])
    .unwrap();

    assert_eq!(
        report.checked,
        vec![KernelInvariant::DeterministicCrashRecovery]
    );
    assert!(
        KernelInvariantValidator::validate_recovery_plan(&["index_replay", "wal_replay"]).is_err()
    );
}

#[test]
fn physical_engine_model_marks_indexes_pointer_oriented() {
    let engine = PhysicalEngine::pointer_index(
        "primary_lsm",
        PhysicalEngineKind::Lsm,
        vec![EngineCapability::PointLookup, EngineCapability::RangeScan],
    );

    assert!(!engine.stores_canonical_values);
    assert!(engine.pointer_oriented);
}

#[test]
fn storage_engine_rejects_full_value_indexes_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();

    let err = engine
        .register_index("bad", "bad", Box::new(FullValueIndex))
        .unwrap_err();

    assert!(err.to_string().contains("pointer-only kernel policy"));
}
