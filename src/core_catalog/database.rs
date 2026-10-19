use crate::PraxisConfig;
use crate::core_records::RecordAuthorityOptions;
use crate::errors::{PraxisError, Result};
use crate::storage::root_format::{
    InspectionOptions, RootInspection, RootKind, RootOwner, inspect_storage_root,
};
use crate::writer_lease::{LOCK_FILE_NAME, WriterLease};

/// A separately admitted v4 core catalog owner.
///
/// Both constructors remain fail-closed until v4 bootstrap and recovery are
/// implemented. A successful owner cannot be constructed by this module yet.
pub struct CatalogDatabase {
    _private: (),
}

impl CatalogDatabase {
    /// Prepare a new v4 catalog only after its complete storage contract exists.
    pub fn create_fresh_v4(config: PraxisConfig, records: RecordAuthorityOptions) -> Result<Self> {
        config.validate()?;
        let _ = records.canonicalize()?;
        let lease = WriterLease::acquire(&config.data_dir)?;
        let report = inspect_storage_root(lease.root(), InspectionOptions::for_admission())?;
        report.require_compatible(RootOwner::Core)?;
        if matches!(report.kind, RootKind::CoreLegacy | RootKind::CoreRecords) {
            return Err(legacy_format(&report));
        }
        if report.kind != RootKind::Empty
            || std::fs::read_dir(lease.root())?
                .any(|entry| entry.map_or(true, |entry| entry.file_name() != LOCK_FILE_NAME))
        {
            return Err(PraxisError::StorageFormatUnsupported {
                path: report.requested_path,
                expected: RootOwner::Core,
                reason: "fresh v4 catalog requires an absent or empty root".into(),
                evidence: report.evidence.into_iter().map(|item| item.path).collect(),
            });
        }
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 catalog bootstrap",
        })
    }

    /// Open an existing v4 catalog only after its recovery contract exists.
    pub fn open_catalog(config: PraxisConfig) -> Result<Self> {
        config.validate()?;
        let lease = WriterLease::acquire(&config.data_dir)?;
        let report = inspect_storage_root(lease.root(), InspectionOptions::for_admission())?;
        report.require_compatible(RootOwner::Core)?;
        if report.kind == RootKind::Empty {
            return Err(PraxisError::StorageFormatIncomplete {
                path: report.requested_path,
                expected: RootOwner::Core,
                reason: "catalog open requires an existing v4 owner".into(),
                evidence: Vec::new(),
            });
        }
        if matches!(report.kind, RootKind::CoreLegacy | RootKind::CoreRecords) {
            return Err(legacy_format(&report));
        }
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 catalog recovery",
        })
    }
}

fn legacy_format(report: &RootInspection) -> PraxisError {
    // Manifest::decode upgrades a v1 manifest to v2 in memory. Inspection
    // retains the raw typed header so the refusal reports the actual version.
    let version = report
        .evidence
        .iter()
        .find(|item| item.owner == RootOwner::Core && item.role == "authoritative manifest")
        .and_then(|item| item.version);
    PraxisError::StorageFormatUnsupported {
        path: report.requested_path.clone(),
        expected: RootOwner::Core,
        reason: match version {
            Some(version) => format!(
                "catalog owner requires format version 4; detected core format version {version}"
            ),
            None => "catalog owner requires format version 4; detected a legacy core root".into(),
        },
        evidence: report
            .evidence
            .iter()
            .map(|item| item.path.clone())
            .collect(),
    }
}
