use super::codec::{Allocator, Envelope, Key, Kind, Role, Row};
use super::{RecordAuthority, RecordAuthorityOptions};
use crate::errors::{PraxisError, Result};
use crate::manifest::{Manifest, ManifestStore};
use crate::storage::root_format::{InspectionOptions, RootKind, RootOwner, inspect_storage_root};
use crate::transactions::WriteBatch;
use crate::wal::record::CoreWalRecord;
use crate::writer_lease::{LOCK_FILE_NAME, WriterLease};
use crate::{PraxisConfig, PraxisEngine};

/// One retained core owner; its KV view shares lease, health, queue and pins.
#[derive(Clone)]
pub struct CoreDatabase {
    engine: PraxisEngine,
}

impl CoreDatabase {
    /// Create an explicit v3 authority in an absent/empty root. No legacy
    /// load-or-create path or interim v2 manifest participates in activation.
    pub fn create_fresh(config: PraxisConfig, records: RecordAuthorityOptions) -> Result<Self> {
        config.validate()?;
        let records = records.canonicalize()?;
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|error| std::io::Error::other(error.to_string()))?;
        if id == [0; 16] {
            return Err(PraxisError::InvalidConfig(
                "OS returned a zero record database identity".into(),
            ));
        }
        let authority = RecordAuthority::new(
            id,
            u32::try_from(records.indexes.len())
                .map_err(|_| PraxisError::InvalidConfig("too many mapping descriptors".into()))?,
        );
        let manifest = Manifest::fresh_records(&config, authority);
        let bootstrap = bootstrap(&manifest, &records)?;
        // Exact complete wire preflight happens before durable format IO.
        bootstrap.try_encode()?;
        let lease = WriterLease::acquire(&config.data_dir)?;
        let report = inspect_storage_root(lease.root(), InspectionOptions::for_admission())?;
        if report.kind != RootKind::Empty
            || std::fs::read_dir(lease.root())?
                .any(|entry| entry.map_or(true, |entry| entry.file_name() != LOCK_FILE_NAME))
        {
            return Err(PraxisError::InvalidConfig(
                "fresh record authority requires an absent or empty root".into(),
            ));
        }
        manifest
            .clone()
            .validate_and_upgrade(&lease.root().join("MANIFEST"))?;
        let layout = crate::disk::DiskLayout::create(lease.root())?;
        phase(Phase::Layout)?;
        let mut wal = crate::wal::Wal::open_core(layout.wal_path(1), 1, config.wal_sync_policy)?;
        phase(Phase::WalHeader)?;
        wal.append_core_unsynced(&bootstrap)?;
        phase(Phase::WalAppend)?;
        wal.sync()?;
        crate::io::sync_parent_dir(wal.path())?;
        phase(Phase::WalSync)?;
        ManifestStore::new(layout.manifest_path()).save_with_policy(&manifest, config.direct_io)?;
        phase(Phase::Manifest)?;
        drop(wal);
        let engine = PraxisEngine::open_records(config, lease, manifest)?;
        Ok(Self { engine })
    }

    /// Open only an existing supported v3 authority. All complete protected
    /// evidence is checked before writable recovery or job reconciliation.
    pub fn open(config: PraxisConfig) -> Result<Self> {
        config.validate()?;
        let lease = WriterLease::acquire(&config.data_dir)?;
        inspect_storage_root(lease.root(), InspectionOptions::for_admission())?
            .require_compatible(RootOwner::Core)?;
        let source = lease.root().join("MANIFEST");
        let manifest = Manifest::decode(&std::fs::read(&source)?, &source)?;
        if manifest.record_authority.is_none() {
            return Err(PraxisError::InvalidConfig(
                "CoreDatabase::open requires an existing v3 record authority".into(),
            ));
        }
        Ok(Self {
            engine: PraxisEngine::open_records(config, lease, manifest)?,
        })
    }

    pub fn kv(&self) -> PraxisEngine {
        self.engine.clone()
    }

    pub fn records(&self) -> super::CoreRecordStore {
        super::CoreRecordStore::new(self.engine.clone())
    }

    /// Immutable durable identity/roles, not a mutable metadata handle.
    pub fn authority(&self) -> RecordAuthority {
        self.engine
            .inner
            .manifest
            .lock()
            .record_authority
            .clone()
            .expect("validated core record owner")
    }
}

fn bootstrap(manifest: &Manifest, options: &RecordAuthorityOptions) -> Result<CoreWalRecord> {
    let source = std::path::Path::new("record-bootstrap");
    let authority = manifest
        .record_authority
        .as_ref()
        .expect("fresh v3 authority");
    let id = authority.identity(source)?;
    let mut batch = WriteBatch::new();
    batch.put(
        Role::Meta.cf(),
        Key::Binding.encode()?,
        Row::Binding {
            database_id: id,
            descriptor_count: authority.index_descriptor_count,
        }
        .encode()?,
    );
    batch.put(
        Role::Meta.cf(),
        Key::Allocator.encode()?,
        Row::Allocator(Allocator::default()).encode()?,
    );
    for (index, descriptor) in options.indexes.iter().enumerate() {
        batch.put(
            Role::Meta.cf(),
            Key::Descriptor(
                u32::try_from(index + 1).map_err(|_| {
                    PraxisError::InvalidConfig("record registry ID overflow".into())
                })?,
            )
            .encode()?,
            Row::Descriptor {
                name: &descriptor.name,
                namespace: &descriptor.namespace,
            }
            .encode()?,
        );
    }
    Ok(CoreWalRecord::Record {
        sequence: 1,
        batch,
        envelope: Envelope {
            kind: Kind::Bootstrap,
            database_id: id,
            prior_rid: 0,
            new_rid: 0,
            prior_compatibility_sequence: 0,
            new_compatibility_sequence: 0,
            prior_append_ordinal: 0,
            new_append_ordinal: 0,
            record_count: 0,
            logical_entry_count: 0,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Layout,
    WalHeader,
    WalAppend,
    WalSync,
    Manifest,
}
fn phase(point: Phase) -> Result<()> {
    #[cfg(test)]
    if FAIL_AT.with(|failure| failure.get()) == Some(point) {
        return Err(std::io::Error::other("bootstrap injected failure").into());
    }
    let _ = point;
    Ok(())
}
#[cfg(test)]
thread_local! { static FAIL_AT: std::cell::Cell<Option<Phase>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
