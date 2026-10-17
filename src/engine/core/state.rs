use crate::accel::Accelerator;
use crate::cache::BlockCache;
use crate::config::PraxisConfig;
use crate::disk::DiskLayout;
use crate::maintenance::{MaintenanceRuntimeController, MaintenanceScheduler};
use crate::manifest::Manifest;
use crate::manifest::ManifestStore;
use crate::memory::{MemTable, SnapshotManager};
use crate::metrics::EngineMetrics;
use crate::types::{ColumnFamily, Key, VersionedValue};
use crate::wal::Wal;
use parking_lot::{Mutex, ReentrantMutex, RwLock};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) type CacheKey = (String, u64, Vec<u8>);
pub(crate) type SegmentIndex = BTreeMap<(ColumnFamily, Key), Vec<VersionedValue>>;

use super::group_commit::GroupCommitCoordinator;

pub(crate) struct EngineInner {
    pub(crate) config: PraxisConfig,
    pub(crate) layout: DiskLayout,
    pub(crate) manifest_store: ManifestStore,
    pub(crate) write_serialization: Mutex<()>,
    pub(crate) maintenance_serialization: ReentrantMutex<()>,
    pub(crate) topology: RwLock<()>,
    pub(crate) manifest: Mutex<Manifest>,
    pub(crate) wal: Mutex<Wal>,
    pub(crate) memtable: RwLock<MemTable>,
    pub(crate) segment_index: RwLock<SegmentIndex>,
    pub(crate) immutable_memtables: Mutex<Vec<MemTable>>,
    pub(crate) cache: Mutex<BlockCache<CacheKey>>,
    pub(crate) cache_bytes_by_cf: Mutex<BTreeMap<String, usize>>,
    pub(crate) scheduler: Mutex<MaintenanceScheduler>,
    pub(crate) runtime: Mutex<MaintenanceRuntimeController>,
    pub(crate) group_commit: GroupCommitCoordinator,
    pub(crate) snapshots: Arc<SnapshotManager>,
    pub(crate) metrics: EngineMetrics,
    pub(crate) accelerator: Arc<dyn Accelerator>,
    // Declared last so file-backed engine state is dropped before its lease.
    pub(crate) _writer_lease: crate::writer_lease::WriterLease,
}
