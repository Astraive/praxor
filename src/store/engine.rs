use super::manifest::{
    DurableFileKind, DurableFileRecord, ManifestEdit, StorageManifest, StorageManifestStore,
};
use super::wal::{StorageWal, StorageWalEntry, StorageWalOperation, StorageWalOptions};
use super::{CompactionStats, PhysicalLocation, PreparedCompaction, RecordId, RecordStore};
use crate::cache::BlockCache;
use crate::errors::{PraxisError, Result};
use crate::index::{IndexPlugin, IndexStats};
use crate::io::create_dir_all_durable;
use crate::kernel::{
    KernelCompactionReport, KernelInvariantValidator, KernelSnapshot, KernelStorageReport,
    StorageKernel, StorageOperationMetrics,
};
use crate::metrics::{EngineMetrics, LatencyTracker};
use crate::recovery::RecoveryPlan;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CacheEntryType {
    PrimaryData,
    IndexBlock(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheBlockKey {
    pub ty: CacheEntryType,
    pub block_id: u64,
}

pub struct UnifiedBlockCache {
    inner: BlockCache<CacheBlockKey>,
}

impl UnifiedBlockCache {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            inner: BlockCache::new(capacity_bytes),
        }
    }

    pub fn put_primary(&mut self, block_id: u64, value: Bytes) {
        self.inner.insert(
            CacheBlockKey {
                ty: CacheEntryType::PrimaryData,
                block_id,
            },
            value,
        );
    }

    pub fn get_primary(&mut self, block_id: u64) -> Option<Bytes> {
        self.inner.get(&CacheBlockKey {
            ty: CacheEntryType::PrimaryData,
            block_id,
        })
    }

    pub fn put_index(&mut self, index: &str, block_id: u64, value: Bytes) {
        self.inner.insert(
            CacheBlockKey {
                ty: CacheEntryType::IndexBlock(index.to_string()),
                block_id,
            },
            value,
        );
    }

    pub fn get_index(&mut self, index: &str, block_id: u64) -> Option<Bytes> {
        self.inner.get(&CacheBlockKey {
            ty: CacheEntryType::IndexBlock(index.to_string()),
            block_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexInsert {
    pub index_type: String,
    pub key: Vec<u8>,
}

impl IndexInsert {
    pub fn new(index_type: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self {
            index_type: index_type.into(),
            key: key.into(),
        }
    }
}

/// Publishes primary records and index changes after their ordered WAL group
/// is durable. A failed WAL write/sync has an ambiguous commit outcome; a
/// plugin error after commit or a partially failed compaction can also leave
/// in-memory state incomplete. In those cases reads, mutations and maintenance
/// return `RecoveryRequired` until the handle is closed and reopened. Recovery
/// applies complete groups and discards only incomplete terminal groups.
pub struct StorageEngine {
    root: PathBuf,
    store: RecordStore,
    wal: StorageWal,
    manifest_store: StorageManifestStore,
    manifest: StorageManifest,
    indexes: HashMap<String, Box<dyn IndexPlugin>>,
    pending_replay: Vec<StorageWalEntry>,
    cache: UnifiedBlockCache,
    compaction_budget_bytes: u64,
    directory_sync_policy: DirectorySyncPolicy,
    dirty_directory_entries: u64,
    metrics: EngineMetrics,
    read_latency: LatencyTracker,
    write_latency: LatencyTracker,
    compaction_latency: LatencyTracker,
    opened_at: Instant,
    recovery_required: bool,
    _writer_lease: crate::writer_lease::WriterLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DirectorySyncPolicy {
    Always,
    Batch(u64),
    Manual,
}

impl DirectorySyncPolicy {
    pub fn should_flush(self, dirty_entries: u64) -> bool {
        match self {
            Self::Always => dirty_entries > 0,
            Self::Batch(threshold) => dirty_entries >= threshold.max(1),
            Self::Manual => false,
        }
    }
}

impl Default for DirectorySyncPolicy {
    fn default() -> Self {
        Self::Batch(64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageEngineOptions {
    pub wal: StorageWalOptions,
    pub directory_sync_policy: DirectorySyncPolicy,
}

impl Default for StorageEngineOptions {
    fn default() -> Self {
        Self {
            wal: StorageWalOptions::default(),
            directory_sync_policy: DirectorySyncPolicy::Batch(64),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BatchRecord<'a> {
    pub value: &'a [u8],
    pub index_inserts: &'a [IndexInsert],
}

impl<'a> BatchRecord<'a> {
    pub fn new(value: &'a [u8], index_inserts: &'a [IndexInsert]) -> Self {
        Self {
            value,
            index_inserts,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexCompactionReport {
    pub index_type: String,
    pub before: IndexStats,
    pub after: IndexStats,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SuggestedMaintenanceJob {
    pub index_type: String,
    pub reason: String,
    pub estimated_versions_pruned: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceCycleOptions {
    pub stale_version_threshold: u64,
    pub max_jobs: usize,
}

impl Default for MaintenanceCycleOptions {
    fn default() -> Self {
        Self {
            stale_version_threshold: 1,
            max_jobs: usize::MAX,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceCycleReport {
    pub suggested: Vec<SuggestedMaintenanceJob>,
    pub executed: Vec<IndexCompactionReport>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageEngineStats {
    pub manifest_version: u64,
    pub last_sequence: u64,
    pub live_records: u64,
    pub live_bytes: u64,
    pub pending_wal_replay: usize,
    pub compaction_budget_bytes: u64,
    pub index_stats: HashMap<String, IndexStats>,
    pub index_compaction_runs: HashMap<String, u64>,
    pub last_compacted_at_sequence: HashMap<String, u64>,
    pub maintenance_cycles_run: u64,
    pub last_maintenance_at_sequence: Option<u64>,
    // Latency metrics (microseconds)
    pub read_latency_p50_us: u64,
    pub read_latency_p95_us: u64,
    pub read_latency_p99_us: u64,
    pub write_latency_p50_us: u64,
    pub write_latency_p95_us: u64,
    pub write_latency_p99_us: u64,
    pub compaction_latency_p50_us: u64,
    pub compaction_latency_p95_us: u64,
    pub reads_total: u64,
    pub writes_total: u64,
    pub deletes_total: u64,
    pub read_errors_total: u64,
    pub write_errors_total: u64,
    pub wal_records_total: u64,
    pub wal_bytes_written: u64,
    pub user_bytes_written: u64,
    // Throughput metrics
    pub reads_per_sec: f64,
    pub writes_per_sec: f64,
    pub wal_bytes_per_sec: f64,
    // Amplification metrics
    pub read_amplification: f64,
    pub write_amplification: f64,
    pub space_amplification: f64,
    pub directory_sync_policy: DirectorySyncPolicy,
    pub dirty_directory_entries: u64,
}

impl StorageEngine {
    const PRIMARY_DIR: &'static str = "primary";
    const INDEX_DIR: &'static str = "indexes";
    const WAL_DIR: &'static str = "wal";
    const WAL_FILE: &'static str = "storage.wal";
    const MANIFEST_FILE: &'static str = "MANIFEST.store";

    pub fn open(root: impl Into<PathBuf>, cache_capacity_bytes: usize) -> Result<Self> {
        Self::open_with_options(root, cache_capacity_bytes, StorageEngineOptions::default())
    }

    pub fn open_with_options(
        root: impl Into<PathBuf>,
        cache_capacity_bytes: usize,
        options: StorageEngineOptions,
    ) -> Result<Self> {
        let writer_lease = crate::writer_lease::WriterLease::acquire(root.into())?;
        let root = writer_lease.root().to_path_buf();
        let primary_lease = writer_lease.acquire_primary()?;
        create_dir_all_durable(&root.join(Self::INDEX_DIR))?;
        create_dir_all_durable(&root.join(Self::WAL_DIR))?;

        let mut store = RecordStore::open_with_lease(primary_lease)?;
        let wal_path = root.join(Self::WAL_DIR).join(Self::WAL_FILE);
        let wal = StorageWal::open_with_options(&wal_path, options.wal)?;
        let replay_entries = StorageWal::replay(&wal_path)?;
        RecoveryPlan::canonical_startup().validate_deterministic_order()?;
        replay_primary_directory(&mut store, &replay_entries)?;

        let manifest_store = StorageManifestStore::new(root.join(Self::MANIFEST_FILE));
        let mut manifest = manifest_store.load_or_create()?;
        reconcile_pending_compaction_cleanup(&root, &mut store, &manifest_store, &mut manifest)?;
        rebuild_durable_inventory(&root, &mut manifest)?;
        KernelInvariantValidator::validate_engine_open(&manifest.kernel_artifacts())?;
        manifest.last_sequence = replay_entries
            .iter()
            .map(|entry| entry.sequence)
            .max()
            .unwrap_or(manifest.last_sequence);
        let pending_replay = replay_entries
            .into_iter()
            .filter(|entry| entry.index_type != "primary")
            .collect();

        Ok(Self {
            root,
            store,
            wal,
            manifest_store,
            manifest,
            indexes: HashMap::new(),
            pending_replay,
            cache: UnifiedBlockCache::new(cache_capacity_bytes),
            compaction_budget_bytes: 0,
            directory_sync_policy: options.directory_sync_policy,
            dirty_directory_entries: 0,
            metrics: EngineMetrics::default(),
            read_latency: LatencyTracker::new(4096),
            write_latency: LatencyTracker::new(4096),
            compaction_latency: LatencyTracker::new(1024),
            opened_at: Instant::now(),
            recovery_required: false,
            _writer_lease: writer_lease,
        })
    }

    pub fn open_with_wal_options(
        root: impl Into<PathBuf>,
        cache_capacity_bytes: usize,
        wal_options: StorageWalOptions,
    ) -> Result<Self> {
        Self::open_with_options(
            root,
            cache_capacity_bytes,
            StorageEngineOptions {
                wal: wal_options,
                ..StorageEngineOptions::default()
            },
        )
    }

    pub fn register_index(
        &mut self,
        index_type: impl Into<String>,
        namespace: impl Into<String>,
        plugin: Box<dyn IndexPlugin>,
    ) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let index_type = index_type.into();
            KernelInvariantValidator::validate_index_registration(
                &index_type,
                plugin.storage_layout(),
            )?;
            self.indexes.insert(index_type.clone(), plugin);
            self.manifest
                .plugin_namespaces
                .insert(index_type.clone(), namespace.into());
            let replay = self.replay_for_index(&index_type);
            if replay.is_err() {
                self.recovery_required = true;
            }
            replay
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn put(&mut self, value: &[u8], index_inserts: &[IndexInsert]) -> Result<RecordId> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let started = Instant::now();
            self.ensure_indexes_exist(
                index_inserts
                    .iter()
                    .map(|insert| insert.index_type.as_str()),
            )?;
            let prepared = self.store.prepare_put(value)?;
            let rid = prepared.rid;
            let location = prepared.location;
            let mut entries = Vec::with_capacity(index_inserts.len() + 1);
            entries.push(StorageWalEntry {
                sequence: 0,
                index_type: "primary".to_string(),
                key: encode_location(location),
                rid: Some(rid),
                operation: StorageWalOperation::Put,
            });
            for insert in index_inserts {
                entries.push(StorageWalEntry {
                    sequence: 0,
                    index_type: insert.index_type.clone(),
                    key: insert.key.clone(),
                    rid: Some(rid),
                    operation: StorageWalOperation::Put,
                });
            }
            StorageWal::validate_batch(&entries)?;
            self.store.sync_active_segment()?;
            self.append_wal_batch(&mut entries)?;
            self.store.publish_puts(&[prepared]);
            KernelInvariantValidator::validate_write(
                true,
                false,
                StorageOperationMetrics {
                    latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    bytes_written: value.len() as u64,
                    io_ops: entries.len() as u64,
                    ..StorageOperationMetrics::default()
                },
            )?;
            for (insert, wal_entry) in index_inserts.iter().zip(entries.iter().skip(1)) {
                let plugin = self.indexes.get_mut(&insert.index_type).ok_or_else(|| {
                    PraxisError::InvalidConfig(format!(
                        "unknown index plugin: {}",
                        insert.index_type
                    ))
                })?;
                plugin.put_with_sequence(&insert.key, rid, wal_entry.sequence)?;
            }
            self.flush_directory_if_needed(1)?;
            KernelInvariantValidator::validate_write(
                true,
                true,
                StorageOperationMetrics {
                    latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    bytes_written: value.len() as u64,
                    io_ops: entries.len() as u64,
                    ..StorageOperationMetrics::default()
                },
            )?;
            self.metrics.writes.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .write_bytes
                .fetch_add(value.len() as u64, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(rid)
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn put_batch(&mut self, records: &[BatchRecord<'_>]) -> Result<Vec<RecordId>> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let started = Instant::now();
            if records.is_empty() {
                return Ok(Vec::new());
            }

            self.ensure_indexes_exist(
                records
                    .iter()
                    .flat_map(|record| record.index_inserts.iter())
                    .map(|insert| insert.index_type.as_str()),
            )?;

            let mut rids = Vec::with_capacity(records.len());
            let mut entries = Vec::with_capacity(
                records.len()
                    + records
                        .iter()
                        .map(|record| record.index_inserts.len())
                        .sum::<usize>(),
            );
            let mut total_value_bytes = 0_u64;
            let mut prepared_puts = Vec::with_capacity(records.len());

            for record in records {
                let prepared = self.store.prepare_put(record.value)?;
                let rid = prepared.rid;
                let location = prepared.location;
                prepared_puts.push(prepared);
                total_value_bytes += record.value.len() as u64;
                rids.push(rid);
                entries.push(StorageWalEntry {
                    sequence: 0,
                    index_type: "primary".to_string(),
                    key: encode_location(location),
                    rid: Some(rid),
                    operation: StorageWalOperation::Put,
                });
                for insert in record.index_inserts {
                    entries.push(StorageWalEntry {
                        sequence: 0,
                        index_type: insert.index_type.clone(),
                        key: insert.key.clone(),
                        rid: Some(rid),
                        operation: StorageWalOperation::Put,
                    });
                }
            }

            StorageWal::validate_batch(&entries)?;
            self.store.sync_active_segment()?;
            self.append_wal_batch(&mut entries)?;
            self.store.publish_puts(&prepared_puts);
            KernelInvariantValidator::validate_write(
                true,
                false,
                StorageOperationMetrics {
                    latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    bytes_written: total_value_bytes,
                    io_ops: entries.len() as u64,
                    ..StorageOperationMetrics::default()
                },
            )?;

            let mut entry_cursor = 0;
            for (record, rid) in records.iter().zip(rids.iter().copied()) {
                entry_cursor += 1; // primary WAL entry
                for insert in record.index_inserts {
                    let wal_entry = &entries[entry_cursor];
                    let plugin = self.indexes.get_mut(&insert.index_type).ok_or_else(|| {
                        PraxisError::InvalidConfig(format!(
                            "unknown index plugin: {}",
                            insert.index_type
                        ))
                    })?;
                    plugin.put_with_sequence(&insert.key, rid, wal_entry.sequence)?;
                    entry_cursor += 1;
                }
            }

            self.flush_directory_if_needed(records.len() as u64)?;
            KernelInvariantValidator::validate_write(
                true,
                true,
                StorageOperationMetrics {
                    latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    bytes_written: total_value_bytes,
                    io_ops: entries.len() as u64,
                    ..StorageOperationMetrics::default()
                },
            )?;
            self.metrics
                .writes
                .fetch_add(records.len() as u64, Ordering::Relaxed);
            self.metrics
                .write_bytes
                .fetch_add(total_value_bytes, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(rids)
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn put_index(&mut self, index_type: &str, key: &[u8], rid: RecordId) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let started = Instant::now();
            self.ensure_indexes_exist(std::iter::once(index_type))?;
            if !self.store.contains(rid) {
                self.metrics.write_errors.fetch_add(1, Ordering::Relaxed);
                return Err(PraxisError::KeyNotFound);
            }
            let sequence = self.append_wal(StorageWalEntry {
                sequence: 0,
                index_type: index_type.to_string(),
                key: key.to_vec(),
                rid: Some(rid),
                operation: StorageWalOperation::Put,
            })?;
            let plugin = self.indexes.get_mut(index_type).ok_or_else(|| {
                PraxisError::InvalidConfig(format!("unknown index plugin: {index_type}"))
            })?;
            plugin.put_with_sequence(key, rid, sequence)?;
            self.metrics.writes.fetch_add(1, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(())
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn delete_index(&mut self, index_type: &str, key: &[u8]) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let started = Instant::now();
            self.ensure_indexes_exist(std::iter::once(index_type))?;
            let sequence = self.append_wal(StorageWalEntry {
                sequence: 0,
                index_type: index_type.to_string(),
                key: key.to_vec(),
                rid: None,
                operation: StorageWalOperation::Delete,
            })?;
            let plugin = self.indexes.get_mut(index_type).ok_or_else(|| {
                PraxisError::InvalidConfig(format!("unknown index plugin: {index_type}"))
            })?;
            plugin.delete_with_sequence(key, sequence)?;
            self.metrics.deletes.fetch_add(1, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(())
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn lookup_rid(&self, index_type: &str, key: &[u8]) -> Result<Option<RecordId>> {
        self.ensure_ready()?;
        let plugin = self.indexes.get(index_type).ok_or_else(|| {
            PraxisError::InvalidConfig(format!("unknown index plugin: {index_type}"))
        })?;
        Ok(plugin.get(key))
    }

    /// Resolve an index mapping at a raw sequence ceiling. This does not make
    /// `fetch(rid)` a historical payload read; primary liveness is independent.
    pub fn lookup_rid_at(
        &self,
        index_type: &str,
        key: &[u8],
        sequence: u64,
    ) -> Result<Option<RecordId>> {
        self.ensure_ready()?;
        let plugin = self.indexes.get(index_type).ok_or_else(|| {
            PraxisError::InvalidConfig(format!("unknown index plugin: {index_type}"))
        })?;
        plugin.get_at_checked(key, sequence)
    }

    pub fn fetch(&self, rid: RecordId) -> Result<Vec<u8>> {
        self.ensure_ready()?;
        let started = Instant::now();
        let result = self.store.get(rid);
        record_latency(&self.read_latency, started);
        match &result {
            Ok(_) => {
                self.metrics.reads.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics.read_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    pub fn fetch_by_index(&self, index_type: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let rid = self.lookup_rid(index_type, key)?;
        match rid {
            Some(id) => match self.fetch(id) {
                Ok(value) => Ok(Some(value)),
                Err(PraxisError::KeyNotFound) => Ok(None),
                Err(err) => Err(err),
            },
            None => Ok(None),
        }
    }

    pub fn delete_record(&mut self, rid: RecordId) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            if !self.store.contains_record(rid) {
                return Err(PraxisError::KeyNotFound);
            }
            let started = Instant::now();
            let _sequence = self.append_wal(StorageWalEntry {
                sequence: 0,
                index_type: "primary".to_string(),
                key: Vec::new(),
                rid: Some(rid),
                operation: StorageWalOperation::Delete,
            })?;
            self.store.delete(rid)?;
            self.flush_directory_if_needed(1)?;
            self.metrics.deletes.fetch_add(1, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(())
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn delete_records(&mut self, rids: &[RecordId]) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            if rids.is_empty() {
                return Ok(());
            }
            if rids.iter().any(|rid| !self.store.contains_record(*rid)) {
                return Err(PraxisError::KeyNotFound);
            }

            let started = Instant::now();
            let mut entries: Vec<StorageWalEntry> = rids
                .iter()
                .copied()
                .map(|rid| StorageWalEntry {
                    sequence: 0,
                    index_type: "primary".to_string(),
                    key: Vec::new(),
                    rid: Some(rid),
                    operation: StorageWalOperation::Delete,
                })
                .collect();
            self.append_wal_batch(&mut entries)?;
            for rid in rids {
                self.store.delete(*rid)?;
            }
            self.flush_directory_if_needed(rids.len() as u64)?;
            self.metrics
                .deletes
                .fetch_add(rids.len() as u64, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(())
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn delete_by_index(&mut self, index_type: &str, key: &[u8]) -> Result<Option<RecordId>> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let rid = self.lookup_rid(index_type, key)?;
            if let Some(rid) = rid {
                self.delete_record_with_index_cleanup(
                    rid,
                    &[IndexInsert::new(index_type, key.to_vec())],
                )?;
            } else {
                self.delete_index(index_type, key)?;
            }
            Ok(rid)
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn delete_record_with_index_cleanup(
        &mut self,
        rid: RecordId,
        index_keys: &[IndexInsert],
    ) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            self.ensure_indexes_exist(index_keys.iter().map(|insert| insert.index_type.as_str()))?;
            if !self.store.contains_record(rid) {
                return Err(PraxisError::KeyNotFound);
            }
            let started = Instant::now();
            let mut entries: Vec<_> = index_keys
                .iter()
                .map(|key| StorageWalEntry {
                    sequence: 0,
                    index_type: key.index_type.clone(),
                    key: key.key.clone(),
                    rid: None,
                    operation: StorageWalOperation::Delete,
                })
                .collect();
            entries.push(StorageWalEntry {
                sequence: 0,
                index_type: "primary".into(),
                key: Vec::new(),
                rid: Some(rid),
                operation: StorageWalOperation::Delete,
            });
            self.append_wal_batch(&mut entries)?;
            for (key, entry) in index_keys.iter().zip(&entries) {
                self.indexes
                    .get_mut(&key.index_type)
                    .expect("indexes prevalidated")
                    .delete_with_sequence(&key.key, entry.sequence)?;
            }
            self.store.delete(rid)?;
            self.flush_directory_if_needed(1)?;
            self.metrics
                .deletes
                .fetch_add(entries.len() as u64, Ordering::Relaxed);
            record_latency(&self.write_latency, started);
            Ok(())
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn compact_primary(&mut self) -> Result<CompactionStats> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let started = Instant::now();
            let job_id = compaction_job_id(self.manifest.last_sequence);
            let prepared = self.prepare_primary_compaction()?;
            let cleaned_segments = self
                .store
                .complete_compaction_cleanup(&prepared.old_segment_ids, prepared.new_segment_id)?;
            self.append_manifest_edit(ManifestEdit::CompactionCleanupComplete {
                job_id,
                cleaned_segments,
            })?;
            record_latency(&self.compaction_latency, started);
            Ok(prepared.stats)
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn compact_indexes(&mut self) -> Result<Vec<IndexCompactionReport>> {
        let mut names: Vec<String> = self.indexes.keys().cloned().collect();
        names.sort();
        self.compact_selected_indexes(&names)
    }

    pub fn compact_selected_indexes(
        &mut self,
        index_types: &[impl AsRef<str>],
    ) -> Result<Vec<IndexCompactionReport>> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let mut reports = Vec::with_capacity(index_types.len());
            for index_name in index_types {
                let index_name = index_name.as_ref();
                let plugin = self.indexes.get_mut(index_name).ok_or_else(|| {
                    PraxisError::InvalidConfig(format!("unknown index plugin: {index_name}"))
                })?;
                let before = plugin.stats();
                plugin.compact()?;
                plugin.flush()?;
                let after = plugin.stats();
                reports.push(IndexCompactionReport {
                    index_type: index_name.to_string(),
                    before,
                    after,
                });
                *self
                    .manifest
                    .index_compaction_runs
                    .entry(index_name.to_string())
                    .or_insert(0) += 1;
                self.manifest
                    .last_compacted_at_sequence
                    .insert(index_name.to_string(), self.manifest.last_sequence);
            }
            self.bump_manifest_version()?;
            Ok(reports)
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            self.store.flush()?;
            self.dirty_directory_entries = 0;
            for plugin in self.indexes.values_mut() {
                plugin.flush()?;
            }
            self.bump_manifest_version()
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn cache_mut(&mut self) -> &mut UnifiedBlockCache {
        &mut self.cache
    }

    pub fn live_count(&self) -> u64 {
        self.store.live_count()
    }

    pub fn live_bytes(&self) -> u64 {
        self.store.live_bytes()
    }

    pub fn canonical_live_bytes(&self) -> u64 {
        self.store.canonical_stats().canonical_live_bytes
    }

    pub fn dead_records(&self) -> u64 {
        self.store.dead_count()
    }

    pub fn manifest(&self) -> &StorageManifest {
        &self.manifest
    }

    pub fn set_compaction_budget_bytes(&mut self, bytes: u64) {
        self.compaction_budget_bytes = bytes;
    }

    pub fn compaction_budget_bytes(&self) -> u64 {
        self.compaction_budget_bytes
    }

    pub fn set_directory_sync_policy(&mut self, policy: DirectorySyncPolicy) {
        self.directory_sync_policy = policy;
    }

    pub fn directory_sync_policy(&self) -> DirectorySyncPolicy {
        self.directory_sync_policy
    }

    pub fn stats(&self) -> StorageEngineStats {
        let index_stats = self
            .indexes
            .iter()
            .map(|(name, plugin)| (name.clone(), plugin.stats()))
            .collect();
        let metrics = self.metrics.snapshot();
        let elapsed_secs = self.opened_at.elapsed().as_secs_f64().max(0.001);
        let live_bytes = self.live_bytes();
        let write_amplification = if metrics.write_bytes == 0 {
            0.0
        } else {
            (metrics.write_bytes + metrics.wal_bytes) as f64 / metrics.write_bytes as f64
        };
        StorageEngineStats {
            manifest_version: self.manifest.version,
            last_sequence: self.manifest.last_sequence,
            live_records: self.live_count(),
            live_bytes,
            pending_wal_replay: self.pending_replay.len(),
            compaction_budget_bytes: self.compaction_budget_bytes,
            index_stats,
            index_compaction_runs: self.manifest.index_compaction_runs.clone(),
            last_compacted_at_sequence: self.manifest.last_compacted_at_sequence.clone(),
            maintenance_cycles_run: self.manifest.maintenance_cycles_run,
            last_maintenance_at_sequence: self.manifest.last_maintenance_at_sequence,
            read_latency_p50_us: self.read_latency.percentile(0.50).unwrap_or(0),
            read_latency_p95_us: self.read_latency.percentile(0.95).unwrap_or(0),
            read_latency_p99_us: self.read_latency.percentile(0.99).unwrap_or(0),
            write_latency_p50_us: self.write_latency.percentile(0.50).unwrap_or(0),
            write_latency_p95_us: self.write_latency.percentile(0.95).unwrap_or(0),
            write_latency_p99_us: self.write_latency.percentile(0.99).unwrap_or(0),
            compaction_latency_p50_us: self.compaction_latency.percentile(0.50).unwrap_or(0),
            compaction_latency_p95_us: self.compaction_latency.percentile(0.95).unwrap_or(0),
            reads_total: metrics.reads,
            writes_total: metrics.writes,
            deletes_total: metrics.deletes,
            read_errors_total: metrics.read_errors,
            write_errors_total: metrics.write_errors,
            wal_records_total: metrics.wal_records,
            wal_bytes_written: metrics.wal_bytes,
            user_bytes_written: metrics.write_bytes,
            reads_per_sec: metrics.reads as f64 / elapsed_secs,
            writes_per_sec: metrics.writes as f64 / elapsed_secs,
            wal_bytes_per_sec: metrics.wal_bytes as f64 / elapsed_secs,
            read_amplification: if metrics.reads == 0 { 0.0 } else { 1.0 },
            write_amplification,
            space_amplification: if live_bytes == 0 { 0.0 } else { 1.0 },
            directory_sync_policy: self.directory_sync_policy,
            dirty_directory_entries: self.dirty_directory_entries,
        }
    }

    /// Heuristic maintenance planner for plugin-local compaction.
    ///
    /// Suggestions count only versions the plugin can safely discard under
    /// its declared snapshot-retention contract.
    pub fn suggest_index_compactions(
        &self,
        stale_version_threshold: u64,
    ) -> Vec<SuggestedMaintenanceJob> {
        let mut suggestions: Vec<SuggestedMaintenanceJob> = self
            .indexes
            .iter()
            .filter_map(|(index_type, plugin)| {
                let stale_versions = plugin.reclaimable_version_count();
                (stale_versions > 0 && stale_versions >= stale_version_threshold).then(|| {
                    SuggestedMaintenanceJob {
                        index_type: index_type.clone(),
                        reason: format!("safely reclaimable index versions={stale_versions}"),
                        estimated_versions_pruned: stale_versions,
                    }
                })
            })
            .collect();
        suggestions.sort_by(|a, b| {
            b.estimated_versions_pruned
                .cmp(&a.estimated_versions_pruned)
                .then_with(|| a.index_type.cmp(&b.index_type))
        });
        suggestions
    }

    /// Run one maintenance cycle: suggest stale-version compactions, execute
    /// them, and return both plan and execution output.
    pub fn run_maintenance_cycle(
        &mut self,
        stale_version_threshold: u64,
    ) -> Result<MaintenanceCycleReport> {
        self.run_maintenance_cycle_with_options(MaintenanceCycleOptions {
            stale_version_threshold,
            ..MaintenanceCycleOptions::default()
        })
    }

    pub fn run_maintenance_cycle_with_options(
        &mut self,
        options: MaintenanceCycleOptions,
    ) -> Result<MaintenanceCycleReport> {
        self.ensure_ready()?;
        let prior_sequence = self.manifest.last_sequence;
        let result = (|| {
            let suggested = self.suggest_index_compactions(options.stale_version_threshold);
            let selected: Vec<String> = suggested
                .iter()
                .take(options.max_jobs)
                .map(|job| job.index_type.clone())
                .collect();
            let executed = if selected.is_empty() {
                Vec::new()
            } else {
                self.compact_selected_indexes(&selected)?
            };
            self.manifest.maintenance_cycles_run += 1;
            self.manifest.last_maintenance_at_sequence = Some(self.manifest.last_sequence);
            self.save_manifest_metadata_only()?;
            Ok(MaintenanceCycleReport {
                suggested,
                executed,
            })
        })();
        self.finish_mutation(prior_sequence, result)
    }

    pub fn wal_path(&self) -> &Path {
        self.wal.path()
    }

    fn append_wal(&mut self, mut entry: StorageWalEntry) -> Result<u64> {
        self.append_wal_batch(std::slice::from_mut(&mut entry))?;
        Ok(entry.sequence)
    }

    fn append_wal_batch(&mut self, entries: &mut [StorageWalEntry]) -> Result<()> {
        self.ensure_ready()?;
        let count = u64::try_from(entries.len())
            .map_err(|_| PraxisError::InvalidConfig("WAL sequence count overflow".into()))?;
        let end = self
            .manifest
            .last_sequence
            .checked_add(count)
            .ok_or_else(|| PraxisError::InvalidConfig("WAL sequence exhausted".into()))?;
        let mut next = self.manifest.last_sequence;
        for entry in entries.iter_mut() {
            next += 1;
            entry.sequence = next;
        }
        let wal_bytes = entries.iter().map(estimated_wal_entry_bytes).sum();
        self.wal.append_batch(entries)?;
        self.manifest.last_sequence = end;
        self.metrics
            .wal_records
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        self.metrics
            .wal_bytes
            .fetch_add(wal_bytes, Ordering::Relaxed);
        Ok(())
    }

    fn save_manifest_metadata_only(&mut self) -> Result<()> {
        self.manifest.version += 1;
        self.manifest_store.save(&self.manifest)
    }

    fn replay_for_index(&mut self, index_type: &str) -> Result<()> {
        let Some(plugin) = self.indexes.get_mut(index_type) else {
            return Ok(());
        };
        let mut remaining = Vec::with_capacity(self.pending_replay.len());
        for entry in self.pending_replay.drain(..) {
            if entry.index_type != index_type {
                remaining.push(entry);
                continue;
            }
            match entry.operation {
                StorageWalOperation::Put => {
                    if let Some(rid) = entry.rid {
                        plugin.put_with_sequence(&entry.key, rid, entry.sequence)?;
                    }
                }
                StorageWalOperation::Delete => {
                    plugin.delete_with_sequence(&entry.key, entry.sequence)?
                }
            }
        }
        self.pending_replay = remaining;
        Ok(())
    }

    fn ensure_indexes_exist<'a>(
        &self,
        index_types: impl IntoIterator<Item = &'a str>,
    ) -> Result<()> {
        for index_type in index_types {
            if !self.indexes.contains_key(index_type) {
                return Err(PraxisError::InvalidConfig(format!(
                    "unknown index plugin: {index_type}"
                )));
            }
        }
        Ok(())
    }

    fn flush_directory_if_needed(&mut self, dirtied_entries: u64) -> Result<()> {
        self.dirty_directory_entries = self.dirty_directory_entries.saturating_add(dirtied_entries);
        if self
            .directory_sync_policy
            .should_flush(self.dirty_directory_entries)
        {
            self.store.flush()?;
            self.dirty_directory_entries = 0;
        }
        Ok(())
    }

    fn prepare_primary_compaction(&mut self) -> Result<PreparedCompaction> {
        // A relocation set is one atomic group. Validate its size before
        // compact_prepare mutates or persists any directory locations.
        let preflight = self
            .store
            .indirection
            .live_rids()
            .map(|rid| {
                Ok(StorageWalEntry {
                    sequence: 0,
                    index_type: "primary".into(),
                    key: encode_location(self.store.location(rid)?),
                    rid: Some(rid),
                    operation: StorageWalOperation::Put,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        StorageWal::validate_batch(&preflight)?;
        self.manifest
            .last_sequence
            .checked_add(
                u64::try_from(preflight.len()).map_err(|_| {
                    PraxisError::InvalidConfig("WAL sequence count overflow".into())
                })?,
            )
            .ok_or_else(|| PraxisError::InvalidConfig("WAL sequence exhausted".into()))?;
        drop(preflight);
        let job_id = compaction_job_id(self.manifest.last_sequence);
        let old_segments = self.store.live_segment_ids()?;
        self.append_manifest_edit(ManifestEdit::CompactionStarted {
            job_id: job_id.clone(),
            old_segments: old_segments.clone(),
        })?;
        let prepared = match self.store.compact_prepare() {
            Ok(prepared) => prepared,
            Err(error) => {
                // compact_prepare may have moved some in-memory mappings
                // before a later source read/IO fails, without advancing WAL.
                self.recovery_required = true;
                return Err(error);
            }
        };
        // Recovery replays the complete primary WAL, including the physical
        // locations written before compaction. Persist replacement locations
        // before installing the compaction or deleting any source segments.
        // This also makes relocation recoverable if the directory is lost.
        let mut relocations = self
            .store
            .indirection
            .live_rids()
            .map(|rid| {
                Ok(StorageWalEntry {
                    sequence: 0,
                    index_type: "primary".to_string(),
                    key: encode_location(self.store.location(rid)?),
                    rid: Some(rid),
                    operation: StorageWalOperation::Put,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        relocations.sort_by_key(|entry| entry.rid);
        self.append_wal_batch(&mut relocations)?;
        self.append_manifest_edit(ManifestEdit::CompactionInstalled {
            job_id,
            old_segments,
            new_segment: prepared.new_segment_id,
            records_retained: prepared.stats.records_retained,
            bytes_written: prepared.stats.bytes_written,
        })?;
        Ok(prepared)
    }

    fn append_manifest_edit(&mut self, edit: ManifestEdit) -> Result<()> {
        self.manifest.append_edit(edit);
        self.bump_manifest_version()
    }

    // Validation errors before any WAL/IO leave the handle usable. Once a
    // sequence is durable or an IO outcome is uncertain, errors require reopen.
    // compact_prepare and index replay also set the flag explicitly when they
    // can mutate state without advancing the sequence.
    fn finish_mutation<T>(&mut self, prior_sequence: u64, result: Result<T>) -> Result<T> {
        if result.is_err()
            && (self.manifest.last_sequence != prior_sequence
                || self.wal.requires_recovery()
                || matches!(&result, Err(PraxisError::Io(_))))
        {
            self.recovery_required = true;
        }
        result
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.recovery_required || self.wal.requires_recovery() {
            Err(PraxisError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn bump_manifest_version(&mut self) -> Result<()> {
        self.manifest.version += 1;
        self.manifest.primary_segments =
            list_files_with_ext(&self.root.join(Self::PRIMARY_DIR).join("records"), "trec")?;

        let index_dir = self.root.join(Self::INDEX_DIR);
        let all_index_files = list_all_files(&index_dir)?;
        let mut tracked_index_types = BTreeSet::new();
        tracked_index_types.extend(self.manifest.index_files.keys().cloned());
        tracked_index_types.extend(self.manifest.plugin_namespaces.keys().cloned());
        tracked_index_types.extend(self.indexes.keys().cloned());
        self.manifest.index_files.clear();
        for index_type in tracked_index_types {
            let prefix = format!("{index_type}.");
            let files = all_index_files
                .iter()
                .filter(|path| path.starts_with(&prefix))
                .cloned()
                .collect();
            self.manifest.index_files.insert(index_type.clone(), files);
        }
        rebuild_durable_inventory(&self.root, &mut self.manifest)?;
        KernelInvariantValidator::validate_durable_artifacts(&self.manifest.kernel_artifacts())?;
        self.manifest_store.save(&self.manifest)
    }
}

impl StorageKernel for StorageEngine {
    fn put_record(&mut self, bytes: &[u8]) -> Result<RecordId> {
        self.put(bytes, &[])
    }

    fn get_record(&self, rid: RecordId) -> Result<Vec<u8>> {
        self.fetch(rid)
    }

    fn delete_record(&mut self, rid: RecordId) -> Result<()> {
        StorageEngine::delete_record(self, rid)
    }

    fn storage_report(&self) -> KernelStorageReport {
        KernelStorageReport {
            live_records: self.live_count(),
            dead_records: self.dead_records(),
            canonical_live_bytes: self.canonical_live_bytes(),
        }
    }

    fn snapshot(&self) -> KernelSnapshot {
        KernelSnapshot {
            sequence: self.manifest.last_sequence,
        }
    }

    fn flush(&mut self) -> Result<()> {
        StorageEngine::flush(self)
    }

    fn compact(&mut self) -> Result<KernelCompactionReport> {
        let stats = self.compact_primary()?;
        Ok(KernelCompactionReport {
            records_retained: stats.records_retained,
            records_dropped: stats.records_dropped,
            bytes_rewritten: stats.bytes_written,
        })
    }
}

fn list_files_with_ext(dir: &Path, ext: &str) -> Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some(ext)
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            out.insert(name.to_string());
        }
    }
    Ok(out.into_iter().collect())
}

fn list_all_files(dir: &Path) -> Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            out.insert(name.to_string());
        }
    }
    Ok(out.into_iter().collect())
}

fn rebuild_durable_inventory(root: &Path, manifest: &mut StorageManifest) -> Result<()> {
    let mut files = Vec::new();
    let manifest_path = root.join(StorageEngine::MANIFEST_FILE);
    files.push(DurableFileRecord::installed(
        "store_manifest",
        manifest_path.to_string_lossy().to_string(),
        DurableFileKind::Manifest,
        1,
        "serde_json_atomic",
    ));

    let indirection_path = root
        .join(StorageEngine::PRIMARY_DIR)
        .join("indirection.tind");
    files.push(DurableFileRecord::installed(
        "record_directory",
        indirection_path.to_string_lossy().to_string(),
        DurableFileKind::RecordDirectory,
        1,
        "serde_json_atomic",
    ));

    for segment in list_files_with_ext(
        &root.join(StorageEngine::PRIMARY_DIR).join("records"),
        "trec",
    )? {
        files.push(DurableFileRecord::installed(
            format!("value_segment:{segment}"),
            root.join(StorageEngine::PRIMARY_DIR)
                .join("records")
                .join(&segment)
                .to_string_lossy()
                .to_string(),
            DurableFileKind::ValueSegment,
            1,
            "record_crc32",
        ));
    }

    for wal_file in list_files_with_ext(&root.join(StorageEngine::WAL_DIR), "swal")? {
        files.push(DurableFileRecord::installed(
            format!("wal_segment:{wal_file}"),
            root.join(StorageEngine::WAL_DIR)
                .join(&wal_file)
                .to_string_lossy()
                .to_string(),
            DurableFileKind::WalSegment,
            1,
            "record_crc32",
        ));
    }

    for index_file in list_all_files(&root.join(StorageEngine::INDEX_DIR))? {
        files.push(DurableFileRecord::installed(
            format!("index_segment:{index_file}"),
            root.join(StorageEngine::INDEX_DIR)
                .join(&index_file)
                .to_string_lossy()
                .to_string(),
            DurableFileKind::IndexSegment,
            1,
            "plugin_declared",
        ));
    }

    manifest.set_durable_files(files);
    Ok(())
}

fn reconcile_pending_compaction_cleanup(
    root: &Path,
    store: &mut RecordStore,
    manifest_store: &StorageManifestStore,
    manifest: &mut StorageManifest,
) -> Result<()> {
    let pending_aborts = manifest.pending_compaction_aborts();
    let pending_cleanups = manifest.pending_compaction_cleanups();
    if pending_aborts.is_empty() && pending_cleanups.is_empty() {
        return Ok(());
    }

    let mut updated = false;
    for compaction in pending_aborts {
        manifest.append_edit(ManifestEdit::CompactionAborted {
            job_id: compaction.job_id,
            old_segments: compaction.old_segments,
            reason: "startup_reconcile_missing_install".to_string(),
        });
        updated = true;
    }
    for compaction in pending_cleanups {
        let cleaned =
            store.complete_compaction_cleanup(&compaction.old_segments, compaction.new_segment)?;
        manifest.append_edit(ManifestEdit::CompactionCleanupComplete {
            job_id: compaction.job_id,
            cleaned_segments: cleaned,
        });
        updated = true;
    }

    if updated {
        manifest.version += 1;
        rebuild_durable_inventory(root, manifest)?;
        KernelInvariantValidator::validate_durable_artifacts(&manifest.kernel_artifacts())?;
        manifest_store.save(manifest)?;
    }
    Ok(())
}

fn compaction_job_id(last_sequence: u64) -> String {
    format!("primary-{last_sequence}")
}

fn replay_primary_directory(store: &mut RecordStore, entries: &[StorageWalEntry]) -> Result<()> {
    let mut repaired = false;
    for entry in entries {
        if entry.index_type != "primary" {
            continue;
        };
        match entry.operation {
            StorageWalOperation::Put => {
                let Some(rid) = entry.rid else {
                    continue;
                };
                let Some(location) = decode_location(&entry.key) else {
                    continue;
                };
                store.replay_primary_put(rid, location)?;
            }
            StorageWalOperation::Delete => {
                if let Some(rid) = entry.rid {
                    store.replay_primary_delete(rid)?;
                }
            }
        }
        repaired = true;
    }
    if repaired {
        store.flush()?;
    }
    Ok(())
}

fn encode_location(location: PhysicalLocation) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&location.segment_id.to_le_bytes());
    out.extend_from_slice(&location.record_offset.to_le_bytes());
    out.extend_from_slice(&location.length.to_le_bytes());
    out
}

fn decode_location(bytes: &[u8]) -> Option<PhysicalLocation> {
    if bytes.len() != 16 {
        return None;
    }

    let segment_id = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let record_offset = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    let length = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    Some(PhysicalLocation {
        segment_id,
        record_offset,
        length,
    })
}

fn estimated_wal_entry_bytes(entry: &StorageWalEntry) -> u64 {
    const WAL_RECORD_HEADER_BYTES: u64 = 8;
    WAL_RECORD_HEADER_BYTES
        + 8
        + entry.index_type.len() as u64
        + entry.key.len() as u64
        + entry.rid.map(|_| 8).unwrap_or(0)
        + 1
}

fn record_latency(tracker: &LatencyTracker, started: Instant) {
    tracker.record(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
}

#[cfg(test)]
mod atomic_group_tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn partial_compaction_relocation_error_requires_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        engine.put(b"one", &[]).unwrap();
        engine.put(b"two", &[]).unwrap();
        engine.put(b"three", &[]).unwrap();
        engine.flush().unwrap();
        // Select the second RID in the same stable in-memory iteration used by
        // compact_prepare, so one mapping moves before the corrupt read fails.
        let order: Vec<_> = engine.store.indirection.live_rids().collect();
        let loc = engine.store.location(order[1]).unwrap();
        let path = dir
            .path()
            .join("primary")
            .join("records")
            .join(format!("{:08x}.trec", loc.segment_id));
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(loc.record_offset + 8)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            engine.compact_primary(),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            engine.fetch(order[0]),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            engine.put(b"later", &[]),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(engine.flush(), Err(PraxisError::RecoveryRequired)));
        assert!(matches!(
            engine.compact_primary(),
            Err(PraxisError::RecoveryRequired)
        ));
    }
}
