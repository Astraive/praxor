use super::group_commit::{CommitLeader, CommitTurn, GroupCommitCoordinator, WriteCondition};
use super::state::{CacheKey, EngineInner};
use crate::accel::gpu::GpuBackendKind;
use crate::accel::{Accelerator, CpuAccelerator, GpuAccelerator};
use crate::cache::BlockCache;
use crate::config::{AcceleratorBackend, PersistedEngineConfig, PraxisConfig};
use crate::disk::DiskLayout;
use crate::engine::compaction::{job_state, planner};
use crate::errors::{PraxisError, Result};
use crate::io::{IoRateLimiter, resolve_io_execution};
use crate::maintenance::MaintenanceScheduler;
use crate::manifest::{
    CheckpointMetadata, ColumnFamilyDescriptor, ColumnFamilyGeneration, ColumnFamilyOptions,
    CompactionJobStatus, ManifestStore,
};
use crate::memory::{MemTable, SnapshotManager};
use crate::metrics::EngineMetrics;
use crate::recovery::{GcReport, RecoveryReport, write_checkpoint_with_policy};
use crate::segments::{SegmentReader, SegmentWriteOptions, SegmentWriter};
use crate::slog;
use crate::transactions::OptimisticTransaction;
use crate::transactions::{BatchOp, WriteBatch};
use crate::types::{
    ColumnFamily, Key, ReadSnapshot, SequenceNumber, StoredValue, Value, VersionedValue,
};
use crate::values::ValueLog;
use crate::wal::{Wal, WalRecord};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PraxisEngine {
    pub(crate) inner: Arc<EngineInner>,
}

#[cfg(test)]
#[path = "engine/cf_generation_tests.rs"]
mod cf_generation_tests;

impl PraxisEngine {
    pub fn open(config: PraxisConfig) -> Result<Self> {
        config.validate()?;
        slog::Logger::init(config.logging.clone());
        let accelerator: Arc<dyn Accelerator> = match config.accelerator {
            AcceleratorBackend::Cpu => Arc::new(CpuAccelerator),
            AcceleratorBackend::Cuda => Arc::new(GpuAccelerator::new(GpuBackendKind::Cuda)),
            AcceleratorBackend::Vulkan => Arc::new(GpuAccelerator::new(GpuBackendKind::Vulkan)),
            AcceleratorBackend::Metal => Arc::new(GpuAccelerator::new(GpuBackendKind::Metal)),
        };
        let layout = DiskLayout::create(&config.data_dir)?;
        let manifest_store = ManifestStore::new(layout.manifest_path());
        let mut manifest = manifest_store.load_or_create(&config)?;
        if manifest.effective_config != config.persisted() {
            return Err(PraxisError::ConfigMismatch(
                "open config differs from persisted effective engine config".to_string(),
            ));
        }
        if job_state::reconcile_unfinished_jobs(&mut manifest) {
            manifest_store.save_with_policy(&manifest, config.direct_io)?;
        }
        let mut segment_index: BTreeMap<(ColumnFamily, Key), Vec<crate::types::VersionedValue>> =
            BTreeMap::new();
        let active_generations = &manifest.column_family_generations;
        for segment in &manifest.segments {
            let entries = SegmentReader::read(
                std::path::Path::new(&segment.path),
                accelerator.as_ref(),
                config.direct_io,
            )?;
            let mut groups = BTreeMap::<(ColumnFamily, Key), Vec<VersionedValue>>::new();
            for entry in entries {
                if !active_generations
                    .get(&entry.cf.0)
                    .is_some_and(|generation| generation.includes(entry.version.sequence))
                {
                    continue;
                }
                groups
                    .entry((entry.cf, entry.key))
                    .or_default()
                    .push(entry.version);
            }
            for (key, versions) in groups {
                // A legacy WAL overlap may have been flushed into a later
                // segment. Prefer that segment's complete batch group, while
                // preserving repeated same-sequence operands inside the group.
                let sequences = versions
                    .iter()
                    .map(|version| version.sequence)
                    .collect::<std::collections::BTreeSet<_>>();
                let chain = segment_index.entry(key).or_default();
                chain.retain(|version| !sequences.contains(&version.sequence));
                chain.extend(versions);
                chain.sort_by_key(|version| version.sequence);
            }
        }
        let wal_records = Wal::replay_dir(&layout.wal_root())?;
        let mut memtable = MemTable::default();
        let snapshots = Arc::new(SnapshotManager::default());
        for record in &wal_records {
            // Retired operations are invisible, but their durable sequence IDs
            // must never be reused, including records below a flush cutoff.
            snapshots.observe(record.sequence);
            if record.sequence <= manifest.flushed_sequence
                && !(record.sequence == 0 && manifest.flushed_sequence == 0)
            {
                continue;
            }
            for op in record.batch.ops() {
                let cf = match op {
                    BatchOp::Put { cf, .. }
                    | BatchOp::PutWithExpiry { cf, .. }
                    | BatchOp::Merge { cf, .. }
                    | BatchOp::Delete { cf, .. } => cf,
                };
                if !active_generations
                    .get(&cf.0)
                    .is_some_and(|generation| generation.includes(record.sequence))
                {
                    continue;
                }
                if manifest.flushed_sequence == 0 {
                    // Legacy flushes retained WALs without a durable cutoff.
                    // Prefer the complete WAL batch over its persisted copies;
                    // keep every operation within that batch, even at one sequence.
                    let (cf, key) = match op {
                        BatchOp::Put { cf, key, .. }
                        | BatchOp::PutWithExpiry { cf, key, .. }
                        | BatchOp::Merge { cf, key, .. }
                        | BatchOp::Delete { cf, key } => (cf, key),
                    };
                    if let Some(versions) =
                        segment_index.get_mut(&(cf.clone(), Bytes::copy_from_slice(key)))
                    {
                        versions.retain(|version| version.sequence != record.sequence);
                    }
                }
                memtable.apply(record.sequence, op);
            }
        }
        snapshots.observe(manifest.last_sequence);
        snapshots.observe(manifest.flushed_sequence);
        // WAL-only commits can be newer than the persisted manifest. Carry
        // their recovered watermark into future structural checkpoints before
        // those checkpoints retire the WAL containing the original sequence.
        manifest.last_sequence = snapshots.snapshot().sequence;
        let wal = Wal::open(
            layout.wal_path(manifest.active_wal_id),
            manifest.active_wal_id,
            config.wal_sync_policy,
        )?;
        let metrics = EngineMetrics::default();
        metrics
            .recovered_records
            .store(wal_records.len() as u64, Ordering::Relaxed);
        let engine = Self {
            inner: Arc::new(EngineInner {
                cache: Mutex::new(BlockCache::new(config.cache_size_bytes)),
                cache_bytes_by_cf: Mutex::new(BTreeMap::new()),
                scheduler: Mutex::new(MaintenanceScheduler::new(
                    config.maintenance_queue_capacity,
                    config.maintenance_retry_limit,
                )),
                runtime: Mutex::new(crate::maintenance::MaintenanceRuntimeController::default()),
                group_commit: GroupCommitCoordinator::new(config.wal_segment_size),
                config,
                layout,
                manifest_store,
                write_serialization: Mutex::new(()),
                maintenance_serialization: parking_lot::ReentrantMutex::new(()),
                topology: RwLock::new(()),
                manifest: Mutex::new(manifest),
                wal: Mutex::new(wal),
                memtable: RwLock::new(memtable),
                segment_index: RwLock::new(segment_index),
                immutable_memtables: Mutex::new(Vec::new()),
                snapshots,
                metrics,
                accelerator,
            }),
        };
        slog::info(
            "engine_open",
            slog::context().with_str("outcome", "success").with_str(
                "data_dir",
                engine.inner.layout.root().to_string_lossy().to_string(),
            ),
        );
        Ok(engine)
    }

    pub fn open_from_file(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open(PraxisConfig::from_file(path)?)
    }

    pub fn effective_config(&self) -> PersistedEngineConfig {
        self.inner.manifest.lock().effective_config.clone()
    }

    pub fn put(&self, key: impl Into<Key>, value: impl Into<Value>) -> Result<SequenceNumber> {
        let mut batch = WriteBatch::new();
        batch.put_default(key, value);
        self.write_batch(batch)
    }

    pub fn delete(&self, key: impl Into<Key>) -> Result<SequenceNumber> {
        let mut batch = WriteBatch::new();
        batch.delete_default(key);
        self.write_batch(batch)
    }

    pub fn put_with_ttl(
        &self,
        key: impl Into<Key>,
        value: impl Into<Value>,
        ttl_seconds: u64,
    ) -> Result<SequenceNumber> {
        let mut batch = WriteBatch::new();
        let expires_at_ms = now_millis().saturating_add(ttl_seconds.saturating_mul(1000));
        batch.put_with_expiry(ColumnFamily::default(), key, value, expires_at_ms);
        self.write_batch(batch)
    }

    pub fn merge(
        &self,
        cf: impl Into<ColumnFamily>,
        key: impl Into<Key>,
        value: impl Into<Value>,
    ) -> Result<SequenceNumber> {
        let mut batch = WriteBatch::new();
        batch.merge(cf, key, value);
        self.write_batch(batch)
    }

    pub fn compare_and_swap(
        &self,
        key: impl Into<Key>,
        expected: Option<&[u8]>,
        value: impl Into<Value>,
    ) -> Result<SequenceNumber> {
        let key = key.into();
        let mut batch = WriteBatch::new();
        batch.put_default(key.clone(), value);
        self.write_batch_conditioned(
            batch,
            WriteCondition::CompareAndSwap {
                key,
                expected: expected.map(<[u8]>::to_vec),
            },
        )
    }

    pub fn begin_transaction(&self) -> OptimisticTransaction {
        OptimisticTransaction::new(self.clone(), self.pin_snapshot())
    }

    pub(crate) fn commit_optimistic_transaction(
        &self,
        snapshot: ReadSnapshot,
        batch: WriteBatch,
    ) -> Result<SequenceNumber> {
        self.write_batch_conditioned(batch, WriteCondition::Optimistic { snapshot })
    }

    pub fn write_batch(&self, batch: WriteBatch) -> Result<SequenceNumber> {
        self.write_batch_conditioned(batch, WriteCondition::Unconditional)
    }

    fn validate_write_condition(
        &self,
        condition: &WriteCondition,
        batch: &WriteBatch,
    ) -> Result<()> {
        self.validate_batch_column_families(batch)?;
        match condition {
            WriteCondition::Unconditional => Ok(()),
            WriteCondition::CompareAndSwap { key, expected } => {
                let current = self.resolve_value_at_snapshot(
                    &ColumnFamily::default(),
                    key,
                    self.snapshot().sequence,
                )?;
                if current.as_deref() == expected.as_deref() {
                    Ok(())
                } else {
                    Err(PraxisError::CompareAndSwapFailed)
                }
            }
            WriteCondition::Optimistic { snapshot } => {
                self.validate_transaction_conflicts(*snapshot, batch)
            }
        }
    }

    fn write_batch_conditioned(
        &self,
        batch: WriteBatch,
        condition: WriteCondition,
    ) -> Result<SequenceNumber> {
        let started = std::time::Instant::now();
        self.inner.group_commit.ensure_writable()?;
        if batch.is_empty() {
            let _writer = self.inner.write_serialization.lock();
            self.inner.group_commit.ensure_writable()?;
            self.validate_write_condition(&condition, &batch)?;
            return Ok(self.snapshot().sequence);
        }
        let (batch, generations) = self.normalize_batch_with_cf_policies(batch)?;
        let encoded_len = WalRecord::checked_encoded_batch_len(&batch)?;
        self.relieve_l0_pressure_before_write()?;
        let ops = batch.len();
        let request = self.inner.group_commit.admit(
            batch,
            generations,
            condition,
            encoded_len,
            &self.inner.metrics,
        )?;
        let sequence = loop {
            match self.inner.group_commit.wait(&request) {
                CommitTurn::Complete(result) => break result?,
                CommitTurn::Lead(leader) => self.commit_closed_group(leader),
            }
        };
        // Leadership was handed off before automatic maintenance. Preserve the
        // existing contract: a postcommit flush failure can return an error.
        if self.inner.memtable.read().approximate_bytes()
            >= self.inner.config.memtable_flush_threshold_bytes
        {
            self.flush()?;
            self.inner
                .metrics
                .automatic_flushes
                .fetch_add(1, Ordering::Relaxed);
        }
        slog::info(
            "write_batch",
            slog::context()
                .with_u64("seq", sequence)
                .with_u64("ops", ops as u64)
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(sequence)
    }

    fn commit_closed_group(&self, leader: CommitLeader<'_>) {
        let writer = self.inner.write_serialization.lock();
        // Rebind after the writer guard so unwind poisoning runs before the
        // writer mutex can be handed to flush/GC or another leader.
        let leader = leader;
        if self.inner.group_commit.ensure_writable().is_err() {
            leader.fail("core storage handle already requires recovery".to_string());
            return;
        }
        let group = leader.drain(self.inner.config.wal_sync_policy, &self.inner.metrics);
        let mut results = Vec::with_capacity(group.len());
        let mut valid = Vec::new();
        for request in &group {
            match self
                .validate_captured_generations(&request.generations)
                .and_then(|()| self.validate_write_condition(&request.condition, &request.batch))
            {
                Ok(()) => {
                    results.push(Ok(0));
                    valid.push(request);
                }
                Err(error) => results.push(Err(error)),
            }
        }
        if valid.is_empty() {
            leader.finish(results);
            drop(writer);
            return;
        }
        let Some(last_sequence) = self.snapshot().sequence.checked_add(valid.len() as u64) else {
            for result in &mut results {
                if result.is_ok() {
                    *result = Err(PraxisError::WriteStalled {
                        reason: "sequence space exhausted".to_string(),
                    });
                }
            }
            leader.finish(results);
            drop(writer);
            return;
        };
        let bytes = valid.iter().map(|request| request.encoded_len).sum();
        if let Err(error) = self.rotate_wal_if_needed(bytes) {
            if self.inner.group_commit.ensure_writable().is_err() {
                leader.fail(error.to_string());
            } else {
                // A failure opening the prospective WAL leaves the original
                // WAL/manifest authoritative and is safe to retry.
                for result in &mut results {
                    if result.is_ok() {
                        *result = Err(PraxisError::Io(std::io::Error::other(error.to_string())));
                    }
                }
                leader.finish(results);
                drop(writer);
            }
            return;
        }
        let first_sequence = last_sequence - valid.len() as u64 + 1;
        let write_result = (|| -> Result<()> {
            let mut wal = self.inner.wal.lock();
            for (index, request) in valid.iter().enumerate() {
                wal.append_unsynced(&WalRecord {
                    sequence: first_sequence + index as u64,
                    batch: request.batch.clone(),
                })?;
            }
            if !matches!(
                self.inner.config.wal_sync_policy,
                crate::config::WalSyncPolicy::Never
            ) {
                let started = std::time::Instant::now();
                self.inner
                    .metrics
                    .commit_sync_attempts
                    .fetch_add(1, Ordering::Relaxed);
                let sync_result = wal.sync();
                self.inner.metrics.commit_sync_ns.fetch_add(
                    started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                    Ordering::Relaxed,
                );
                sync_result?;
                self.inner
                    .metrics
                    .commit_syncs
                    .fetch_add(1, Ordering::Release);
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            self.inner
                .metrics
                .write_errors
                .fetch_add(valid.len() as u64, Ordering::Relaxed);
            slog::error(
                "core_commit_failed",
                slog::context()
                    .with_str("reason", error.to_string())
                    .with_str("outcome", "recovery_required"),
            );
            leader.fail(error.to_string());
            return;
        }
        {
            let mut memtable = self.inner.memtable.write();
            for (index, request) in valid.iter().enumerate() {
                let sequence = first_sequence + index as u64;
                for op in request.batch.ops() {
                    memtable.apply(sequence, op);
                    match op {
                        BatchOp::Delete { .. } => {
                            self.inner.metrics.deletes.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            self.inner.metrics.writes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            self.inner.snapshots.observe(last_sequence);
            self.inner
                .metrics
                .memtable_bytes
                .store(memtable.approximate_bytes() as u64, Ordering::Relaxed);
        }
        self.inner.manifest.lock().last_sequence = last_sequence;
        self.inner
            .metrics
            .wal_records
            .fetch_add(valid.len() as u64, Ordering::Relaxed);
        self.inner
            .metrics
            .commit_groups
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .metrics
            .commit_batches
            .fetch_add(valid.len() as u64, Ordering::Relaxed);
        let mut sequence = first_sequence;
        for result in &mut results {
            if result.is_ok() {
                *result = Ok(sequence);
                sequence = sequence.saturating_add(1);
            }
        }
        leader.finish(results);
        drop(writer);
    }

    fn validate_captured_generations(&self, captured: &BTreeMap<String, u64>) -> Result<()> {
        let manifest = self.inner.manifest.lock();
        for (name, id) in captured {
            if manifest
                .column_family_generations
                .get(name)
                .map(|generation| generation.id)
                != Some(*id)
            {
                return Err(PraxisError::WriteStalled {
                    reason: format!(
                        "column family {name:?} was dropped or replaced while its write was pending; retry the entire batch"
                    ),
                });
            }
        }
        Ok(())
    }

    fn normalize_batch_with_cf_policies(
        &self,
        batch: WriteBatch,
    ) -> Result<(WriteBatch, BTreeMap<String, u64>)> {
        let mut options = BTreeMap::new();
        let mut generations = BTreeMap::new();
        {
            // Capture policy and incarnation in one manifest view, without the
            // writer mutex. Followers can still accumulate behind that mutex.
            let manifest = self.inner.manifest.lock();
            for op in batch.ops() {
                let cf = match op {
                    BatchOp::Put { cf, .. }
                    | BatchOp::PutWithExpiry { cf, .. }
                    | BatchOp::Merge { cf, .. }
                    | BatchOp::Delete { cf, .. } => cf,
                };
                if options.contains_key(&cf.0) {
                    continue;
                }
                let descriptor = manifest
                    .column_families
                    .iter()
                    .find(|descriptor| descriptor.name == cf.0)
                    .ok_or_else(|| PraxisError::UnknownColumnFamily(cf.0.clone()))?;
                let generation =
                    manifest
                        .column_family_generations
                        .get(&cf.0)
                        .ok_or_else(|| PraxisError::Corrupt {
                            path: self.inner.manifest_store.path().to_path_buf(),
                            reason: "active column family has no incarnation metadata".to_string(),
                        })?;
                options.insert(cf.0.clone(), descriptor.options.clone());
                generations.insert(cf.0.clone(), generation.id);
            }
        }
        let mut normalized = WriteBatch::new();
        for op in batch.ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    if let Some(ttl_seconds) = options.get(&cf.0).and_then(|cf| cf.ttl_seconds) {
                        let expires_at_ms = now_millis().saturating_add(ttl_seconds * 1000);
                        normalized.put_with_expiry(
                            cf.clone(),
                            Bytes::copy_from_slice(key),
                            Bytes::copy_from_slice(value),
                            expires_at_ms,
                        );
                    } else {
                        normalized.put(
                            cf.clone(),
                            Bytes::copy_from_slice(key),
                            Bytes::copy_from_slice(value),
                        );
                    }
                }
                BatchOp::PutWithExpiry {
                    cf,
                    key,
                    value,
                    expires_at_ms,
                } => {
                    normalized.put_with_expiry(
                        cf.clone(),
                        Bytes::copy_from_slice(key),
                        Bytes::copy_from_slice(value),
                        *expires_at_ms,
                    );
                }
                BatchOp::Merge { cf, key, value } => {
                    normalized.merge(
                        cf.clone(),
                        Bytes::copy_from_slice(key),
                        Bytes::copy_from_slice(value),
                    );
                }
                BatchOp::Delete { cf, key } => {
                    normalized.delete(cf.clone(), Bytes::copy_from_slice(key));
                }
            };
        }
        Ok((normalized, generations))
    }

    fn rotate_wal_if_needed(&self, next_record_len: usize) -> Result<()> {
        let should_rotate = self
            .inner
            .wal
            .lock()
            .should_rotate(next_record_len, self.inner.config.wal_segment_size);
        if !should_rotate {
            return Ok(());
        }
        self.install_new_active_wal()
    }

    fn install_new_active_wal(&self) -> Result<()> {
        if let Err(error) = self.inner.wal.lock().sync() {
            self.inner.group_commit.poison(error.to_string());
            return Err(PraxisError::RecoveryRequired);
        }
        let mut manifest = self.inner.manifest.lock();
        let new_wal_id = manifest.next_wal_id;
        let new_wal = Wal::open(
            self.inner.layout.wal_path(new_wal_id),
            new_wal_id,
            self.inner.config.wal_sync_policy,
        )?;
        let mut installed = manifest.clone();
        installed.active_wal_id = new_wal_id;
        installed.next_wal_id += 1;
        if let Err(error) = self
            .inner
            .manifest_store
            .save_with_policy(&installed, self.inner.config.direct_io)
        {
            self.inner.group_commit.poison(error.to_string());
            return Err(PraxisError::RecoveryRequired);
        }
        *self.inner.wal.lock() = new_wal;
        *manifest = installed;
        Ok(())
    }

    /// Reclaim only WAL files covered by a durably installed flush.
    fn gc_old_wals(&self) {
        let manifest = self.inner.manifest.lock();
        let cutoff = manifest.flushed_wal_id;
        let active_id = manifest.active_wal_id;
        drop(manifest);
        if let Ok(entries) = fs::read_dir(self.inner.layout.wal_root()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("wal") {
                    continue;
                }
                if let Some(id) = path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.parse::<u64>().ok())
                    && id <= cutoff
                    && id != active_id
                {
                    fs::remove_file(path).ok();
                }
            }
        }
    }

    fn relieve_l0_pressure_before_write(&self) -> Result<()> {
        let l0_count = self.l0_segment_count();
        if l0_count < self.inner.config.l0_slowdown_segments {
            return Ok(());
        }
        self.inner
            .metrics
            .write_stalls
            .fetch_add(1, Ordering::Relaxed);
        self.compact()?;
        self.inner
            .metrics
            .l0_pressure_compactions
            .fetch_add(1, Ordering::Relaxed);
        let l0_count = self.l0_segment_count();
        if l0_count >= self.inner.config.l0_stop_segments {
            return Err(PraxisError::WriteStalled {
                reason: format!(
                    "level-0 segment count {l0_count} exceeds hard stop {}",
                    self.inner.config.l0_stop_segments
                ),
            });
        }
        Ok(())
    }

    fn l0_segment_count(&self) -> usize {
        self.inner
            .manifest
            .lock()
            .segments
            .iter()
            .filter(|segment| segment.level == 0)
            .count()
    }

    pub fn create_column_family(&self, mut descriptor: ColumnFamilyDescriptor) -> Result<()> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        if descriptor.name == ColumnFamily::default().0 {
            return Ok(());
        }
        if descriptor.options == ColumnFamilyOptions::default() {
            descriptor.options.memtable_kind = self.inner.config.default_memtable_kind;
            descriptor.options.compaction_strategy = self.inner.config.default_compaction_strategy;
        }
        let mut manifest = self.inner.manifest.lock();
        if manifest
            .column_families
            .iter()
            .any(|existing| existing.name == descriptor.name)
        {
            return Err(PraxisError::ColumnFamilyExists(descriptor.name));
        }
        let name = descriptor.name.clone();
        let mut installed = manifest.clone();
        let id = installed.next_column_family_generation;
        installed.next_column_family_generation =
            id.checked_add(1).ok_or_else(|| PraxisError::WriteStalled {
                reason: "column-family generation space exhausted".to_string(),
            })?;
        installed.column_family_generations.insert(
            name.clone(),
            ColumnFamilyGeneration {
                id,
                visible_after_sequence: self.snapshot().sequence,
            },
        );
        installed.column_families.push(descriptor);
        if let Err(error) = self
            .inner
            .manifest_store
            .save_with_policy(&installed, self.inner.config.direct_io)
        {
            self.inner.group_commit.poison(error.to_string());
            slog::error(
                "core_cf_transition_failed",
                slog::context()
                    .with_str("cf", name)
                    .with_str("operation", "create")
                    .with_str("reason", error.to_string())
                    .with_str("outcome", "recovery_required"),
            );
            return Err(PraxisError::RecoveryRequired);
        }
        *manifest = installed;
        Ok(())
    }

    pub fn drop_column_family(&self, name: &str) -> Result<()> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        let _topology = self.inner.topology.write();
        if name == ColumnFamily::default().0 {
            return Err(PraxisError::CannotDropDefaultColumnFamily);
        }
        // Check CF exists and remove from manifest
        {
            let mut manifest = self.inner.manifest.lock();
            let mut installed = manifest.clone();
            let original_len = installed.column_families.len();
            installed
                .column_families
                .retain(|family| family.name != name);
            if installed.column_families.len() == original_len {
                return Err(PraxisError::UnknownColumnFamily(name.to_string()));
            }
            installed.column_family_generations.remove(name);
            if let Err(error) = self
                .inner
                .manifest_store
                .save_with_policy(&installed, self.inner.config.direct_io)
            {
                self.inner.group_commit.poison(error.to_string());
                slog::error(
                    "core_cf_transition_failed",
                    slog::context()
                        .with_str("cf", name)
                        .with_str("operation", "drop")
                        .with_str("reason", error.to_string())
                        .with_str("outcome", "recovery_required"),
                );
                return Err(PraxisError::RecoveryRequired);
            }
            *manifest = installed;
        }

        let cf = ColumnFamily(name.to_string());

        // Remove from memtable
        {
            let mut mt = self.inner.memtable.write();
            mt.remove_cf(&cf);
        }

        // Remove from immutable memtables
        {
            let mut immutables = self.inner.immutable_memtables.lock();
            for imm in immutables.iter_mut() {
                imm.remove_cf(&cf);
            }
        }

        // Remove from segment_index
        {
            let mut si = self.inner.segment_index.write();
            si.retain(|(k_cf, _), _| k_cf != &cf);
        }

        // Remove from cache
        {
            let cf_name = name.to_string();
            let mut cache = self.inner.cache.lock();
            cache.retain(|key: &CacheKey| key.0 != cf_name);
        }

        // Remove from cache_bytes_by_cf
        {
            let mut by_cf = self.inner.cache_bytes_by_cf.lock();
            by_cf.remove(name);
        }

        Ok(())
    }

    pub fn list_column_families(&self) -> Vec<ColumnFamilyDescriptor> {
        self.inner.manifest.lock().column_families.clone()
    }

    pub fn column_family(&self, name: &str) -> Result<ColumnFamily> {
        let cf = ColumnFamily(name.to_string());
        self.ensure_column_family(&cf)?;
        Ok(cf)
    }

    fn validate_batch_column_families(&self, batch: &WriteBatch) -> Result<()> {
        for op in batch.ops() {
            let cf = match op {
                BatchOp::Put { cf, .. }
                | BatchOp::PutWithExpiry { cf, .. }
                | BatchOp::Merge { cf, .. }
                | BatchOp::Delete { cf, .. } => cf,
            };
            self.ensure_column_family(cf)?;
        }
        Ok(())
    }

    fn validate_transaction_conflicts(
        &self,
        snapshot: ReadSnapshot,
        batch: &WriteBatch,
    ) -> Result<()> {
        for op in batch.ops() {
            let (cf, key) = match op {
                BatchOp::Put { cf, key, .. }
                | BatchOp::PutWithExpiry { cf, key, .. }
                | BatchOp::Merge { cf, key, .. }
                | BatchOp::Delete { cf, key } => (cf, key),
            };
            if self.latest_sequence_for_key(cf, key)? > snapshot.sequence {
                return Err(PraxisError::TransactionConflict {
                    cf: cf.0.clone(),
                    key: String::from_utf8_lossy(key).to_string(),
                });
            }
        }
        Ok(())
    }

    fn latest_sequence_for_key(&self, cf: &ColumnFamily, key: &[u8]) -> Result<SequenceNumber> {
        self.ensure_column_family(cf)?;
        let memtable_sequence = self
            .inner
            .memtable
            .read()
            .latest_sequence(cf, key)
            .unwrap_or_default();
        let immutable_sequence = self
            .inner
            .immutable_memtables
            .lock()
            .iter()
            .filter_map(|imm| imm.latest_sequence(cf, key))
            .max()
            .unwrap_or_default();
        let segment_sequence = self
            .inner
            .segment_index
            .read()
            .get(&(cf.clone(), Bytes::copy_from_slice(key)))
            .and_then(|versions| versions.last())
            .map(|version| version.sequence)
            .unwrap_or_default();
        Ok(memtable_sequence
            .max(immutable_sequence)
            .max(segment_sequence))
    }

    pub(crate) fn ensure_column_family(&self, cf: &ColumnFamily) -> Result<()> {
        if self
            .inner
            .manifest
            .lock()
            .column_families
            .iter()
            .any(|family| family.name == cf.0)
        {
            Ok(())
        } else {
            Err(PraxisError::UnknownColumnFamily(cf.0.clone()))
        }
    }

    pub fn flush(&self) -> Result<Option<u64>> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let started = std::time::Instant::now();
        // Lock order: maintenance -> writer -> topology -> tier locks. New
        // writes use a fresh WAL while the frozen tables remain readable.
        let (flushed_wal_id, flushed_sequence) = {
            let _writer = self.inner.write_serialization.lock();
            self.inner.group_commit.ensure_writable()?;
            let _topology = self.inner.topology.write();
            let mut mt = self.inner.memtable.write();
            let mut immutables = self.inner.immutable_memtables.lock();
            if mt.is_empty() && immutables.is_empty() {
                return Ok(None);
            }
            let wal_id = self.inner.wal.lock().segment_id();
            // Do not freeze the table unless a new WAL can be installed.
            self.install_new_active_wal()?;
            if !mt.is_empty() {
                immutables.push(std::mem::take(&mut *mt));
            }
            (wal_id, self.snapshot().sequence)
        };
        let segment_entries = self
            .inner
            .immutable_memtables
            .lock()
            .iter()
            .flat_map(MemTable::versions)
            .map(|(cf, key, version)| crate::segments::block::SegmentEntry { cf, key, version })
            .collect::<Vec<_>>();
        let segment_id = {
            let mut manifest = self.inner.manifest.lock();
            let id = manifest.next_segment_id;
            manifest.next_segment_id += 1;
            id
        };
        let path = self.inner.layout.segment_path(0, segment_id);
        let mut value_log = ValueLog::open(self.inner.layout.value_log_path(segment_id))?;
        let cf_options = self.cf_options_map();
        let partitioned_bloom = infer_partitioned_bloom(&segment_entries, &cf_options);
        let mut limiter = IoRateLimiter::new(self.inner.config.flush_rate_limit_bytes_per_sec);
        limiter.consume(segment_entries.len() * 256);
        let compression = effective_segment_compression(
            &segment_entries,
            &cf_options,
            self.inner.config.compression,
        );
        let metadata = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
                id: segment_id,
                level: 0,
                compression,
                accelerator: self.inner.accelerator.as_ref(),
                value_log: &mut value_log,
                large_value_threshold: self.inner.config.large_value_threshold,
                block_size: self.inner.config.block_size,
                partitioned_bloom,
                direct_io: self.inner.config.direct_io,
            },
            segment_entries.clone(),
        )?;
        let flushed_entries = metadata.entries;
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        {
            // Readers hold the topology guard through value resolution. Install
            // disk state and retire its immutable sources as one transition.
            let _topology = self.inner.topology.write();
            let mut manifest = self.inner.manifest.lock();
            let mut installed = manifest.clone();
            installed.segments.push(metadata);
            installed.flushed_sequence = flushed_sequence;
            installed.flushed_wal_id = flushed_wal_id;
            self.inner
                .manifest_store
                .save_with_policy(&installed, self.inner.config.direct_io)?;
            let mut index = self.inner.segment_index.write();
            for entry in segment_entries {
                index
                    .entry((entry.cf, entry.key))
                    .or_default()
                    .push(entry.version);
            }
            self.inner.immutable_memtables.lock().clear();
            *manifest = installed;
        }
        self.inner.metrics.memtable_bytes.store(
            self.inner.memtable.read().approximate_bytes() as u64,
            Ordering::Relaxed,
        );
        self.gc_old_wals();
        self.inner
            .metrics
            .segment_flushes
            .fetch_add(1, Ordering::Relaxed);
        slog::info(
            "flush",
            slog::context()
                .with_u64("segment_id", segment_id)
                .with_u64("entries", flushed_entries)
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(Some(segment_id))
    }

    pub fn compact(&self) -> Result<u64> {
        self.compact_with_strategy(self.inner.config.default_compaction_strategy)
    }

    pub fn compact_with_strategy(
        &self,
        strategy: crate::config::CompactionStrategy,
    ) -> Result<u64> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let started = std::time::Instant::now();
        self.flush()?;
        let plan = self.pick_compaction_plan(strategy);
        let target_level = plan.target_level;
        if plan.source_segment_ids.is_empty() {
            return Ok(0);
        }
        // This implementation rewrites the entire resident segment index, so
        // every represented segment must be retired to avoid replaying merges twice.
        let source_segment_ids = self
            .inner
            .manifest
            .lock()
            .segments
            .iter()
            .map(|segment| segment.id)
            .collect::<Vec<_>>();
        let (job_id, segment_id) =
            self.begin_compaction_job(strategy, source_segment_ids.clone())?;
        self.mark_compaction_job_running(job_id)?;
        let latest_sequence = self.snapshot().sequence;
        let pinned_snapshots = self.inner.snapshots.pinned_sequences();
        let mut compacted = Vec::new();
        let cf_options = self.cf_options_map();
        for ((cf, key), versions) in self.inner.segment_index.read().iter() {
            let strategy = cf_options
                .get(&cf.0)
                .map(|options| options.compaction_strategy)
                .unwrap_or(self.inner.config.default_compaction_strategy);
            compacted.extend(self.compaction_retained_versions(
                cf,
                key,
                versions,
                latest_sequence,
                &pinned_snapshots,
                strategy,
            ));
        }
        if compacted.is_empty() {
            let _writer = self.inner.write_serialization.lock();
            self.inner.group_commit.ensure_writable()?;
            let _topology = self.inner.topology.write();
            let mut manifest = self.inner.manifest.lock();
            let mut installed = manifest.clone();
            installed
                .segments
                .retain(|segment| !source_segment_ids.contains(&segment.id));
            job_state::finish_job(&mut installed, job_id, None, CompactionJobStatus::Installed);
            self.inner
                .manifest_store
                .save_with_policy(&installed, self.inner.config.direct_io)?;
            self.inner.segment_index.write().clear();
            *manifest = installed;
            return Ok(0);
        }
        let path = self.inner.layout.segment_path(target_level, segment_id);
        crate::io::create_dir_all_durable(path.parent().expect("segment path has parent"))?;
        let mut value_log = ValueLog::open(self.inner.layout.value_log_path(segment_id))?;
        let mut compaction_limiter =
            IoRateLimiter::new(self.inner.config.compaction_rate_limit_bytes_per_sec);
        compaction_limiter.consume(compacted.len() * 256);
        let partitioned_bloom = infer_partitioned_bloom(&compacted, &cf_options);
        let compression =
            effective_segment_compression(&compacted, &cf_options, self.inner.config.compression);
        let metadata = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
                id: segment_id,
                level: target_level,
                compression,
                accelerator: self.inner.accelerator.as_ref(),
                value_log: &mut value_log,
                large_value_threshold: self.inner.config.large_value_threshold,
                block_size: self.inner.config.block_size,
                partitioned_bloom,
                direct_io: self.inner.config.direct_io,
            },
            compacted,
        )?;
        let compacted_entries = metadata.entries;
        let loaded = SegmentReader::read(
            &path,
            self.inner.accelerator.as_ref(),
            self.inner.config.direct_io,
        )?;
        let mut rebuilt = BTreeMap::new();
        for entry in loaded {
            rebuilt
                .entry((entry.cf, entry.key))
                .or_insert_with(Vec::new)
                .push(entry.version);
        }
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        let _topology = self.inner.topology.write();
        {
            let mut manifest = self.inner.manifest.lock();
            let mut installed = manifest.clone();
            installed
                .segments
                .retain(|segment| !source_segment_ids.contains(&segment.id));
            installed.segments.push(metadata);
            job_state::finish_job(
                &mut installed,
                job_id,
                Some(segment_id),
                CompactionJobStatus::Installed,
            );
            self.inner
                .manifest_store
                .save_with_policy(&installed, self.inner.config.direct_io)?;
            *self.inner.segment_index.write() = rebuilt;
            *manifest = installed;
        }
        slog::info(
            "compact",
            slog::context()
                .with_u64("new_segments", 1)
                .with_u64("entries", compacted_entries)
                .with_u64("target_level", target_level as u64)
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(1)
    }

    fn begin_compaction_job(
        &self,
        strategy: crate::config::CompactionStrategy,
        source_segment_ids: Vec<u64>,
    ) -> Result<(u64, u64)> {
        let mut manifest = self.inner.manifest.lock();
        let output_segment_id = manifest.next_segment_id;
        manifest.next_segment_id += 1;
        let id = job_state::reserve_compaction_job(
            &mut manifest,
            strategy,
            source_segment_ids,
            output_segment_id,
        );
        self.inner
            .manifest_store
            .save_with_policy(&manifest, self.inner.config.direct_io)?;
        Ok((id, output_segment_id))
    }

    fn mark_compaction_job_running(&self, job_id: u64) -> Result<()> {
        let mut manifest = self.inner.manifest.lock();
        job_state::mark_running(&mut manifest, job_id);
        self.inner
            .manifest_store
            .save_with_policy(&manifest, self.inner.config.direct_io)
    }

    fn pick_compaction_plan(
        &self,
        strategy: crate::config::CompactionStrategy,
    ) -> planner::CompactionPlan {
        let manifest = self.inner.manifest.lock();
        planner::pick_compaction_plan(strategy, &manifest.segments)
    }

    fn compaction_retained_versions(
        &self,
        cf: &ColumnFamily,
        key: &Key,
        versions: &[VersionedValue],
        latest_sequence: SequenceNumber,
        pinned_snapshots: &[SequenceNumber],
        strategy: crate::config::CompactionStrategy,
    ) -> Vec<crate::segments::block::SegmentEntry> {
        // Keep complete operand chains for current and pinned views. An expired
        // value is still a deletion barrier, so never filter it before resolution.
        let mut keep = std::collections::BTreeSet::new();
        if matches!(strategy, crate::config::CompactionStrategy::Tiered) {
            keep.extend(0..versions.len());
        } else {
            for snapshot in std::iter::once(&latest_sequence).chain(pinned_snapshots.iter()) {
                let Some(mut index) = versions.iter().rposition(|v| v.sequence <= *snapshot) else {
                    continue;
                };
                loop {
                    keep.insert(index);
                    if !matches!(versions[index].value, StoredValue::Merge(_)) || index == 0 {
                        break;
                    }
                    index -= 1;
                }
            }
        }
        keep.into_iter()
            .map(|index| crate::segments::block::SegmentEntry {
                cf: cf.clone(),
                key: key.clone(),
                version: versions[index].clone(),
            })
            .collect()
    }

    pub(crate) fn resolve_value_at_snapshot(
        &self,
        cf: &ColumnFamily,
        key: &[u8],
        snapshot: SequenceNumber,
    ) -> Result<Option<Vec<u8>>> {
        let _topology = self.inner.topology.read();
        let mut chain = self
            .inner
            .segment_index
            .read()
            .get(&(cf.clone(), Bytes::copy_from_slice(key)))
            .cloned()
            .unwrap_or_default();
        chain.extend(self.inner.memtable.read().versions_for_key(cf, key));
        for imm in self.inner.immutable_memtables.lock().iter() {
            chain.extend(imm.versions_for_key(cf, key));
        }
        chain.sort_by_key(|version| version.sequence);
        self.resolve_versions_chain(cf, &chain, snapshot)
    }

    pub(crate) fn resolve_versions_chain(
        &self,
        cf: &ColumnFamily,
        chain: &[VersionedValue],
        snapshot: SequenceNumber,
    ) -> Result<Option<Vec<u8>>> {
        let merge_operator = self
            .cf_options_map()
            .get(&cf.0)
            .and_then(|options| options.merge_operator.clone())
            .unwrap_or_else(|| "append_bytes".to_string());
        let mut state = None::<Vec<u8>>;
        for version in chain.iter().filter(|version| version.sequence <= snapshot) {
            match version.value {
                StoredValue::Put(ref value) => state = Some(value.clone()),
                StoredValue::PutWithExpiry {
                    ref value,
                    expires_at_ms,
                } => {
                    if expires_at_ms > now_millis() {
                        state = Some(value.clone());
                    } else {
                        state = None;
                    }
                }
                StoredValue::Merge(ref delta) => {
                    let base = state.as_deref().unwrap_or(&[]);
                    state = apply_merge_operator(&merge_operator, base, delta);
                }
                StoredValue::Delete => state = None,
                StoredValue::BlobPointer(ref pointer) => {
                    state = Some(ValueLog::read_pointer(pointer)?);
                }
            }
        }
        Ok(state)
    }

    pub(crate) fn cf_options_map(&self) -> BTreeMap<String, ColumnFamilyOptions> {
        self.inner
            .manifest
            .lock()
            .column_families
            .iter()
            .map(|descriptor| (descriptor.name.clone(), descriptor.options.clone()))
            .collect()
    }

    pub fn checkpoint(&self) -> Result<CheckpointMetadata> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let started = std::time::Instant::now();
        self.flush()?;
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        let checkpoint_id = self.snapshot().sequence;
        let path = self.inner.layout.checkpoint_path(checkpoint_id);
        let checkpoint = {
            let manifest = self.inner.manifest.lock();
            write_checkpoint_with_policy(
                &path,
                checkpoint_id,
                &manifest,
                self.inner.config.direct_io,
            )?
        };
        {
            let mut manifest = self.inner.manifest.lock();
            manifest.latest_checkpoint = Some(checkpoint.clone());
            self.inner
                .manifest_store
                .save_with_policy(&manifest, self.inner.config.direct_io)?;
        }
        self.inner
            .metrics
            .checkpoints
            .fetch_add(1, Ordering::Relaxed);
        slog::info(
            "checkpoint",
            slog::context()
                .with_u64("id", checkpoint.id)
                .with_u64("sequence", checkpoint.sequence)
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(checkpoint)
    }

    pub fn garbage_collect(&self) -> Result<GcReport> {
        let _maintenance = self.inner.maintenance_serialization.lock();
        let _writer = self.inner.write_serialization.lock();
        self.inner.group_commit.ensure_writable()?;
        let _topology = self.inner.topology.write();
        let started = std::time::Instant::now();
        let manifest = self.inner.manifest.lock().clone();
        let mut live_files = HashSet::new();
        for segment in &manifest.segments {
            live_files.insert(PathBuf::from(&segment.path));
            live_files.insert(self.inner.layout.value_log_path(segment.id));
        }
        // Record payloads can point into value logs owned by older segments.
        for versions in self.inner.segment_index.read().values() {
            for version in versions {
                if let StoredValue::BlobPointer(pointer) = &version.value {
                    live_files.insert(PathBuf::from(&pointer.path));
                }
            }
        }
        for entry in fs::read_dir(self.inner.layout.wal_root())? {
            let path = entry?.path();
            if let Some(id) = path
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<u64>().ok())
                && (id > manifest.flushed_wal_id || id == manifest.active_wal_id)
            {
                live_files.insert(path);
            }
        }
        if let Some(checkpoint) = &manifest.latest_checkpoint {
            live_files.insert(PathBuf::from(&checkpoint.path));
        }

        let mut report = GcReport::default();
        self.collect_stale_files(
            &self.inner.layout.segment_root(),
            "tseg",
            &live_files,
            &mut report,
        )?;
        self.collect_stale_files(
            &self.inner.layout.value_root(),
            "tval",
            &live_files,
            &mut report,
        )?;
        self.collect_stale_files(
            &self.inner.layout.wal_root(),
            "wal",
            &live_files,
            &mut report,
        )?;

        self.inner
            .metrics
            .garbage_collections
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .metrics
            .gc_files_reclaimed
            .fetch_add(report.files_reclaimed, Ordering::Relaxed);
        self.inner
            .metrics
            .gc_bytes_reclaimed
            .fetch_add(report.bytes_reclaimed, Ordering::Relaxed);
        slog::info(
            "garbage_collect",
            slog::context()
                .with_u64("files_reclaimed", report.files_reclaimed)
                .with_u64("bytes_reclaimed", report.bytes_reclaimed)
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(report)
    }

    pub fn verify(&self) -> Result<crate::recovery::VerificationReport> {
        let manifest = self.inner.manifest.lock().clone();
        let mut report = crate::recovery::VerificationReport {
            manifest_generation: manifest.next_segment_id,
            segments_checked: 0,
            checkpoints_checked: 0,
            value_logs_checked: 0,
            bytes_checked: 0,
        };
        for segment in &manifest.segments {
            let path = PathBuf::from(&segment.path);
            let metadata = std::fs::metadata(&path)?;
            let digest = crate::io::file_digest(&path)?.to_hex().to_string();
            if digest != segment.file_digest {
                return Err(PraxisError::Corrupt {
                    path,
                    reason: "segment digest mismatch".to_string(),
                });
            }
            report.segments_checked += 1;
            report.bytes_checked += metadata.len();
            let value_log_path = self.inner.layout.value_log_path(segment.id);
            if value_log_path.exists() {
                report.value_logs_checked += 1;
                report.bytes_checked += std::fs::metadata(value_log_path)?.len();
            }
        }
        if let Some(checkpoint) = &manifest.latest_checkpoint {
            let path = PathBuf::from(&checkpoint.path);
            let metadata = std::fs::metadata(&path)?;
            let digest = crate::io::file_digest(&path)?.to_hex().to_string();
            if digest != checkpoint.file_digest {
                return Err(PraxisError::Corrupt {
                    path,
                    reason: "checkpoint digest mismatch".to_string(),
                });
            }
            report.checkpoints_checked += 1;
            report.bytes_checked += metadata.len();
        }
        Ok(report)
    }

    pub fn backup_to(&self, backup_dir: impl AsRef<Path>) -> Result<()> {
        let started = std::time::Instant::now();
        self.checkpoint()?;
        let backup_dir = backup_dir.as_ref();
        if backup_dir.exists() {
            fs::remove_dir_all(backup_dir)?;
        }
        fs::create_dir_all(backup_dir)?;
        copy_dir_recursive(self.inner.layout.root(), backup_dir)?;
        slog::info(
            "backup_complete",
            slog::context()
                .with_str("backup_dir", backup_dir.to_string_lossy().to_string())
                .with_u64("duration_ms", started.elapsed().as_millis() as u64)
                .with_str("outcome", "success"),
        );
        Ok(())
    }

    pub fn restore_from_backup(
        backup_dir: impl AsRef<Path>,
        target_dir: impl AsRef<Path>,
    ) -> Result<()> {
        let backup_dir = backup_dir.as_ref();
        let target_dir = target_dir.as_ref();
        if !backup_dir.exists() {
            return Err(PraxisError::InvalidConfig(format!(
                "backup directory does not exist: {}",
                backup_dir.to_string_lossy()
            )));
        }
        if target_dir.exists() {
            fs::remove_dir_all(target_dir)?;
        }
        fs::create_dir_all(target_dir)?;
        copy_dir_recursive(backup_dir, target_dir)?;
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.flush().map(|_| ())
    }

    fn collect_stale_files(
        &self,
        root: &Path,
        extension: &str,
        live_files: &HashSet<PathBuf>,
        report: &mut GcReport,
    ) -> Result<()> {
        if !root.exists() {
            return Ok(());
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some(extension) {
                    continue;
                }
                if live_files.contains(&path) {
                    continue;
                }
                let len = entry.metadata()?.len();
                std::fs::remove_file(&path)?;
                report.files_reclaimed += 1;
                report.bytes_reclaimed += len;
            }
        }
        Ok(())
    }

    pub fn recover(&self) -> RecoveryReport {
        RecoveryReport {
            wal_records_replayed: self.inner.metrics.recovered_records.load(Ordering::Relaxed),
            last_sequence: self.snapshot().sequence,
            segment_count: self.inner.manifest.lock().segments.len() as u64,
        }
    }

    pub fn stats(&self) -> serde_json::Value {
        let maintenance = self.maintenance_status();
        serde_json::json!({
            "accelerator": self.inner.accelerator.name(),
            "effective_config": self.effective_config(),
            "metrics": self.inner.metrics.snapshot(),
            "write_state": { "recovery_required": self.inner.group_commit.ensure_writable().is_err() },
            "manifest": &*self.inner.manifest.lock(),
            "active_wal": self.active_wal_stats(),
            "snapshots": {
                "pinned_count": self.inner.snapshots.pinned_count(),
                "oldest_pinned_sequence": self.inner.snapshots.oldest_pinned_sequence(),
            },
            "maintenance": {
                "queue_len": maintenance.queued.len(),
                "failed_jobs": maintenance.failed.len(),
                "queued": maintenance.queued,
                "running": maintenance.running,
                "failed": maintenance.failed,
                "capacity": maintenance.capacity,
                "retry_limit": maintenance.retry_limit,
                "runtime": maintenance.runtime,
            },
            "cache": {
                "bytes_by_cf": self.inner.cache_bytes_by_cf.lock().clone(),
            },
            "io": serde_json::json!({
                "capability": crate::io::detect_io_capability(),
                "execution": resolve_io_execution(self.inner.config.direct_io),
            }),
            "data_dir": self.inner.layout.root(),
        })
    }

    fn active_wal_stats(&self) -> serde_json::Value {
        let wal = self.inner.wal.lock();
        serde_json::json!({
            "id": wal.segment_id(),
            "path": wal.path().to_string_lossy(),
        })
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn apply_merge_operator(name: &str, current: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    match name {
        "sum_i64" => {
            let left = if current.is_empty() {
                0_i64
            } else {
                i64::from_le_bytes(current.try_into().ok()?)
            };
            let right = i64::from_le_bytes(delta.try_into().ok()?);
            Some((left + right).to_le_bytes().to_vec())
        }
        "max_u64" => {
            let left = if current.is_empty() {
                0_u64
            } else {
                u64::from_le_bytes(current.try_into().ok()?)
            };
            let right = u64::from_le_bytes(delta.try_into().ok()?);
            Some(left.max(right).to_le_bytes().to_vec())
        }
        _ => {
            let mut merged = Vec::with_capacity(current.len() + delta.len());
            merged.extend_from_slice(current);
            merged.extend_from_slice(delta);
            Some(merged)
        }
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let src = entry.path();
        let dst = destination.join(entry.file_name());
        if src.is_dir() {
            fs::create_dir_all(&dst)?;
            copy_dir_recursive(&src, &dst)?;
        } else {
            fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

fn infer_partitioned_bloom(
    entries: &[crate::segments::block::SegmentEntry],
    cf_options: &BTreeMap<String, ColumnFamilyOptions>,
) -> Option<(usize, usize)> {
    let first_cf = entries.first()?.cf.0.clone();
    if entries.iter().any(|entry| entry.cf.0 != first_cf) {
        return None;
    }
    let prefix_len = cf_options.get(&first_cf)?.prefix_extractor_len?;
    if prefix_len == 0 || entries.iter().any(|entry| entry.key.len() < prefix_len) {
        return None;
    }
    Some((prefix_len, 16))
}

fn effective_segment_compression(
    entries: &[crate::segments::block::SegmentEntry],
    cf_options: &BTreeMap<String, ColumnFamilyOptions>,
    default: crate::config::Compression,
) -> crate::config::Compression {
    let Some(first_cf) = entries.first().map(|entry| entry.cf.0.as_str()) else {
        return default;
    };
    if entries.iter().any(|entry| entry.cf.0 != first_cf) {
        return default;
    }
    cf_options
        .get(first_cf)
        .and_then(|options| options.compression_override)
        .unwrap_or(default)
}

impl Clone for PraxisEngine {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl crate::disk::PoiesisStorageAdapter for PraxisEngine {
    fn put_page_value(&self, key: Key, value: Value) -> Result<SequenceNumber> {
        self.put(key, value)
    }

    fn read_page_value(&self, key: &[u8], snapshot: ReadSnapshot) -> Result<Option<Value>> {
        self.get_cf(&ColumnFamily::default(), key, snapshot)
    }

    fn write_kv_batch(&self, batch: WriteBatch) -> Result<SequenceNumber> {
        self.write_batch(batch)
    }

    fn flush_durable(&self) -> Result<()> {
        self.flush().map(|_| ())
    }
}
