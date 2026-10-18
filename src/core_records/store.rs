//! Logical RID view over the existing core owner. Numeric raw ceilings select
//! mappings at the current core view; they do not pin historical payloads.
use super::codec::{Allocator, Decision, Key, Role, Row};
use super::intent::{IntentKind, Mapping, NewRecord, RecordIntent, RecordResult};
use super::schema::corrupt;
use super::snapshot::CoreRecordSnapshot;
use crate::memory::PinnedSnapshot;
use crate::recovery::GcReport;
use crate::store::{BatchRecord, IndexInsert, RecordId};
use crate::types::ColumnFamily;
use crate::{PraxisEngine, PraxisError, Result};
use bytes::Bytes;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

/// Cloneable record view sharing the core lease, queue, health, WAL and pins.
#[derive(Clone)]
pub struct CoreRecordStore {
    engine: PraxisEngine,
}

/// Result of one requested protected-history rewrite and ordinary whole-file GC.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordHistoryReclaimReport {
    pub rewrite_performed: bool,
    pub protected_versions_removed: u64,
    pub gc: GcReport,
}

/// Limits on the new collections owned by one fixture-root State scan. The
/// underlying engine's per-key version-chain and value allocations are not
/// bounded by these limits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordScanLimits {
    max_candidate_keys: usize,
    max_raw_key_bytes: usize,
    max_candidate_key_bytes: usize,
    max_live_rows: u64,
    max_payload_bytes: u64,
}

impl RecordScanLimits {
    pub(crate) fn fixture_v1() -> Self {
        Self {
            max_candidate_keys: 65_536,
            max_raw_key_bytes: 4_096,
            max_candidate_key_bytes: 4 * 1024 * 1024,
            max_live_rows: 16_384,
            max_payload_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CoreRecordScanError {
    Storage(PraxisError),
    ResourceLimit { code: &'static str },
}

impl From<PraxisError> for CoreRecordScanError {
    fn from(error: PraxisError) -> Self {
        Self::Storage(error)
    }
}

impl CoreRecordStore {
    pub(super) fn new(engine: PraxisEngine) -> Self {
        Self { engine }
    }

    fn pin(&self) -> Result<PinnedSnapshot> {
        self.engine.inner.group_commit.ensure_writable()?;
        self.engine.try_pin_snapshot()
    }

    /// Retain the current published core view and this actual live owner.
    /// This registers one process-local pin; it is not a durability barrier.
    pub fn pin_snapshot(&self) -> Result<CoreRecordSnapshot> {
        CoreRecordSnapshot::new(self.engine.clone(), self.pin()?)
    }

    /// Fetch canonical state/payload at the held view. A live guard never expires.
    pub fn fetch_at_snapshot(
        &self,
        rid: RecordId,
        snapshot: &CoreRecordSnapshot,
    ) -> Result<Vec<u8>> {
        self.fetch_at(rid, snapshot.pin_for(&self.engine)?)
    }

    /// Resolve a mapping head at the held core view, distinct from a raw ceiling.
    pub fn lookup_rid_at_snapshot(
        &self,
        index_type: &str,
        key: &[u8],
        snapshot: &CoreRecordSnapshot,
    ) -> Result<Option<RecordId>> {
        let pin = snapshot.pin_for(&self.engine)?;
        self.lookup(&self.mapping(index_type, key, pin)?, pin)
    }

    /// Resolve head, state and payload with the same retained pin.
    pub fn fetch_by_index_at_snapshot(
        &self,
        index_type: &str,
        key: &[u8],
        snapshot: &CoreRecordSnapshot,
    ) -> Result<Option<Vec<u8>>> {
        let pin = snapshot.pin_for(&self.engine)?;
        let Some(rid) = self.lookup(&self.mapping(index_type, key, pin)?, pin)? else {
            return Ok(None);
        };
        match self.fetch_at(rid, pin) {
            Ok(value) => Ok(Some(value)),
            Err(PraxisError::KeyNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn value(&self, role: Role, key: &Key<'_>, pin: &PinnedSnapshot) -> Result<Option<Vec<u8>>> {
        self.engine.resolve_value_at_snapshot(
            &ColumnFamily(role.cf().into()),
            &key.encode()?,
            pin.sequence(),
        )
    }

    /// Validate a retained view without registering a second pin.
    pub(crate) fn validate_snapshot(&self, snapshot: &CoreRecordSnapshot) -> Result<()> {
        snapshot.pin_for(&self.engine).map(|_| ())
    }

    /// Capture all physical State keys while flush/compaction topology is
    /// stable. Every tier lock is released before any point resolution.
    fn bounded_state_candidates(
        &self,
        limits: RecordScanLimits,
    ) -> std::result::Result<BTreeSet<Bytes>, CoreRecordScanError> {
        let cf = ColumnFamily(Role::State.cf().into());
        let _topology = self.engine.inner.topology.read();
        let mut keys = BTreeSet::new();
        let mut total_bytes = 0usize;
        let mut insert = |key: &Bytes| -> std::result::Result<(), CoreRecordScanError> {
            if key.len() > limits.max_raw_key_bytes {
                return Err(CoreRecordScanError::ResourceLimit {
                    code: "raw_state_key_bytes",
                });
            }
            if keys.contains(key) {
                return Ok(());
            }
            let next_count =
                keys.len()
                    .checked_add(1)
                    .ok_or(CoreRecordScanError::ResourceLimit {
                        code: "state_candidates",
                    })?;
            if next_count > limits.max_candidate_keys {
                return Err(CoreRecordScanError::ResourceLimit {
                    code: "state_candidates",
                });
            }
            let next_bytes =
                total_bytes
                    .checked_add(key.len())
                    .ok_or(CoreRecordScanError::ResourceLimit {
                        code: "candidate_key_bytes",
                    })?;
            if next_bytes > limits.max_candidate_key_bytes {
                return Err(CoreRecordScanError::ResourceLimit {
                    code: "candidate_key_bytes",
                });
            }
            keys.insert(key.clone());
            total_bytes = next_bytes;
            Ok(())
        };
        {
            let mutable = self.engine.inner.memtable.read();
            for key in mutable.keys_in_cf(&cf) {
                insert(key)?;
            }
        }
        {
            let immutables = self.engine.inner.immutable_memtables.lock();
            for immutable in immutables.iter() {
                for key in immutable.keys_in_cf(&cf) {
                    insert(key)?;
                }
            }
        }
        {
            let segments = self.engine.inner.segment_index.read();
            for ((_, key), _) in segments
                .range((cf.clone(), Bytes::new())..)
                .take_while(|((entry_cf, _), _)| entry_cf == &cf)
            {
                insert(key)?;
            }
        }
        drop(insert);
        Ok(keys)
    }

    /// Materialize every live record from one retained State/Payload view.
    /// A late fault discards the buffered rows; no partial result is returned.
    pub(crate) fn scan_live_at_snapshot(
        &self,
        snapshot: &CoreRecordSnapshot,
        limits: RecordScanLimits,
    ) -> std::result::Result<Vec<(RecordId, Vec<u8>)>, CoreRecordScanError> {
        let pin = snapshot.pin_for(&self.engine)?;
        let allocator_key = Key::Allocator;
        let allocator_bytes = self
            .value(Role::Meta, &allocator_key, pin)?
            .ok_or_else(|| {
                corrupt(
                    self.engine.inner.layout.root(),
                    "record allocator is missing",
                )
            })?;
        let Row::Allocator(allocator) = Row::decode(
            &allocator_key,
            &allocator_bytes,
            self.engine.inner.layout.root(),
        )?
        else {
            unreachable!()
        };
        let candidate_limit = u64::try_from(limits.max_candidate_keys).map_err(|_| {
            CoreRecordScanError::ResourceLimit {
                code: "state_candidates",
            }
        })?;
        if allocator.last_rid > candidate_limit {
            return Err(CoreRecordScanError::ResourceLimit {
                code: "state_candidates",
            });
        }
        if allocator.live_count > limits.max_live_rows {
            return Err(CoreRecordScanError::ResourceLimit { code: "live_rows" });
        }
        if allocator.live_payload_bytes > limits.max_payload_bytes {
            return Err(CoreRecordScanError::ResourceLimit {
                code: "payload_bytes",
            });
        }

        let candidates = self.bounded_state_candidates(limits)?;
        #[cfg(test)]
        read_phase(ReadPhase::ScanCaptured);
        let state_cf = ColumnFamily(Role::State.cf().into());
        let mut rows = Vec::new();
        let mut visible_states = 0u64;
        let mut live_count = 0u64;
        let mut dead_count = 0u64;
        let mut live_bytes = 0u64;
        for raw_key in candidates {
            #[cfg(test)]
            read_phase(ReadPhase::ScanState);
            let Some(state_bytes) = self.engine.resolve_value_at_snapshot(
                &state_cf,
                raw_key.as_ref(),
                pin.sequence(),
            )?
            else {
                // A physical candidate first written after this pin is not
                // part of the retained view, even if its key is malformed.
                continue;
            };
            let Key::State(rid) = Key::decode(
                Role::State,
                raw_key.as_ref(),
                self.engine.inner.layout.root(),
            )?
            else {
                unreachable!()
            };
            visible_states = visible_states.checked_add(1).ok_or_else(|| {
                corrupt(
                    self.engine.inner.layout.root(),
                    "visible State count overflow",
                )
            })?;
            if rid > allocator.last_rid || rid != visible_states {
                return Err(corrupt(
                    self.engine.inner.layout.root(),
                    "visible State RIDs disagree with held allocator",
                )
                .into());
            }
            let Row::State {
                live,
                payload_length,
            } = Row::decode(
                &Key::State(rid),
                &state_bytes,
                self.engine.inner.layout.root(),
            )?
            else {
                unreachable!()
            };
            if live {
                live_count = live_count.checked_add(1).ok_or_else(|| {
                    corrupt(self.engine.inner.layout.root(), "live State count overflow")
                })?;
                if live_count > limits.max_live_rows {
                    return Err(CoreRecordScanError::ResourceLimit { code: "live_rows" });
                }
                live_bytes = live_bytes.checked_add(payload_length).ok_or_else(|| {
                    corrupt(
                        self.engine.inner.layout.root(),
                        "live payload byte count overflow",
                    )
                })?;
                if live_bytes > limits.max_payload_bytes {
                    return Err(CoreRecordScanError::ResourceLimit {
                        code: "payload_bytes",
                    });
                }
                #[cfg(test)]
                read_phase(ReadPhase::ScanPayload);
                let payload_key = Key::Payload(rid);
                let payload_bytes =
                    self.value(Role::Payload, &payload_key, pin)?
                        .ok_or_else(|| {
                            corrupt(
                                self.engine.inner.layout.root(),
                                "live RID has no canonical payload",
                            )
                        })?;
                let Row::Payload(payload) = Row::decode(
                    &payload_key,
                    &payload_bytes,
                    self.engine.inner.layout.root(),
                )?
                else {
                    unreachable!()
                };
                let actual_length = u64::try_from(payload.len()).map_err(|_| {
                    CoreRecordScanError::ResourceLimit {
                        code: "payload_bytes",
                    }
                })?;
                if actual_length != payload_length {
                    return Err(corrupt(
                        self.engine.inner.layout.root(),
                        "live RID payload length disagrees with state",
                    )
                    .into());
                }
                rows.push((RecordId(rid), payload.to_vec()));
            } else {
                dead_count = dead_count.checked_add(1).ok_or_else(|| {
                    corrupt(self.engine.inner.layout.root(), "dead State count overflow")
                })?;
            }
        }
        if visible_states != allocator.last_rid
            || live_count != allocator.live_count
            || dead_count != allocator.dead_count
            || live_bytes != allocator.live_payload_bytes
        {
            return Err(corrupt(
                self.engine.inner.layout.root(),
                "visible State counts or bytes disagree with held allocator",
            )
            .into());
        }
        #[cfg(test)]
        read_phase(ReadPhase::ScanBeforeReturn);
        self.validate_snapshot(snapshot)?;
        Ok(rows)
    }

    /// Gather only matching tier keys while topology is coherent, then release
    /// every tier/topology guard before calling the point resolver.
    fn keys(&self, role: Role, lower: Vec<u8>, upper: Vec<u8>) -> BTreeSet<Bytes> {
        let cf = ColumnFamily(role.cf().into());
        let lower = Bytes::from(lower);
        let upper = Bytes::from(upper);
        let _topology = self.engine.inner.topology.read();
        let mut keys = BTreeSet::new();
        keys.extend(
            self.engine
                .inner
                .memtable
                .read()
                .keys_in_range(&cf, &lower, &upper)
                .cloned(),
        );
        for immutable in self.engine.inner.immutable_memtables.lock().iter() {
            keys.extend(immutable.keys_in_range(&cf, &lower, &upper).cloned());
        }
        keys.extend(
            self.engine
                .inner
                .segment_index
                .read()
                .range((cf.clone(), lower)..=(cf, upper))
                .map(|((_, key), _)| key.clone()),
        );
        keys
    }

    fn descriptor(&self, name: &str, pin: &PinnedSnapshot) -> Result<u32> {
        // Validated immutable registry IDs are contiguous and names are sorted.
        // u64 exclusive bounds handle the full u32 range in at most 32 probes.
        let count = self
            .engine
            .inner
            .manifest
            .lock()
            .record_authority
            .as_ref()
            .expect("record view requires validated authority")
            .index_descriptor_count;
        let (mut lower, mut upper) = (1u64, u64::from(count) + 1);
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let index = middle as u32;
            let key = Key::Descriptor(index);
            let bytes = self.value(Role::Meta, &key, pin)?.ok_or_else(|| {
                corrupt(
                    self.engine.inner.layout.root(),
                    "mapping descriptor is missing",
                )
            })?;
            let Row::Descriptor { name: stored, .. } =
                Row::decode(&key, &bytes, self.engine.inner.layout.root())?
            else {
                unreachable!()
            };
            match stored.as_bytes().cmp(name.as_bytes()) {
                std::cmp::Ordering::Equal => return Ok(index),
                std::cmp::Ordering::Less => lower = middle + 1,
                std::cmp::Ordering::Greater => upper = middle,
            }
        }
        Err(PraxisError::InvalidConfig(format!(
            "unknown record mapping descriptor: {name}"
        )))
    }

    fn mapping(&self, name: &str, key: &[u8], pin: &PinnedSnapshot) -> Result<Mapping> {
        Ok(Mapping {
            index: self.descriptor(name, pin)?,
            key: key.to_vec(),
        })
    }

    fn mappings(&self, inserts: &[IndexInsert], pin: &PinnedSnapshot) -> Result<Vec<Mapping>> {
        inserts
            .iter()
            .map(|insert| self.mapping(&insert.index_type, &insert.key, pin))
            .collect()
    }

    fn submit(&self, kind: IntentKind) -> Result<RecordResult> {
        let receipt = self.engine.commit_record(RecordIntent::new(kind)?)?;
        // A postcommit maintenance failure is ambiguous, as for the KV view.
        if self.engine.inner.memtable.read().approximate_bytes()
            >= self.engine.inner.config.memtable_flush_threshold_bytes
        {
            self.engine.flush()?;
            self.engine
                .inner
                .metrics
                .automatic_flushes
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(receipt.result)
    }

    pub fn put(&self, value: &[u8], index_inserts: &[IndexInsert]) -> Result<RecordId> {
        let ids = self.put_batch(&[BatchRecord::new(value, index_inserts)])?;
        Ok(ids[0])
    }

    pub fn put_batch(&self, records: &[BatchRecord<'_>]) -> Result<Vec<RecordId>> {
        let pin = self.pin()?;
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let inputs = records
            .iter()
            .map(|record| {
                Ok(NewRecord {
                    payload: record.value.to_vec(),
                    mappings: self.mappings(record.index_inserts, &pin)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        drop(pin);
        match self.submit(IntentKind::Create(inputs))? {
            RecordResult::Created(ids) => Ok(ids),
            _ => unreachable!(),
        }
    }

    pub fn put_index(&self, index_type: &str, key: &[u8], rid: RecordId) -> Result<()> {
        let pin = self.pin()?;
        let mapping = self.mapping(index_type, key, &pin)?;
        drop(pin);
        self.submit(IntentKind::IndexPut(mapping, rid))?;
        Ok(())
    }

    pub fn delete_index(&self, index_type: &str, key: &[u8]) -> Result<()> {
        let pin = self.pin()?;
        let mapping = self.mapping(index_type, key, &pin)?;
        drop(pin);
        self.submit(IntentKind::IndexDelete(mapping))?;
        Ok(())
    }

    fn lookup(&self, mapping: &Mapping, pin: &PinnedSnapshot) -> Result<Option<RecordId>> {
        let key = Key::Head {
            index: mapping.index,
            incarnation: 1,
            key: &mapping.key,
        };
        let Some(bytes) = self.value(Role::Index, &key, pin)? else {
            return Ok(None);
        };
        let Row::Head { decision, .. } =
            Row::decode(&key, &bytes, self.engine.inner.layout.root())?
        else {
            unreachable!()
        };
        #[cfg(test)]
        read_phase(ReadPhase::Head);
        Ok(match decision {
            Decision::Put(rid) => Some(RecordId(rid)),
            Decision::Delete => None,
        })
    }

    pub fn lookup_rid(&self, index_type: &str, key: &[u8]) -> Result<Option<RecordId>> {
        let pin = self.pin()?;
        self.lookup(&self.mapping(index_type, key, &pin)?, &pin)
    }

    /// Mapping-only raw ceiling at one current core pin. No historical payload
    /// visibility or numeric late pin is created by this operation.
    pub fn lookup_rid_at(
        &self,
        index_type: &str,
        key: &[u8],
        sequence: u64,
    ) -> Result<Option<RecordId>> {
        let pin = self.pin()?;
        let index = self.descriptor(index_type, &pin)?;
        let bound = |raw_sequence| {
            Key::Fact {
                index,
                incarnation: 1,
                key,
                raw_sequence,
            }
            .encode()
        };
        let mut last: Option<(u64, Decision)> = None;
        #[cfg(test)]
        read_phase(ReadPhase::RangeKeys);
        for encoded in self.keys(Role::Index, bound(0)?, bound(sequence)?) {
            let decoded = Key::decode(Role::Index, &encoded, self.engine.inner.layout.root())?;
            let Key::Fact {
                index: found,
                incarnation: 1,
                key: found_key,
                raw_sequence,
            } = decoded
            else {
                return Err(corrupt(
                    self.engine.inner.layout.root(),
                    "mapping range has a foreign key",
                ));
            };
            if found != index || found_key != key || raw_sequence > sequence {
                return Err(corrupt(
                    self.engine.inner.layout.root(),
                    "mapping range escaped its bounds",
                ));
            }
            // Tier key capture can include a concurrent fact published after
            // this pin. It legitimately has no visible version at the pin.
            let Some(bytes) = self.value(Role::Index, &decoded, &pin)? else {
                continue;
            };
            let Row::Fact {
                append_ordinal,
                decision,
            } = Row::decode(&decoded, &bytes, self.engine.inner.layout.root())?
            else {
                unreachable!()
            };
            if last.is_none_or(|(ordinal, _)| append_ordinal > ordinal) {
                last = Some((append_ordinal, decision));
            }
        }
        Ok(match last.map(|(_, decision)| decision) {
            Some(Decision::Put(rid)) => Some(RecordId(rid)),
            _ => None,
        })
    }

    fn fetch_at(&self, rid: RecordId, pin: &PinnedSnapshot) -> Result<Vec<u8>> {
        if rid.0 == 0 {
            return Err(PraxisError::KeyNotFound);
        }
        let key = Key::State(rid.0);
        let Some(bytes) = self.value(Role::State, &key, pin)? else {
            return Err(PraxisError::KeyNotFound);
        };
        let Row::State {
            live,
            payload_length,
        } = Row::decode(&key, &bytes, self.engine.inner.layout.root())?
        else {
            unreachable!()
        };
        if !live {
            return Err(PraxisError::KeyNotFound);
        }
        #[cfg(test)]
        read_phase(ReadPhase::State);
        let key = Key::Payload(rid.0);
        let bytes = self.value(Role::Payload, &key, pin)?.ok_or_else(|| {
            corrupt(
                self.engine.inner.layout.root(),
                "live RID has no canonical payload",
            )
        })?;
        let Row::Payload(payload) = Row::decode(&key, &bytes, self.engine.inner.layout.root())?
        else {
            unreachable!()
        };
        if payload.len() as u64 != payload_length {
            return Err(corrupt(
                self.engine.inner.layout.root(),
                "live RID payload length disagrees with state",
            ));
        }
        Ok(payload.to_vec())
    }

    pub fn fetch(&self, rid: RecordId) -> Result<Vec<u8>> {
        self.fetch_at(rid, &self.pin()?)
    }

    pub fn fetch_by_index(&self, index_type: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let pin = self.pin()?;
        let mapping = self.mapping(index_type, key, &pin)?;
        let Some(rid) = self.lookup(&mapping, &pin)? else {
            return Ok(None);
        };
        match self.fetch_at(rid, &pin) {
            Ok(value) => Ok(Some(value)),
            Err(PraxisError::KeyNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn delete_record(&self, rid: RecordId) -> Result<()> {
        self.delete_records(&[rid])
    }

    pub fn delete_records(&self, ids: &[RecordId]) -> Result<()> {
        self.engine.inner.group_commit.ensure_writable()?;
        if ids.is_empty() {
            return Ok(());
        }
        self.submit(IntentKind::DeleteRecords(ids.to_vec()))?;
        Ok(())
    }

    pub fn delete_record_with_index_cleanup(
        &self,
        rid: RecordId,
        keys: &[IndexInsert],
    ) -> Result<()> {
        let pin = self.pin()?;
        let mappings = self.mappings(keys, &pin)?;
        drop(pin);
        self.submit(IntentKind::Cleanup(rid, mappings))?;
        Ok(())
    }

    pub fn delete_by_index(&self, index_type: &str, key: &[u8]) -> Result<Option<RecordId>> {
        let pin = self.pin()?;
        let mapping = self.mapping(index_type, key, &pin)?;
        drop(pin);
        match self.submit(IntentKind::DeleteByIndex(mapping))? {
            RecordResult::DeletedByIndex(rid) => Ok(rid),
            _ => unreachable!(),
        }
    }

    fn allocator(&self) -> Result<Allocator> {
        let pin = self.pin()?;
        let key = Key::Allocator;
        let bytes = self.value(Role::Meta, &key, &pin)?.ok_or_else(|| {
            corrupt(
                self.engine.inner.layout.root(),
                "record allocator is missing",
            )
        })?;
        let Row::Allocator(value) = Row::decode(&key, &bytes, self.engine.inner.layout.root())?
        else {
            unreachable!()
        };
        Ok(value)
    }

    pub fn live_count(&self) -> Result<u64> {
        Ok(self.allocator()?.live_count)
    }
    pub fn live_bytes(&self) -> Result<u64> {
        Ok(self.allocator()?.live_payload_bytes)
    }
    pub fn dead_records(&self) -> Result<u64> {
        Ok(self.allocator()?.dead_count)
    }
    /// Fresh logical entry watermark, distinct from the core commit sequence
    /// and legacy physical relocation sequence domain.
    pub fn compatibility_sequence(&self) -> Result<u64> {
        Ok(self.allocator()?.compatibility_sequence)
    }

    pub fn flush(&self) -> Result<()> {
        self.engine.durable_barrier()?;
        self.engine.flush()?;
        Ok(())
    }

    /// Remove protected versions needed by neither the latest view nor any
    /// registered core pin. Physical bytes are reclaimed only by whole-file GC.
    pub fn reclaim_snapshot_history(&self) -> Result<RecordHistoryReclaimReport> {
        self.engine.inner.group_commit.ensure_writable()?;
        self.engine.durable_barrier()?;
        self.engine.reclaim_record_snapshot_history()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadPhase {
    Head,
    State,
    RangeKeys,
    ScanCaptured,
    ScanState,
    ScanPayload,
    ScanBeforeReturn,
}
#[cfg(test)]
type ReadHook = Box<dyn Fn(ReadPhase)>;
#[cfg(test)]
thread_local! { static READ_HOOK: std::cell::RefCell<Option<ReadHook>> = std::cell::RefCell::new(None); }
#[cfg(test)]
fn read_phase(phase: ReadPhase) {
    READ_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(phase);
        }
    });
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
