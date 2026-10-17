use praxis::store::StorageEngine;
use praxis::{BTreeIndex, IndexPlugin, IndexSnapshotCapability, LsmIndex, RecordId};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::tempdir;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Lsm,
    Btree,
}

impl Kind {
    fn open(self, dir: &Path) -> Box<dyn IndexPlugin> {
        match self {
            Self::Lsm => Box::new(LsmIndex::open("snapshot", dir).unwrap()),
            Self::Btree => Box::new(BTreeIndex::open("snapshot", dir).unwrap()),
        }
    }
    fn file(self) -> &'static str {
        match self {
            Self::Lsm => "snapshot.lsm",
            Self::Btree => "snapshot.btidx",
        }
    }
    fn magic(self) -> u32 {
        match self {
            Self::Lsm => 0x4c53_4d32,
            Self::Btree => 0x4254_5232,
        }
    }
}

type History = Vec<(u64, Option<RecordId>)>;

// Independent model: visit original appends forward and replace the candidate
// whenever an eligible append is encountered. Do not prune/sort the input.
fn model(history: &[(u64, Option<RecordId>)], ceiling: u64) -> Option<RecordId> {
    let mut result = None;
    for &(sequence, rid) in history {
        if sequence <= ceiling {
            result = rid;
        }
    }
    result
}

fn ceilings(history: &[(u64, Option<RecordId>)]) -> BTreeSet<u64> {
    let mut ceilings = BTreeSet::from([0, u64::MAX - 1, u64::MAX]);
    for &(sequence, _) in history {
        ceilings.insert(sequence);
        if sequence > 0 {
            ceilings.insert(sequence - 1);
        }
        if sequence < u64::MAX {
            ceilings.insert(sequence + 1);
        }
    }
    ceilings
}

fn visible_append_count(history: &[(u64, Option<RecordId>)]) -> u64 {
    ceilings(history)
        .into_iter()
        .filter_map(|ceiling| {
            let mut selected = None;
            for (index, (sequence, _)) in history.iter().enumerate() {
                if *sequence <= ceiling {
                    selected = Some(index);
                }
            }
            selected
        })
        .collect::<BTreeSet<_>>()
        .len() as u64
}

fn append(index: &mut dyn IndexPlugin, history: &[(u64, Option<RecordId>)]) {
    for &(sequence, rid) in history {
        match rid {
            Some(rid) => index.put_with_sequence(b"key", rid, sequence).unwrap(),
            None => index.delete_with_sequence(b"key", sequence).unwrap(),
        }
    }
}

fn assert_reads(index: &dyn IndexPlugin, history: &[(u64, Option<RecordId>)]) {
    for ceiling in ceilings(history) {
        assert_eq!(
            index.get_at(b"key", ceiling),
            model(history, ceiling),
            "ceiling={ceiling}, original history={history:?}"
        );
    }
    assert_eq!(index.get(b"key"), model(history, u64::MAX));
    assert_eq!(index.get_at(b"absent", u64::MAX), None);
}

#[test]
fn compact_flush_and_binary_reopen_preserve_every_snapshot_mapping() {
    let traces: Vec<History> = vec![
        vec![
            (10, Some(RecordId(1))),
            (20, Some(RecordId(2))),
            (30, None),
            (40, Some(RecordId(3))),
        ],
        vec![(0, Some(RecordId(1))), (10, Some(RecordId(2))), (20, None)],
        vec![
            (u64::MAX, Some(RecordId(9))),
            (10, Some(RecordId(1))),
            (20, None),
            (20, Some(RecordId(2))),
            (5, Some(RecordId(3))),
            (30, None),
            (u64::MAX, Some(RecordId(4))),
        ],
        vec![(u64::MAX, Some(RecordId(1)))],
        vec![(u64::MAX, None)],
        vec![],
    ];
    for kind in [Kind::Lsm, Kind::Btree] {
        for history in &traces {
            let dir = tempdir().unwrap();
            let mut index = kind.open(dir.path());
            append(index.as_mut(), history);
            assert_reads(index.as_ref(), history);
            index.flush().unwrap();
            index.compact().unwrap();
            assert_reads(index.as_ref(), history);
            assert_eq!(
                index.stats().versions,
                visible_append_count(history),
                "retained append decisions for {kind:?}: {history:?}"
            );
            index.flush().unwrap();
            let bytes = std::fs::read(dir.path().join(kind.file())).unwrap();
            assert_eq!(&bytes[..4], &kind.magic().to_le_bytes());
            assert_eq!(bytes[4], 1);
            drop(index);
            let mut index = kind.open(dir.path());
            assert_reads(index.as_ref(), history);
            let retained = index.stats().versions;
            index.compact().unwrap();
            assert_eq!(index.stats().versions, retained);
            assert_reads(index.as_ref(), history);
        }
    }
}

#[test]
fn randomized_public_histories_match_model_before_and_after_compaction() {
    let mut random = 0x3f71_8d0b_29ce_44a5u64;
    for kind in [Kind::Lsm, Kind::Btree] {
        for _ in 0..96 {
            let dir = tempdir().unwrap();
            let mut index = kind.open(dir.path());
            let mut history = Vec::new();
            for append_index in 0..48 {
                random = random
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let sequence = match random % 13 {
                    0 => 0,
                    1 => u64::MAX,
                    _ => (random >> 24) % 64,
                };
                let rid = (random & 7 != 0).then_some(RecordId(append_index + 1));
                history.push((sequence, rid));
            }
            append(index.as_mut(), &history);
            assert_reads(index.as_ref(), &history);
            index.compact().unwrap();
            assert_reads(index.as_ref(), &history);
            assert_eq!(index.stats().versions, visible_append_count(&history));
        }
    }
}

#[test]
fn legacy_json_empty_and_tombstoned_histories_survive_compact_and_migrate() {
    let history = vec![
        (0, Some(RecordId(1))),
        (10, None),
        (10, Some(RecordId(2))),
        (20, None),
    ];
    for kind in [Kind::Lsm, Kind::Btree] {
        let dir = tempdir().unwrap();
        let versions: Vec<_> = history
            .iter()
            .map(|(sequence, rid)| serde_json::json!({"sequence":sequence,"rid":rid}))
            .collect();
        let fixture = serde_json::json!({"next_sequence":20,"entries":[[b"key".to_vec(),versions],[b"empty".to_vec(),[]]],"page_size":128});
        std::fs::write(
            dir.path().join(kind.file()),
            serde_json::to_vec(&fixture).unwrap(),
        )
        .unwrap();
        let mut index = kind.open(dir.path());
        assert_reads(index.as_ref(), &history);
        assert_eq!(index.get_at(b"empty", 0), None);
        index.compact().unwrap();
        assert_reads(index.as_ref(), &history);
        assert_eq!(index.stats().versions, 3);
        index.flush().unwrap();
        drop(index);
        let index = kind.open(dir.path());
        assert_reads(index.as_ref(), &history);
    }
}

#[derive(Default)]
struct LatestOnly {
    entries: BTreeMap<Vec<u8>, RecordId>,
    reads: Arc<AtomicUsize>,
}
impl IndexPlugin for LatestOnly {
    fn name(&self) -> &str {
        "latest"
    }
    fn put(&mut self, key: &[u8], rid: RecordId) -> praxis::Result<()> {
        self.entries.insert(key.to_vec(), rid);
        Ok(())
    }
    fn get(&self, key: &[u8]) -> Option<RecordId> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.entries.get(key).copied()
    }
    fn delete(&mut self, key: &[u8]) -> praxis::Result<()> {
        self.entries.remove(key);
        Ok(())
    }
    fn flush(&mut self) -> praxis::Result<()> {
        Ok(())
    }
}

#[test]
fn legacy_default_snapshot_read_fails_closed_without_calling_latest_get() {
    let mut index = LatestOnly::default();
    index.put(b"key", RecordId(99)).unwrap();
    assert_eq!(
        index.get_at(b"key", 0),
        None,
        "a plugin without snapshot support must not expose a future RID"
    );
    assert_eq!(index.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn checked_storage_snapshot_rejects_unsupported_plugin_without_poisoning() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let index = LatestOnly::default();
    let reads = index.reads.clone();
    engine
        .register_index("latest", "default", Box::new(index))
        .unwrap();
    let rid = engine.put(b"future-payload", &[]).unwrap();
    engine.put_index("latest", b"key", rid).unwrap();
    let result = engine.lookup_rid_at("latest", b"key", 0);
    assert!(
        result.is_err(),
        "unsupported snapshot read returned {result:?}"
    );
    assert!(matches!(
        result,
        Err(praxis::PraxisError::UnsupportedIndexSnapshotRead { .. })
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(engine.lookup_rid("latest", b"key").unwrap(), Some(rid));
    let second = engine.put(b"healthy", &[]).unwrap();
    assert_eq!(engine.fetch(second).unwrap(), b"healthy");
}

#[test]
fn maintenance_estimates_only_safe_reduction_and_stops_after_one_prune() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let rids: Vec<_> = (0..4)
        .map(|_| engine.put(b"payload", &[]).unwrap())
        .collect();
    let mut index = LsmIndex::open("snapshot", dir.path().join("indexes")).unwrap();
    append(
        &mut index,
        &[
            (10, Some(rids[0])),
            (20, Some(rids[1])),
            (10, Some(rids[2])),
            (30, Some(rids[3])),
        ],
    );
    engine
        .register_index("snapshot", "default", Box::new(index))
        .unwrap();
    let suggested = engine.suggest_index_compactions(1);
    assert_eq!(suggested.len(), 1);
    assert_eq!(suggested[0].estimated_versions_pruned, 2);
    let report = engine.run_maintenance_cycle(1).unwrap();
    assert_eq!(report.executed.len(), 1);
    assert_eq!(report.executed[0].before.versions, 4);
    assert_eq!(report.executed[0].after.versions, 2);
    assert_eq!(
        engine.lookup_rid_at("snapshot", b"key", 10).unwrap(),
        Some(rids[2])
    );
    assert!(engine.suggest_index_compactions(0).is_empty());
    assert!(engine.run_maintenance_cycle(0).unwrap().executed.is_empty());
}

#[test]
fn monotonic_history_is_not_automatically_rewritten_even_at_zero_threshold() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let mut index = LsmIndex::open("snapshot", dir.path().join("indexes")).unwrap();
    append(
        &mut index,
        &[(10, Some(RecordId(1))), (20, Some(RecordId(2))), (30, None)],
    );
    engine
        .register_index("snapshot", "default", Box::new(index))
        .unwrap();
    assert!(engine.suggest_index_compactions(1).is_empty());
    assert!(engine.suggest_index_compactions(0).is_empty());
}

#[test]
fn current_metadata_does_not_gate_tombstoned_historical_keys() {
    let dir = tempdir().unwrap();
    let history = [(10, Some(RecordId(1))), (20, None)];
    let mut lsm = LsmIndex::open("lsm", dir.path()).unwrap();
    append(&mut lsm, &history);
    lsm.compact().unwrap();
    assert_eq!(lsm.stats().live_keys, 0);
    assert!(!lsm.may_contain_key(b"key"));
    assert_eq!(lsm.fence_bounds(), (None, None));
    assert_eq!(lsm.get_at_checked(b"key", 10).unwrap(), Some(RecordId(1)));

    let mut btree = BTreeIndex::open("btree", dir.path()).unwrap();
    append(&mut btree, &history);
    btree.compact().unwrap();
    assert!(btree.page_metadata().is_empty());
    assert_eq!(btree.get_at_checked(b"key", 10).unwrap(), Some(RecordId(1)));
}

#[test]
fn dominance_pruning_does_not_reset_the_assigned_sequence_counter() {
    for kind in [Kind::Lsm, Kind::Btree] {
        let dir = tempdir().unwrap();
        let mut index = kind.open(dir.path());
        append(
            index.as_mut(),
            &[(100, Some(RecordId(1))), (5, Some(RecordId(2))), (50, None)],
        );
        index.compact().unwrap();
        assert_eq!(index.stats().versions, 2);
        index.flush().unwrap();
        drop(index);
        let mut index = kind.open(dir.path());
        index.put(b"key", RecordId(3)).unwrap();
        assert_eq!(index.get_at(b"key", 100), None);
        assert_eq!(index.get_at(b"key", 101), Some(RecordId(3)));
    }
}

struct VersionedWrapper {
    inner: LsmIndex,
    opt_in: bool,
    snapshot_calls: Arc<AtomicUsize>,
}

impl IndexPlugin for VersionedWrapper {
    fn name(&self) -> &str {
        "custom"
    }
    fn put(&mut self, key: &[u8], rid: RecordId) -> praxis::Result<()> {
        self.inner.put(key, rid)
    }
    fn put_with_sequence(
        &mut self,
        key: &[u8],
        rid: RecordId,
        sequence: u64,
    ) -> praxis::Result<()> {
        self.inner.put_with_sequence(key, rid, sequence)
    }
    fn get(&self, key: &[u8]) -> Option<RecordId> {
        self.inner.get(key)
    }
    fn get_at(&self, key: &[u8], sequence: u64) -> Option<RecordId> {
        self.snapshot_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.get_at(key, sequence)
    }
    fn snapshot_read_capability(&self) -> IndexSnapshotCapability {
        if self.opt_in {
            IndexSnapshotCapability::RawSequenceCeilings
        } else {
            IndexSnapshotCapability::Unsupported
        }
    }
    fn delete(&mut self, key: &[u8]) -> praxis::Result<()> {
        self.inner.delete(key)
    }
    fn delete_with_sequence(&mut self, key: &[u8], sequence: u64) -> praxis::Result<()> {
        self.inner.delete_with_sequence(key, sequence)
    }
    fn flush(&mut self) -> praxis::Result<()> {
        self.inner.flush()
    }
    fn compact(&mut self) -> praxis::Result<()> {
        self.inner.compact()
    }
    fn stats(&self) -> praxis::index::IndexStats {
        self.inner.stats()
    }
    fn reclaimable_version_count(&self) -> u64 {
        self.inner.reclaimable_version_count()
    }
}

#[test]
fn custom_versioned_plugin_requires_explicit_opt_in_and_can_report_safe_maintenance() {
    for opt_in in [false, true] {
        let dir = tempdir().unwrap();
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        let rids: Vec<_> = (0..3)
            .map(|_| engine.put(b"payload", &[]).unwrap())
            .collect();
        let mut inner = LsmIndex::open("custom", dir.path().join("indexes")).unwrap();
        append(
            &mut inner,
            &[
                (10, Some(rids[0])),
                (20, Some(rids[1])),
                (10, Some(rids[2])),
            ],
        );
        let snapshot_calls = Arc::new(AtomicUsize::new(0));
        engine
            .register_index(
                "custom",
                "default",
                Box::new(VersionedWrapper {
                    inner,
                    opt_in,
                    snapshot_calls: snapshot_calls.clone(),
                }),
            )
            .unwrap();
        let result = engine.lookup_rid_at("custom", b"key", 10);
        if opt_in {
            assert_eq!(result.unwrap(), Some(rids[2]));
            assert_eq!(snapshot_calls.load(Ordering::Relaxed), 1);
        } else {
            assert!(matches!(
                result,
                Err(praxis::PraxisError::UnsupportedIndexSnapshotRead { .. })
            ));
            assert_eq!(snapshot_calls.load(Ordering::Relaxed), 0);
        }
        let report = engine
            .run_maintenance_cycle_with_options(praxis::store::MaintenanceCycleOptions {
                stale_version_threshold: 2,
                max_jobs: 1,
            })
            .unwrap();
        assert_eq!(report.executed.len(), 1);
        assert_eq!(report.executed[0].before.versions, 3);
        assert_eq!(report.executed[0].after.versions, 1);
        assert!(engine.suggest_index_compactions(0).is_empty());
        assert_eq!(engine.lookup_rid("custom", b"key").unwrap(), Some(rids[2]));
        let rid = engine.put(b"healthy", &[]).unwrap();
        assert_eq!(engine.fetch(rid).unwrap(), b"healthy");
    }
}

#[test]
fn failed_snapshot_flush_requires_reopen_and_original_history_remains_readable() {
    for kind in [Kind::Lsm, Kind::Btree] {
        let dir = tempdir().unwrap();
        let index_dir = dir.path().join("indexes");
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        let rids: Vec<_> = (0..3)
            .map(|_| engine.put(b"payload", &[]).unwrap())
            .collect();
        let history = [
            (10, Some(rids[0])),
            (20, Some(rids[1])),
            (10, Some(rids[2])),
            (30, None),
        ];
        let mut index = kind.open(&index_dir);
        append(index.as_mut(), &history);
        engine.register_index("snapshot", "default", index).unwrap();
        engine.flush().unwrap();

        // Preserve the durable snapshot and block the next snapshot file write
        // with a directory. This models an ordinary persistence error, not a
        // power interruption or a partial-write durability guarantee.
        let snapshot = index_dir.join(kind.file());
        let backup = index_dir.join("saved-snapshot");
        std::fs::rename(&snapshot, &backup).unwrap();
        std::fs::create_dir(&snapshot).unwrap();
        assert!(matches!(
            engine.compact_selected_indexes(&["snapshot"]),
            Err(praxis::PraxisError::Io(_))
        ));
        assert!(matches!(
            engine.lookup_rid_at("snapshot", b"key", 10),
            Err(praxis::PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            engine.lookup_rid("snapshot", b"key"),
            Err(praxis::PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            engine.put(b"blocked", &[]),
            Err(praxis::PraxisError::RecoveryRequired)
        ));
        drop(engine);
        std::fs::remove_dir(&snapshot).unwrap();
        std::fs::rename(&backup, &snapshot).unwrap();

        let mut index = kind.open(&index_dir);
        assert_reads(index.as_ref(), &history);
        index.compact().unwrap();
        assert_reads(index.as_ref(), &history);
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine.register_index("snapshot", "default", index).unwrap();
        assert_eq!(
            engine.lookup_rid_at("snapshot", b"key", 10).unwrap(),
            Some(rids[2])
        );
        assert_eq!(engine.fetch(rids[2]).unwrap(), b"payload");
        let healthy = engine.put(b"healthy", &[]).unwrap();
        assert_eq!(engine.fetch(healthy).unwrap(), b"healthy");
    }
}
