use praxis::index::{IndexPlugin, IndexStats};
use praxis::storage::lsm::LsmIndex;
use praxis::store::{
    BatchRecord, IndexInsert, RecordId, StorageEngine, StorageWal, StorageWalEntry,
    StorageWalOperation, StorageWalOptions,
};
use praxis::{PraxisError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn segment(root: &Path, id: u64) -> PathBuf {
    root.join(format!("storage.{id:020}.swal"))
}
fn entry(sequence: u64) -> StorageWalEntry {
    StorageWalEntry {
        sequence,
        index_type: "kv".into(),
        key: vec![sequence as u8; 9],
        rid: Some(RecordId(sequence)),
        operation: StorageWalOperation::Put,
    }
}

fn v1_payload(e: &StorageWalEntry) -> Vec<u8> {
    let mut p = vec![0x42, 0x57, 0x53, 0x54, 1];
    p.extend_from_slice(&e.sequence.to_le_bytes());
    p.push(1);
    p.extend_from_slice(&(e.index_type.len() as u16).to_le_bytes());
    p.extend_from_slice(&(e.key.len() as u32).to_le_bytes());
    p.push(1);
    p.extend_from_slice(&e.rid.unwrap().0.to_le_bytes());
    p.extend_from_slice(e.index_type.as_bytes());
    p.extend_from_slice(&e.key);
    p
}
fn group_payload(entries: &[StorageWalEntry]) -> Vec<u8> {
    let mut p = vec![0x42, 0x57, 0x53, 0x54, 2, 0, 0, 0, 0];
    p.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let inner = v1_payload(e);
        p.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        p.extend(inner);
    }
    let n = p.len() as u32;
    p[5..9].copy_from_slice(&n.to_le_bytes());
    p
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn mixed_json_v1_binary_and_v2_groups_replay_in_entry_order() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let mut bytes = vec![0x4c, 0x57, 0x53, 0x54, 1];
    bytes.extend(frame(&serde_json::to_vec(&entry(1)).unwrap()));
    bytes.extend(frame(&v1_payload(&entry(2))));
    bytes.extend(frame(&group_payload(&[entry(3), entry(4)])));
    fs::write(segment(dir.path(), 1), bytes).unwrap();
    assert_eq!(
        StorageWal::replay(&path).unwrap(),
        vec![entry(1), entry(2), entry(3), entry(4)]
    );
}

#[test]
fn legacy_single_file_entries_survive_open_and_new_segmented_appends() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let mut bytes = vec![0x4c, 0x57, 0x53, 0x54, 1];
    bytes.extend(frame(&serde_json::to_vec(&entry(1)).unwrap()));
    bytes.extend(frame(&v1_payload(&entry(2))));
    fs::write(&path, &bytes).unwrap();
    let mut wal = StorageWal::open(&path).unwrap();
    wal.append_batch(&[entry(3), entry(4)]).unwrap();
    drop(wal);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        StorageWal::replay(&path).unwrap(),
        vec![entry(1), entry(2), entry(3), entry(4)]
    );
}

#[test]
fn malformed_groups_are_corruption_and_are_never_truncated() {
    let valid = group_payload(&[entry(1), entry(2)]);
    let mut cases = Vec::new();
    let mut p = valid.clone();
    p[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(frame(&p));
    let mut p = valid.clone();
    p[9..13].copy_from_slice(&1_u32.to_le_bytes());
    cases.push(frame(&p));
    let mut p = valid.clone();
    p[13..17].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(frame(&p));
    let mut p = valid.clone();
    p[21] = 9;
    cases.push(frame(&p));
    let mut p = valid.clone();
    p[4] = 3;
    let mut b = frame(&p);
    b[..4].copy_from_slice(&((p.len() + 1) as u32).to_le_bytes());
    cases.push(b);
    let mut p = valid.clone();
    p.push(0);
    let len = p.len() as u32;
    p[5..9].copy_from_slice(&len.to_le_bytes());
    cases.push(frame(&p));
    let mut b = frame(&valid);
    b[..4].copy_from_slice(&((valid.len() + 1) as u32).to_le_bytes());
    cases.push(b);
    let mut b = frame(&valid);
    b[4] ^= 1;
    cases.push(b);
    let mut p = vec![0x42, 0x57, 0x53, 0x54, 2];
    p.extend_from_slice(&(64_u32 * 1024 * 1024 + 1).to_le_bytes());
    p.extend_from_slice(&1_u32.to_le_bytes());
    let mut b = frame(&p);
    b[..4].copy_from_slice(&(64_u32 * 1024 * 1024 + 1).to_le_bytes());
    cases.push(b);
    for bad in cases {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage.wal");
        let mut bytes = vec![0x4c, 0x57, 0x53, 0x54, 1];
        bytes.extend(bad);
        let active = segment(dir.path(), 1);
        fs::write(&active, &bytes).unwrap();
        assert!(StorageWal::replay(&path).is_err());
        assert!(StorageWal::open(&path).is_err());
        assert_eq!(fs::read(&active).unwrap(), bytes);
    }
}

#[test]
fn oversized_groups_are_rejected_before_any_wal_change() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let mut wal = StorageWal::open(&path).unwrap();
    let mut large = entry(1);
    large.key = vec![0; 64 * 1024 * 1024];
    let before = fs::read(segment(dir.path(), 1)).unwrap();
    assert!(wal.append_batch(&[large]).is_err());
    assert_eq!(fs::read(segment(dir.path(), 1)).unwrap(), before);
    wal.append(&entry(2)).unwrap();
    assert_eq!(StorageWal::replay(&path).unwrap(), vec![entry(2)]);
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &target);
        } else {
            fs::copy(item.path(), target).unwrap();
        }
    }
}

#[test]
fn engine_batch_recovery_publishes_all_primary_and_secondary_entries_together() {
    let source = tempdir().unwrap();
    let mut engine = StorageEngine::open(source.path(), 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", source.path().join("indexes")).unwrap()),
        )
        .unwrap();
    let old = engine.put(b"old", &[]).unwrap();
    engine.flush().unwrap();
    let active = segment(&source.path().join("wal"), 1);
    let start = fs::metadata(&active).unwrap().len() as usize;
    let one = [IndexInsert::new("kv", b"one".to_vec())];
    let two = [IndexInsert::new("kv", b"two".to_vec())];
    let rids = engine
        .put_batch(&[
            BatchRecord::new(b"first", &one),
            BatchRecord::new(b"second", &two),
        ])
        .unwrap();
    drop(engine);
    let full = fs::read(&active).unwrap();
    let mut cuts = vec![
        start,
        start + 1,
        start + 4,
        start + 7,
        start + 8,
        full.len() - 1,
        full.len(),
    ];
    // Include all independently framed v1 boundaries in the baseline and all
    // nested v2 entry boundaries after the fix, plus an interior payload cut.
    if full[start + 12] == 2 {
        let mut cursor = start + 8 + 13;
        while cursor < full.len() {
            let n = u32::from_le_bytes(full[cursor..cursor + 4].try_into().unwrap()) as usize;
            cuts.push(cursor + 4 + n / 2);
            cursor += 4 + n;
            if cursor < full.len() {
                cuts.push(cursor);
            }
        }
    } else {
        let mut cursor = start;
        while cursor < full.len() {
            let n = u32::from_le_bytes(full[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 8 + n;
            if cursor < full.len() {
                cuts.push(cursor);
            }
        }
    }
    for cut in cuts {
        let dir = tempdir().unwrap();
        copy_tree(source.path(), dir.path());
        fs::write(segment(&dir.path().join("wal"), 1), &full[..cut]).unwrap();
        let mut recovered = StorageEngine::open(dir.path(), 1024).unwrap();
        recovered
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
            )
            .unwrap();
        assert_eq!(recovered.fetch(old).unwrap(), b"old");
        let complete = cut == full.len();
        assert_eq!(
            recovered.live_count(),
            if complete { 3 } else { 1 },
            "cut {cut}"
        );
        for (rid, key, value) in [
            (rids[0], b"one".as_slice(), b"first".as_slice()),
            (rids[1], b"two".as_slice(), b"second".as_slice()),
        ] {
            assert_eq!(
                recovered.fetch_by_index("kv", key).unwrap(),
                complete.then(|| value.to_vec()),
                "cut {cut}"
            );
            assert_eq!(recovered.fetch(rid).is_ok(), complete);
        }
        let later = recovered.put(b"later", &[]).unwrap();
        drop(recovered);
        let again = StorageEngine::open(dir.path(), 1024).unwrap();
        assert_eq!(again.fetch(later).unwrap(), b"later");
    }
}

#[test]
fn every_torn_group_cut_recovers_none_of_the_group_and_can_append_again() {
    let fixture = tempdir().unwrap();
    let path = fixture.path().join("storage.wal");
    let first = entry(1);
    let group = [entry(2), entry(3), entry(4)];
    let mut wal = StorageWal::open(&path).unwrap();
    wal.append(&first).unwrap();
    let boundary = fs::metadata(segment(fixture.path(), 1)).unwrap().len() as usize;
    wal.append_batch(&group).unwrap();
    drop(wal);
    let full = fs::read(segment(fixture.path(), 1)).unwrap();
    for cut in boundary..full.len() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage.wal");
        fs::write(segment(dir.path(), 1), &full[..cut]).unwrap();
        assert_eq!(
            StorageWal::replay(&path).unwrap(),
            vec![first.clone()],
            "cut {cut}"
        );
        let mut reopened = StorageWal::open(&path).unwrap();
        reopened.append(&entry(5)).unwrap();
        drop(reopened);
        assert_eq!(
            StorageWal::replay(&path).unwrap(),
            vec![first.clone(), entry(5)],
            "append after cut {cut}"
        );
    }
    assert_eq!(
        StorageWal::replay(&path).unwrap(),
        vec![first, group[0].clone(), group[1].clone(), group[2].clone()]
    );
}

struct RejectingIndex;
impl IndexPlugin for RejectingIndex {
    fn name(&self) -> &str {
        "reject"
    }
    fn put(&mut self, _: &[u8], _: RecordId) -> Result<()> {
        Err(PraxisError::InvalidConfig("injected index failure".into()))
    }
    fn get(&self, _: &[u8]) -> Option<RecordId> {
        None
    }
    fn delete(&mut self, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn stats(&self) -> IndexStats {
        IndexStats::default()
    }
}

#[test]
fn deterministic_wal_encoding_failure_does_not_publish_primary_records_or_sequences() {
    for batch in [false, true] {
        let dir = tempdir().unwrap();
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        let name = "x".repeat(65536);
        engine
            .register_index(&name, "default", Box::new(RejectingIndex))
            .unwrap();
        let indexes = [IndexInsert::new(&name, b"bad".to_vec())];
        let failed = if batch {
            engine
                .put_batch(&[
                    BatchRecord::new(b"first", &indexes),
                    BatchRecord::new(b"second", &[]),
                ])
                .map(|_| ())
        } else {
            engine.put(b"first", &indexes).map(|_| ())
        };
        assert!(failed.is_err());
        assert_eq!(
            engine.live_count(),
            0,
            "failed preparation cannot become live"
        );
        assert_eq!(engine.manifest().last_sequence, 0);
        engine.flush().unwrap();
        let good = engine.put(b"good", &[]).unwrap();
        drop(engine);
        let recovered = StorageEngine::open(dir.path(), 1024).unwrap();
        assert_eq!(recovered.live_count(), 1);
        assert_eq!(recovered.fetch(good).unwrap(), b"good");
    }
}

#[test]
fn ambiguous_wal_io_blocks_the_handle_until_reopen_without_publishing_prepared_put() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open_with_wal_options(
        dir.path(),
        1024,
        StorageWalOptions {
            max_segment_bytes: 1024,
        },
    )
    .unwrap();
    let first = engine.put(&[1; 16], &[]).unwrap();
    // Fill the active WAL past its target using one large but valid index key.
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
        )
        .unwrap();
    engine.put_index("kv", &[2; 1100], first).unwrap();
    let next = segment(&dir.path().join("wal"), 3);
    fs::create_dir(&next).unwrap();
    let before = engine.manifest().last_sequence;
    assert!(engine.put(b"uncommitted", &[]).is_err());
    assert_eq!(engine.live_count(), 1);
    assert_eq!(engine.manifest().last_sequence, before);
    assert!(
        engine.fetch(first).is_err(),
        "uncertain handles require recovery"
    );
    assert!(engine.flush().is_err());
    assert!(engine.compact_primary().is_err());
    assert!(engine.put(b"cannot continue", &[]).is_err());
    drop(engine);
    fs::remove_dir(&next).unwrap();
    let recovered = StorageEngine::open(dir.path(), 1024).unwrap();
    assert_eq!(recovered.live_count(), 1);
    assert_eq!(recovered.fetch(first).unwrap(), vec![1; 16]);
}

#[test]
fn post_wal_plugin_failure_blocks_reads_and_maintenance_until_complete_replay() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
    engine
        .register_index("kv", "default", Box::new(RejectingIndex))
        .unwrap();
    assert!(
        engine
            .put(b"committed", &[IndexInsert::new("kv", b"key".to_vec())])
            .is_err()
    );
    let entries = StorageWal::replay(engine.wal_path()).unwrap();
    assert_eq!(entries.len(), 2);
    let rid = entries[0].rid.unwrap();
    assert!(engine.fetch(rid).is_err());
    assert!(engine.lookup_rid("kv", b"key").is_err());
    assert!(engine.lookup_rid_at("kv", b"key", u64::MAX).is_err());
    assert!(engine.flush().is_err());
    assert!(engine.compact_primary().is_err());
    assert!(engine.put(b"later", &[]).is_err());
    drop(engine);
    let mut recovered = StorageEngine::open(dir.path(), 1024).unwrap();
    recovered
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
        )
        .unwrap();
    assert_eq!(
        recovered.fetch_by_index("kv", b"key").unwrap(),
        Some(b"committed".to_vec())
    );
}

#[test]
fn multi_index_put_rotates_as_one_group_and_never_recovers_a_partial_index_set() {
    let source = tempdir().unwrap();
    let options = StorageWalOptions {
        max_segment_bytes: 1024,
    };
    let mut engine = StorageEngine::open_with_wal_options(source.path(), 1024, options).unwrap();
    for name in ["left", "right"] {
        engine
            .register_index(
                name,
                "default",
                Box::new(LsmIndex::open(name, source.path().join("indexes")).unwrap()),
            )
            .unwrap();
    }
    let old = engine.put(b"old", &[]).unwrap();
    engine.flush().unwrap();
    let inserts = [
        IndexInsert::new("left", vec![1; 700]),
        IndexInsert::new("right", vec![2; 700]),
    ];
    let rid = engine.put(b"new", &inserts).unwrap();
    drop(engine);
    let active = segment(&source.path().join("wal"), 2);
    assert!(active.exists());
    assert!(!segment(&source.path().join("wal"), 3).exists());
    let full = fs::read(&active).unwrap();
    let first_entry_end = 5 + 8 + 13 + 4 + 29 + "primary".len() + 16;
    for cut in [5, 6, 12, first_entry_end, full.len() - 1, full.len()] {
        let dir = tempdir().unwrap();
        copy_tree(source.path(), dir.path());
        fs::write(segment(&dir.path().join("wal"), 2), &full[..cut]).unwrap();
        let mut recovered =
            StorageEngine::open_with_wal_options(dir.path(), 1024, options).unwrap();
        for name in ["left", "right"] {
            recovered
                .register_index(
                    name,
                    "default",
                    Box::new(LsmIndex::open(name, dir.path().join("indexes")).unwrap()),
                )
                .unwrap();
        }
        let complete = cut == full.len();
        assert_eq!(recovered.fetch(old).unwrap(), b"old");
        assert_eq!(recovered.fetch(rid).is_ok(), complete);
        for insert in &inserts {
            assert_eq!(
                recovered
                    .lookup_rid(&insert.index_type, &insert.key)
                    .unwrap(),
                complete.then_some(rid)
            );
        }
    }
}

#[test]
fn compaction_relocation_group_is_atomic_before_install_and_repairs_a_lost_directory() {
    use praxis::store::ManifestEdit;
    let source = tempdir().unwrap();
    let old_files = tempdir().unwrap();
    let mut engine = StorageEngine::open(source.path(), 1024).unwrap();
    let first = engine.put(b"one", &[]).unwrap();
    let second = engine.put(b"two", &[]).unwrap();
    engine.flush().unwrap();
    copy_tree(
        &source.path().join("primary").join("records"),
        old_files.path(),
    );
    let active = segment(&source.path().join("wal"), 1);
    let start = fs::metadata(&active).unwrap().len() as usize;
    let prior = StorageWal::replay(engine.wal_path()).unwrap().len();
    engine.compact_primary().unwrap();
    let mut pending = engine.manifest().clone();
    pending.edits.retain(|edit| {
        !matches!(
            edit,
            ManifestEdit::CompactionInstalled { .. }
                | ManifestEdit::CompactionCleanupComplete { .. }
        )
    });
    drop(engine);
    let full = fs::read(&active).unwrap();
    let first_inner_end = start + 8 + 13 + 4 + 29 + "primary".len() + 16;
    for cut in [
        start,
        start + 8,
        first_inner_end,
        full.len() - 1,
        full.len(),
    ] {
        let dir = tempdir().unwrap();
        copy_tree(source.path(), dir.path());
        // Restore the exact pre-install crash state: both output and sources
        // exist, and only CompactionStarted is durably published.
        copy_tree(
            old_files.path(),
            &dir.path().join("primary").join("records"),
        );
        fs::write(
            dir.path().join("MANIFEST.store"),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        fs::write(segment(&dir.path().join("wal"), 1), &full[..cut]).unwrap();
        let entries = StorageWal::replay(&dir.path().join("wal").join("storage.wal")).unwrap();
        assert_eq!(entries.len(), prior + if cut == full.len() { 2 } else { 0 });
        let recovered = StorageEngine::open(dir.path(), 1024).unwrap();
        assert_eq!(recovered.fetch(first).unwrap(), b"one");
        assert_eq!(recovered.fetch(second).unwrap(), b"two");
    }
    // After installation/cleanup, the complete relocation group is enough to
    // reconstruct every physical pointer without the directory snapshot.
    fs::remove_file(source.path().join("primary").join("indirection.tind")).unwrap();
    let recovered = StorageEngine::open(source.path(), 1024).unwrap();
    assert_eq!(recovered.fetch(first).unwrap(), b"one");
    assert_eq!(recovered.fetch(second).unwrap(), b"two");
}

#[test]
fn cleanup_delete_recovers_the_primary_and_all_indexes_as_one_group() {
    for by_index in [false, true] {
        let source = tempdir().unwrap();
        let mut engine = StorageEngine::open(source.path(), 1024).unwrap();
        for name in ["left", "right"] {
            engine
                .register_index(
                    name,
                    "default",
                    Box::new(LsmIndex::open(name, source.path().join("indexes")).unwrap()),
                )
                .unwrap();
        }
        let keys = [
            IndexInsert::new("left", b"one".to_vec()),
            IndexInsert::new("right", b"two".to_vec()),
        ];
        let rid = engine
            .put(b"value", if by_index { &keys[..1] } else { &keys })
            .unwrap();
        engine.flush().unwrap();
        let active = segment(&source.path().join("wal"), 1);
        let start = fs::metadata(&active).unwrap().len() as usize;
        if by_index {
            assert_eq!(engine.delete_by_index("left", b"one").unwrap(), Some(rid));
        } else {
            engine.delete_record_with_index_cleanup(rid, &keys).unwrap();
        }
        drop(engine);
        let full = fs::read(&active).unwrap();
        for cut in start..=full.len() {
            let dir = tempdir().unwrap();
            copy_tree(source.path(), dir.path());
            fs::write(segment(&dir.path().join("wal"), 1), &full[..cut]).unwrap();
            let mut recovered = StorageEngine::open(dir.path(), 1024).unwrap();
            for name in ["left", "right"] {
                recovered
                    .register_index(
                        name,
                        "default",
                        Box::new(LsmIndex::open(name, dir.path().join("indexes")).unwrap()),
                    )
                    .unwrap();
            }
            let committed = cut == full.len();
            assert_eq!(
                recovered.fetch(rid).is_ok(),
                !committed,
                "primary cut {cut}"
            );
            for key in if by_index { &keys[..1] } else { &keys } {
                assert_eq!(
                    recovered.lookup_rid(&key.index_type, &key.key).unwrap(),
                    (!committed).then_some(rid),
                    "index cut {cut}"
                );
            }
        }
    }
}

#[test]
fn invalid_delete_targets_leave_records_indexes_sequences_and_handle_unchanged() {
    for operation in 0..3 {
        let dir = tempdir().unwrap();
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
            )
            .unwrap();
        let keys = [IndexInsert::new("kv", b"key".to_vec())];
        let rid = engine.put(b"keep", &keys).unwrap();
        let before = engine.manifest().last_sequence;
        let result = match operation {
            0 => engine.delete_record(RecordId(9999)),
            1 => engine.delete_records(&[rid, RecordId(9999)]),
            _ => engine.delete_record_with_index_cleanup(RecordId(9999), &keys),
        };
        assert!(matches!(result, Err(PraxisError::KeyNotFound)));
        assert_eq!(engine.manifest().last_sequence, before);
        assert_eq!(engine.fetch(rid).unwrap(), b"keep");
        assert_eq!(engine.lookup_rid("kv", b"key").unwrap(), Some(rid));
        engine.flush().unwrap();
        engine.put(b"next", &[]).unwrap();
        drop(engine);
        let recovered = StorageEngine::open(dir.path(), 1024).unwrap();
        assert_eq!(recovered.fetch(rid).unwrap(), b"keep");
        assert_eq!(recovered.live_count(), 2);
    }
}

#[test]
fn known_tombstones_allow_repeated_deletes_and_stale_index_cleanup() {
    for operation in 0..4 {
        let dir = tempdir().unwrap();
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
            )
            .unwrap();
        let keys = [IndexInsert::new("kv", b"stale".to_vec())];
        let rid = engine.put(b"deleted", &keys).unwrap();
        engine.delete_record(rid).unwrap();
        assert_eq!(engine.lookup_rid("kv", b"stale").unwrap(), Some(rid));
        match operation {
            0 => engine.delete_record(rid).unwrap(),
            1 => assert_eq!(engine.delete_by_index("kv", b"stale").unwrap(), Some(rid)),
            2 => engine.delete_record_with_index_cleanup(rid, &keys).unwrap(),
            _ => engine.delete_records(&[rid, rid]).unwrap(),
        }
        assert_eq!(engine.live_count(), 0);
        assert_eq!(
            engine.lookup_rid("kv", b"stale").unwrap(),
            if operation == 1 || operation == 2 {
                None
            } else {
                Some(rid)
            }
        );
        let before = engine.manifest().last_sequence;
        assert!(matches!(
            engine.delete_records(&[rid, RecordId(9999)]),
            Err(PraxisError::KeyNotFound)
        ));
        assert_eq!(engine.manifest().last_sequence, before);
        let later = engine.put(b"healthy", &[]).unwrap();
        engine.flush().unwrap();
        drop(engine);
        let mut recovered = StorageEngine::open(dir.path(), 1024).unwrap();
        recovered
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", dir.path().join("indexes")).unwrap()),
            )
            .unwrap();
        assert_eq!(recovered.live_count(), 1);
        assert_eq!(recovered.fetch(later).unwrap(), b"healthy");
        assert!(recovered.fetch(rid).is_err());
        recovered.delete_record(rid).unwrap();
        assert_eq!(
            recovered.lookup_rid("kv", b"stale").unwrap(),
            if operation == 1 || operation == 2 {
                None
            } else {
                Some(rid)
            }
        );
    }
}
