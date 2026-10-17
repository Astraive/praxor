use super::*;
use crate::core_records::codec::{Allocator, Decision, Key as RecordKey, Role, Row};
use crate::core_records::intent::{
    IntentKind, Mapping, NewRecord, RecordIntent, RecordReceipt, RecordResult,
};
use crate::core_records::transition::{Context, Rows, Summary, validate_installed};
use crate::core_records::{CoreDatabase, MappingDescriptor, RecordAuthorityOptions};
use crate::store::RecordId;

fn database(
    policy: crate::WalSyncPolicy,
    threshold: usize,
) -> (tempfile::TempDir, PraxisConfig, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = policy;
    config.wal_segment_size = 128 * 1024 * 1024;
    config.memtable_flush_threshold_bytes = usize::MAX;
    config.large_value_threshold = threshold;
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "test".into(),
            }],
        },
    )
    .unwrap();
    (dir, config, db)
}
fn mapping() -> Mapping {
    Mapping {
        index: 1,
        key: b"k".to_vec(),
    }
}

#[test]
fn public_semantic_verify_uses_one_capture_while_never_writes_continue() {
    use crate::engine::core::backup::{Phase, hooks};
    let (dir, _config, db) = database(crate::WalSyncPolicy::Never, usize::MAX);
    db.records().put(b"record", &[]).unwrap();
    let engine = db.kv();
    let captured_bytes = std::fs::metadata(engine.inner.wal.lock().path())
        .unwrap()
        .len();
    let attempts = engine
        .inner
        .metrics
        .commit_sync_attempts
        .load(Ordering::Relaxed);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let reader = engine.clone();
    let join = std::thread::spawn(move || {
        let _hook = hooks::install(move |phase| {
            if phase == Phase::Captured {
                ready_tx.send(()).unwrap();
                resume_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
            }
            Ok(())
        });
        reader.verify()
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(engine.inner.maintenance_serialization.try_lock().is_none());
    engine.put("late never", "published after capture").unwrap();
    let before = disk_state(dir.path());
    resume_tx.send(()).unwrap();
    let report = join.join().unwrap().unwrap();
    assert_eq!(report.bytes_checked, captured_bytes);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        attempts
    );
    assert_eq!(disk_state(dir.path()), before);
}
fn create(payload: &[u8], mappings: usize) -> IntentKind {
    IntentKind::Create(vec![NewRecord {
        payload: payload.into(),
        mappings: vec![mapping(); mappings],
    }])
}
fn queue(engine: &PraxisEngine, kind: IntentKind) -> Arc<CommitRequest> {
    engine
        .inner
        .group_commit
        .admit_record(RecordIntent::new(kind).unwrap(), &engine.inner.metrics)
        .unwrap()
}
fn user(engine: &PraxisEngine, key: &str) -> Arc<CommitRequest> {
    let mut batch = WriteBatch::new();
    batch.put_default(key.to_owned(), "value");
    let (batch, generations) = engine.normalize_batch_with_cf_policies(batch).unwrap();
    let len = WalRecord::checked_encoded_batch_len(&batch).unwrap();
    engine
        .inner
        .group_commit
        .admit(
            batch,
            generations,
            WriteCondition::Unconditional,
            len,
            &engine.inner.metrics,
        )
        .unwrap()
}
fn receipt(sequence: u64, compatibility_sequence: u64, result: RecordResult) -> CommitOutcome {
    CommitOutcome::Record(RecordReceipt {
        core_sequence: sequence,
        compatibility_sequence,
        result,
    })
}
fn protected_rows(engine: &PraxisEngine) -> Rows {
    let mut keys = std::collections::BTreeSet::new();
    for (cf, key) in engine.inner.segment_index.read().keys() {
        if let Some(role) = Role::from_cf(&cf.0) {
            keys.insert((role, key.to_vec()));
        }
    }
    for (cf, key) in engine.inner.memtable.read().keys() {
        if let Some(role) = Role::from_cf(&cf.0) {
            keys.insert((role, key.to_vec()));
        }
    }
    for imm in engine.inner.immutable_memtables.lock().iter() {
        for (cf, key) in imm.keys() {
            if let Some(role) = Role::from_cf(&cf.0) {
                keys.insert((role, key.to_vec()));
            }
        }
    }
    keys.into_iter()
        .map(|(role, key)| {
            let value = engine
                .resolve_value_at_snapshot(
                    &ColumnFamily(role.cf().into()),
                    &key,
                    engine.snapshot().sequence,
                )
                .unwrap();
            let summary = value
                .map(|bytes| Summary::decode(role, &key, &bytes, Path::new("oracle")).unwrap());
            ((role, key), summary)
        })
        .collect()
}
fn check_oracle(engine: &PraxisEngine) {
    let rows = protected_rows(engine);
    let authority = engine
        .inner
        .manifest
        .lock()
        .record_authority
        .clone()
        .unwrap();
    assert_eq!(
        validate_installed(
            &rows,
            &Context {
                id: authority.identity(Path::new("oracle")).unwrap(),
                descriptors: 1,
                source: Path::new("oracle")
            }
        )
        .unwrap(),
        Allocator {
            last_rid: 3,
            compatibility_sequence: 11,
            append_ordinal: 11,
            live_count: 1,
            dead_count: 2,
            live_payload_bytes: 1
        }
    );
    let mut facts = Vec::new();
    for ((role, key), summary) in &rows {
        if *role != Role::Index {
            continue;
        }
        let key = RecordKey::decode(*role, key, Path::new("oracle")).unwrap();
        if let RecordKey::Fact { raw_sequence, .. } = key {
            let Row::Fact {
                append_ordinal,
                decision,
            } = Row::decode(
                &key,
                summary
                    .as_ref()
                    .unwrap()
                    .bytes(Path::new("oracle"))
                    .unwrap(),
                Path::new("oracle"),
            )
            .unwrap()
            else {
                panic!()
            };
            facts.push((raw_sequence, append_ordinal, decision));
        }
    }
    assert_eq!(
        facts,
        vec![
            (2, 2, Decision::Put(1)),
            (3, 3, Decision::Put(1)),
            (8, 8, Decision::Put(2)),
            (9, 9, Decision::Delete),
            (11, 11, Decision::Delete)
        ]
    );
    let ceilings = [0, 1, 2, 3, 5, 7, 8, 9, 10, 11, u64::MAX];
    let expected = [
        None,
        None,
        Some(1),
        Some(1),
        Some(1),
        Some(1),
        Some(2),
        None,
        None,
        None,
        None,
    ];
    for (ceiling, expected) in ceilings.into_iter().zip(expected) {
        let actual = facts
            .iter()
            .filter(|(raw, _, _)| *raw <= ceiling)
            .max_by_key(|(_, ordinal, _)| *ordinal)
            .and_then(|(_, _, decision)| match decision {
                Decision::Put(rid) => Some(*rid),
                Decision::Delete => None,
            });
        assert_eq!(actual, expected);
    }
    assert_eq!(engine.get("before").unwrap().unwrap().as_ref(), b"value");
    assert_eq!(engine.get("after").unwrap().unwrap().as_ref(), b"value");
    let head = engine
        .resolve_value_at_snapshot(
            &ColumnFamily(Role::Index.cf().into()),
            &RecordKey::Head {
                index: 1,
                incarnation: 1,
                key: b"k",
            }
            .encode()
            .unwrap(),
            engine.snapshot().sequence,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        Row::decode(
            &RecordKey::Head {
                index: 1,
                incarnation: 1,
                key: b"k"
            },
            &head,
            Path::new("oracle")
        )
        .unwrap(),
        Row::Head {
            raw_sequence: 11,
            append_ordinal: 11,
            decision: Decision::Delete
        }
    );
}

#[test]
fn hand_computed_mixed_group_oracle_survives_all_lifecycle_paths() {
    for policy in [
        crate::WalSyncPolicy::EveryBatch,
        crate::WalSyncPolicy::GroupCommit,
        crate::WalSyncPolicy::Never,
    ] {
        let (_dir, config, db) = database(policy, 1);
        let engine = db.kv();
        let requests = vec![
            user(&engine, "before"),
            queue(&engine, create(b"aa", 2)),
            queue(
                &engine,
                IntentKind::Create(vec![
                    NewRecord {
                        payload: b"b".to_vec(),
                        mappings: vec![],
                    },
                    NewRecord {
                        payload: b"c".to_vec(),
                        mappings: vec![],
                    },
                ]),
            ),
            queue(
                &engine,
                IntentKind::DeleteRecords(vec![RecordId(1), RecordId(999)]),
            ),
            queue(
                &engine,
                IntentKind::DeleteRecords(vec![RecordId(1), RecordId(1)]),
            ),
            queue(&engine, IntentKind::IndexPut(mapping(), RecordId(1))),
            queue(&engine, IntentKind::IndexPut(mapping(), RecordId(2))),
            queue(&engine, IntentKind::DeleteByIndex(mapping())),
            queue(&engine, IntentKind::DeleteByIndex(mapping())),
            user(&engine, "after"),
            engine
                .inner
                .group_commit
                .admit_barrier(&engine.inner.metrics)
                .unwrap(),
        ];
        let expected = [
            Some(CommitOutcome::Write { sequence: 2 }),
            Some(receipt(3, 3, RecordResult::Created(vec![RecordId(1)]))),
            Some(receipt(
                4,
                5,
                RecordResult::Created(vec![RecordId(2), RecordId(3)]),
            )),
            None,
            Some(receipt(5, 7, RecordResult::Unit)),
            None,
            Some(receipt(6, 8, RecordResult::Unit)),
            Some(receipt(
                7,
                10,
                RecordResult::DeletedByIndex(Some(RecordId(2))),
            )),
            Some(receipt(8, 11, RecordResult::DeletedByIndex(None))),
            Some(CommitOutcome::Write { sequence: 9 }),
            Some(CommitOutcome::Barrier {
                through_sequence: 9,
            }),
        ];
        for (request, expected) in requests.iter().zip(expected) {
            match expected {
                Some(expected) => assert_eq!(engine.wait_for_commit(request).unwrap(), expected),
                None => assert!(matches!(
                    engine.wait_for_commit(request),
                    Err(PraxisError::KeyNotFound)
                )),
            }
        }
        assert_eq!(engine.snapshot().sequence, 9);
        assert_eq!(
            engine
                .inner
                .metrics
                .commit_sync_attempts
                .load(Ordering::Relaxed),
            match policy {
                crate::WalSyncPolicy::EveryBatch => 9,
                crate::WalSyncPolicy::GroupCommit => 2,
                crate::WalSyncPolicy::Never => 7,
            }
        );
        check_oracle(&engine);
        let suffix_backup = tempfile::tempdir().unwrap();
        engine.backup_to(suffix_backup.path()).unwrap();
        let suffix_restore = tempfile::tempdir().unwrap();
        PraxisEngine::restore_from_backup(suffix_backup.path(), suffix_restore.path()).unwrap();
        let mut suffix_config = config.clone();
        suffix_config.data_dir = suffix_restore.path().into();
        let suffix_db = CoreDatabase::open(suffix_config).unwrap();
        check_oracle(&suffix_db.kv());
        drop(suffix_db);
        engine.flush().unwrap();
        check_oracle(&engine);
        for strategy in [
            crate::CompactionStrategy::Leveled,
            crate::CompactionStrategy::Tiered,
            crate::CompactionStrategy::Universal,
        ] {
            engine
                .put(format!("compaction-input-{strategy:?}"), "marker")
                .unwrap();
            engine.flush().unwrap();
            assert_ne!(
                engine.compact_with_strategy(strategy).unwrap(),
                0,
                "exercise actual rewrite"
            );
            check_oracle(&engine);
            engine.garbage_collect().unwrap();
            check_oracle(&engine);
        }
        let backup = tempfile::tempdir().unwrap();
        engine.backup_to(backup.path()).unwrap();
        let restored = tempfile::tempdir().unwrap();
        PraxisEngine::restore_from_backup(backup.path(), restored.path()).unwrap();
        let mut restored_config = config.clone();
        restored_config.data_dir = restored.path().into();
        let restored_db = CoreDatabase::open(restored_config).unwrap();
        check_oracle(&restored_db.kv());
        drop(restored_db);
        drop(engine);
        drop(db);
        for _ in 0..2 {
            let db = CoreDatabase::open(config.clone()).unwrap();
            check_oracle(&db.kv());
        }
        let db = CoreDatabase::open(config).unwrap();
        let next_core_sequence = db.kv().snapshot().sequence + 1;
        let next = db
            .kv()
            .commit_record(RecordIntent::new(create(b"next", 0)).unwrap())
            .unwrap();
        assert_eq!(
            next,
            RecordReceipt {
                core_sequence: next_core_sequence,
                compatibility_sequence: 12,
                result: RecordResult::Created(vec![RecordId(4)])
            }
        );
    }
}

#[test]
fn exact_wire_limit_precedes_rotation_and_conservative_charge_is_not_wire_size() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::WalSyncPolicy::Never;
    config.wal_segment_size = config.page_size;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let db =
        CoreDatabase::create_fresh(config, RecordAuthorityOptions { indexes: vec![] }).unwrap();
    let engine = db.kv();
    // Exact wire arithmetic from the frozen three-op shape and 88-byte control,
    // independent of the production sizing walker.
    let overhead = 12
        + 5
        + 88
        + (1 + 4 + Role::Payload.cf().len() + 4 + 9 + 4 + 12)
        + (1 + 4 + Role::State.cf().len() + 4 + 9 + 4 + 24)
        + (1 + 4 + Role::Meta.cf().len() + 4 + 1 + 4 + 56);
    let payload_len = crate::wal::record::MAX_WAL_PAYLOAD_BYTES - overhead;
    let input = RecordIntent::new(IntentKind::Create(vec![NewRecord {
        payload: vec![b'a'; payload_len],
        mappings: vec![],
    }]))
    .unwrap();
    assert!(input.admission_bytes() > crate::wal::record::MAX_WAL_PAYLOAD_BYTES);
    assert_eq!(
        engine.commit_record(input).unwrap().result,
        RecordResult::Created(vec![RecordId(1)])
    );
    assert_eq!(
        fs::metadata(engine.inner.wal.lock().path()).unwrap().len(),
        (crate::wal::record::MAX_WAL_PAYLOAD_BYTES + 32) as u64
    );
    let before = disk_state(dir.path());
    let counters = protected_rows(&engine);
    let invalid = RecordIntent::new(IntentKind::Create(vec![NewRecord {
        payload: vec![b'x'; payload_len + 1],
        mappings: vec![],
    }]))
    .unwrap();
    assert!(engine.commit_record(invalid).is_err());
    assert_eq!(
        disk_state(dir.path()),
        before,
        "no rotation/header/manifest mutation before size refusal"
    );
    assert_eq!(protected_rows(&engine), counters);
    engine.inner.group_commit.ensure_writable().unwrap();
    assert_eq!(
        engine
            .commit_record(RecordIntent::new(create(b"after", 0)).unwrap())
            .unwrap()
            .result,
        RecordResult::Created(vec![RecordId(2)])
    );
}

fn disk_state(root: &Path) -> BTreeMap<PathBuf, (u64, blake3::Hash)> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, (u64, blake3::Hash)>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_name() == LOCK_FILE_NAME {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, out);
            } else {
                let bytes = fs::read(&path).unwrap();
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    (bytes.len() as u64, blake3::hash(&bytes)),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[test]
fn invalid_record_durable_only_group_has_no_io_and_owner_remains_healthy() {
    let (_dir, _config, db) = database(crate::WalSyncPolicy::Never, 1);
    let engine = db.kv();
    let before = disk_state(engine.inner.layout.root());
    for kind in [
        IntentKind::DeleteRecords(vec![RecordId(1)]),
        IntentKind::IndexPut(mapping(), RecordId::NULL),
        IntentKind::Create(vec![NewRecord {
            payload: b"scratch".to_vec(),
            mappings: vec![Mapping {
                index: 99,
                key: b"bad".to_vec(),
            }],
        }]),
    ] {
        assert!(
            engine
                .commit_record(RecordIntent::new(kind).unwrap())
                .is_err()
        );
    }
    assert_eq!(engine.snapshot().sequence, 1);
    assert_eq!(disk_state(engine.inner.layout.root()), before);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        0
    );
    engine.inner.group_commit.ensure_writable().unwrap();
    let result = engine
        .commit_record(RecordIntent::new(create(b"valid", 0)).unwrap())
        .unwrap();
    assert_eq!(
        result,
        RecordReceipt {
            core_sequence: 2,
            compatibility_sequence: 1,
            result: RecordResult::Created(vec![RecordId(1)])
        }
    );
}
