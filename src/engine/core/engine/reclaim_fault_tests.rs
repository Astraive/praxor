use super::*;
use crate::core_records::codec::{Key as RecordKey, Role};
use crate::core_records::{CoreDatabase, MappingDescriptor, RecordAuthorityOptions};
use crate::store::{IndexInsert, RecordId};
use std::collections::BTreeMap;
use std::process::Command;

const CHILD_CUT_EXIT: i32 = 77;
const OLD_PAYLOAD: [u8; 1024] = [b'a'; 1024];
const LIVE_PAYLOAD: [u8; 1024] = [b'b'; 1024];

fn fixture_config(root: &Path) -> PraxisConfig {
    let mut config = PraxisConfig::new(root);
    config.default_compaction_strategy = crate::CompactionStrategy::Tiered;
    config.memtable_flush_threshold_bytes = usize::MAX;
    config.large_value_threshold = 128;
    config
}

fn fixture(root: &Path) -> CoreDatabase {
    let config = fixture_config(root);
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "faults".into(),
            }],
        },
    )
    .unwrap();
    let records = db.records();
    let mapping = [IndexInsert::new("kv", b"shared".to_vec())];
    assert_eq!(records.put(&OLD_PAYLOAD, &mapping).unwrap(), RecordId(1));
    records.delete_record(RecordId(1)).unwrap();
    assert_eq!(records.put(&LIVE_PAYLOAD, &mapping).unwrap(), RecordId(2));
    records.flush().unwrap();
    assert_eq!(db.kv().inner.manifest.lock().segments.len(), 1);
    db.kv().verify().unwrap();
    drop(records);
    drop(db);
    // Persisted pointers, including the obsolete old payload, share log 1.
    let db = CoreDatabase::open(config).unwrap();
    let old = payload_versions(&db, 1);
    let live = payload_versions(&db, 2);
    assert_eq!(old.len(), 2);
    let StoredValue::BlobPointer(old_pointer) = &old[0].value else {
        panic!("old payload must have a persisted pointer");
    };
    let StoredValue::BlobPointer(live_pointer) = &live[0].value else {
        panic!("live payload must have a persisted pointer");
    };
    assert_eq!(old_pointer.path, live_pointer.path);
    db
}

fn payload_versions(db: &CoreDatabase, rid: u64) -> Vec<VersionedValue> {
    db.kv()
        .inner
        .segment_index
        .read()
        .get(&(
            ColumnFamily(Role::Payload.cf().into()),
            Bytes::from(RecordKey::Payload(rid).encode().unwrap()),
        ))
        .cloned()
        .unwrap_or_default()
}

fn live_log(db: &CoreDatabase) -> PathBuf {
    let versions = payload_versions(db, 2);
    let StoredValue::BlobPointer(pointer) = &versions[0].value else {
        panic!("live payload pointer missing");
    };
    PathBuf::from(&pointer.path)
}

fn gc_inventory(db: &CoreDatabase) -> BTreeMap<PathBuf, u64> {
    fn visit(dir: &Path, files: &mut BTreeMap<PathBuf, u64>) {
        if !dir.exists() {
            return;
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("tseg" | "tval" | "wal")
            ) {
                files.insert(path, entry.metadata().unwrap().len());
            }
        }
    }
    let layout = &db.kv().inner.layout;
    let mut files = BTreeMap::new();
    for dir in [
        layout.segment_root(),
        layout.value_root(),
        layout.wal_root(),
    ] {
        visit(&dir, &mut files);
    }
    files
}

fn assert_current_rows(db: &CoreDatabase) {
    let records = db.records();
    assert_eq!(records.fetch(RecordId(2)).unwrap(), LIVE_PAYLOAD);
    assert!(matches!(
        records.fetch(RecordId(1)),
        Err(PraxisError::KeyNotFound)
    ));
    assert_eq!(
        records.lookup_rid("kv", b"shared").unwrap(),
        Some(RecordId(2))
    );
    assert_eq!(
        records.lookup_rid_at("kv", b"shared", 2).unwrap(),
        Some(RecordId(1))
    );
    assert_eq!(records.live_count().unwrap(), 1);
    assert_eq!(records.dead_records().unwrap(), 1);
    assert_eq!(records.live_bytes().unwrap(), LIVE_PAYLOAD.len() as u64);
    let current = records.pin_snapshot().unwrap();
    assert_eq!(
        records.fetch_at_snapshot(RecordId(2), &current).unwrap(),
        LIVE_PAYLOAD
    );
    assert!(matches!(
        records.fetch_at_snapshot(RecordId(1), &current),
        Err(PraxisError::KeyNotFound)
    ));
}

fn named_phase(phase: &reclaim_hooks::Phase) -> &'static str {
    use reclaim_hooks::Phase;
    match phase {
        Phase::AfterPinnedViews => "after-pinned-views",
        Phase::AfterRunning => "after-running",
        Phase::BeforeReplacementWrite => "before-replacement-write",
        Phase::AfterReplacementWrite(_) => "after-replacement-write",
        Phase::AfterReplacementValidated => "after-replacement-validated",
        Phase::AfterManifestSave => "after-manifest-save",
        Phase::AfterIndexSwapBeforeGc => "after-index-swap-before-gc",
    }
}

#[test]
#[ignore = "spawned by reclaim_process_cuts_reopen_at_the_installed_authority"]
fn child_reclaim_cut() {
    let root = PathBuf::from(std::env::var("PRAXIS_RECLAIM_CHILD_ROOT").unwrap());
    let marker = PathBuf::from(std::env::var("PRAXIS_RECLAIM_CHILD_MARKER").unwrap());
    let selected = std::env::var("PRAXIS_RECLAIM_CHILD_PHASE").unwrap();
    let db = fixture(&root);
    let _hook = reclaim_hooks::install_rewrite(move |phase| {
        if named_phase(&phase) == selected {
            std::fs::write(&marker, named_phase(&phase)).unwrap();
            std::process::exit(CHILD_CUT_EXIT);
        }
        Ok(())
    });
    db.records().reclaim_snapshot_history().unwrap();
    panic!("requested process cut was never reached");
}

#[test]
fn reclaim_process_cuts_reopen_at_the_installed_authority() {
    for (phase, installed) in [
        ("after-running", false),
        ("after-replacement-validated", false),
        ("after-manifest-save", true),
        ("after-index-swap-before-gc", true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("db");
        let marker = temp.path().join("reached-phase");
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "engine::core::engine::reclaim_fault_tests::child_reclaim_cut",
                "--nocapture",
            ])
            .env("PRAXIS_RECLAIM_CHILD_ROOT", &root)
            .env("PRAXIS_RECLAIM_CHILD_MARKER", &marker)
            .env("PRAXIS_RECLAIM_CHILD_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(CHILD_CUT_EXIT),
            "phase {phase}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), phase);

        // No process-local token survives this abrupt exit. Open a new owner
        // and test only its freshly published current view.
        let db = CoreDatabase::open(fixture_config(&root)).unwrap();
        let manifest = db.kv().inner.manifest.lock().clone();
        assert_eq!(manifest.segments.len(), 1, "phase {phase}");
        assert_eq!(manifest.segments[0].id, if installed { 2 } else { 1 });
        assert!(Path::new(&manifest.segments[0].path).is_file());
        assert!(db.kv().inner.layout.segment_path(0, 1).is_file());
        let job = manifest.compaction_jobs.last().unwrap();
        assert_eq!(
            job.status,
            if installed {
                CompactionJobStatus::Installed
            } else {
                CompactionJobStatus::Aborted
            },
            "phase {phase}"
        );
        db.kv().verify().unwrap();
        assert_current_rows(&db);
        let pointer_log = live_log(&db);
        assert!(pointer_log.is_file(), "phase {phase}");
        assert_eq!(
            payload_versions(&db, 1).len(),
            if installed { 1 } else { 2 }
        );
        if !installed {
            let old = payload_versions(&db, 1);
            let StoredValue::BlobPointer(old_pointer) = &old[0].value else {
                panic!("pre-install old payload pointer missing at {phase}");
            };
            assert_eq!(Path::new(&old_pointer.path), pointer_log);
        }
        let before_gc = gc_inventory(&db);
        let collected = db.kv().garbage_collect().unwrap();
        let after_gc = gc_inventory(&db);
        let removed = before_gc
            .iter()
            .filter(|(path, _)| !after_gc.contains_key(*path))
            .collect::<Vec<_>>();
        assert_eq!(collected.files_reclaimed, removed.len() as u64);
        assert_eq!(
            collected.bytes_reclaimed,
            removed.iter().map(|(_, bytes)| **bytes).sum::<u64>()
        );
        assert!(
            pointer_log.is_file(),
            "GC removed the live shared log at {phase}"
        );
        db.kv().verify().unwrap();
        println!(
            "phase={phase} installed={installed} segment={} job={:?} gc_files={} gc_bytes={} live_log={}",
            manifest.segments[0].id,
            job.status,
            collected.files_reclaimed,
            collected.bytes_reclaimed,
            pointer_log.display()
        );
    }
}

#[test]
fn preinstall_write_and_readback_errors_propagate_without_losing_old_authority() {
    for corrupt_output in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("db");
        let db = fixture(&root);
        let source = db.kv().inner.manifest.lock().clone();
        let live_pointer = live_log(&db);
        let _hook = reclaim_hooks::install_rewrite(move |phase| match phase {
            reclaim_hooks::Phase::BeforeReplacementWrite if !corrupt_output => Err(
                PraxisError::Io(std::io::Error::other("injected prewrite failure")),
            ),
            reclaim_hooks::Phase::AfterReplacementWrite(path) if corrupt_output => {
                std::fs::write(path, b"invalid replacement segment").unwrap();
                Ok(())
            }
            _ => Ok(()),
        });
        let result = db.records().reclaim_snapshot_history();
        if corrupt_output {
            assert!(
                matches!(result, Err(PraxisError::Corrupt { .. })),
                "{result:?}"
            );
        } else {
            assert!(matches!(result, Err(PraxisError::Io(_))), "{result:?}");
        }
        let after = db.kv().inner.manifest.lock().clone();
        assert_eq!(after.segments, source.segments);
        assert!(live_pointer.is_file());
        assert_current_rows(&db);
        db.kv().verify().unwrap();
        drop(_hook);
        drop(db);
        let reopened = CoreDatabase::open(fixture_config(&root)).unwrap();
        let manifest = reopened.kv().inner.manifest.lock().clone();
        assert_eq!(manifest.segments, source.segments);
        assert_eq!(
            manifest.compaction_jobs.last().unwrap().status,
            CompactionJobStatus::Aborted
        );
        reopened.kv().verify().unwrap();
        assert_current_rows(&reopened);
        assert!(live_log(&reopened).is_file());
    }
}

#[test]
fn verify_and_backup_capture_held_history_before_and_after_pruning() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("db");
    let config = fixture_config(&root);
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "faults".into(),
            }],
        },
    )
    .unwrap();
    let mapping = [IndexInsert::new("kv", b"shared".to_vec())];
    let records = db.records();
    let old = records.put(&OLD_PAYLOAD, &mapping).unwrap();
    records.flush().unwrap();
    drop(records);
    drop(db);
    let db = CoreDatabase::open(config.clone()).unwrap();
    let records = db.records();
    let old_log = {
        let versions = payload_versions(&db, old.0);
        let StoredValue::BlobPointer(pointer) = &versions[0].value else {
            panic!("old payload must be external");
        };
        PathBuf::from(&pointer.path)
    };
    let held = records.pin_snapshot().unwrap();
    records.delete_record(old).unwrap();
    let live = records.put(&LIVE_PAYLOAD, &mapping).unwrap();
    records.flush().unwrap();

    for stage in ["before", "held"] {
        db.kv().verify().unwrap();
        let copy = temp.path().join(format!("backup-{stage}"));
        db.kv().backup_to(&copy).unwrap();
        let mut copied_config = config.clone();
        copied_config.data_dir = copy;
        let copied = CoreDatabase::open(copied_config).unwrap();
        copied.kv().verify().unwrap();
        assert_eq!(payload_versions(&copied, old.0).len(), 2);
        assert_eq!(copied.records().fetch(live).unwrap(), LIVE_PAYLOAD);
        assert!(matches!(
            copied.records().fetch_at_snapshot(old, &held),
            Err(PraxisError::ForeignRecordSnapshot { .. })
        ));
        drop(copied);
        assert_eq!(records.fetch_at_snapshot(old, &held).unwrap(), OLD_PAYLOAD);
        assert!(old_log.is_file());
        if stage == "before" {
            let first = records.reclaim_snapshot_history().unwrap();
            assert!(first.rewrite_performed);
            assert_eq!(payload_versions(&db, old.0).len(), 2);
        }
    }
    drop(held);
    let retired = records.reclaim_snapshot_history().unwrap();
    assert!(retired.rewrite_performed);
    assert!(retired.protected_versions_removed >= 1);
    assert_eq!(payload_versions(&db, old.0).len(), 1);
    assert!(!old_log.exists());
    db.kv().verify().unwrap();
    let copy = temp.path().join("backup-pruned");
    db.kv().backup_to(&copy).unwrap();
    let mut copied_config = config;
    copied_config.data_dir = copy;
    let copied = CoreDatabase::open(copied_config).unwrap();
    copied.kv().verify().unwrap();
    assert_eq!(payload_versions(&copied, old.0).len(), 1);
    assert_eq!(copied.records().fetch(live).unwrap(), LIVE_PAYLOAD);
}
