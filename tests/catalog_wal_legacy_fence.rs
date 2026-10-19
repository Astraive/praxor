use praxis::manifest::{CompactionJobState, CompactionJobStatus, Manifest, ManifestStore};
use praxis::{CoreDatabase, PraxisConfig, PraxisEngine, PraxisError, RecordAuthorityOptions};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

// Literal, independently audited v4 frames from query-q3-v4-wal-oracle-fixtures.json.
const BOOTSTRAP: &[u8; 563] = include_bytes!("fixtures/catalog_tag6_bootstrap_s1.bin");
const CREATE: &[u8; 424] = include_bytes!("fixtures/catalog_tag7_create_s2.bin");
const LOCK: &str = ".praxor.writer.lock";

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    LockedFile(u64),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for item in fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if path.is_dir() {
                out.insert(relative, Entry::Directory);
                visit(root, &path, out);
            } else {
                let value = match fs::read(&path) {
                    Ok(bytes) => Entry::File(bytes),
                    Err(error)
                        if relative == Path::new(LOCK) && error.raw_os_error() == Some(33) =>
                    {
                        Entry::LockedFile(fs::metadata(&path).unwrap().len())
                    }
                    Err(error) => panic!("cannot snapshot {path:?}: {error}"),
                };
                out.insert(relative, value);
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut out);
    }
    out
}

fn manifest(root: &Path) -> Manifest {
    toml::from_str(&fs::read_to_string(root.join("MANIFEST")).unwrap()).unwrap()
}

fn save_manifest(root: &Path, value: &Manifest) {
    ManifestStore::new(root.join("MANIFEST"))
        .save(value)
        .unwrap();
}

fn downgrade_v1(root: &Path) {
    let mut value = manifest(root);
    value.format_version = 1;
    value.column_family_generations.clear();
    value.next_column_family_generation = 1;
    let encoded = toml::to_string_pretty(&value)
        .unwrap()
        .replace("next_column_family_generation = 1\n", "")
        .replace("[column_family_generations]\n", "");
    fs::write(root.join("MANIFEST"), encoded).unwrap();
}

fn wal(root: &Path, id: u64) -> PathBuf {
    root.join("wal").join(format!("{id:020}.wal"))
}

fn append(root: &Path, id: u64, frame: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(wal(root, id))
        .unwrap()
        .write_all(frame)
        .unwrap();
}

fn replace_payload(root: &Path, id: u64, frame: &[u8]) {
    let bytes = fs::read(wal(root, id)).unwrap();
    assert!(bytes.len() >= 16);
    let mut replacement = bytes[..16].to_vec();
    replacement.extend_from_slice(frame);
    fs::write(wal(root, id), replacement).unwrap();
}

fn seed_lock(root: &Path) {
    fs::write(root.join(LOCK), b"preexisting lock bytes").unwrap();
}

fn running_job(root: &Path) {
    let mut value = manifest(root);
    value.compaction_jobs.push(CompactionJobState {
        id: 1,
        strategy: praxis::CompactionStrategy::Leveled,
        status: CompactionJobStatus::Running,
        source_segment_ids: vec![],
        output_segment_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
    });
    save_manifest(root, &value);
}

fn assert_catalog(error: PraxisError) {
    assert!(
        matches!(error, PraxisError::CatalogAuthorityWalRequired { .. }),
        "expected typed catalog WAL refusal, got {error:?}"
    );
}

#[test]
fn generic_v1_v2_open_refuse_each_literal_before_job_or_layout_mutation() {
    for v1 in [false, true] {
        for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("generic");
            drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
            running_job(&root);
            fs::remove_dir(root.join("tmp")).unwrap();
            if v1 {
                downgrade_v1(&root);
            }
            append(&root, 1, frame);
            seed_lock(&root);
            let before = tree(&root);
            let error = match PraxisEngine::open(PraxisConfig::new(&root)) {
                Ok(_) => panic!("legacy generic open admitted catalog control"),
                Err(error) => error,
            };
            assert_catalog(error);
            assert_eq!(
                tree(&root),
                before,
                "legacy open changed manifest/layout/lease"
            );
            assert!(!root.join("tmp").exists());
        }
    }
}

#[test]
fn v3_open_refuses_each_literal_before_job_reconciliation() {
    for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("records");
        drop(
            CoreDatabase::create_fresh(PraxisConfig::new(&root), RecordAuthorityOptions::default())
                .unwrap(),
        );
        if frame == BOOTSTRAP {
            replace_payload(&root, 1, frame);
        } else {
            append(&root, 1, frame);
            let mut value = manifest(&root);
            value.last_sequence = 2;
            save_manifest(&root, &value);
        }
        running_job(&root);
        seed_lock(&root);
        let before = tree(&root);
        let error = match CoreDatabase::open(PraxisConfig::new(&root)) {
            Ok(_) => panic!("v3 owner admitted catalog control"),
            Err(error) => error,
        };
        assert_catalog(error);
        assert_eq!(tree(&root), before, "v3 open changed source");
    }
}

#[test]
fn offline_v1_v2_v3_restore_refuses_each_literal_before_target_acquisition() {
    for owner in [1, 2, 3] {
        for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
            for existing in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("source");
                let bundle = temp.path().join("bundle");
                if owner == 3 {
                    let source = CoreDatabase::create_fresh(
                        PraxisConfig::new(&root),
                        RecordAuthorityOptions::default(),
                    )
                    .unwrap();
                    source.kv().backup_to(&bundle).unwrap();
                } else {
                    let source = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
                    source.backup_to(&bundle).unwrap();
                }
                if owner == 3 && frame == BOOTSTRAP {
                    replace_payload(&bundle, 1, frame);
                } else {
                    append(&bundle, 1, frame);
                }
                let mut value = manifest(&bundle);
                value.last_sequence = if frame == BOOTSTRAP { 1 } else { 2 };
                save_manifest(&bundle, &value);
                if owner == 1 {
                    downgrade_v1(&bundle);
                }
                seed_lock(&bundle);
                let destination = temp.path().join("target");
                if existing {
                    let target = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
                    target.put("existing", "row").unwrap();
                    drop(target);
                }
                let before_bundle = tree(&bundle);
                let before_destination = tree(&destination);
                let error = PraxisEngine::restore_from_backup(&bundle, &destination).unwrap_err();
                assert_catalog(error);
                assert_eq!(tree(&bundle), before_bundle, "restore changed source");
                assert_eq!(
                    tree(&destination),
                    before_destination,
                    "restore acquired or changed target"
                );
                if !existing {
                    assert!(!destination.exists(), "restore created absent target");
                }
            }
        }
    }
}

#[test]
fn live_v1_v2_v3_backup_refuses_each_literal_before_target_acquisition() {
    for owner in [1, 2, 3] {
        for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("live-source");
            let core = if owner == 3 {
                Some(
                    CoreDatabase::create_fresh(
                        PraxisConfig::new(&root),
                        RecordAuthorityOptions::default(),
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let source = if let Some(core) = &core {
                core.kv()
            } else if owner == 1 {
                drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
                downgrade_v1(&root);
                let reopened = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
                // The reopened handle upgrades its in-memory model to v2;
                // the legacy v1 source on disk is preserved until a write.
                assert_eq!(manifest(&root).format_version, 1);
                reopened
            } else {
                PraxisEngine::open(PraxisConfig::new(&root)).unwrap()
            };
            if owner == 3 && frame == BOOTSTRAP {
                replace_payload(&root, 1, frame);
            } else {
                append(&root, 1, frame);
            }
            let destination = temp.path().join("target");
            let before = tree(&root);
            let error = source.backup_to(&destination).unwrap_err();
            assert_catalog(error);
            assert_eq!(tree(&root), before, "backup changed live source");
            assert!(!destination.exists(), "backup acquired target");
        }
    }
}

#[test]
fn retired_generic_wal_refuses_each_literal_before_restore_target_acquisition() {
    for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let bundle = temp.path().join("bundle");
        let source = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
        source.put("kept", "row").unwrap();
        source.flush().unwrap();
        source.backup_to(&bundle).unwrap();
        drop(source);
        let saved = manifest(&bundle);
        assert_eq!(saved.flushed_wal_id, 1);
        assert_eq!(saved.active_wal_id, 2);
        let mut retired = fs::read(wal(&bundle, 2)).unwrap()[..16].to_vec();
        retired[8..16].copy_from_slice(&1u64.to_le_bytes());
        retired.extend_from_slice(frame);
        fs::write(wal(&bundle, 1), retired).unwrap();
        seed_lock(&bundle);
        let before = tree(&bundle);
        let destination = temp.path().join("absent-target");
        let error = PraxisEngine::restore_from_backup(&bundle, &destination).unwrap_err();
        assert_catalog(error);
        assert!(
            !destination.exists(),
            "retired WAL preflight acquired target"
        );
        assert_eq!(tree(&bundle), before, "retired WAL source changed");
    }
}

#[test]
fn live_literal_backup_preserves_existing_destination_including_retired_generic_wal() {
    for (record_owner, retired_generic) in [(false, false), (true, false), (false, true)] {
        for frame in [BOOTSTRAP.as_slice(), CREATE.as_slice()] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("live-source");
            let core = if record_owner {
                Some(
                    CoreDatabase::create_fresh(
                        PraxisConfig::new(&root),
                        RecordAuthorityOptions::default(),
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let source = if let Some(core) = &core {
                core.kv()
            } else {
                PraxisEngine::open(PraxisConfig::new(&root)).unwrap()
            };
            if retired_generic {
                source.put("kept", "row").unwrap();
                source.flush().unwrap();
                let mut header = fs::read(wal(&root, 2)).unwrap()[..16].to_vec();
                header[8..16].copy_from_slice(&1u64.to_le_bytes());
                fs::write(wal(&root, 1), header).unwrap();
            }
            if record_owner && frame == BOOTSTRAP {
                replace_payload(&root, 1, frame);
            } else {
                append(&root, 1, frame);
            }
            let destination = temp.path().join("existing-target");
            let target = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
            target.put("existing", "row").unwrap();
            drop(target);
            let before_source = tree(&root);
            let before_destination = tree(&destination);
            let error = source.backup_to(&destination).unwrap_err();
            assert_catalog(error);
            assert_eq!(tree(&root), before_source, "live backup changed source");
            assert_eq!(
                tree(&destination),
                before_destination,
                "live backup changed populated destination"
            );
        }
    }
}
