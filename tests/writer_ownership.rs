use praxis::store::{RecordId, RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;

const LOCK_NAME: &str = ".praxor.writer.lock";

#[derive(Clone, Copy, Debug)]
enum Kind {
    Core,
    Pointer,
    Record,
}

enum Owner {
    Core(PraxisEngine),
    Pointer(Box<StorageEngine>),
    Record(RecordStore),
}

impl Kind {
    fn open(self, root: &Path) -> praxis::Result<Owner> {
        Ok(match self {
            Self::Core => Owner::Core(PraxisEngine::open(PraxisConfig::new(root))?),
            Self::Pointer => Owner::Pointer(Box::new(StorageEngine::open(root, 1024)?)),
            Self::Record => Owner::Record(RecordStore::open(root)?),
        })
    }
    fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Pointer => "pointer",
            Self::Record => "record",
        }
    }
}

impl Owner {
    fn write_marker(&mut self) {
        match self {
            Self::Core(engine) => {
                engine.put("marker", "acknowledged").unwrap();
                engine.flush().unwrap();
            }
            Self::Pointer(engine) => {
                assert_eq!(engine.put(b"acknowledged", &[]).unwrap(), RecordId(1));
                engine.flush().unwrap();
            }
            Self::Record(store) => {
                assert_eq!(store.put(b"acknowledged").unwrap(), RecordId(1));
                store.flush().unwrap();
            }
        }
    }
    fn assert_marker(&self) {
        let bytes = match self {
            Self::Core(engine) => engine.get("marker").unwrap().unwrap().to_vec(),
            Self::Pointer(engine) => engine.fetch(RecordId(1)).unwrap(),
            Self::Record(store) => store.get(RecordId(1)).unwrap(),
        };
        assert_eq!(bytes, b"acknowledged");
    }
}

fn denied<T>(result: praxis::Result<T>) {
    match result {
        Err(praxis::PraxisError::AlreadyOpen { .. }) => {}
        Err(error) => panic!("expected typed AlreadyOpen, received {error}"),
        Ok(_) => panic!("a second independent writer was admitted"),
    }
}

fn contents(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == LOCK_NAME {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                visit(base, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[test]
fn all_live_root_writers_exclude_each_other_without_changing_data() {
    for first in [Kind::Core, Kind::Pointer, Kind::Record] {
        let dir = tempdir().unwrap();
        let mut owner = first.open(dir.path()).unwrap();
        owner.write_marker();
        let before = contents(dir.path());
        for second in [Kind::Core, Kind::Pointer, Kind::Record] {
            denied(second.open(dir.path()));
            assert_eq!(contents(dir.path()), before, "{first:?} / {second:?}");
            owner.assert_marker();
        }
        drop(owner);
        let owner = first.open(dir.path()).unwrap();
        owner.assert_marker();
    }
}

#[test]
fn independent_core_open_cannot_lose_an_acknowledged_wal_prefix() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let first = PraxisEngine::open(config.clone()).unwrap();
    match PraxisEngine::open(config.clone()) {
        Ok(second) => {
            first.put("a", "first").unwrap();
            second.put("b", "second").unwrap();
            first.flush().unwrap();
            drop(second);
            drop(first);
            let reopened = PraxisEngine::open(config).unwrap();
            assert_eq!(
                reopened.get("b").unwrap().as_deref(),
                Some(b"second".as_slice()),
                "independent sequence allocators let one flush retire another writer's acknowledged WAL"
            );
        }
        Err(praxis::PraxisError::AlreadyOpen { .. }) => {
            first.put("a", "first").unwrap();
            assert_eq!(
                first.get("a").unwrap().as_deref(),
                Some(b"first".as_slice())
            );
        }
        Err(error) => panic!("unexpected open failure: {error}"),
    }
}

#[test]
fn independent_primary_open_cannot_overwrite_an_acknowledged_payload() {
    let dir = tempdir().unwrap();
    let mut first = RecordStore::open(dir.path()).unwrap();
    match RecordStore::open(dir.path()) {
        Ok(mut second) => {
            let rid = first.put(b"alpha").unwrap();
            second.put(b"bravo").unwrap();
            assert_eq!(
                first.get(rid).unwrap(),
                b"alpha",
                "independent RID/cursor state overwrote acknowledged bytes"
            );
        }
        Err(praxis::PraxisError::AlreadyOpen { .. }) => {
            let rid = first.put(b"alpha").unwrap();
            assert_eq!(first.get(rid).unwrap(), b"alpha");
        }
        Err(error) => panic!("unexpected open failure: {error}"),
    }
}

#[test]
fn pointer_and_standalone_primary_exclude_both_orderings_without_self_deadlock() {
    let dir = tempdir().unwrap();
    let primary = dir.path().join("primary");
    let standalone = RecordStore::open(&primary).unwrap();
    denied(StorageEngine::open(dir.path(), 1024));
    assert!(!dir.path().join("MANIFEST.store").exists());
    assert!(!dir.path().join("wal").exists());
    drop(standalone);
    let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
    let rid = engine.put(b"nested", &[]).unwrap();
    denied(RecordStore::open(&primary));
    assert_eq!(engine.fetch(rid).unwrap(), b"nested");
    engine.flush().unwrap();
    drop(engine);
    let standalone = RecordStore::open(&primary).unwrap();
    assert_eq!(standalone.get(rid).unwrap(), b"nested");
}

#[test]
fn clones_transactions_and_close_keep_ownership_until_last_engine_owner_drops() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    let clone = engine.clone();
    engine.close().unwrap();
    drop(engine);
    denied(PraxisEngine::open(config.clone()));
    let mut transaction = clone.begin_transaction();
    drop(clone);
    denied(PraxisEngine::open(config.clone()));
    transaction.put("txn", "committed");
    transaction.commit().unwrap();
    let reopened = PraxisEngine::open(config).unwrap();
    assert_eq!(
        reopened.get("txn").unwrap().as_deref(),
        Some(b"committed".as_slice())
    );
}

#[test]
fn failed_open_releases_ownership_and_lock_file_survives_drop() {
    let dir = tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    drop(PraxisEngine::open(config.clone()).unwrap());
    assert!(dir.path().join(LOCK_NAME).is_file());
    let mut incompatible = config.clone();
    incompatible.block_size *= 2;
    assert!(matches!(
        PraxisEngine::open(incompatible),
        Err(praxis::PraxisError::ConfigMismatch(_))
    ));
    let owner = PraxisEngine::open(config.clone()).unwrap();
    denied(PraxisEngine::open(config.clone()));
    drop(owner);
    assert!(dir.path().join(LOCK_NAME).is_file());
    drop(PraxisEngine::open(config).unwrap());
}

#[test]
fn root_aliases_share_the_same_writer_lock() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("database");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    denied(StorageEngine::open(root.join("."), 1024));
    denied(RecordStore::open(root.join("..").join("database")));
    let alias = dir.path().join("alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_dir(&root, &alias) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            return;
        }
        panic!("cannot create symlink: {error}");
    }
    denied(PraxisEngine::open(PraxisConfig::new(&alias)));
    drop(engine);
    drop(PraxisEngine::open(PraxisConfig::new(&alias)).unwrap());
}

#[test]
fn restore_cannot_replace_a_live_root_or_primary_and_releases_ownership_after_copy() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    source.put("backup", "retained").unwrap();
    let backup = dir.path().join("backup");
    source.backup_to(&backup).unwrap();
    for kind in [Kind::Core, Kind::Pointer, Kind::Record] {
        let target = dir.path().join(kind.name());
        let mut owner = kind.open(&target).unwrap();
        owner.write_marker();
        let before = contents(&target);
        denied(PraxisEngine::restore_from_backup(&backup, &target));
        assert_eq!(contents(&target), before);
        owner.assert_marker();
        drop(owner);
        PraxisEngine::restore_from_backup(&backup, &target).unwrap();
        let restored = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        assert_eq!(
            restored.get("backup").unwrap().as_deref(),
            Some(b"retained".as_slice())
        );
    }
    let target = dir.path().join("nested");
    let store = RecordStore::open(target.join("primary")).unwrap();
    denied(PraxisEngine::restore_from_backup(&backup, &target));
    drop(store);
    PraxisEngine::restore_from_backup(&backup, &target).unwrap();
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn backup_cannot_replace_a_live_destination_or_its_nested_primary() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    source.put("source", "retained").unwrap();
    for kind in [Kind::Core, Kind::Pointer, Kind::Record] {
        let target = dir.path().join(kind.name());
        let mut owner = kind.open(&target).unwrap();
        owner.write_marker();
        let before = contents(&target);
        denied(source.backup_to(&target));
        assert_eq!(contents(&target), before);
        owner.assert_marker();
        drop(owner);
        source.backup_to(&target).unwrap();
        let reopened = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        assert_eq!(
            reopened.get("source").unwrap().as_deref(),
            Some(b"retained".as_slice())
        );
    }
    let target = dir.path().join("nested");
    let store = RecordStore::open(target.join("primary")).unwrap();
    denied(source.backup_to(&target));
    drop(store);
    source.backup_to(&target).unwrap();
}

#[test]
fn backup_does_not_delete_its_own_source_root() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    source.put("source", "retained").unwrap();
    assert!(matches!(
        source.backup_to(dir.path()),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert_eq!(
        source.get("source").unwrap().as_deref(),
        Some(b"retained".as_slice())
    );
    assert!(dir.path().join("MANIFEST").is_file());
}

#[test]
fn backup_restore_preserve_existing_lock_contents_and_reject_overlapping_roots() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("live");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(LOCK_NAME), b"source diagnostic").unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    engine.put("record", "retained").unwrap();
    let backup = dir.path().join("backup");
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::write(backup.join(LOCK_NAME), b"backup diagnostic").unwrap();
    engine.backup_to(&backup).unwrap();
    assert_eq!(
        std::fs::read(backup.join(LOCK_NAME)).unwrap(),
        b"backup diagnostic"
    );
    let restored = dir.path().join("restored");
    std::fs::create_dir_all(&restored).unwrap();
    std::fs::write(restored.join(LOCK_NAME), b"restore diagnostic").unwrap();
    PraxisEngine::restore_from_backup(&backup, &restored).unwrap();
    assert_eq!(
        std::fs::read(restored.join(LOCK_NAME)).unwrap(),
        b"restore diagnostic"
    );
    let before = contents(&root);
    assert!(matches!(
        engine.backup_to(root.join("nested")),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert!(matches!(
        engine.backup_to(dir.path()),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert_eq!(contents(&root), before);
    let backup_before = contents(&backup);
    assert!(matches!(
        PraxisEngine::restore_from_backup(&backup, backup.join("nested")),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert_eq!(contents(&backup), backup_before);
    drop(engine);
    assert_eq!(
        std::fs::read(root.join(LOCK_NAME)).unwrap(),
        b"source diagnostic"
    );
    // A rejected ancestor destination must not leave a new ownership artifact
    // that would prevent the original database from reopening.
    drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
}

#[test]
fn repeated_backup_restore_and_reuse_do_not_copy_or_reject_ownership_artifacts() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    let backup = dir.path().join("backup");
    let target = dir.path().join("target");
    source.put("record", "first").unwrap();
    source.backup_to(&backup).unwrap();
    PraxisEngine::restore_from_backup(&backup, &target).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
    restored.put("record", "second").unwrap();
    restored.backup_to(&backup).unwrap();
    drop(restored);
    PraxisEngine::restore_from_backup(&backup, &target).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
    assert_eq!(
        restored.get("record").unwrap().as_deref(),
        Some(b"second".as_slice())
    );
    let before = contents(&target);
    denied(PraxisEngine::restore_from_backup(
        dir.path().join("source"),
        &target,
    ));
    assert_eq!(contents(&target), before);
}

#[test]
fn destination_cleanup_never_follows_a_directory_alias_into_another_writer() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    source.put("source", "retained").unwrap();
    let outside = dir.path().join("outside");
    let mut owner = Kind::Core.open(&outside).unwrap();
    owner.write_marker();
    let before = contents(&outside);
    let target = dir.path().join("backup");
    std::fs::create_dir_all(&target).unwrap();
    let alias = target.join("external");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &alias) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            return;
        }
        panic!("cannot create symlink: {error}");
    }
    source.backup_to(&target).unwrap();
    assert!(!alias.exists());
    assert_eq!(contents(&outside), before);
    owner.assert_marker();
}

#[test]
fn copy_refuses_unrelated_nested_writer_roots_before_any_deletion() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    source.put("source", "retained").unwrap();
    let backup = dir.path().join("backup");
    source.backup_to(&backup).unwrap();
    for active in [true, false] {
        let target = dir.path().join(format!("target-{active}"));
        let nested = target.join("other_db");
        let mut owner = Kind::Core.open(&nested).unwrap();
        owner.write_marker();
        let before = contents(&target);
        let owner = active.then_some(owner);
        assert!(
            source.backup_to(&target).is_err(),
            "backup deleted an unrelated nested database"
        );
        assert_eq!(contents(&target), before);
        assert!(
            PraxisEngine::restore_from_backup(&backup, &target).is_err(),
            "restore deleted an unrelated nested database"
        );
        assert_eq!(contents(&target), before);
        if let Some(owner) = owner {
            owner.assert_marker();
        }
    }
}

#[test]
fn core_open_refuses_nested_source_databases_before_they_can_be_backed_up() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("source");
    let nested = Kind::Core.open(&root.join("other_db")).unwrap();
    let before = contents(&root);
    assert!(matches!(
        PraxisEngine::open(PraxisConfig::new(&root)),
        Err(praxis::PraxisError::StorageFormatAmbiguous { .. })
    ));
    assert_eq!(contents(&root), before);
    drop(nested);
    assert!(matches!(
        PraxisEngine::open(PraxisConfig::new(&root)),
        Err(praxis::PraxisError::StorageFormatAmbiguous { .. })
    ));
    assert_eq!(contents(&root), before);
    assert!(!dir.path().join("backup").exists());
}

#[test]
fn an_owned_root_refuses_new_independent_nested_databases() {
    for kind in [Kind::Core, Kind::Pointer, Kind::Record] {
        let dir = tempdir().unwrap();
        let owner = kind.open(dir.path()).unwrap();
        let nested = dir.path().join("new_db");
        assert!(
            Kind::Core.open(&nested).is_err(),
            "nested open bypassed an owning ancestor"
        );
        assert!(!nested.join("MANIFEST").exists());
        denied(RecordStore::open(dir.path().join("primary")));
        drop(owner);
    }
}

#[test]
fn rejected_nested_open_does_not_poison_later_parent_backups() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("live");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    engine.put("record", "retained").unwrap();
    let child = root.join("unsupported-child");
    assert!(PraxisEngine::open(PraxisConfig::new(&child)).is_err());
    assert!(
        !child.join(LOCK_NAME).exists(),
        "a denied open left a permanent unrelated root artifact"
    );
    engine.backup_to(dir.path().join("backup")).unwrap();
}

#[test]
fn reserved_primary_alias_is_rejected_without_locking_or_mutating_its_target() {
    let dir = tempdir().unwrap();
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    let backup = dir.path().join("backup");
    source.backup_to(&backup).unwrap();
    let target = dir.path().join("target");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("payload"), b"untouched").unwrap();
    let alias = target.join("primary");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &alias) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            return;
        }
        panic!("cannot create symlink: {error}");
    }
    assert!(matches!(
        source.backup_to(&target),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert!(matches!(
        PraxisEngine::restore_from_backup(&backup, &target),
        Err(praxis::PraxisError::InvalidConfig(_))
    ));
    assert!(matches!(
        StorageEngine::open(&target, 1024),
        Err(praxis::PraxisError::StorageFormatIncomplete { .. })
    ));
    assert_eq!(
        std::fs::read(outside.join("payload")).unwrap(),
        b"untouched"
    );
    assert!(!outside.join(LOCK_NAME).exists());
}

#[test]
fn writer_process_holder() {
    let Some(root) = std::env::var_os("PRAXIS_WRITER_TEST_ROOT") else {
        return;
    };
    let kind = match std::env::var("PRAXIS_WRITER_TEST_KIND").unwrap().as_str() {
        "core" => Kind::Core,
        "pointer" => Kind::Pointer,
        "record" => Kind::Record,
        _ => unreachable!(),
    };
    let mut owner = kind.open(Path::new(&root)).unwrap();
    owner.write_marker();
    println!("WRITER_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    owner.assert_marker();
}

#[test]
fn another_process_is_excluded_and_kill_releases_all_writer_leases() {
    for kind in [Kind::Core, Kind::Pointer, Kind::Record] {
        let dir = tempdir().unwrap();
        let mut child = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "writer_process_holder",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("PRAXIS_WRITER_TEST_ROOT", dir.path())
                .env("PRAXIS_WRITER_TEST_KIND", kind.name())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let ready = BufReader::new(stdout)
                .lines()
                .any(|line| line.is_ok_and(|line| line.contains("WRITER_READY")));
            let _ = sender.send(ready);
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap(),
            "child failed to open its writer"
        );
        reader.join().unwrap();
        let before = contents(dir.path());
        for second in [Kind::Core, Kind::Pointer, Kind::Record] {
            denied(second.open(dir.path()));
        }
        assert_eq!(contents(dir.path()), before);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let recovered = kind.open(dir.path()).unwrap();
        recovered.assert_marker();
    }
}
