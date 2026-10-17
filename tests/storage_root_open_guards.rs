use bytes::Bytes;
use praxis::store::{RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[derive(Clone, Copy, Debug)]
enum Owner {
    Core,
    Pointer,
    Record,
}

fn seed(root: &Path, owner: Owner) {
    match owner {
        Owner::Core => {
            let engine = PraxisEngine::open(PraxisConfig::new(root)).unwrap();
            engine
                .put(
                    Bytes::from_static(b"key"),
                    Bytes::from_static(b"acknowledged"),
                )
                .unwrap();
        }
        Owner::Pointer => {
            let mut engine = StorageEngine::open(root, 1024).unwrap();
            engine.put(b"acknowledged", &[]).unwrap();
            engine.flush().unwrap();
        }
        Owner::Record => {
            let mut store = RecordStore::open(root).unwrap();
            store.put(b"acknowledged").unwrap();
            store.flush().unwrap();
        }
    }
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let ty = entry.file_type().unwrap();
            // A writable admission gate may acquire only its permanent regular lock.
            if ty.is_file()
                && (relative == Path::new(".praxor.writer.lock")
                    || relative == Path::new("primary/.praxor.writer.lock"))
            {
                continue;
            }
            assert!(!ty.is_symlink());
            out.insert(
                relative,
                if ty.is_dir() {
                    None
                } else {
                    Some(fs::read(&path).unwrap())
                },
            );
            if ty.is_dir() {
                visit(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn rejects_other_owner(existing: Owner, requested: Owner) {
    let dir = tempdir().unwrap();
    seed(dir.path(), existing);
    let before = tree(dir.path());
    let refused = match requested {
        Owner::Core => PraxisEngine::open(PraxisConfig::new(dir.path())).is_err(),
        Owner::Pointer => StorageEngine::open(dir.path(), 1024).is_err(),
        Owner::Record => RecordStore::open(dir.path()).is_err(),
    };
    assert!(
        refused,
        "{requested:?} must refuse an existing {existing:?} root"
    );
    assert_eq!(
        tree(dir.path()),
        before,
        "refused open modified durable files or directory entries"
    );
}

#[test]
fn core_refuses_pointer_root_instead_of_returning_an_empty_view() {
    let dir = tempdir().unwrap();
    seed(dir.path(), Owner::Pointer);
    let before = tree(dir.path());
    let result = PraxisEngine::open(PraxisConfig::new(dir.path()));
    if let Ok(engine) = &result {
        assert_eq!(
            engine.get("key").unwrap(),
            None,
            "the regression fixture should expose an empty core view"
        );
    }
    assert!(
        result.is_err(),
        "core accepted a modern pointer .swal root and returned an empty database view"
    );
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn core_refuses_standalone_record_root() {
    rejects_other_owner(Owner::Record, Owner::Core);
}
#[test]
fn pointer_refuses_core_root() {
    rejects_other_owner(Owner::Core, Owner::Pointer);
}
#[test]
fn pointer_refuses_standalone_record_root() {
    rejects_other_owner(Owner::Record, Owner::Pointer);
}
#[test]
fn standalone_record_refuses_core_root() {
    rejects_other_owner(Owner::Core, Owner::Record);
}
#[test]
fn standalone_record_refuses_pointer_root() {
    rejects_other_owner(Owner::Pointer, Owner::Record);
}

#[test]
fn standalone_primary_refuses_core_parent_before_creating_the_child() {
    let dir = tempdir().unwrap();
    seed(dir.path(), Owner::Core);
    let before = tree(dir.path());
    assert!(
        RecordStore::open(dir.path().join("primary")).is_err(),
        "a standalone primary must not initialize inside a core owner"
    );
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn standalone_primary_refuses_page_parent_before_creating_the_child() {
    let dir = tempdir().unwrap();
    drop(praxis::catalog::CatalogStore::open(dir.path()).unwrap());
    let before = tree(dir.path());
    assert!(
        RecordStore::open(dir.path().join("primary")).is_err(),
        "a standalone primary must not initialize inside a page application base"
    );
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn rejected_nested_backup_and_restore_create_no_directory_entries() {
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    let root = dir.path().join("core");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    let backup = dir.path().join("backup");
    engine.backup_to(&backup).unwrap();
    for destination in [
        root.join("new-child"),
        root.join("missing-parent/../new-child"),
        root.strip_prefix(&cwd).unwrap().join("relative-new-child"),
    ] {
        let before = tree(&root);
        assert!(engine.backup_to(destination).is_err());
        assert_eq!(tree(&root), before, "denied backup created a directory");
    }
    for destination in [
        backup.join("new-child"),
        backup.join("missing-parent/../new-child"),
    ] {
        let before = tree(&backup);
        assert!(PraxisEngine::restore_from_backup(&backup, destination).is_err());
        assert_eq!(tree(&backup), before, "denied restore created a directory");
    }
}

#[test]
fn matching_core_and_pointer_legacy_wals_keep_torn_tail_recovery() {
    use std::io::Write;
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "acknowledged").unwrap();
    drop(engine);
    let wal = dir.path().join("wal/00000000000000000001.wal");
    let bytes = fs::read(&wal).unwrap();
    fs::write(&wal, &bytes[16..]).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&wal)
        .unwrap()
        .write_all(&[0x32, 0x41])
        .unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    assert_eq!(
        engine.get("key").unwrap().unwrap(),
        Bytes::from_static(b"acknowledged")
    );
    drop(engine);
    let dir = tempdir().unwrap();
    let mut pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    let rid = pointer.put(b"acknowledged", &[]).unwrap();
    drop(pointer);
    let legacy = dir.path().join("wal/storage.wal");
    fs::rename(
        dir.path().join("wal/storage.00000000000000000001.swal"),
        &legacy,
    )
    .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(legacy)
        .unwrap()
        .write_all(&[3, 0, 0])
        .unwrap();
    let pointer = StorageEngine::open(dir.path(), 1024).unwrap();
    assert_eq!(pointer.fetch(rid).unwrap(), b"acknowledged");
}

#[test]
fn live_primary_parent_ownership_precedes_format_diagnosis() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let before = tree(dir.path());
    assert!(matches!(
        RecordStore::open(dir.path().join("primary")),
        Err(praxis::PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(tree(dir.path()), before);
    drop(engine);
}

#[test]
fn precreated_empty_standalone_primary_initializes_and_reopens() {
    for with_child_lock in [false, true] {
        let dir = tempdir().unwrap();
        let primary = dir.path().join("primary");
        fs::create_dir(&primary).unwrap();
        if with_child_lock {
            fs::write(primary.join(".praxor.writer.lock"), b"permanent").unwrap();
        }
        let mut store = RecordStore::open(&primary)
            .expect("a precreated empty standalone primary remains an initializable record root");
        let rid = store.put(b"acknowledged standalone payload").unwrap();
        store.flush().unwrap();
        drop(store);
        let store = RecordStore::open(&primary).unwrap();
        assert_eq!(store.get(rid).unwrap(), b"acknowledged standalone payload");
        drop(store);
        if with_child_lock {
            assert_eq!(
                fs::read(primary.join(".praxor.writer.lock")).unwrap(),
                b"permanent"
            );
        }
    }
    let dir = tempdir().unwrap();
    let primary = dir.path().join("primary");
    fs::create_dir(&primary).unwrap();
    fs::write(primary.join("unrelated.bin"), b"application payload").unwrap();
    let before = tree(dir.path());
    assert!(RecordStore::open(&primary).is_err());
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn populated_standalone_primary_reopens_without_granting_pointer_adoption() {
    let dir = tempdir().unwrap();
    let primary = dir.path().join("primary");
    let mut store = RecordStore::open(&primary).unwrap();
    let rid = store.put(b"acknowledged standalone payload").unwrap();
    store.flush().unwrap();
    drop(store);
    let before = tree(dir.path());
    let store = RecordStore::open(&primary)
        .expect("same standalone primary must retain its own complete record authority");
    assert_eq!(store.get(rid).unwrap(), b"acknowledged standalone payload");
    drop(store);
    assert_eq!(tree(dir.path()), before);
    assert!(
        StorageEngine::open(dir.path(), 1024).is_err(),
        "a populated standalone primary must not be silently adopted by a new pointer engine"
    );
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn copy_destination_cannot_traverse_a_file_before_parent_components() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("core");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("marker"), b"must survive").unwrap();
    let blocker = dir.path().join("file");
    fs::write(&blocker, b"a file cannot be traversed as a directory").unwrap();
    let before = tree(&target);
    assert!(
        engine.backup_to(blocker.join("../target")).is_err(),
        "invalid file/../ spelling must not select and clear a different destination"
    );
    assert_eq!(tree(&target), before);
}

fn large_record_fixture(root: &Path, count: u64) {
    use std::fmt::Write;
    fs::create_dir_all(root.join("records")).unwrap();
    let mut data = 0x5452_4543_u32.to_le_bytes().to_vec();
    data.push(1);
    data.extend_from_slice(&0_u32.to_le_bytes());
    let mut directory = format!("{{\"next_rid\":{count},\"next_segment_id\":0,\"entries\":{{");
    for id in 1..=count {
        let offset = data.len();
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&crc32fast::hash(b"x").to_le_bytes());
        data.push(b'x');
        if id > 1 {
            directory.push(',');
        }
        write!(&mut directory, "\"{id}\":{{\"location\":{{\"segment_id\":0,\"record_offset\":{offset},\"length\":1}},\"alive\":true}}").unwrap();
    }
    directory.push_str("}}");
    fs::write(root.join("records/00000000.trec"), data).unwrap();
    fs::write(root.join("indirection.tind"), directory).unwrap();
}

#[test]
fn standard_record_and_pointer_opens_support_control_files_larger_than_diagnostic_budget() {
    let dir = tempdir().unwrap();
    large_record_fixture(dir.path(), 100_000);
    assert!(
        fs::metadata(dir.path().join("indirection.tind"))
            .unwrap()
            .len()
            > 8 * 1024 * 1024
    );
    let report =
        praxis::storage::root_format::inspect_storage_root(dir.path(), Default::default()).unwrap();
    assert_eq!(
        report.kind,
        praxis::storage::root_format::RootKind::Incomplete
    );
    let store = RecordStore::open(dir.path())
        .expect("standard open must preserve existing valid record cardinality");
    assert_eq!(store.get(praxis::store::RecordId(100_000)).unwrap(), b"x");
    drop(store);
    let dir = tempdir().unwrap();
    drop(StorageEngine::open(dir.path(), 1024).unwrap());
    large_record_fixture(&dir.path().join("primary"), 100_000);
    let pointer = StorageEngine::open(dir.path(), 1024)
        .expect("standard pointer open must preserve existing valid record cardinality");
    assert_eq!(
        pointer.fetch(praxis::store::RecordId(100_000)).unwrap(),
        b"x"
    );
}

#[test]
fn standard_record_open_supports_more_actual_segments_than_diagnostic_entry_budget() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("records")).unwrap();
    for id in 0_u32..=4096 {
        let mut header = 0x5452_4543_u32.to_le_bytes().to_vec();
        header.push(1);
        header.extend_from_slice(&id.to_le_bytes());
        fs::write(dir.path().join(format!("records/{id:08x}.trec")), header).unwrap();
    }
    fs::write(
        dir.path().join("indirection.tind"),
        b"{\"next_rid\":0,\"next_segment_id\":4096,\"entries\":{}}",
    )
    .unwrap();
    let report =
        praxis::storage::root_format::inspect_storage_root(dir.path(), Default::default()).unwrap();
    assert_eq!(
        report.kind,
        praxis::storage::root_format::RootKind::Incomplete
    );
    let mut store = RecordStore::open(dir.path())
        .expect("standard open must preserve actual segment cardinality");
    let rid = store.put(b"new record").unwrap();
    assert_eq!(store.get(rid).unwrap(), b"new record");
}

#[test]
fn copy_overlap_resolves_existing_alias_before_parent_components() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let dir = tempdir().unwrap();
    let root = dir.path().join("core");
    let engine = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    let alias = dir.path().join("alias");
    symlink_dir(root.join("segments"), &alias).unwrap();
    let before = tree(&root);
    assert!(engine.backup_to(alias.join("../new-child")).is_err());
    assert_eq!(tree(&root), before);
    assert!(!dir.path().join("new-child").exists());
    let backup = dir.path().join("backup");
    engine.backup_to(&backup).unwrap();
    let alias = dir.path().join("backup-alias");
    symlink_dir(backup.join("segments"), &alias).unwrap();
    let before = tree(&backup);
    assert!(PraxisEngine::restore_from_backup(&backup, alias.join("../new-child")).is_err());
    assert_eq!(tree(&backup), before);
}
