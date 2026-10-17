use praxis::api::service::PagePrimitiveStorageService;
use praxis::identity::{Aid, Cid, Eid, FieldId};
use praxis::record::{PageDatabase, PageRecordStore};
use praxis::sdk::LocalPagepraxisClient;
use praxis::store::{RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine, PraxisError};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Alias(PathBuf),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        for item in std::fs::read_dir(at).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            let ty = item.file_type().unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            // The permanent regular caller-base lease is the only admitted addition.
            if ty.is_file() && relative == Path::new(".praxor.writer.lock") {
                continue;
            }
            let value = if ty.is_symlink() {
                Entry::Alias(std::fs::read_link(&path).unwrap())
            } else if ty.is_dir() {
                Entry::Directory
            } else {
                Entry::File(std::fs::read(&path).unwrap())
            };
            result.insert(relative, value);
            if ty.is_dir() && !ty.is_symlink() {
                visit(root, &path, result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn format_refusal(error: &PraxisError) -> bool {
    matches!(
        error,
        PraxisError::StorageFormatMismatch { .. }
            | PraxisError::StorageFormatAmbiguous { .. }
            | PraxisError::StorageFormatIncomplete { .. }
            | PraxisError::StorageFormatUnsupported { .. }
    )
}

fn refusal_matrix(root: &Path) -> bool {
    let refused = |result: praxis::Result<()>| result.as_ref().is_err_and(format_refusal);
    let before = tree(root);
    let results = [
        refused(PageDatabase::open(root).map(drop)),
        refused(PageRecordStore::open(root, Cid(1), Eid(2)).map(drop)),
        refused(PagePrimitiveStorageService::open(root).map(drop)),
        refused(LocalPagepraxisClient::open(root).map(drop)),
        refused(PageDatabase::recover_from_page_wal(root).map(drop)),
    ];
    results.into_iter().all(|result| result) && tree(root) == before
}

#[test]
fn page_open_facades_refuse_foreign_engine_roots_before_layout_creation() {
    let mut violations = Vec::new();
    for owner in ["core", "pointer", "record"] {
        let dir = tempfile::tempdir().unwrap();
        match owner {
            "core" => {
                let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
                engine.put("key", "acknowledged").unwrap();
            }
            "pointer" => {
                let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
                engine.put(b"acknowledged", &[]).unwrap();
                engine.flush().unwrap();
            }
            _ => {
                let mut store = RecordStore::open(dir.path()).unwrap();
                store.put(b"acknowledged").unwrap();
                store.flush().unwrap();
            }
        }
        if !refusal_matrix(dir.path()) {
            violations.push(owner);
        }
    }
    assert!(
        violations.is_empty(),
        "page admitted or changed foreign roots: {violations:?}"
    );
}

#[test]
fn page_facades_refuse_reserved_or_incomplete_storage_evidence_without_changes() {
    let mut violations = Vec::new();
    for (name, bytes) in [
        ("PRAXOR_ROOT", b"future identity".as_slice()),
        ("PRAXOR_ROOT.tmp", b"uncommitted future identity"),
        ("MANIFEST", b"damaged core manifest"),
        ("MANIFEST.store", b"damaged pointer manifest"),
        ("indirection.tind", b"orphan pointer indirection"),
        ("wal/00000000000000000001.wal", b"orphan core WAL"),
        (
            "wal/storage.00000000000000000001.swal",
            b"orphan pointer WAL",
        ),
        ("records/00000001.trec", b"orphan primary"),
        (".praxis/unrecognized.bin", b"unknown page namespace"),
        (
            ".praxis/catalog/page-layout.manifest",
            b"damaged page authority",
        ),
        (".praxis/.praxor.writer.lock", b"misplaced namespace lease"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, bytes);
        if !refusal_matrix(dir.path()) {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "page admitted or changed incompatible evidence: {violations:?}"
    );
}

#[test]
fn page_facades_refuse_misplaced_collection_lease() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    store
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    drop(store);
    drop(database);
    write(
        dir.path(),
        ".praxis/data/0001/.praxor.writer.lock",
        b"misplaced collection lease",
    );
    assert!(refusal_matrix(dir.path()));
}

#[test]
fn already_open_precedes_format_diagnosis_for_every_page_facade() {
    let dir = tempfile::tempdir().unwrap();
    let _foreign_owner = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let before = tree(dir.path());
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert!(matches!(
        PageRecordStore::open(dir.path(), Cid(1), Eid(2)),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert!(matches!(
        PagePrimitiveStorageService::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert!(matches!(
        LocalPagepraxisClient::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert!(matches!(
        PageDatabase::recover_from_page_wal(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn page_base_allows_application_siblings_and_empty_probe_directories() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", b"ordinary application");
    write(dir.path(), "assets/image.bin", b"application asset");
    for relative in ["primary", "primary/records", "records", "wal"] {
        std::fs::create_dir_all(dir.path().join(relative)).unwrap();
    }
    let before = tree(dir.path());
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = store
        .put(&[(FieldId::Fixed(Aid(1)), b"page value")])
        .unwrap();
    drop(store);
    drop(database);
    let store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    assert_eq!(store.get(rid).unwrap(), b"page value");
    let after = tree(dir.path());
    for (path, entry) in before {
        assert_eq!(after.get(&path), Some(&entry));
    }
}

#[cfg(any(unix, windows))]
#[test]
fn page_facades_refuse_namespace_alias_without_touching_its_target() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let outside = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(outside.path()).unwrap());
    let outside_before = tree(outside.path());
    let dir = tempfile::tempdir().unwrap();
    symlink_dir(outside.path().join(".praxis"), dir.path().join(".praxis")).unwrap();
    assert!(refusal_matrix(dir.path()));
    assert_eq!(tree(outside.path()), outside_before);
}

#[test]
fn header_only_wal_requires_exact_bytes_and_a_complete_page_scaffold() {
    let mut header = vec![0; 16];
    header[..4].copy_from_slice(&0x5450_5746_u32.to_le_bytes());
    header[4..8].copy_from_slice(&1_u32.to_le_bytes());
    let mut wrong_version = header.clone();
    wrong_version[4] = 2;
    let mut reserved_nonzero = header.clone();
    reserved_nonzero[8] = 1;
    let mut bad_magic = header.clone();
    bad_magic[0] ^= 1;
    let mut extra_byte = header.clone();
    extra_byte.push(0);
    for bytes in [
        vec![],
        header[..15].to_vec(),
        wrong_version,
        reserved_nonzero,
        bad_magic,
        extra_byte,
    ] {
        let dir = tempfile::tempdir().unwrap();
        drop(PageDatabase::open(dir.path()).unwrap());
        write(dir.path(), ".praxis/logs/page.wal", &bytes);
        assert!(
            refusal_matrix(dir.path()),
            "malformed empty WAL accepted: {bytes:?}"
        );
    }
    let partial = tempfile::tempdir().unwrap();
    write(partial.path(), ".praxis/logs/page.wal", &header);
    assert!(
        refusal_matrix(partial.path()),
        "logs-only root was silently adopted"
    );
    let unknown = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(unknown.path()).unwrap());
    write(unknown.path(), ".praxis/logs/unknown.wal", &header);
    assert!(refusal_matrix(unknown.path()));
}
