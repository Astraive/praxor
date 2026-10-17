use praxis::layout::PraxisLayout;
use praxis::store::{RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn contents(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".praxor.writer.lock" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
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
fn a_forged_incomplete_marker_never_authorizes_erasing_foreign_roots() {
    for kind in ["pointer", "record", "page"] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        let engine = PraxisEngine::open(PraxisConfig::new(source)).unwrap();
        engine.put("source", "source").unwrap();
        match kind {
            "pointer" => {
                let mut store = StorageEngine::open(&target, 1024).unwrap();
                store.put(b"foreign", &[]).unwrap();
                store.flush().unwrap();
            }
            "record" => {
                let mut store = RecordStore::open(&target).unwrap();
                store.put(b"foreign").unwrap();
                store.flush().unwrap();
            }
            _ => {
                PraxisLayout::new(&target).create_all().unwrap();
            }
        }
        std::fs::write(
            target.join("CORE_COPY_INCOMPLETE"),
            b"praxor core copy incomplete v1\n",
        )
        .unwrap();
        let before = contents(&target);
        assert!(
            engine.backup_to(&target).is_err(),
            "a forged marker admitted {kind}"
        );
        assert_eq!(contents(&target), before, "refusal changed {kind} data");
    }
}

#[test]
fn an_unrecognized_marker_is_not_a_copy_retry_capability() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("CORE_COPY_INCOMPLETE"), b"unknown writer").unwrap();
    let before = contents(&target);
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path().join("source"))).unwrap();
    assert!(engine.backup_to(&target).is_err());
    assert_eq!(contents(&target), before);
}

fn unflushed_bundle(base: &Path) -> PathBuf {
    let mut config = PraxisConfig::new(base.join("live"));
    config.wal_segment_size = config.page_size;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine
        .put("first", vec![b'F'; config.page_size * 2])
        .unwrap();
    engine.put("second", "second").unwrap();
    let bundle = base.join("bundle");
    engine.backup_to(&bundle).unwrap();
    bundle
}

#[test]
fn missing_required_wal_refuses_restore_without_replacing_existing_rows() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = unflushed_bundle(dir.path());
    std::fs::remove_file(bundle.join("wal/00000000000000000001.wal")).unwrap();
    let target = dir.path().join("target");
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("old", "old").unwrap();
        old.flush().unwrap();
    }
    let before = contents(&target);
    assert!(PraxisEngine::restore_from_backup(bundle, &target).is_err());
    assert_eq!(contents(&target), before);
}

#[test]
fn a_whole_missing_committed_frame_is_not_a_complete_backup() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = unflushed_bundle(dir.path());
    let wal = bundle.join("wal/00000000000000000002.wal");
    std::fs::OpenOptions::new()
        .write(true)
        .open(wal)
        .unwrap()
        .set_len(16)
        .unwrap();
    let target = dir.path().join("target");
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("old", "old").unwrap();
        old.flush().unwrap();
    }
    let before = contents(&target);
    assert!(PraxisEngine::restore_from_backup(bundle, &target).is_err());
    assert_eq!(contents(&target), before);
}

#[test]
fn invalid_segment_roles_digests_and_value_records_never_replace_previous_data() {
    use praxis::manifest::ManifestStore;
    for damage in [
        "missing",
        "digest",
        "role",
        "origin",
        "value-header",
        "value-crc",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PraxisConfig::new(dir.path().join("live"));
        config.large_value_threshold = 8;
        let source = PraxisEngine::open(config).unwrap();
        source.put("external", vec![b'X'; 4096]).unwrap();
        source.flush().unwrap();
        let bundle = dir.path().join("bundle");
        source.backup_to(&bundle).unwrap();
        let store = ManifestStore::new(bundle.join("MANIFEST"));
        let mut manifest = store.load_or_create(&PraxisConfig::new(&bundle)).unwrap();
        let segment = PathBuf::from(&manifest.segments[0].path);
        match damage {
            "missing" => std::fs::remove_file(&segment).unwrap(),
            "digest" => {
                let mut bytes = std::fs::read(&segment).unwrap();
                bytes[25] ^= 1;
                std::fs::write(&segment, bytes).unwrap();
            }
            "role" => {
                manifest.segments[0].path = bundle
                    .join("segments/0/00000000000000099999.tseg")
                    .to_string_lossy()
                    .into_owned();
                store.save(&manifest).unwrap();
            }
            "origin" => {
                manifest.segments[0].path = dir
                    .path()
                    .join("foreign")
                    .join(
                        segment
                            .strip_prefix(bundle.canonicalize().unwrap())
                            .unwrap(),
                    )
                    .to_string_lossy()
                    .into_owned();
                store.save(&manifest).unwrap();
            }
            _ => {
                let value = std::fs::read_dir(bundle.join("values"))
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                let mut bytes = std::fs::read(&value).unwrap();
                let position = if damage == "value-header" {
                    0
                } else {
                    bytes.len() - 1
                };
                bytes[position] ^= 1;
                std::fs::write(value, bytes).unwrap();
            }
        }
        let source_before = contents(&bundle);
        let target = dir.path().join("target");
        {
            let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
            old.put("old", "old").unwrap();
            old.flush().unwrap();
        }
        let before = contents(&target);
        assert!(
            PraxisEngine::restore_from_backup(&bundle, &target).is_err(),
            "accepted {damage}"
        );
        assert_eq!(contents(&target), before, "replaced target for {damage}");
        assert_eq!(
            contents(&bundle),
            source_before,
            "modified source for {damage}"
        );
    }
}
