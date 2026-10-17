use praxis::PraxisError;
use praxis::catalog::{CatalogSnapshot, CatalogStore};
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid};
use praxis::layout::PraxisLayout;
use praxis::manifest::{ManifestTrackedFile, PageLayoutManifest, PageManifestStore};
use praxis::record::PageDatabase;
use praxis::wal::page::PageWalScanStop;
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Alias(PathBuf),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for item in std::fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if relative == Path::new(".praxor.writer.lock") && metadata.is_file() {
                continue;
            }
            #[cfg(windows)]
            let alias = {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let alias = metadata.file_type().is_symlink();
            if alias {
                out.insert(relative, Entry::Alias(std::fs::read_link(path).unwrap()));
            } else if metadata.is_dir() {
                out.insert(relative, Entry::Directory);
                visit(root, &path, out);
            } else {
                assert!(metadata.is_file());
                out.insert(relative, Entry::File(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn seed(root: &Path) -> PraxisLayout {
    let database = PageDatabase::open(root).unwrap();
    let mut page = database.entity(Cid(0x1_0001), Eid(0x2_0002)).unwrap();
    let rid = page
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    assert_eq!(rid, Rid(1));
    assert_eq!(page.get(rid).unwrap(), b"acknowledged");
    page.layout().clone()
}

fn assert_read(root: &Path) {
    let database = PageDatabase::open(root).unwrap();
    assert_eq!(
        database
            .entity(Cid(0x1_0001), Eid(0x2_0002))
            .unwrap()
            .get(Rid(1))
            .unwrap(),
        b"acknowledged"
    );
}

fn move_owned(from: &Path, to: &Path, owned: &Path) {
    let absolute = from.canonicalize().unwrap();
    assert!(absolute.is_absolute() && absolute.starts_with(owned) && absolute != owned);
    assert!(
        to.parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(owned)
    );
    assert!(!to.exists());
    std::fs::rename(from, to).unwrap();
}

#[test]
fn whole_non_wal_collection_loss_refuses_without_touching_the_surviving_tree() {
    let fixture = tempfile::tempdir().unwrap();
    let owned = fixture.path().canonicalize().unwrap();
    let root = owned.join("database");
    let layout = seed(&root);
    assert_read(&root);
    assert_eq!(
        PageManifestStore::open(layout.page_manifest_path().path)
            .load()
            .unwrap()
            .files
            .len(),
        3
    );
    let intact = tree(&root);
    let collection = layout.collection_root(Cid(0x1_0001));
    let parked = owned.join("parked-collection");
    move_owned(&collection, &parked, &owned);
    let before = tree(&root);
    let result = PageDatabase::open(&root);
    let refused = matches!(result, Err(PraxisError::PageRecoveryRequired { .. }));
    println!("whole collection refusal={refused}; actual={result:?}");
    drop(result); // No allocator/entity operation is attempted on a damaged root.
    assert_eq!(tree(&root), before);
    move_owned(&parked, &collection, &owned);
    assert_eq!(tree(&root), intact);
    assert_read(&root);
    assert!(
        refused,
        "surviving known inventory must detect whole collection loss"
    );
}

#[test]
fn each_known_role_and_whole_entity_or_frame_loss_refuses_before_mutation() {
    for kind in [
        "record-page",
        "slot-directory",
        "rid-directory",
        "entity",
        "frame",
    ] {
        let fixture = tempfile::tempdir().unwrap();
        let owned = fixture.path().canonicalize().unwrap();
        let root = owned.join("database");
        let layout = seed(&root);
        let store = PageManifestStore::open(layout.page_manifest_path().path);
        let manifest = store.load().unwrap();
        let source = match kind {
            "entity" => layout.entity_root(Cid(0x1_0001), Eid(0x2_0002)),
            "frame" => layout.frame_root(Cid(0x1_0001), Eid(0x2_0002), Fid(1)),
            _ => PathBuf::from(
                &manifest
                    .files
                    .iter()
                    .find(|row| row.format == kind)
                    .unwrap()
                    .path,
            ),
        };
        let parked = owned.join("parked");
        move_owned(&source, &parked, &owned);
        let before = tree(&root);
        let result = PageDatabase::open(&root);
        assert!(
            matches!(result, Err(PraxisError::PageRecoveryRequired { .. })),
            "{kind}: {result:?}"
        );
        assert_eq!(tree(&root), before, "{kind}");
        move_owned(&parked, &source, &owned);
        assert_read(&root);
    }
}

#[test]
fn missing_slot_inventory_prevents_proven_torn_wal_repair_and_layout_creation() {
    let dir = tempfile::tempdir().unwrap();
    let layout = seed(dir.path());
    let database = PageDatabase::open(dir.path()).unwrap();
    let wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let wal_path = wal.path().to_path_buf();
    drop(wal);
    drop(database);
    let frame = PageWalRecord {
        sequence: 1,
        mutation: PageWalMutation::Delete {
            cid: Cid(0x1_0001),
            eid: Eid(0x2_0002),
            rid: Rid(1),
        },
    }
    .try_encode()
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&wal_path)
        .unwrap()
        .write_all(&frame[..7])
        .unwrap();
    assert!(matches!(
        PageWal::replay_prefix(&wal_path).unwrap().stop,
        PageWalScanStop::ProvenV2Torn { .. }
    ));
    let slot = layout
        .slot_directory_path(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1))
        .path;
    let original = std::fs::read(&slot).unwrap();
    std::fs::remove_file(&slot).unwrap();
    std::fs::remove_file(layout.config_root().join("cache.toml")).unwrap();
    let before = tree(dir.path());
    let result = PageDatabase::open(dir.path());
    assert!(
        matches!(result, Err(PraxisError::PageRecoveryRequired { .. }))
            && tree(dir.path()) == before,
        "missing slot allowed owner/repair/layout: {result:?}; WAL length={}",
        std::fs::metadata(&wal_path).unwrap().len()
    );
    std::fs::write(slot, original).unwrap();
    assert_read(dir.path()); // Existing #39 repair succeeds only after evidence is restored.
    assert_eq!(
        PageWal::replay_prefix(&wal_path).unwrap().stop,
        PageWalScanStop::Clean
    );
}

#[test]
fn literal_unix_windows_verbatim_and_unc_role_labels_resolve_under_current_root() {
    let dir = tempfile::tempdir().unwrap();
    let layout = seed(dir.path());
    let store = PageManifestStore::open(layout.page_manifest_path().path);
    let original = store.load().unwrap();
    for (prefix, separator) in [
        ("/absent/.praxis/old", '/'),
        (r"C:\absent", '\\'),
        (r"\\?\C:\absent", '\\'),
        (r"\\server\share\absent", '\\'),
        (r"\\?\UNC\server\share\absent", '\\'),
    ] {
        let mut inventory = original.clone();
        for row in &mut inventory.files {
            let suffix = match row.format.as_str() {
                "record-page" => {
                    ".praxis/data/10001/entities/20002/pages/frames/0001/pages/0001.page"
                }
                "slot-directory" => {
                    ".praxis/data/10001/entities/20002/slots/0001/0001/slot.directory"
                }
                "rid-directory" => ".praxis/data/10001/kv/critical/rid_to_slot.kv",
                _ => unreachable!(),
            };
            row.path = format!(
                "{prefix}{separator}{}",
                suffix.replace('/', &separator.to_string())
            );
            row.checksum = "foreign checksum is not a relocated content witness".into();
        }
        store.save(&inventory).unwrap();
        let before = tree(dir.path());
        assert_read(dir.path());
        assert_eq!(tree(dir.path()), before);
        assert_eq!(store.load().unwrap(), inventory);
    }
}

#[test]
fn known_roles_cannot_bypass_presence_with_false_flag_or_unresolvable_labels() {
    let dir = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    let store = PageManifestStore::open(PraxisLayout::new(dir.path()).page_manifest_path().path);
    let cases = [
        (
            "rid-directory",
            "/absent/.praxis/data/0001/kv/critical/rid_to_slot.kv",
        ),
        (
            "record-page",
            "/absent/.praxis/data/0001/entities/0002/pages/frames/0001/pages/0001.page/extra",
        ),
        (
            "record-page",
            "/absent/.praxis/data/0001/entities/0002/pages/frames/0001/../pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/0001/entities/0002/pages\\frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/0000/entities/0002/pages/frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/00001/entities/0002/pages/frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/100000000/entities/0002/pages/frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/FFFF/entities/0002/pages/frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/+001/entities/0002/pages/frames/0001/pages/0001.page",
        ),
        (
            "record-page",
            "/absent/.praxis/data/0001/kv/critical/rid_to_slot.kv",
        ),
        (
            "slot-directory",
            "/absent/.praxis/data/0001/entities/0002/slots/0001/0001/slot.directory/extra",
        ),
        (
            "rid-directory",
            "/absent/not.praxis/data/0001/kv/critical/rid_to_slot.kv",
        ),
    ];
    for (format, label) in cases {
        for recoverable in [false, true] {
            store
                .save(&PageLayoutManifest {
                    files: vec![ManifestTrackedFile {
                        path: label.into(),
                        format: format.into(),
                        format_version: 1,
                        checksum: "opaque".into(),
                        recoverable,
                    }],
                })
                .unwrap();
            let before = tree(dir.path());
            let result = PageDatabase::open(dir.path());
            assert!(
                matches!(result, Err(PraxisError::PageRecoveryRequired { .. })),
                "{format} {label} {recoverable}: {result:?}"
            );
            assert_eq!(tree(dir.path()), before);
        }
    }
}

#[test]
fn unknown_formats_versions_and_legacy_absence_remain_non_authority() {
    let dir = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    let path = PraxisLayout::new(dir.path()).page_manifest_path().path;
    let store = PageManifestStore::open(&path);
    let inventory = PageLayoutManifest {
        files: vec![
            ManifestTrackedFile::durable("opaque\0/not/a/path", "unknown", 1, "opaque"),
            ManifestTrackedFile::durable("malformed-known-label", "record-page", 0, "opaque"),
            ManifestTrackedFile::durable(
                "malformed-known-label",
                "slot-directory",
                u16::MAX,
                "opaque",
            ),
        ],
    };
    store.save(&inventory).unwrap();
    let before = tree(dir.path());
    drop(PageDatabase::open(dir.path()).unwrap());
    assert_eq!(tree(dir.path()), before);
    assert_eq!(store.load().unwrap(), inventory);
    store.save(&PageLayoutManifest::default()).unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    std::fs::remove_file(path).unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    let catalog_root = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(catalog_root.path()).unwrap();
    catalog.save(&CatalogSnapshot::default()).unwrap();
    drop(catalog);
    drop(PageDatabase::open(catalog_root.path()).unwrap());
}

#[test]
fn maximum_canonical_ids_and_unparsed_slot_body_are_presence_only() {
    let dir = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    let layout = PraxisLayout::new(dir.path());
    let slot = layout
        .slot_directory_path(Cid(u32::MAX), Eid(u32::MAX), Fid(u32::MAX), Pid(u32::MAX))
        .path;
    std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
    std::fs::write(&slot, b"slot body is not decoded by this slice").unwrap();
    let row = ManifestTrackedFile::durable(
        "/absent/.praxis/data/ffffffff/entities/ffffffff/slots/ffffffff/ffffffff/slot.directory",
        "slot-directory",
        1,
        "not selected for checksum",
    );
    PageManifestStore::open(layout.page_manifest_path().path)
        .save(&PageLayoutManifest { files: vec![row] })
        .unwrap();
    let before = tree(dir.path());
    drop(PageDatabase::open(dir.path()).unwrap());
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn known_slot_leaf_directory_is_rejected_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let layout = seed(dir.path());
    let path = layout
        .slot_directory_path(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1))
        .path;
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = tree(dir.path());
    assert!(PageDatabase::open(dir.path()).is_err());
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn existing_foreign_source_cannot_supply_a_missing_current_role() {
    let dir = tempfile::tempdir().unwrap();
    let owned = dir.path().canonicalize().unwrap();
    let a = owned.join("A");
    let b = owned.join("B");
    seed(&a);
    std::fs::create_dir(&b).unwrap();
    // Copy bytes/entries independently; manifest still names the existing A.
    for (relative, entry) in tree(&a) {
        let path = b.join(relative);
        match entry {
            Entry::Directory => std::fs::create_dir_all(path).unwrap(),
            Entry::File(bytes) => std::fs::write(path, bytes).unwrap(),
            Entry::Alias(_) => unreachable!(),
        }
    }
    assert_read(&b);
    let layout = PraxisLayout::new(&b);
    let slot = layout
        .slot_directory_path(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1))
        .path;
    let parked = owned.join("parked");
    move_owned(&slot, &parked, &owned);
    let a_before = tree(&a);
    let b_before = tree(&b);
    let result = PageDatabase::open(&b);
    assert!(
        matches!(result, Err(PraxisError::PageRecoveryRequired { .. })),
        "{result:?}"
    );
    assert_eq!(tree(&a), a_before);
    assert_eq!(tree(&b), b_before);
    assert_read(&a);
}

#[test]
fn a_current_slot_ancestor_file_is_not_absence_or_an_adoptable_directory() {
    let dir = tempfile::tempdir().unwrap();
    let owned = dir.path().canonicalize().unwrap();
    let root = owned.join("database");
    let layout = seed(&root);
    let slots = layout.slot_directory_root(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1));
    move_owned(&slots, &owned.join("parked"), &owned);
    std::fs::write(slots, b"not a directory").unwrap();
    let before = tree(&root);
    let result = PageDatabase::open(&root);
    assert!(
        matches!(result, Err(PraxisError::PageRecoveryRequired { .. })),
        "{result:?}"
    );
    assert_eq!(tree(&root), before);
}

#[cfg(any(unix, windows))]
#[test]
fn known_slot_leaf_and_ancestor_aliases_never_adopt_peer_evidence() {
    #[cfg(unix)]
    use std::os::unix::fs::{symlink as symlink_dir, symlink as symlink_file};
    #[cfg(windows)]
    use std::os::windows::fs::{symlink_dir, symlink_file};
    for alias_parent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let owned = dir.path().canonicalize().unwrap();
        let root = owned.join("database");
        let layout = seed(&root);
        let slot = layout
            .slot_directory_path(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1))
            .path;
        let target = if alias_parent {
            slot.parent().unwrap()
        } else {
            &slot
        };
        let peer = owned.join("parked");
        move_owned(target, &peer, &owned);
        if alias_parent {
            symlink_dir(&peer, target).unwrap();
        } else {
            symlink_file(&peer, target).unwrap();
        }
        let before = tree(&root);
        let peer_before = if alias_parent {
            tree(&peer)
        } else {
            BTreeMap::from([(PathBuf::new(), Entry::File(std::fs::read(&peer).unwrap()))])
        };
        assert!(PageDatabase::open(&root).is_err());
        assert_eq!(tree(&root), before);
        if alias_parent {
            assert_eq!(tree(&peer), peer_before);
        } else {
            assert_eq!(
                std::fs::read(&peer).unwrap(),
                match &peer_before[Path::new("")] {
                    Entry::File(bytes) => bytes.clone(),
                    _ => unreachable!(),
                }
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn a_windows_directory_junction_is_refused_without_touching_its_peer() {
    use std::os::windows::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let owned = dir.path().canonicalize().unwrap();
    let root = owned.join("database");
    let layout = seed(&root);
    let slots = layout.slot_directory_root(Cid(0x1_0001), Eid(0x2_0002), Fid(1), Pid(1));
    let peer = owned.join("parked");
    move_owned(&slots, &peer, &owned);
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&slots)
        .arg(&peer)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "junction creation failed: {output:?}"
    );
    assert_ne!(
        std::fs::symlink_metadata(&slots).unwrap().file_attributes() & 0x400,
        0
    );
    let before = tree(&root);
    let peer_before = tree(&peer);
    let result = PageDatabase::open(&root);
    assert!(
        matches!(result, Err(PraxisError::PageRecoveryRequired { .. })),
        "{result:?}"
    );
    assert_eq!(tree(&root), before);
    assert_eq!(tree(&peer), peer_before);
    std::fs::remove_dir(slots).unwrap(); // Remove only the junction, never its target.
}
