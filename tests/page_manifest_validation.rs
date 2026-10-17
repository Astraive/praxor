use praxis::PraxisError;
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::io::crc32_ieee;
use praxis::layout::PraxisLayout;
use praxis::manifest::{ManifestTrackedFile, PageLayoutManifest, PageManifestStore};
use praxis::record::PageDatabase;
use praxis::wal::page::PageWalScanStop;
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = 0x5450_4d46_u32.to_le_bytes().to_vec();
    out.push(1);
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn minimal_row(version: u32, flag: u8) -> Vec<u8> {
    let mut payload = vec![0; 21];
    payload[..4].copy_from_slice(&1_u32.to_le_bytes());
    payload[12..16].copy_from_slice(&version.to_le_bytes());
    payload[20] = flag;
    payload
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if relative == Path::new(".praxor.writer.lock") && metadata.is_file() {
                continue;
            }
            if metadata.is_dir() {
                out.insert(relative, None);
                visit(root, &path, out);
            } else {
                assert!(metadata.is_file());
                out.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[test]
fn invalid_utf8_and_claimed_string_lengths_are_corrupt_without_read_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest");
    let store = PageManifestStore::open(&path);
    for offset in [4, 8, 16] {
        let mut payload = minimal_row(0, 0);
        payload[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        payload.insert(offset + 4, 0xff);
        std::fs::write(&path, frame(&payload)).unwrap();
        let before = tree(dir.path());
        assert!(matches!(store.load(), Err(PraxisError::Corrupt { .. })));
        assert_eq!(tree(dir.path()), before);
        let mut payload = minimal_row(0, 0);
        payload[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, frame(&payload)).unwrap();
        let before = tree(dir.path());
        assert!(matches!(store.load(), Err(PraxisError::Corrupt { .. })));
        assert_eq!(tree(dir.path()), before);
    }
}

#[test]
fn exact_frame_extent_bad_identity_and_every_payload_truncation_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest");
    let store = PageManifestStore::open(&path);
    let payload = minimal_row(0, 0);
    for end in 0..payload.len() {
        let bytes = frame(&payload[..end]);
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(store.load(), Err(PraxisError::Corrupt { .. })));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    for (offset, value) in [(0, 0_u8), (4, 0), (4, 2)] {
        let mut bytes = frame(&payload);
        bytes[offset] = value;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(store.load(), Err(PraxisError::Corrupt { .. })));
    }
    for length in [0_u32, 20, 22, u32::MAX] {
        let mut bytes = frame(&payload);
        bytes[5..9].copy_from_slice(&length.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(store.load(), Err(PraxisError::Corrupt { .. })));
    }
}

#[test]
fn opaque_strings_full_version_range_flags_and_duplicate_order_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest");
    let store = PageManifestStore::open(&path);
    let first = ManifestTrackedFile {
        path: String::new(),
        format: String::new(),
        format_version: 0,
        checksum: String::new(),
        recoverable: false,
    };
    let last = ManifestTrackedFile {
        path: "../opaque\0/猫".into(),
        format: "unregistered-kind🦀".into(),
        format_version: u16::MAX,
        checksum: "not-a-digest\n".into(),
        recoverable: true,
    };
    let expected = PageLayoutManifest {
        files: vec![last.clone(), first.clone(), last, first],
    };
    store.save(&expected).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(store.load().unwrap(), expected);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn malformed_manifest_without_collections_refuses_before_layout_initialization() {
    for (version, flag) in [(1, 2), (65_537, 1)] {
        let dir = tempfile::tempdir().unwrap();
        drop(PageDatabase::open(dir.path()).unwrap());
        let layout = PraxisLayout::new(dir.path());
        let path = layout.page_manifest_path().path;
        std::fs::write(&path, frame(&minimal_row(version, flag))).unwrap();
        // This optional placeholder would be silently recreated by create_all.
        std::fs::remove_file(layout.config_root().join("cache.toml")).unwrap();
        let before = tree(dir.path());
        let result = PageDatabase::open(dir.path());
        assert!(
            matches!(result, Err(PraxisError::Corrupt { .. })) && tree(dir.path()) == before,
            "malformed manifest exposed empty owner or initialized layout: {result:?}"
        );
    }
}

#[test]
fn malformed_manifest_prevents_proven_v2_tail_repair_without_collections() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let wal_path = wal.path().to_path_buf();
    drop(wal);
    drop(database);
    let layout = PraxisLayout::new(dir.path());
    let manifest_path = layout.page_manifest_path().path;
    // A complete managed scaffold plus valid nonempty manifest is independent
    // page authority. No complete WAL record or collection is needed for this tail.
    let good = frame(&minimal_row(1, 1));
    std::fs::write(&manifest_path, &good).unwrap();
    let encoded = PageWalRecord {
        sequence: 1,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(1),
        },
    }
    .try_encode()
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&wal_path)
        .unwrap()
        .write_all(&encoded[..7])
        .unwrap();
    let report = PageWal::replay_prefix(&wal_path).unwrap();
    assert!(matches!(report.stop, PageWalScanStop::ProvenV2Torn { .. }));
    assert!(report.records.is_empty());
    std::fs::write(&manifest_path, frame(&minimal_row(1, 2))).unwrap();
    let before = tree(dir.path());
    let result = PageDatabase::open(dir.path());
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })) && tree(dir.path()) == before,
        "invalid manifest allowed owner/repair: {result:?}; WAL now {}bytes, expected {}",
        std::fs::metadata(&wal_path).unwrap().len(),
        report.physical_len
    );
    // Restoring valid input permits the existing #39 repair and healthy writes.
    std::fs::write(&manifest_path, good).unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(
        PageWal::replay_prefix(&wal_path).unwrap().stop,
        PageWalScanStop::Clean
    );
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = page.put(&[(FieldId::Fixed(Aid(1)), b"healthy")]).unwrap();
    assert_eq!(page.get(rid).unwrap(), b"healthy");
}

#[test]
fn valid_unresolved_inventory_without_collections_remains_compatible_and_usable() {
    let dir = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(dir.path()).unwrap());
    let layout = PraxisLayout::new(dir.path());
    let path = layout.page_manifest_path().path;
    let expected = PageLayoutManifest {
        files: vec![ManifestTrackedFile {
            path: "opaque/not-present".into(),
            format: "unknown-is-opaque".into(),
            format_version: u16::MAX,
            checksum: String::new(),
            recoverable: false,
        }],
    };
    PageManifestStore::open(&path).save(&expected).unwrap();
    let before = tree(dir.path());
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(tree(dir.path()), before);
    assert_eq!(PageManifestStore::open(&path).load().unwrap(), expected);
    let mut a = database.entity(Cid(1), Eid(2)).unwrap();
    let mut b = database.entity(Cid(3), Eid(4)).unwrap();
    let arid = a.put(&[(FieldId::Fixed(Aid(1)), b"A")]).unwrap();
    let brid = b.put(&[(FieldId::Fixed(Aid(1)), b"B")]).unwrap();
    drop(a);
    drop(b);
    drop(database);
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(
        database.entity(Cid(1), Eid(2)).unwrap().get(arid).unwrap(),
        b"A"
    );
    assert_eq!(
        database.entity(Cid(3), Eid(4)).unwrap().get(brid).unwrap(),
        b"B"
    );
}
