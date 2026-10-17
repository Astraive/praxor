use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::io::crc32_ieee;
use praxis::record::PageDatabase;
use praxis::wal::page::PageWalScanStop;
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[path = "support/page_wal_legacy.rs"]
mod legacy;

fn header() -> Vec<u8> {
    let mut bytes = 0x5450_5746_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(&bytes).to_le_bytes());
    bytes
}

fn deletion(sequence: u64) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(1),
        },
    }
}

fn wal_path(root: &Path) -> PathBuf {
    root.join(".praxis/logs/page.wal")
}

fn authoritative(root: &Path) {
    let owner = PageDatabase::open(root).unwrap();
    let mut store = owner.entity(Cid(1), Eid(2)).unwrap();
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"unlogged")]).unwrap(),
        Rid(1)
    );
}

#[test]
fn new_managed_writers_publish_a_v2_file_barrier_and_v2_records() {
    let directory = tempfile::tempdir().unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    let mut store = owner.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = owner.page_wal(WalSyncPolicy::Never).unwrap();
    assert_eq!(std::fs::read(wal.path()).unwrap(), header());
    let rid = store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"v2")])
        .unwrap();
    wal.sync().unwrap();
    let bytes = std::fs::read(wal.path()).unwrap();
    assert_eq!(&bytes[16..20], &0x5450_5732_u32.to_le_bytes());
    assert_eq!(wal.bytes_written().unwrap(), bytes.len() as u64);
    drop(wal);
    drop(store);
    drop(owner);
    let owner = PageDatabase::open(directory.path()).unwrap();
    assert_eq!(
        owner.entity(Cid(1), Eid(2)).unwrap().get(rid).unwrap(),
        b"v2"
    );
}

#[test]
fn owned_legacy_activation_preserves_exact_prefix_bytes() {
    for with_header in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let frame = legacy::encode(&deletion(3));
        let mut bytes = Vec::new();
        if with_header {
            bytes.extend_from_slice(&header());
            bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
            bytes[8..16].fill(0);
        }
        bytes.extend_from_slice(&frame);
        let path = wal_path(directory.path());
        std::fs::write(&path, &bytes).unwrap();
        let owner = PageDatabase::open(directory.path()).unwrap();
        // Read-only normal open does not activate a clean historical log.
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let mut wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [header(), frame.clone()].concat()
        );
        let mut store = owner.entity(Cid(1), Eid(2)).unwrap();
        assert_eq!(store.get(Rid(1)).unwrap(), b"unlogged");
        let rid = store
            .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"new")])
            .unwrap();
        assert_eq!(rid, Rid(2));
        let all = PageWal::replay(&path).unwrap();
        assert_eq!(
            all.iter().map(|record| record.sequence).collect::<Vec<_>>(),
            [3, 4]
        );
        let installed = std::fs::read(&path).unwrap();
        assert_eq!(&installed[16..16 + frame.len()], frame);
        drop(wal);
        drop(store);
        drop(owner);
        for _ in 0..2 {
            let owner = PageDatabase::open(directory.path()).unwrap();
            assert_eq!(
                owner.entity(Cid(1), Eid(2)).unwrap().get(rid).unwrap(),
                b"new"
            );
            assert_eq!(std::fs::read(&path).unwrap(), installed);
        }
    }
}

#[test]
fn every_owned_v2_frame_cut_repairs_before_append_and_two_reopens() {
    let frame = deletion(1).try_encode().unwrap();
    for cut in 1..frame.len() {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let path = wal_path(directory.path());
        let bytes = [header(), frame[..cut].to_vec()].concat();
        std::fs::write(&path, &bytes).unwrap();
        assert!(PageWal::replay(&path).is_err());
        let owner = PageDatabase::open(directory.path())
            .unwrap_or_else(|error| panic!("cut {cut}: {error}"));
        assert_eq!(std::fs::read(&path).unwrap(), header());
        let mut store = owner.entity(Cid(1), Eid(2)).unwrap();
        assert_eq!(store.get(Rid(1)).unwrap(), b"unlogged");
        let mut wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        let rid = store
            .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"after repair")])
            .unwrap();
        assert_eq!(rid, Rid(2));
        assert_eq!(PageWal::replay(&path).unwrap()[0].sequence, 1);
        assert_eq!(
            wal.bytes_written().unwrap(),
            std::fs::metadata(&path).unwrap().len()
        );
        drop(wal);
        drop(store);
        drop(owner);
        for _ in 0..2 {
            let owner = PageDatabase::open(directory.path()).unwrap();
            assert_eq!(
                owner.entity(Cid(1), Eid(2)).unwrap().get(rid).unwrap(),
                b"after repair"
            );
            assert_eq!(PageWal::replay(&path).unwrap().len(), 1);
        }
    }
}

#[test]
fn authoritative_header_repair_keeps_early_version_ambiguity_closed() {
    let full = header();
    for cut in 1..full.len() {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let path = wal_path(directory.path());
        std::fs::write(&path, &full[..cut]).unwrap();
        if cut <= 4 {
            assert!(PageDatabase::open(directory.path()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), full[..cut]);
        } else {
            let owner = PageDatabase::open(directory.path())
                .unwrap_or_else(|error| panic!("header cut {cut}: {error}"));
            assert_eq!(std::fs::read(&path).unwrap(), full);
            assert_eq!(
                owner.entity(Cid(1), Eid(2)).unwrap().get(Rid(1)).unwrap(),
                b"unlogged"
            );
        }
    }
}

#[test]
fn exact_v2_header_is_admitted_only_on_a_complete_empty_scaffold() {
    let directory = tempfile::tempdir().unwrap();
    drop(PageDatabase::open(directory.path()).unwrap());
    let path = wal_path(directory.path());
    std::fs::write(&path, header()).unwrap();
    drop(PageDatabase::open(directory.path()).unwrap());
    assert_eq!(std::fs::read(path).unwrap(), header());
}

#[test]
fn complete_v2_corruption_and_ambiguous_legacy_never_repair() {
    for mut frame in [
        deletion(1).try_encode().unwrap(),
        legacy::encode(&deletion(1)),
    ] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let v2 = frame[4] == 2;
        if v2 {
            *frame.last_mut().unwrap() ^= 1;
        } else {
            frame.truncate(7);
        }
        let bytes = if v2 {
            [header(), frame].concat()
        } else {
            frame
        };
        let path = wal_path(directory.path());
        std::fs::write(&path, &bytes).unwrap();
        assert!(PageDatabase::open(directory.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(!matches!(
            PageWal::replay_prefix(&path).unwrap().stop,
            PageWalScanStop::Clean
        ));
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(path).unwrap() {
            let path = item.unwrap().path();
            let key = path.strip_prefix(root).unwrap().to_path_buf();
            if path.is_dir() {
                output.insert(key, None);
                walk(root, &path, output);
            } else {
                output.insert(key, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}

#[test]
fn all_directory_and_semantic_validation_precedes_torn_repair() {
    for failure in [
        "later collection page",
        "missing directory",
        "semantic conflict",
    ] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let owner = PageDatabase::open(directory.path()).unwrap();
        let mut later = owner.entity(Cid(2), Eid(2)).unwrap();
        later.put(&[(FieldId::Fixed(Aid(1)), b"later")]).unwrap();
        let later_page = later
            .layout()
            .page_path(
                Cid(2),
                Eid(2),
                praxis::identity::Fid(1),
                praxis::identity::Pid(1),
            )
            .path;
        let rid_directory = later.layout().critical_map_path(Cid(1), "rid_to_slot").path;
        drop(later);
        drop(owner);
        let first = if failure == "semantic conflict" {
            PageWalRecord {
                sequence: 1,
                mutation: PageWalMutation::Put {
                    cid: Cid(1),
                    eid: Eid(2),
                    rid: Rid(1),
                    fields: vec![(FieldId::Fixed(Aid(1)), b"conflicting".to_vec())],
                },
            }
        } else {
            deletion(1)
        };
        let tail = deletion(2).try_encode().unwrap();
        let bytes = [header(), first.try_encode().unwrap(), tail[..20].to_vec()].concat();
        let path = wal_path(directory.path());
        std::fs::write(&path, &bytes).unwrap();
        if failure == "later collection page" {
            let mut bytes = std::fs::read(&later_page).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(&later_page, bytes).unwrap();
        } else if failure == "missing directory" {
            std::fs::remove_file(rid_directory).unwrap();
        }
        assert!(matches!(
            PageWal::replay_prefix(&path).unwrap().stop,
            PageWalScanStop::ProvenV2Torn { .. }
        ));
        let before = snapshot(directory.path());
        assert!(PageDatabase::open(directory.path()).is_err(), "{failure}");
        assert_eq!(snapshot(directory.path()), before, "{failure}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn stale_upgrade_siblings_never_supply_canonical_history() {
    let directory = tempfile::tempdir().unwrap();
    authoritative(directory.path());
    let path = wal_path(directory.path());
    let stale = path.with_file_name("page.wal.upgrade-stale.tmp");
    let stale_bytes = [header(), deletion(99).try_encode().unwrap()].concat();
    std::fs::write(&stale, &stale_bytes).unwrap();
    let original = legacy::encode(&deletion(1));
    std::fs::write(&path, &original).unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    let _wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    assert_eq!(PageWal::replay(&path).unwrap(), [deletion(1)]);
    assert_eq!(std::fs::read(&stale).unwrap(), stale_bytes);
    assert_eq!(std::fs::read(path).unwrap(), [header(), original].concat());
}

#[cfg(unix)]
#[test]
fn upgrade_replaces_the_path_while_external_old_descriptor_keeps_its_inode() {
    use std::io::Read;
    let directory = tempfile::tempdir().unwrap();
    authoritative(directory.path());
    let path = wal_path(directory.path());
    let original = legacy::encode(&deletion(1));
    std::fs::write(&path, &original).unwrap();
    let mut old_descriptor = std::fs::File::open(&path).unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    let mut wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    owner
        .entity(Cid(1), Eid(2))
        .unwrap()
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"new inode")])
        .unwrap();
    let mut old_bytes = Vec::new();
    old_descriptor.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, original);
    assert_eq!(PageWal::replay(&path).unwrap().len(), 2);
}

#[cfg(windows)]
#[test]
fn windows_share_delete_denial_keeps_the_original_and_poisons_activation() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = tempfile::tempdir().unwrap();
    authoritative(directory.path());
    let path = wal_path(directory.path());
    let original = legacy::encode(&deletion(1));
    std::fs::write(&path, &original).unwrap();
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(&path)
        .unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    assert!(owner.page_wal(WalSyncPolicy::EveryBatch).is_err());
    assert!(owner.entity(Cid(1), Eid(2)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    drop(blocker);
    drop(owner);
    let owner = PageDatabase::open(directory.path()).unwrap();
    let _wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), [header(), original].concat());
}

#[cfg(windows)]
#[test]
fn windows_readonly_target_refuses_replacement_without_unlinking() {
    let directory = tempfile::tempdir().unwrap();
    authoritative(directory.path());
    let path = wal_path(directory.path());
    let original = legacy::encode(&deletion(1));
    std::fs::write(&path, &original).unwrap();
    let original_permissions = std::fs::metadata(&path).unwrap().permissions();
    let mut permissions = original_permissions.clone();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    let result = owner.page_wal(WalSyncPolicy::EveryBatch);
    let original_preserved = std::fs::read(&path).unwrap() == original;
    std::fs::set_permissions(&path, original_permissions).unwrap();
    assert!(result.is_err());
    assert!(original_preserved);
}

#[test]
fn repaired_owner_clones_share_one_sequence_across_collections() {
    let directory = tempfile::tempdir().unwrap();
    authoritative(directory.path());
    let path = wal_path(directory.path());
    let prefix = deletion(1).try_encode().unwrap();
    let tail = deletion(2).try_encode().unwrap();
    std::fs::write(&path, [header(), prefix, tail[..20].to_vec()].concat()).unwrap();
    let owner = PageDatabase::open(directory.path()).unwrap();
    let mut workers = Vec::new();
    for index in 0..4 {
        let owner = owner.clone();
        workers.push(std::thread::spawn(move || {
            let cid = Cid(1 + index % 2);
            let mut store = owner.entity(cid, Eid(2)).unwrap();
            let mut wal = owner.page_wal(WalSyncPolicy::EveryBatch).unwrap();
            (0..6)
                .map(|step| {
                    let value = format!("worker {index} step {step}").into_bytes();
                    let rid = store
                        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), &value)])
                        .unwrap();
                    (cid, rid, value)
                })
                .collect::<Vec<_>>()
        }));
    }
    let receipts: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        PageWal::replay(&path)
            .unwrap()
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        (1..=25).collect::<Vec<_>>()
    );
    drop(owner);
    for _ in 0..2 {
        let owner = PageDatabase::open(directory.path()).unwrap();
        for (cid, rid, value) in &receipts {
            assert_eq!(
                owner.entity(*cid, Eid(2)).unwrap().get(*rid).unwrap(),
                *value
            );
        }
        assert_eq!(
            owner.entity(Cid(1), Eid(2)).unwrap().get(Rid(1)).unwrap(),
            b"unlogged"
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_activation_preserves_restrictive_canonical_wal_mode() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o600, 0o640] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let path = wal_path(directory.path());
        let original = legacy::encode(&deletion(1));
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let owner = PageDatabase::open(directory.path()).unwrap();
        let _wal = owner.page_wal(WalSyncPolicy::Never).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode
        );
        assert_eq!(std::fs::read(&path).unwrap(), [header(), original].concat());
    }
}
