#[path = "../support/page_wal_legacy.rs"]
mod legacy;
use praxis::PraxisError;
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::record::PageDatabase;
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn put_record(sequence: u64, rid: u64, value: &[u8]) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(rid),
            fields: vec![(FieldId::Fixed(Aid(1)), value.to_vec())],
        },
    }
}

fn write_log(root: &Path, records: &[PageWalRecord], tail: &[u8]) -> PathBuf {
    let path = root.join(".praxis/logs/page.wal");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x5450_5746_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    for record in records {
        bytes.extend_from_slice(&legacy::encode(record));
    }
    bytes.extend_from_slice(tail);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn contents(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(base, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

#[test]
fn managed_page_wal_roundtrips_put_and_delete_records() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let rid = store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"value")])
        .unwrap();
    store.delete_durable(&mut wal, rid).unwrap();
    let replayed = PageWal::replay(wal.path()).unwrap();
    assert_eq!(
        replayed,
        vec![
            put_record(1, rid.0, b"value"),
            PageWalRecord {
                sequence: 2,
                mutation: PageWalMutation::Delete {
                    cid: Cid(1),
                    eid: Eid(2),
                    rid
                }
            }
        ]
    );
}

#[test]
fn directory_loss_is_ambiguous_even_when_all_visible_wal_records_look_complete() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"durable")])
        .unwrap();
    std::fs::remove_file(store.layout().critical_map_path(Cid(1), "rid_to_slot").path).unwrap();
    drop(wal);
    drop(store);
    drop(database);
    let before = contents(dir.path());
    assert!(matches!(
        PageDatabase::recover_from_page_wal(dir.path()),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert_eq!(contents(dir.path()), before);
    assert_eq!(
        PageWal::replay(&dir.path().join(".praxis/logs/page.wal"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn identical_unlogged_payload_and_lost_high_water_cannot_be_inferred_from_wal() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let first = store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"x")])
        .unwrap();
    store.delete(first).unwrap();
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"x")]).unwrap(),
        Rid(2)
    );
    for name in [
        "rid_to_slot",
        "rid_to_page",
        "rid_to_entity",
        "sequence",
        "commit_state",
    ] {
        std::fs::remove_file(store.layout().critical_map_path(Cid(1), name).path).unwrap();
    }
    drop(wal);
    drop(store);
    drop(database);
    let before = contents(dir.path());
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        PageDatabase::recover_from_page_wal(dir.path()),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn unapplied_source_history_is_refused_and_records_can_be_applied_to_an_explicit_fresh_target() {
    let source = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(source.path()).unwrap();
    drop(database);
    let path = write_log(source.path(), &[put_record(1, 7, b"logged subset")], &[]);
    let before = contents(source.path());
    assert!(matches!(
        PageDatabase::open(source.path()),
        Err(PraxisError::PageRecoveryRequired { .. } | PraxisError::StorageFormatIncomplete { .. })
    ));
    let records = PageWal::replay(&path).unwrap();
    let target = tempfile::tempdir().unwrap();
    let target_database = PageDatabase::open(target.path()).unwrap();
    let mut store = target_database.entity(Cid(1), Eid(2)).unwrap();
    store.replay_page_wal(&records).unwrap();
    assert_eq!(store.get(Rid(7)).unwrap(), b"logged subset");
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"next")]).unwrap(),
        Rid(8)
    );
    assert_eq!(contents(source.path()), before);
}

#[test]
fn intact_directory_recovery_and_repeated_delete_preserve_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let rid = store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"gone")])
        .unwrap();
    store.delete_durable(&mut wal, rid).unwrap();
    drop(wal);
    drop(store);
    drop(database);
    let database = PageDatabase::recover_from_page_wal(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let record = PageWalRecord {
        sequence: 2,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid,
        },
    };
    store.apply_page_wal_record(&record).unwrap();
    store.apply_page_wal_record(&record).unwrap();
    assert!(matches!(store.get(rid), Err(PraxisError::KeyNotFound)));
}

#[test]
fn forensic_prefix_does_not_authorize_writable_open_after_a_torn_record() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    drop(database);
    let first = put_record(1, 1, b"good");
    let second = legacy::encode(&put_record(2, 2, b"torn"));
    let path = write_log(
        dir.path(),
        std::slice::from_ref(&first),
        &second[..second.len() / 2],
    );
    assert!(PageWal::replay(&path).is_err());
    let report = PageWal::replay_prefix(&path).unwrap();
    assert_eq!(report.records, vec![first]);
    assert!(matches!(
        report.stop,
        praxis::wal::page::PageWalScanStop::LegacyAmbiguousTail { .. }
    ));
    let before = contents(dir.path());
    assert!(PageDatabase::open(dir.path()).is_err());
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn managed_handles_share_sequence_policy_and_final_owner_lifetime() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut first = database.page_wal(WalSyncPolicy::GroupCommit).unwrap();
    let mut second = database.page_wal(WalSyncPolicy::GroupCommit).unwrap();
    assert!(matches!(
        database.page_wal(WalSyncPolicy::Never),
        Err(PraxisError::InvalidConfig(_))
    ));
    store
        .put_durable(&mut first, &[(FieldId::Fixed(Aid(1)), b"one")])
        .unwrap();
    store
        .put_durable(&mut second, &[(FieldId::Fixed(Aid(1)), b"two")])
        .unwrap();
    assert_eq!(
        first.bytes_written().unwrap(),
        second.bytes_written().unwrap()
    );
    assert_eq!(
        PageWal::replay(second.path())
            .unwrap()
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    drop(first);
    drop(store);
    drop(database);
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    second.sync().unwrap();
    drop(second);
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(
        database
            .entity(Cid(1), Eid(2))
            .unwrap()
            .put(&[(FieldId::Fixed(Aid(1)), b"next")])
            .unwrap(),
        Rid(3)
    );
}

#[test]
fn normal_open_rejects_a_complete_wal_conflicting_with_canonical_payload() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    assert_eq!(
        store
            .put(&[(FieldId::Fixed(Aid(1)), b"canonical")])
            .unwrap(),
        Rid(1)
    );
    drop(store);
    drop(database);
    write_log(dir.path(), &[put_record(1, 1, b"conflicting")], &[]);
    let before = contents(dir.path());

    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn normal_open_preserves_nonwal_tombstones_and_an_intact_allocator() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let deleted = store
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"x")])
        .unwrap();
    store.delete(deleted).unwrap();
    let survivor = store.put(&[(FieldId::Fixed(Aid(1)), b"x")]).unwrap();
    drop(wal);
    drop(store);
    drop(database);
    for recover in [false, true] {
        let database = if recover {
            PageDatabase::recover_from_page_wal(dir.path())
        } else {
            PageDatabase::open(dir.path())
        }
        .unwrap();
        let store = database.entity(Cid(1), Eid(2)).unwrap();
        assert!(matches!(store.get(deleted), Err(PraxisError::KeyNotFound)));
        assert_eq!(store.get(survivor).unwrap(), b"x");
    }
}

#[test]
fn unapplied_wal_allocation_is_reserved_without_automatic_replay() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap(),
        Rid(1)
    );
    drop(store);
    drop(database);
    write_log(dir.path(), &[put_record(1, 10, b"pending")], &[]);
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    assert!(matches!(store.get(Rid(10)), Err(PraxisError::KeyNotFound)));
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"next")]).unwrap(),
        Rid(11)
    );
    assert_eq!(store.get(Rid(1)).unwrap(), b"old");
}

#[test]
fn managed_writer_upgrades_headerless_v1_without_reencoding_legacy_frames() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"legacy")]).unwrap(),
        Rid(1)
    );
    drop(store);
    drop(database);
    let path = write_log(dir.path(), &[put_record(1, 1, b"legacy")], &[]);
    let file = std::fs::read(&path).unwrap();
    std::fs::write(&path, &file[16..]).unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), file[16..]);
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    assert_eq!(
        store
            .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"new")])
            .unwrap(),
        Rid(2)
    );
    let installed = std::fs::read(&path).unwrap();
    assert_eq!(&installed[..4], &0x5450_5746_u32.to_le_bytes());
    assert_eq!(&installed[4..8], &2_u32.to_le_bytes());
    assert_eq!(&installed[16..file.len()], &file[16..]);
    assert_eq!(
        PageWal::replay(&path)
            .unwrap()
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn exhausted_wal_sequence_fails_before_io_without_poisoning_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap();
    drop(store);
    drop(database);
    let path = write_log(dir.path(), &[put_record(u64::MAX, 1, b"old")], &[]);
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        store.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"new")]),
        Err(PraxisError::WriteStalled { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(store.get(Rid(1)).unwrap(), b"old");
}

#[test]
fn an_empty_managed_wal_root_reopens_without_requiring_a_first_record() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    assert_eq!(wal.bytes_written().unwrap(), 16);
    drop(wal);
    drop(database);
    let reopened = PageDatabase::open(dir.path());
    assert!(
        reopened.is_ok(),
        "empty managed WAL prevented reopen: {reopened:?}"
    );
}

#[test]
fn canonical_open_and_recovery_reject_unknown_delete_followed_by_put() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    store
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    drop(store);
    drop(database);
    write_log(
        dir.path(),
        &[
            PageWalRecord {
                sequence: 1,
                mutation: PageWalMutation::Delete {
                    cid: Cid(1),
                    eid: Eid(2),
                    rid: Rid(10),
                },
            },
            put_record(2, 10, b"must remain deleted"),
        ],
        &[],
    );
    let before = contents(dir.path());
    let opened = PageDatabase::open(dir.path());
    let open_rejected = matches!(opened, Err(PraxisError::Corrupt { .. }));
    drop(opened);
    let recovered = PageDatabase::recover_from_page_wal(dir.path());
    let recovery_rejected = matches!(recovered, Err(PraxisError::Corrupt { .. }));
    drop(recovered);
    assert!(
        open_rejected && recovery_rejected,
        "open rejected={open_rejected}, recovery rejected={recovery_rejected}"
    );
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn empty_managed_wal_with_an_initialized_entity_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    drop(database.entity(Cid(1), Eid(2)).unwrap());
    drop(database.page_wal(WalSyncPolicy::EveryBatch).unwrap());
    drop(database);
    let database = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(
        database
            .entity(Cid(1), Eid(2))
            .unwrap()
            .put(&[(FieldId::Fixed(Aid(1)), b"first")])
            .unwrap(),
        Rid(1)
    );
}
