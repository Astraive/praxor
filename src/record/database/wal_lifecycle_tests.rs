use super::*;
use crate::catalog::{CatalogSnapshot, CatalogStore};
use crate::identity::{Aid, FieldId};
use crate::wal::page::PageWalFailure;
use crate::wal::page::owned::LifecyclePhase as Phase;
use std::path::Path;

fn header() -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&0x5450_5746_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&2_u32.to_le_bytes());
    let crc = crate::io::crc32_ieee(&bytes[..12]);
    bytes[12..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn authoritative(root: &Path) {
    let database = PageDatabase::open(root).unwrap();
    database
        .entity(Cid(1), Eid(2))
        .unwrap()
        .put(&[(FieldId::Fixed(Aid(1)), b"original")])
        .unwrap();
}

fn legacy_delete() -> Vec<u8> {
    let record = PageWalRecord {
        sequence: 1,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(1),
        },
    };
    let frame = record.try_encode().unwrap();
    // Explicit old framing around its unchanged payload, not a public v1 writer.
    let mut old = 0x5450_5752_u32.to_le_bytes().to_vec();
    old.push(1);
    old.extend_from_slice(&frame[5..13]);
    old.extend_from_slice(&frame[17..]);
    old
}

fn assert_shared_poison(
    database: &PageDatabase,
    store: &mut PageRecordStore,
    catalog: &CatalogStore,
) {
    assert!(matches!(
        store.get(Rid(1)),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"retry")]),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        database.page_wal(WalSyncPolicy::EveryBatch),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        catalog.load(),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        catalog.save(&CatalogSnapshot::default()),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
}

#[test]
fn every_upgrade_fault_preserves_a_complete_canonical_and_poison_is_shared() {
    for phase in [
        Phase::StageCreate,
        Phase::StageWrite,
        Phase::StageSync,
        Phase::StageValidate,
        Phase::Replace,
        Phase::ParentSync,
        Phase::Reopen,
        Phase::InstalledValidate,
        Phase::InstalledFileSync,
        Phase::InstalledParentSync,
    ] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let path = directory.path().join(".praxis/logs/page.wal");
        let original = legacy_delete();
        std::fs::write(&path, &original).unwrap();
        let database = PageDatabase::open(directory.path()).unwrap();
        let mut store = database.entity(Cid(1), Eid(2)).unwrap();
        let catalog = CatalogStore::new(database.clone());
        assert!(
            database
                .page_wal_with_lifecycle(WalSyncPolicy::Never, &mut WalLifecycle::failing(phase))
                .is_err(),
            "{phase:?}"
        );
        assert_shared_poison(&database, &mut store, &catalog);
        let installed = std::fs::read(&path).unwrap();
        if matches!(
            phase,
            Phase::ParentSync
                | Phase::Reopen
                | Phase::InstalledValidate
                | Phase::InstalledFileSync
                | Phase::InstalledParentSync
        ) {
            assert_eq!(installed, [header().to_vec(), original].concat());
        } else {
            assert_eq!(installed, original);
        }
        assert_eq!(PageWal::replay(&path).unwrap().len(), 1);
        drop(catalog);
        drop(store);
        drop(database);
        let reopened = PageDatabase::open(directory.path()).unwrap();
        let _wal = reopened.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        assert_eq!(PageWal::replay(&path).unwrap().len(), 1);
    }
}

#[test]
fn creation_barrier_faults_poison_views_even_under_never_policy() {
    for phase in [
        Phase::HeaderWrite,
        Phase::HeaderSync,
        Phase::HeaderParentSync,
        Phase::Reopen,
        Phase::InstalledValidate,
        Phase::InstalledFileSync,
        Phase::InstalledParentSync,
    ] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let database = PageDatabase::open(directory.path()).unwrap();
        let mut store = database.entity(Cid(1), Eid(2)).unwrap();
        let catalog = CatalogStore::new(database.clone());
        assert!(
            database
                .page_wal_with_lifecycle(WalSyncPolicy::Never, &mut WalLifecycle::failing(phase))
                .is_err()
        );
        assert_shared_poison(&database, &mut store, &catalog);
        drop(catalog);
        drop(store);
        drop(database);
        let reopened = PageDatabase::open(directory.path()).unwrap();
        assert_eq!(
            reopened
                .entity(Cid(1), Eid(2))
                .unwrap()
                .get(Rid(1))
                .unwrap(),
            b"original"
        );
    }
}

#[test]
fn repair_faults_expose_no_owner_and_restart_only_uses_canonical_bytes() {
    for phase in [
        Phase::RepairOpen,
        Phase::RepairTruncate,
        Phase::RepairHeader,
        Phase::RepairSync,
        Phase::RepairRescan,
    ] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let path = directory.path().join(".praxis/logs/page.wal");
        let header = header();
        std::fs::write(&path, &header[..7]).unwrap();
        assert!(
            PageDatabase::open_with_lifecycle(directory.path(), &mut WalLifecycle::failing(phase))
                .is_err()
        );
        let reopened = PageDatabase::open(directory.path()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), header);
        assert_eq!(
            reopened
                .entity(Cid(1), Eid(2))
                .unwrap()
                .get(Rid(1))
                .unwrap(),
            b"original"
        );
    }
}

#[test]
fn seek_and_write_uncertainty_poison_existing_wal_and_catalog_views() {
    for failure in [PageWalFailure::Seek, PageWalFailure::Write] {
        let directory = tempfile::tempdir().unwrap();
        authoritative(directory.path());
        let database = PageDatabase::open(directory.path()).unwrap();
        let mut store = database.entity(Cid(1), Eid(2)).unwrap();
        let catalog = CatalogStore::new(database.clone());
        let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        let before = std::fs::read(wal.path()).unwrap();
        database
            .inner
            .state
            .lock()
            .unwrap()
            .wal
            .as_mut()
            .unwrap()
            .fail_next(failure);
        assert!(
            store
                .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"uncertain")])
                .is_err()
        );
        assert_shared_poison(&database, &mut store, &catalog);
        assert!(wal.sync().is_err());
        assert!(wal.bytes_written().is_err());
        assert_eq!(std::fs::read(wal.path()).unwrap(), before);
    }
}

#[test]
fn retry_after_uncertain_publication_must_refence_even_a_clean_v2_file() {
    let mut missed = Vec::new();
    for first in [Phase::HeaderParentSync, Phase::ParentSync] {
        for retry in [Phase::InstalledFileSync, Phase::InstalledParentSync] {
            let directory = tempfile::tempdir().unwrap();
            authoritative(directory.path());
            let path = directory.path().join(".praxis/logs/page.wal");
            if first == Phase::ParentSync {
                std::fs::write(&path, legacy_delete()).unwrap();
            }
            let database = PageDatabase::open(directory.path()).unwrap();
            assert!(
                database
                    .page_wal_with_lifecycle(
                        WalSyncPolicy::Never,
                        &mut WalLifecycle::failing(first)
                    )
                    .is_err()
            );
            drop(database);
            let database = PageDatabase::open(directory.path()).unwrap();
            let mut store = database.entity(Cid(1), Eid(2)).unwrap();
            let catalog = CatalogStore::new(database.clone());
            let before = std::fs::read(&path).unwrap();
            match database
                .page_wal_with_lifecycle(WalSyncPolicy::Never, &mut WalLifecycle::failing(retry))
            {
                Ok(wal) => {
                    missed.push(format!("first {first:?}, retry {retry:?}"));
                    drop(wal);
                }
                Err(_) => assert_shared_poison(&database, &mut store, &catalog),
            }
            assert_eq!(std::fs::read(&path).unwrap(), before);
            drop(catalog);
            drop(store);
            drop(database);
            let database = PageDatabase::open(directory.path()).unwrap();
            let mut store = database.entity(Cid(1), Eid(2)).unwrap();
            let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
            let rid = store
                .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"after fence")])
                .unwrap();
            let expected_records = if first == Phase::ParentSync { 2 } else { 1 };
            assert_eq!(PageWal::replay(&path).unwrap().len(), expected_records);
            drop(wal);
            drop(store);
            drop(database);
            for _ in 0..2 {
                let database = PageDatabase::open(directory.path()).unwrap();
                assert_eq!(
                    database.entity(Cid(1), Eid(2)).unwrap().get(rid).unwrap(),
                    b"after fence"
                );
            }
        }
    }
    assert!(
        missed.is_empty(),
        "clean v2 retry skipped fences: {missed:?}"
    );
}
