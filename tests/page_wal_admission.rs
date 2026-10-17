#[path = "support/page_wal_legacy.rs"]
mod legacy;
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::record::PageDatabase;
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};
use std::path::{Path, PathBuf};

fn record(sequence: u64, rid: u64) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(rid),
            fields: vec![(FieldId::Fixed(Aid(1)), b"value".to_vec())],
        },
    }
}

fn log_path(root: &Path) -> PathBuf {
    root.join(".praxis/logs/page.wal")
}

fn file_bytes(records: &[PageWalRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x5450_5746_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    for record in records {
        bytes.extend_from_slice(&legacy::encode(record));
    }
    bytes
}

#[test]
fn writable_page_wal_refuses_a_torn_suffix_without_changing_it() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let path = log_path(dir.path());
    let mut bytes = file_bytes(&[record(1, 1)]);
    bytes.extend_from_slice(&legacy::encode(&record(2, 2))[..7]);
    std::fs::write(&path, &bytes).unwrap();

    let result = database.page_wal(WalSyncPolicy::EveryBatch);
    assert!(
        result.is_err(),
        "writable open accepted a truncated canonical log"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn writable_page_wal_refuses_bad_middle_crc_even_with_a_later_valid_record() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let path = log_path(dir.path());
    let mut bytes = file_bytes(&[record(1, 1)]);
    let mut bad = legacy::encode(&record(2, 2));
    bad[9] ^= 1;
    bytes.extend_from_slice(&bad);
    bytes.extend_from_slice(&legacy::encode(&record(3, 3)));
    std::fs::write(&path, &bytes).unwrap();
    assert!(PageWal::replay(&path).is_err());
    let report = PageWal::replay_prefix(&path).unwrap();
    assert_eq!(report.records.len(), 1);
    assert!(matches!(
        report.stop,
        praxis::wal::page::PageWalScanStop::Corrupt { .. }
    ));

    assert!(
        database.page_wal(WalSyncPolicy::EveryBatch).is_err(),
        "writer treated a valid prefix as a complete canonical log"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn writable_page_wal_refuses_nonmonotone_persisted_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let path = log_path(dir.path());
    let bytes = file_bytes(&[record(2, 1), record(1, 2)]);
    std::fs::write(&path, &bytes).unwrap();

    assert!(
        database.page_wal(WalSyncPolicy::EveryBatch).is_err(),
        "writer admitted a sequence regression"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn durable_put_rejects_another_roots_wal_before_publication() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let first_database = PageDatabase::open(first.path()).unwrap();
    let mut store = first_database.entity(Cid(1), Eid(2)).unwrap();
    let second_database = PageDatabase::open(second.path()).unwrap();
    let path = log_path(second.path());
    let mut wal = second_database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let before = std::fs::read(&path).unwrap();

    let result = store.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"foreign")]);
    assert!(
        result.is_err(),
        "foreign WAL handle committed across two root owners"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(store.get(Rid(1)).is_err());
}
