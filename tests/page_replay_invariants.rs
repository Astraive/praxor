use praxis::errors::PraxisError;
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid};
use praxis::record::PageDatabase;
use praxis::wal::{PageWalMutation, PageWalRecord};

fn put_record(sequence: u64, eid: Eid, rid: Rid, value: &[u8]) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid,
            rid,
            fields: vec![(FieldId::Fixed(Aid(1)), value.to_vec())],
        },
    }
}

#[test]
fn replay_cannot_steal_a_rid_from_another_entity() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut first = database.entity(Cid(1), Eid(2)).unwrap();
    let mut other = database.entity(Cid(1), Eid(3)).unwrap();
    let rid = first.put(&[(FieldId::Fixed(Aid(1)), b"first")]).unwrap();

    let result = other.apply_page_wal_record(&put_record(1, Eid(3), rid, b"other"));
    let kept = first.get(rid).is_ok_and(|value| value == b"first");
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })) && kept,
        "conflicting replay result={result:?}, acknowledged first record retained={kept}"
    );
}

#[test]
fn replay_rejects_conflicting_payload_for_an_existing_rid() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = store.put(&[(FieldId::Fixed(Aid(1)), b"first")]).unwrap();

    let result = store.apply_page_wal_record(&put_record(1, Eid(2), rid, b"conflict"));
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "conflicting payload was silently treated as exact replay: {result:?}"
    );
    assert_eq!(store.get(rid).unwrap(), b"first");
}

#[test]
fn replay_of_an_old_put_cannot_resurrect_a_nonwal_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = store.put(&[(FieldId::Fixed(Aid(1)), b"deleted")]).unwrap();
    store.delete(rid).unwrap();

    store
        .apply_page_wal_record(&put_record(1, Eid(2), rid, b"deleted"))
        .unwrap();
    assert!(
        matches!(store.get(rid), Err(PraxisError::KeyNotFound)),
        "older logged Put resurrected a later non-WAL delete"
    );
}

#[test]
fn replay_rejects_nonmonotone_sequences_before_any_page_publication() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let path = store
        .layout()
        .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
        .path;

    let result = store.replay_page_wal(&[
        put_record(2, Eid(2), Rid(10), b"ten"),
        put_record(1, Eid(2), Rid(11), b"eleven"),
    ]);
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })) && !path.exists(),
        "invalid ordering result={result:?}, page published={}",
        path.exists()
    );
}

#[test]
fn replay_rejects_reserved_zero_rid_as_corrupt_input() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let result = store.apply_page_wal_record(&put_record(1, Eid(2), Rid::NULL, b"invalid"));
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "reserved replay identity was not rejected as corrupt input: {result:?}"
    );
}

#[test]
fn exact_replay_remains_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let record = put_record(1, Eid(2), Rid(1), b"same");
    store.apply_page_wal_record(&record).unwrap();
    store.apply_page_wal_record(&record).unwrap();
    assert_eq!(store.get(Rid(1)).unwrap(), b"same");
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"next")]).unwrap(),
        Rid(2)
    );
}

#[test]
fn duplicate_delete_replay_remains_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = store.put(&[(FieldId::Fixed(Aid(1)), b"deleted")]).unwrap();
    let record = PageWalRecord {
        sequence: 1,
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
fn unknown_delete_is_a_terminal_barrier_before_a_later_put() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let path = store
        .layout()
        .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
        .path;
    let result = store.replay_page_wal(&[
        PageWalRecord {
            sequence: 1,
            mutation: PageWalMutation::Delete {
                cid: Cid(1),
                eid: Eid(2),
                rid: Rid(10),
            },
        },
        put_record(2, Eid(2), Rid(10), b"must remain deleted"),
    ]);
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })) && !path.exists(),
        "delete-before-put result={result:?}, page published={}",
        path.exists()
    );
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"healthy")]).unwrap(),
        Rid(1)
    );
}

#[test]
fn repeated_unknown_deletes_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let delete = |sequence| PageWalRecord {
        sequence,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(10),
        },
    };
    store.replay_page_wal(&[delete(1), delete(2)]).unwrap();
    assert!(matches!(store.get(Rid(10)), Err(PraxisError::KeyNotFound)));
}

fn reject_repeated_field_identity(first: Vec<(FieldId, Vec<u8>)>, second: Vec<(FieldId, Vec<u8>)>) {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    let record = |sequence, fields| PageWalRecord {
        sequence,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(10),
            fields,
        },
    };
    let path = store
        .layout()
        .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
        .path;
    let result = store.replay_page_wal(&[record(1, first), record(2, second)]);
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })) && !path.exists(),
        "conflicting field identity result={result:?}, page published={}",
        path.exists()
    );
    assert_eq!(
        store.put(&[(FieldId::Fixed(Aid(1)), b"healthy")]).unwrap(),
        Rid(1)
    );
}

#[test]
fn repeated_puts_preserve_field_boundaries_even_when_flattened_bytes_match() {
    reject_repeated_field_identity(
        vec![
            (FieldId::Fixed(Aid(1)), b"ab".to_vec()),
            (FieldId::Fixed(Aid(2)), b"c".to_vec()),
        ],
        vec![
            (FieldId::Fixed(Aid(1)), b"a".to_vec()),
            (FieldId::Fixed(Aid(2)), b"bc".to_vec()),
        ],
    );
}

#[test]
fn repeated_puts_preserve_field_ids_even_when_flattened_bytes_match() {
    reject_repeated_field_identity(
        vec![(FieldId::Fixed(Aid(1)), b"abc".to_vec())],
        vec![(FieldId::Fixed(Aid(2)), b"abc".to_vec())],
    );
}

#[test]
fn repeated_puts_preserve_field_order_even_when_flattened_bytes_match() {
    reject_repeated_field_identity(
        vec![
            (FieldId::Fixed(Aid(1)), b"a".to_vec()),
            (FieldId::Fixed(Aid(2)), b"a".to_vec()),
        ],
        vec![
            (FieldId::Fixed(Aid(2)), b"a".to_vec()),
            (FieldId::Fixed(Aid(1)), b"a".to_vec()),
        ],
    );
}
