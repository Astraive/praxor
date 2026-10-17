use praxis::store::{IndexInsert, RecordId};
use praxis::{
    CompactionStrategy, CoreDatabase, CoreRecordSnapshot, MappingDescriptor, PraxisConfig,
    PraxisError, RecordAuthorityOptions,
};

fn database() -> (tempfile::TempDir, PraxisConfig, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 1;
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "snapshots".into(),
            }],
        },
    )
    .unwrap();
    (dir, config, db)
}

#[test]
fn retained_views_preserve_rows_mapping_barriers_and_current_raw_ceilings() {
    for strategy in [
        CompactionStrategy::Leveled,
        CompactionStrategy::Tiered,
        CompactionStrategy::Universal,
    ] {
        let (_dir, _config, db) = database();
        let records = db.records();
        let empty = records.pin_snapshot().unwrap();
        assert_eq!(empty.core_sequence(), 1);
        let first = records
            .put(
                b"old payload",
                &[IndexInsert::new("kv", b"k\0\xff".to_vec())],
            )
            .unwrap();
        let old = records.pin_snapshot().unwrap();
        let old_raw = records.compatibility_sequence().unwrap();
        records.flush().unwrap();
        records.delete_index("kv", b"k\0\xff").unwrap();
        let gap = records.pin_snapshot().unwrap();
        let gap_raw = records.compatibility_sequence().unwrap();
        let second = records
            .put(
                b"new payload",
                &[IndexInsert::new("kv", b"k\0\xff".to_vec())],
            )
            .unwrap();
        records.delete_record(first).unwrap();
        let current = records.pin_snapshot().unwrap();
        records.flush().unwrap();
        assert!(db.kv().compact_with_strategy(strategy).unwrap() > 0);
        db.kv().garbage_collect().unwrap();
        db.kv().verify().unwrap();

        assert!(matches!(
            records.fetch_at_snapshot(first, &empty),
            Err(PraxisError::KeyNotFound)
        ));
        assert_eq!(
            records
                .lookup_rid_at_snapshot("kv", b"k\0\xff", &empty)
                .unwrap(),
            None
        );
        assert_eq!(
            records.fetch_at_snapshot(first, &old).unwrap(),
            b"old payload"
        );
        assert_eq!(
            records
                .fetch_by_index_at_snapshot("kv", b"k\0\xff", &old)
                .unwrap(),
            Some(b"old payload".to_vec())
        );
        assert_eq!(
            records.fetch_at_snapshot(first, &gap).unwrap(),
            b"old payload"
        );
        assert_eq!(
            records
                .lookup_rid_at_snapshot("kv", b"k\0\xff", &gap)
                .unwrap(),
            None
        );
        assert!(matches!(
            records.fetch_at_snapshot(first, &current),
            Err(PraxisError::KeyNotFound)
        ));
        assert_eq!(
            records
                .fetch_by_index_at_snapshot("kv", b"k\0\xff", &current)
                .unwrap(),
            Some(b"new payload".to_vec())
        );
        assert_eq!(
            records.lookup_rid_at("kv", b"k\0\xff", old_raw).unwrap(),
            Some(first)
        );
        assert_eq!(
            records.lookup_rid_at("kv", b"k\0\xff", gap_raw).unwrap(),
            None
        );
        assert_eq!(
            records.lookup_rid_at("kv", b"k\0\xff", u64::MAX).unwrap(),
            Some(second)
        );
        assert!(matches!(
            records.fetch(first),
            Err(PraxisError::KeyNotFound)
        ));
    }
}

#[test]
fn stale_mapping_and_true_absence_remain_distinct_from_errors() {
    let (_dir, _config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"v", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    records.delete_record(rid).unwrap();
    let held = records.pin_snapshot().unwrap();
    assert_eq!(
        records.lookup_rid_at_snapshot("kv", b"k", &held).unwrap(),
        Some(rid)
    );
    assert_eq!(
        records
            .fetch_by_index_at_snapshot("kv", b"k", &held)
            .unwrap(),
        None
    );
    for missing in [RecordId::NULL, RecordId(999)] {
        assert!(matches!(
            records.fetch_at_snapshot(missing, &held),
            Err(PraxisError::KeyNotFound)
        ));
    }
    assert!(matches!(
        records.lookup_rid_at_snapshot("unknown", b"k", &held),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert_eq!(
        records.lookup_rid_at_snapshot("kv", b"k", &held).unwrap(),
        Some(rid)
    );
}

#[test]
fn token_clones_are_send_sync_and_retain_the_owner_until_last_drop() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CoreRecordSnapshot>();
    let (_dir, config, db) = database();
    let records = db.records();
    let rid = records.put(b"v", &[]).unwrap();
    let token = records.pin_snapshot().unwrap();
    let clone = token.clone();
    let reader = records.clone();
    let thread_token = token.clone();
    assert_eq!(
        std::thread::spawn(move || reader.fetch_at_snapshot(rid, &thread_token))
            .join()
            .unwrap()
            .unwrap(),
        b"v"
    );
    drop(records);
    drop(db);
    drop(token);
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    let unwinding_clone = clone.clone();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = unwinding_clone;
        panic!("test token cleanup");
    }));
    assert!(unwind.is_err());
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    drop(clone);
    let reopened = CoreDatabase::open(config).unwrap();
    let current = reopened.records().pin_snapshot().unwrap();
    assert_eq!(
        reopened.records().fetch_at_snapshot(rid, &current).unwrap(),
        b"v"
    );
}

#[test]
fn restored_same_identity_and_other_fresh_owners_refuse_foreign_tokens() {
    let (_dir, config, db) = database();
    let records = db.records();
    let rid = records
        .put(b"v", &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    let token = records.pin_snapshot().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let copy = destination.path().join("copy");
    db.kv().backup_to(&copy).unwrap();
    let mut restored_config = config;
    restored_config.data_dir = copy;
    let restored = CoreDatabase::open(restored_config).unwrap();
    assert_eq!(restored.authority(), db.authority());
    let (_other_dir, _other_config, other) = database();
    for foreign in [restored.records(), other.records()] {
        assert!(matches!(
            foreign.fetch_at_snapshot(rid, &token),
            Err(PraxisError::ForeignRecordSnapshot { .. })
        ));
        assert!(matches!(
            foreign.lookup_rid_at_snapshot("unknown", b"k", &token),
            Err(PraxisError::ForeignRecordSnapshot { .. })
        ));
        assert!(matches!(
            foreign.fetch_by_index_at_snapshot("unknown", b"k", &token),
            Err(PraxisError::ForeignRecordSnapshot { .. })
        ));
    }
    assert_eq!(records.fetch_at_snapshot(rid, &token).unwrap(), b"v");
}
