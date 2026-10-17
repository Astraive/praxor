use praxis::storage::lsm::LsmIndex;
use praxis::store::{IndexInsert, StorageEngine};
use tempfile::tempdir;

#[test]
fn primary_compaction_preserves_values_and_indexes_after_restart() {
    let dir = tempdir().unwrap();
    let indexes = dir.path().join("indexes");
    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &indexes).unwrap()),
            )
            .unwrap();
        let rid = engine
            .put(b"survivor", &[IndexInsert::new("kv", b"key".to_vec())])
            .unwrap();
        engine.compact_primary().unwrap();
        assert_eq!(engine.fetch(rid).unwrap(), b"survivor");
        rid
    };

    let mut reopened = StorageEngine::open(dir.path(), 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &indexes).unwrap()),
        )
        .unwrap();
    assert_eq!(reopened.fetch(rid).unwrap(), b"survivor");
    assert_eq!(
        reopened.fetch_by_index("kv", b"key").unwrap(),
        Some(b"survivor".to_vec())
    );
}

#[test]
fn primary_compaction_wal_repairs_missing_record_directory() {
    let dir = tempdir().unwrap();
    let (live, deleted) = {
        let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
        let live = engine.put(b"relocated", &[]).unwrap();
        let deleted = engine.put(b"deleted", &[]).unwrap();
        engine.delete_record(deleted).unwrap();
        engine.compact_primary().unwrap();
        (live, deleted)
    };
    std::fs::remove_file(dir.path().join("primary").join("indirection.tind")).unwrap();

    let reopened = StorageEngine::open(dir.path(), 1024).unwrap();
    assert_eq!(reopened.fetch(live).unwrap(), b"relocated");
    assert!(reopened.fetch(deleted).is_err());
    assert_eq!(reopened.live_count(), 1);
}

#[test]
fn primary_compaction_replay_survives_repeated_compactions() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024).unwrap();
    let survivor = engine.put(b"first", &[]).unwrap();
    let deleted = engine.put(b"discard", &[]).unwrap();
    engine.compact_primary().unwrap();
    engine.delete_record(deleted).unwrap();
    let later = engine.put(b"later", &[]).unwrap();
    engine.compact_primary().unwrap();
    engine.compact_primary().unwrap();
    drop(engine);

    for _ in 0..2 {
        let reopened = StorageEngine::open(dir.path(), 1024).unwrap();
        assert_eq!(reopened.fetch(survivor).unwrap(), b"first");
        assert_eq!(reopened.fetch(later).unwrap(), b"later");
        assert!(reopened.fetch(deleted).is_err());
        assert_eq!(reopened.live_count(), 2);
    }
}
