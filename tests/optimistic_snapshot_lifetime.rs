use bytes::Bytes;
use praxis::{
    ColumnFamily, CompactionStrategy, PraxisConfig, PraxisEngine, PraxisError, WriteBatch,
};
use tempfile::tempdir;

fn assert_pin_count(engine: &PraxisEngine, expected: u64) {
    assert_eq!(
        engine.stats()["snapshots"]["pinned_count"].as_u64(),
        Some(expected)
    );
}

fn assert_transaction_survives_compaction(strategy: CompactionStrategy) {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.default_compaction_strategy = strategy;
    let engine = PraxisEngine::open(config).unwrap();
    engine.put("key", "before").unwrap();
    engine.flush().unwrap();
    let transaction = engine.begin_transaction();

    engine.put("key", "after").unwrap();
    engine.flush().unwrap();
    engine.compact_with_strategy(strategy).unwrap();

    assert_eq!(
        transaction.get("key").unwrap(),
        Some(Bytes::from_static(b"before"))
    );
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"after"))
    );
    drop(transaction);
    assert_pin_count(&engine, 0);
}

#[test]
fn transaction_reads_its_original_value_after_leveled_compaction() {
    assert_transaction_survives_compaction(CompactionStrategy::Leveled);
}

#[test]
fn transaction_reads_its_original_value_after_tiered_compaction() {
    assert_transaction_survives_compaction(CompactionStrategy::Tiered);
}

#[test]
fn transaction_reads_its_original_value_after_universal_compaction() {
    assert_transaction_survives_compaction(CompactionStrategy::Universal);
}

#[test]
fn cloned_transactions_share_one_pin_until_the_last_clone_drops() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "before").unwrap();
    engine.flush().unwrap();
    let original = engine.begin_transaction();
    let remaining = original.clone();
    assert_pin_count(&engine, 1);
    drop(original);
    assert_pin_count(&engine, 1);

    engine.put("key", "after").unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();
    assert_eq!(
        remaining.get("key").unwrap(),
        Some(Bytes::from_static(b"before"))
    );

    drop(remaining);
    assert_pin_count(&engine, 0);
}

#[test]
fn successful_commit_releases_the_transaction_pin() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.put("key", "committed");
    assert_pin_count(&engine, 1);

    transaction.commit().unwrap();

    assert_pin_count(&engine, 0);
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"committed"))
    );
}

#[test]
fn conflicting_commit_releases_the_transaction_pin() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "before").unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.put("key", "transaction");
    engine.put("key", "concurrent").unwrap();
    assert_pin_count(&engine, 1);

    assert!(matches!(
        transaction.commit(),
        Err(PraxisError::TransactionConflict { .. })
    ));

    assert_pin_count(&engine, 0);
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"concurrent"))
    );
}

#[test]
fn dropping_an_uncommitted_transaction_releases_its_pin() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.put("key", "uncommitted");
    assert_pin_count(&engine, 1);

    drop(transaction);

    assert_pin_count(&engine, 0);
    assert_eq!(engine.get("key").unwrap(), None);
}

#[test]
fn committing_one_clone_keeps_the_other_clones_snapshot_protected() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "before").unwrap();
    engine.flush().unwrap();
    let original = engine.begin_transaction();
    let mut committed = original.clone();
    committed.put("key", "after");
    committed.commit().unwrap();
    assert_pin_count(&engine, 1);

    engine.flush().unwrap();
    engine.compact().unwrap();
    assert_eq!(
        original.get("key").unwrap(),
        Some(Bytes::from_static(b"before"))
    );

    drop(original);
    assert_pin_count(&engine, 0);
}

#[test]
fn transaction_snapshot_preserves_same_sequence_merge_operands() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut batch = WriteBatch::new();
    batch.put_default("key", "a");
    batch.merge(ColumnFamily::default(), "key", "b");
    batch.merge(ColumnFamily::default(), "key", "c");
    engine.write_batch(batch).unwrap();
    engine.flush().unwrap();
    let transaction = engine.begin_transaction();

    engine.put("key", "replacement").unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();

    assert_eq!(
        transaction.get("key").unwrap(),
        Some(Bytes::from_static(b"abc"))
    );
}
