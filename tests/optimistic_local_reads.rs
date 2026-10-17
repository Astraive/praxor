use bytes::Bytes;
use praxis::{PraxisConfig, PraxisEngine, PraxisError};
use tempfile::tempdir;

#[test]
fn staged_put_is_readable_before_commit_and_hidden_from_the_engine() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.put("key", "local");

    assert_eq!(
        transaction.get("key").unwrap(),
        Some(Bytes::from_static(b"local"))
    );
    assert_eq!(engine.get("key").unwrap(), None);
    transaction.commit().unwrap();
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"local"))
    );
}

#[test]
fn staged_delete_masks_the_original_value_without_changing_storage() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "original").unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.delete("key");

    assert_eq!(transaction.get("key").unwrap(), None);
    assert_eq!(
        engine.get("key").unwrap(),
        Some(Bytes::from_static(b"original"))
    );
}

#[test]
fn staged_put_and_delete_order_determines_the_local_value() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("key", "original").unwrap();
    let mut transaction = engine.begin_transaction();
    transaction
        .put("key", "first")
        .delete("key")
        .put("key", "last");

    assert_eq!(
        transaction.get("key").unwrap(),
        Some(Bytes::from_static(b"last"))
    );
    transaction.delete("key");
    assert_eq!(transaction.get("key").unwrap(), None);
}

#[test]
fn local_reads_keep_untouched_keys_at_the_snapshot_and_preserve_commit_conflicts() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("target", "original").unwrap();
    engine.put("untouched", "original").unwrap();
    let mut transaction = engine.begin_transaction();
    engine.put("target", "external").unwrap();
    engine.put("untouched", "external").unwrap();
    transaction.put("target", "local");

    assert_eq!(
        transaction.get("target").unwrap(),
        Some(Bytes::from_static(b"local"))
    );
    assert_eq!(
        transaction.get("untouched").unwrap(),
        Some(Bytes::from_static(b"original"))
    );
    assert!(matches!(
        transaction.commit(),
        Err(PraxisError::TransactionConflict { .. })
    ));
    assert_eq!(
        engine.get("target").unwrap(),
        Some(Bytes::from_static(b"external"))
    );
}

#[test]
fn cloned_transactions_keep_independent_staged_writes() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut original = engine.begin_transaction();
    original.put("key", "shared at clone");
    let mut cloned = original.clone();
    assert_eq!(
        cloned.get("key").unwrap(),
        Some(Bytes::from_static(b"shared at clone"))
    );
    original.put("key", "original only");
    cloned.delete("key");

    assert_eq!(
        original.get("key").unwrap(),
        Some(Bytes::from_static(b"original only"))
    );
    assert_eq!(cloned.get("key").unwrap(), None);
    assert_eq!(engine.get("key").unwrap(), None);
}

#[test]
fn empty_staged_values_are_present_and_aborted_writes_never_escape() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    let mut transaction = engine.begin_transaction();
    transaction.put(Bytes::from_static(&[0, 255]), Bytes::new());

    assert_eq!(transaction.get([0, 255]).unwrap(), Some(Bytes::new()));
    drop(transaction);
    assert_eq!(engine.get([0, 255]).unwrap(), None);
}
