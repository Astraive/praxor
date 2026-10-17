use bytes::Bytes;
use praxis::manifest::{ColumnFamilyDescriptor, ColumnFamilyOptions};
use praxis::{ColumnFamily, PraxisConfig, PraxisEngine, WriteBatch};
use tempfile::tempdir;

#[test]
fn active_tombstone_hides_a_flushed_value() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("gone", "old").unwrap();
    engine.flush().unwrap();
    engine.delete("gone").unwrap();

    assert_eq!(engine.get("gone").unwrap(), None);
    assert_eq!(engine.scan(None, None, 10).unwrap(), vec![]);
}

#[test]
fn expired_active_value_hides_a_flushed_value() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("expired", "old").unwrap();
    engine.flush().unwrap();
    let mut batch = WriteBatch::new();
    batch.put_with_expiry(ColumnFamily::default(), "expired", "expired replacement", 0);
    engine.write_batch(batch).unwrap();

    assert_eq!(engine.get("expired").unwrap(), None);
    assert_eq!(engine.scan_prefix(b"exp", 10).unwrap(), vec![]);
}

#[test]
fn active_merge_chain_resolves_against_a_flushed_base() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("merged", "base").unwrap();
    engine.flush().unwrap();
    engine
        .merge(ColumnFamily::default(), "merged", "+one")
        .unwrap();
    engine
        .merge(ColumnFamily::default(), "merged", "+two")
        .unwrap();

    assert_eq!(
        engine.get("merged").unwrap(),
        Some(Bytes::from("base+one+two"))
    );
    assert_eq!(
        engine.scan(None, None, 10).unwrap(),
        vec![(Bytes::from("merged"), Bytes::from("base+one+two"))]
    );
}

#[test]
fn merge_only_keys_use_the_column_family_merge_operator() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "counter".into(),
            options: ColumnFamilyOptions {
                merge_operator: Some("sum_i64".into()),
                ..ColumnFamilyOptions::default()
            },
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let cf = ColumnFamily("counter".into());
    engine
        .merge(
            cf.clone(),
            "hits",
            Bytes::from(2_i64.to_le_bytes().to_vec()),
        )
        .unwrap();
    engine
        .merge(
            cf.clone(),
            "hits",
            Bytes::from(3_i64.to_le_bytes().to_vec()),
        )
        .unwrap();
    let expected = Bytes::from(5_i64.to_le_bytes().to_vec());

    assert_eq!(
        engine.get_cf(&cf, b"hits", engine.snapshot()).unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        engine.scan_cf(&cf, None, None, 10).unwrap(),
        vec![(Bytes::from("hits"), expected)]
    );
    assert_eq!(engine.scan(None, None, 10).unwrap(), vec![]);
}

#[test]
fn snapshot_scans_resolve_each_visible_version_across_tiers() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("doc/a", "base").unwrap();
    engine.put("doc/b", "old").unwrap();
    engine.flush().unwrap();
    engine
        .merge(ColumnFamily::default(), "doc/a", "+snapshot")
        .unwrap();
    engine.put("doc/c", "snapshot").unwrap();
    let snapshot = engine.pin_snapshot();
    engine.delete("doc/a").unwrap();
    engine.put("doc/b", "new").unwrap();
    engine.delete("doc/c").unwrap();
    engine.put("doc/d", "later").unwrap();

    assert_eq!(
        engine
            .get_cf(&ColumnFamily::default(), b"doc/a", snapshot.snapshot())
            .unwrap(),
        Some(Bytes::from("base+snapshot"))
    );
    assert_eq!(
        engine
            .scan_prefix_at_snapshot(b"doc/", 10, snapshot.snapshot())
            .unwrap(),
        vec![
            (Bytes::from("doc/a"), Bytes::from("base+snapshot")),
            (Bytes::from("doc/b"), Bytes::from("old")),
            (Bytes::from("doc/c"), Bytes::from("snapshot")),
        ]
    );
    assert_eq!(
        engine.scan_prefix(b"doc/", 10).unwrap(),
        vec![
            (Bytes::from("doc/b"), Bytes::from("new")),
            (Bytes::from("doc/d"), Bytes::from("later")),
        ]
    );
}

#[test]
fn scan_limit_counts_live_rows_after_range_filtering() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    for key in ["a", "b", "c", "d", "e"] {
        engine.put(key, "value").unwrap();
    }
    engine.flush().unwrap();
    engine.delete("b").unwrap();
    let mut batch = WriteBatch::new();
    batch.put_with_expiry(ColumnFamily::default(), "c", "expired", 0);
    engine.write_batch(batch).unwrap();

    assert_eq!(
        engine.scan(Some(b"b"), Some(b"e"), 1).unwrap(),
        vec![(Bytes::from("d"), Bytes::from("value"))]
    );
    assert_eq!(engine.scan(None, None, 0).unwrap(), vec![]);
}

#[test]
fn merge_after_a_tombstone_does_not_reuse_the_flushed_base() {
    let dir = tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.put("merged", "old").unwrap();
    engine.flush().unwrap();
    engine.delete("merged").unwrap();
    engine
        .merge(ColumnFamily::default(), "merged", "new")
        .unwrap();

    assert_eq!(engine.get("merged").unwrap(), Some(Bytes::from("new")));
    assert_eq!(
        engine.scan(None, None, 10).unwrap(),
        vec![(Bytes::from("merged"), Bytes::from("new"))]
    );
}
