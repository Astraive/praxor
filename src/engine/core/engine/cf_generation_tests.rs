use super::*;

#[test]
fn queued_old_policy_batch_is_rejected_whole_without_consuming_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::config::WalSyncPolicy::GroupCommit;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "tenant".into(),
            options: ColumnFamilyOptions {
                ttl_seconds: Some(60),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let mut batch = WriteBatch::new();
    batch.put("tenant", "stale", "old-policy");
    batch.put_default("must-not-publish", "old-batch");
    let writer = engine.inner.write_serialization.lock();
    let (normalized, generations) = engine.normalize_batch_with_cf_policies(batch).unwrap();
    assert!(matches!(normalized.ops()[0], BatchOp::PutWithExpiry { .. }));
    let bytes = WalRecord::encoded_batch_len(&normalized);
    let stale = engine
        .inner
        .group_commit
        .admit(
            normalized,
            generations,
            WriteCondition::Unconditional,
            bytes,
            &engine.inner.metrics,
        )
        .unwrap();
    drop(writer);
    engine.drop_column_family("tenant").unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: "tenant".into(),
            ..Default::default()
        })
        .unwrap();
    let mut healthy = WriteBatch::new();
    healthy.put_default("healthy", "new");
    let (healthy, generations) = engine.normalize_batch_with_cf_policies(healthy).unwrap();
    let bytes = WalRecord::encoded_batch_len(&healthy);
    let healthy = engine
        .inner
        .group_commit
        .admit(
            healthy,
            generations,
            WriteCondition::Unconditional,
            bytes,
            &engine.inner.metrics,
        )
        .unwrap();
    match engine.inner.group_commit.wait(&stale) {
        CommitTurn::Lead(leader) => engine.commit_closed_group(leader),
        _ => panic!("unexpected completion"),
    }
    assert!(matches!(
        engine.inner.group_commit.wait(&stale),
        CommitTurn::Complete(Err(PraxisError::WriteStalled { .. }))
    ));
    assert!(matches!(
        engine.inner.group_commit.wait(&healthy),
        CommitTurn::Complete(Ok(1))
    ));
    assert_eq!(engine.snapshot().sequence, 1);
    assert!(engine.get("must-not-publish").unwrap().is_none());
    assert!(
        engine
            .get_cf(&"tenant".into(), b"stale", engine.snapshot())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine.inner.metrics.commit_batches.load(Ordering::Relaxed),
        1
    );
    assert!(engine.put("still-healthy", "yes").is_ok());
    drop(engine);
    let engine = PraxisEngine::open(config).unwrap();
    assert!(engine.get("must-not-publish").unwrap().is_none());
    assert!(
        engine
            .get_cf(&"tenant".into(), b"stale", engine.snapshot())
            .unwrap()
            .is_none()
    );
}

#[test]
fn exhausted_generation_counter_rejects_create_without_poison_or_ram_change() {
    let dir = tempfile::tempdir().unwrap();
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    engine.inner.manifest.lock().next_column_family_generation = u64::MAX;
    let before = engine.inner.manifest.lock().clone();
    assert!(matches!(
        engine.create_column_family(ColumnFamilyDescriptor {
            name: "overflow".into(),
            ..Default::default()
        }),
        Err(PraxisError::WriteStalled { .. })
    ));
    assert_eq!(*engine.inner.manifest.lock(), before);
    assert!(engine.put("healthy", "value").is_ok());
}
