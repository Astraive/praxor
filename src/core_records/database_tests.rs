use super::*;
use crate::core_records::MappingDescriptor;
use crate::manifest::{ColumnFamilyDescriptor, CompactionJobState, CompactionJobStatus};
use crate::transactions::{BatchOp, NestedTransaction, SavepointTransaction};
use crate::types::ColumnFamily;
use crate::wal::{WalRecord, record::CoreRecordPrefix};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

fn options() -> RecordAuthorityOptions {
    RecordAuthorityOptions {
        indexes: vec![
            MappingDescriptor {
                name: "z".into(),
                namespace: "shared".into(),
            },
            MappingDescriptor {
                name: "é".into(),
                namespace: "shared".into(),
            },
        ],
    }
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == LOCK_FILE_NAME {
                continue;
            }
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                out.insert(relative, None);
                visit(root, &path, out);
            } else {
                out.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn manifest(root: &Path) -> Manifest {
    Manifest::decode(
        &std::fs::read(root.join("MANIFEST")).unwrap(),
        &root.join("MANIFEST"),
    )
    .unwrap()
}
fn append(root: &Path, bytes: &[u8]) {
    let path = root
        .join("wal")
        .join(format!("{:020}.wal", manifest(root).active_wal_id));
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn unfinished(root: &Path) {
    let mut manifest = manifest(root);
    manifest.compaction_jobs.push(CompactionJobState {
        id: 1,
        strategy: crate::CompactionStrategy::Leveled,
        status: CompactionJobStatus::Running,
        source_segment_ids: vec![],
        output_segment_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
    });
    ManifestStore::new(root.join("MANIFEST"))
        .save(&manifest)
        .unwrap();
}
fn denied_unchanged(root: &Path, config: &PraxisConfig) {
    let before = tree(root);
    assert!(CoreDatabase::open(config.clone()).is_err());
    assert_eq!(tree(root), before);
}

#[test]
fn explicit_owner_bootstrap_shared_lifetime_and_legacy_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    assert_eq!(database.authority().index_descriptor_count, 2);
    let kv = database.kv();
    assert_eq!(kv.snapshot().sequence, 1);
    let before = tree(temp.path());
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(tree(temp.path()), before);
    assert_eq!(kv.put("key", "value").unwrap(), 2);
    drop(database);
    kv.close().unwrap();
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    drop(kv);
    let before = tree(temp.path());
    assert!(matches!(
        PraxisEngine::open(config.clone()),
        Err(PraxisError::RecordAuthorityOpenRequired { .. })
    ));
    assert_eq!(tree(temp.path()), before);
    let reopened = CoreDatabase::open(config).unwrap();
    assert_eq!(
        reopened.kv().get("key").unwrap().unwrap().as_ref(),
        b"value"
    );
    assert_eq!(reopened.kv().put("next", "value").unwrap(), 3);
}

#[test]
fn fresh_factory_never_adopts_legacy_unknown_or_incomplete_roots() {
    for legacy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        if legacy {
            drop(PraxisEngine::open(config.clone()).unwrap());
        } else {
            std::fs::write(temp.path().join("user-file"), b"preserve").unwrap();
        }
        let before = tree(temp.path());
        assert!(CoreDatabase::create_fresh(config.clone(), options()).is_err());
        assert_eq!(tree(temp.path()), before);
        assert!(CoreDatabase::open(config).is_err());
        assert_eq!(tree(temp.path()), before);
    }
}

#[test]
fn bootstrap_fault_boundaries_leave_no_interim_legacy_authority() {
    for point in [
        Phase::Layout,
        Phase::WalHeader,
        Phase::WalAppend,
        Phase::WalSync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        FAIL_AT.with(|failure| failure.set(Some(point)));
        let result = CoreDatabase::create_fresh(config.clone(), options());
        FAIL_AT.with(|failure| failure.set(None));
        assert!(result.is_err());
        assert!(!temp.path().join("MANIFEST").exists());
        let before = tree(temp.path());
        assert!(PraxisEngine::open(config.clone()).is_err());
        assert!(CoreDatabase::open(config.clone()).is_err());
        assert!(CoreDatabase::create_fresh(config, options()).is_err());
        assert_eq!(tree(temp.path()), before, "phase{point:?}");
    }
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    FAIL_AT.with(|failure| failure.set(Some(Phase::Manifest)));
    let result = CoreDatabase::create_fresh(config.clone(), options());
    FAIL_AT.with(|failure| failure.set(None));
    assert!(result.is_err());
    assert!(
        CoreDatabase::open(config).is_ok(),
        "postpublication error is ambiguous"
    );
}

#[test]
fn every_no_manifest_activation_cut_refuses_all_factories_unchanged() {
    let fixture = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(fixture.path());
    drop(CoreDatabase::create_fresh(config, options()).unwrap());
    let wal = std::fs::read(fixture.path().join("wal/00000000000000000001.wal")).unwrap();
    for cut in [0, 1, 2, 3, 16, 28, wal.len()] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        crate::disk::DiskLayout::create(temp.path()).unwrap();
        std::fs::write(
            temp.path().join("wal/00000000000000000001.wal"),
            &wal[..cut],
        )
        .unwrap();
        let before = tree(temp.path());
        assert!(PraxisEngine::open(config.clone()).is_err(), "cut{cut}");
        assert!(CoreDatabase::open(config.clone()).is_err());
        assert!(CoreDatabase::create_fresh(config, options()).is_err());
        assert_eq!(tree(temp.path()), before);
    }
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    std::fs::copy(
        fixture.path().join("MANIFEST"),
        temp.path().join("MANIFEST.tmp"),
    )
    .unwrap();
    let before = tree(temp.path());
    assert!(PraxisEngine::open(config.clone()).is_err());
    assert!(CoreDatabase::open(config.clone()).is_err());
    assert!(CoreDatabase::create_fresh(config, options()).is_err());
    assert_eq!(tree(temp.path()), before);
}

#[test]
fn central_public_protection_blocks_batches_transactions_handles_and_policies() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let database = CoreDatabase::create_fresh(config, options()).unwrap();
    let kv = database.kv();
    for name in super::super::schema::ROLES
        .iter()
        .map(|(_, name)| *name)
        .chain(["__praxor_record_future"])
    {
        let cf = ColumnFamily(name.into());
        let before = tree(temp.path());
        assert!(matches!(
            kv.column_family(name),
            Err(PraxisError::ProtectedRecordColumnFamily(_))
        ));
        assert!(kv.get_cf(&cf, &[0], kv.snapshot()).is_err());
        assert!(kv.scan_cf(&cf, None, None, 0).is_err());
        assert!(kv.scan_prefix_cf(&cf, b"", 1).is_err());
        let operations = [
            BatchOp::Put {
                cf: cf.clone(),
                key: vec![0],
                value: vec![1],
            },
            BatchOp::Delete {
                cf: cf.clone(),
                key: vec![0],
            },
            BatchOp::Merge {
                cf: cf.clone(),
                key: vec![0],
                value: vec![1],
            },
            BatchOp::PutWithExpiry {
                cf: cf.clone(),
                key: vec![0],
                value: vec![1],
                expires_at_ms: 0,
            },
        ];
        for op in operations {
            let mut batch = WriteBatch::new();
            batch.push_op(op);
            assert!(matches!(
                kv.write_batch(batch.clone()),
                Err(PraxisError::ProtectedRecordColumnFamily(_))
            ));
            assert!(
                kv.commit_optimistic_transaction(kv.snapshot(), batch)
                    .is_err()
            );
        }
        let mut savepoint = SavepointTransaction::new(1);
        savepoint.put(cf.clone(), "key", "value");
        assert!(kv.write_batch(savepoint.batch().clone()).is_err());
        let mut nested = NestedTransaction::new(1);
        let mut child = nested.begin_child();
        child.put(cf, "key", "value");
        nested.commit_child(child).unwrap();
        assert!(kv.write_batch(nested.commit().unwrap()).is_err());
        assert!(kv.drop_column_family(name).is_err());
        let descriptor = ColumnFamilyDescriptor {
            name: name.into(),
            ..ColumnFamilyDescriptor::default()
        };
        assert!(kv.create_column_family(descriptor).is_err());
        assert_eq!(tree(temp.path()), before);
    }
    assert_eq!(kv.list_column_families().len(), 1);
    let key = "__praxor_record_meta_v1";
    kv.put(key, "ordinary").unwrap();
    kv.compare_and_swap(key, Some(b"ordinary"), "cas").unwrap();
    let mut transaction = kv.begin_transaction();
    transaction.put(key, "transaction");
    transaction.commit().unwrap();
    assert_eq!(kv.get(key).unwrap().unwrap().as_ref(), b"transaction");
    let mut descriptor = ColumnFamilyDescriptor {
        name: "user".into(),
        ..ColumnFamilyDescriptor::default()
    };
    descriptor.options.ttl_seconds = Some(60);
    kv.create_column_family(descriptor).unwrap();
    let mut batch = WriteBatch::new();
    batch.put("user", key, "user-value");
    kv.write_batch(batch).unwrap();
    assert!(
        kv.get_cf(&ColumnFamily("user".into()), key.as_bytes(), kv.snapshot())
            .unwrap()
            .is_some()
    );
    kv.drop_column_family("user").unwrap();
}

#[test]
fn invalid_protected_wal_and_nonbootstrap_transitions_refuse_before_reconciliation_or_tail_repair()
{
    for kind in [
        None,
        Some(Kind::Create),
        Some(Kind::DeleteRecords),
        Some(Kind::IndexPut),
        Some(Kind::IndexDelete),
        Some(Kind::DeleteWithIndexCleanup),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
        let id = database.authority().identity(temp.path()).unwrap();
        drop(database);
        let encoded = if let Some(kind) = kind {
            let logical = if kind == Kind::DeleteWithIndexCleanup {
                2
            } else {
                1
            };
            CoreWalRecord::Record {
                sequence: 2,
                batch: WriteBatch::new(),
                envelope: Envelope {
                    kind,
                    database_id: id,
                    prior_rid: 0,
                    new_rid: u64::from(kind == Kind::Create),
                    prior_compatibility_sequence: 0,
                    new_compatibility_sequence: logical,
                    prior_append_ordinal: 0,
                    new_append_ordinal: logical,
                    record_count: u32::from(matches!(
                        kind,
                        Kind::Create | Kind::DeleteRecords | Kind::DeleteWithIndexCleanup
                    )),
                    logical_entry_count: logical as u32,
                },
            }
            .try_encode()
            .unwrap()
        } else {
            let mut batch = WriteBatch::new();
            batch.put(Role::Meta.cf(), vec![1], b"forged".to_vec());
            WalRecord { sequence: 2, batch }.encode()
        };
        append(temp.path(), &encoded);
        append(temp.path(), &[0x32]);
        unfinished(temp.path());
        let before = tree(temp.path());
        let result = CoreDatabase::open(config);
        assert!(
            result.is_err(),
            "malformed nonbootstrap operations remain refused"
        );
        assert_eq!(tree(temp.path()), before);
    }
}

#[test]
fn threshold_one_externalized_bootstrap_and_old_envelope_are_validated_after_flush() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(temp.path());
    config.large_value_threshold = 1;
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    let bootstrap_bytes = std::fs::read(temp.path().join("wal/00000000000000000001.wal")).unwrap();
    database.kv().flush().unwrap();
    let id = database.authority().database_id;
    drop(database);
    let database = CoreDatabase::open(config.clone()).unwrap();
    assert_eq!(database.authority().database_id, id);
    drop(database);
    let state = manifest(temp.path());
    assert!(state.flushed_sequence >= 1);
    // Flush legitimately reclaims WAL1. Restore its captured complete bytes as
    // retained old evidence, then corrupt only that retired envelope identity.
    let wal_path = temp.path().join("wal/00000000000000000001.wal");
    let mut bytes = bootstrap_bytes;
    let CoreRecordPrefix::Complete {
        record:
            CoreWalRecord::Record {
                sequence,
                mut envelope,
                batch,
            },
        ..
    } = crate::wal::record::parse_core_record_prefix(&bytes[16..], &wal_path).unwrap()
    else {
        panic!("typed bootstrap")
    };
    envelope.database_id[0] ^= 1;
    bytes.truncate(16);
    bytes.extend(
        CoreWalRecord::Record {
            sequence,
            envelope,
            batch,
        }
        .try_encode()
        .unwrap(),
    );
    std::fs::write(wal_path, bytes).unwrap();
    unfinished(temp.path());
    denied_unchanged(temp.path(), &config);
}

#[test]
fn v3_foreign_writer_admission_is_unchanged_and_lease_releases_on_failure() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    drop(CoreDatabase::create_fresh(config.clone(), options()).unwrap());
    let before = tree(temp.path());
    assert!(crate::store::StorageEngine::open(temp.path(), 1024).is_err());
    assert!(crate::store::RecordStore::open(temp.path()).is_err());
    assert!(crate::record::PageDatabase::open(temp.path()).is_err());
    assert!(crate::catalog::CatalogStore::open(temp.path()).is_err());
    assert_eq!(tree(temp.path()), before);
    assert!(CoreDatabase::open(config).is_ok());
}

#[test]
fn backup_restore_retains_typed_bootstrap_identity_and_externalized_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(temp.path());
    config.large_value_threshold = 1;
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    database.kv().put("key", "value").unwrap();
    database.kv().flush().unwrap();
    let identity = database.authority().database_id;
    database.kv().backup_to(backup.path()).unwrap();
    drop(database);
    PraxisEngine::restore_from_backup(backup.path(), target.path()).unwrap();
    config.data_dir = target.path().into();
    let restored = CoreDatabase::open(config).unwrap();
    assert_eq!(restored.authority().database_id, identity);
    assert_eq!(
        restored.kv().get("key").unwrap().unwrap().as_ref(),
        b"value"
    );
}

#[test]
fn invalid_protected_segment_operations_or_missing_binding_never_reconcile() {
    for mutation in 0..5 {
        let temp = tempfile::tempdir().unwrap();
        let mut config = PraxisConfig::new(temp.path());
        config.large_value_threshold = 1;
        let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
        database.kv().flush().unwrap();
        drop(database);
        let mut manifest = manifest(temp.path());
        let metadata = &mut manifest.segments[0];
        let path = Path::new(&metadata.path);
        let mut raw = crate::segments::codec::decode_segment(
            &std::fs::read(path).unwrap(),
            path,
            &crate::accel::CpuAccelerator,
        )
        .unwrap();
        let entry = raw
            .blocks
            .iter_mut()
            .flatten()
            .find(|row| row.entry.cf.0 == Role::Meta.cf() && row.entry.key.as_ref() == [0])
            .unwrap();
        use crate::types::StoredValue;
        match mutation {
            0 => entry.entry.version.value = StoredValue::Merge(b"forged".to_vec()),
            1 => entry.entry.version.value = StoredValue::Delete,
            2 => entry.blob_expiry = Some(0),
            3 => {
                let StoredValue::BlobPointer(pointer) = &mut entry.entry.version.value else {
                    panic!("threshold1 must externalize binding")
                };
                pointer.len = u64::MAX;
            }
            _ => {
                for block in &mut raw.blocks {
                    block.retain(|row| {
                        row.entry.cf.0 != Role::Meta.cf() || row.entry.key.as_ref() != [0]
                    });
                }
                metadata.entries -= 1;
            }
        }
        let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
        std::fs::write(path, &bytes).unwrap();
        metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
        ManifestStore::new(temp.path().join("MANIFEST"))
            .save(&manifest)
            .unwrap();
        unfinished(temp.path());
        denied_unchanged(temp.path(), &config);
    }
}

#[test]
fn offline_restore_checks_retained_flushed_typed_wal_before_replacing_destination() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(source.path());
    let database = CoreDatabase::create_fresh(config, options()).unwrap();
    let path = source.path().join("wal/00000000000000000001.wal");
    let bytes = std::fs::read(&path).unwrap();
    database.kv().flush().unwrap();
    drop(database);
    let CoreRecordPrefix::Complete {
        record:
            CoreWalRecord::Record {
                sequence,
                mut envelope,
                batch,
            },
        ..
    } = crate::wal::record::parse_core_record_prefix(&bytes[16..], &path).unwrap()
    else {
        panic!("typed bootstrap")
    };
    envelope.database_id[0] ^= 1;
    let mut corrupt = bytes[..16].to_vec();
    corrupt.extend(
        CoreWalRecord::Record {
            sequence,
            envelope,
            batch,
        }
        .try_encode()
        .unwrap(),
    );
    std::fs::write(path, corrupt).unwrap();
    let target = PraxisEngine::open(PraxisConfig::new(destination.path())).unwrap();
    target.put("preserve", "target-data").unwrap();
    drop(target);
    let before = tree(destination.path());
    let source_before = tree(source.path());
    assert!(PraxisEngine::restore_from_backup(source.path(), destination.path()).is_err());
    assert_eq!(tree(destination.path()), before);
    assert_eq!(tree(source.path()), source_before);
}

#[test]
fn accepted_user_torn_suffix_repairs_only_after_complete_authority_validation() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    let kv = database.kv();
    kv.put("accepted", "present").unwrap();
    drop(kv);
    drop(database);
    let before = tree(temp.path());
    append(temp.path(), &[0x32]);
    let database = CoreDatabase::open(config).unwrap();
    assert_eq!(
        database.kv().get("accepted").unwrap().unwrap().as_ref(),
        b"present"
    );
    drop(database);
    assert_eq!(tree(temp.path()), before);
}

#[test]
fn legacy_wal_api_cannot_strip_the_envelope_or_repair_its_tail() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    drop(CoreDatabase::create_fresh(config, options()).unwrap());
    append(temp.path(), &[0x32]);
    let path = temp.path().join("wal/00000000000000000001.wal");
    let before = tree(temp.path());
    assert!(matches!(
        crate::wal::Wal::replay(&path),
        Err(PraxisError::RecordAuthorityWalRequired { .. })
    ));
    assert!(matches!(
        crate::wal::Wal::open(&path, 1, crate::WalSyncPolicy::EveryBatch),
        Err(PraxisError::RecordAuthorityWalRequired { .. })
    ));
    assert_eq!(tree(temp.path()), before);
}

#[test]
fn bad_registry_options_fail_before_creating_the_requested_root() {
    let temp = tempfile::tempdir().unwrap();
    for names in [vec![""], vec!["duplicate", "duplicate"]] {
        let root = temp.path().join("not-created");
        let options = RecordAuthorityOptions {
            indexes: names
                .into_iter()
                .map(|name| MappingDescriptor {
                    name: name.into(),
                    namespace: "".into(),
                })
                .collect(),
        };
        assert!(CoreDatabase::create_fresh(PraxisConfig::new(&root), options).is_err());
        assert!(!root.exists());
    }
}

#[test]
fn final_manifest_without_bootstrap_and_every_temporary_manifest_cut_refuse_unchanged() {
    let fixture = tempfile::tempdir().unwrap();
    drop(CoreDatabase::create_fresh(PraxisConfig::new(fixture.path()), options()).unwrap());
    let manifest_bytes = std::fs::read(fixture.path().join("MANIFEST")).unwrap();
    let wal = std::fs::read(fixture.path().join("wal/00000000000000000001.wal")).unwrap();
    for cut in [0, 1, 3, manifest_bytes.len()] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        std::fs::write(temp.path().join("MANIFEST.tmp"), &manifest_bytes[..cut]).unwrap();
        let before = tree(temp.path());
        assert!(CoreDatabase::open(config.clone()).is_err());
        assert!(CoreDatabase::create_fresh(config.clone(), options()).is_err());
        assert!(PraxisEngine::open(config).is_err());
        assert_eq!(tree(temp.path()), before);
    }
    for cut in [0, 1, 3, 16, wal.len() - 1] {
        let temp = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temp.path());
        crate::disk::DiskLayout::create(temp.path()).unwrap();
        std::fs::write(temp.path().join("MANIFEST"), &manifest_bytes).unwrap();
        std::fs::write(
            temp.path().join("wal/00000000000000000001.wal"),
            &wal[..cut],
        )
        .unwrap();
        denied_unchanged(temp.path(), &config);
    }
}

#[test]
fn legacy_names_and_user_prefix_bytes_keep_their_existing_meaning() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine
        .create_column_family(ColumnFamilyDescriptor {
            name: Role::Meta.cf().into(),
            ..ColumnFamilyDescriptor::default()
        })
        .unwrap();
    let mut batch = WriteBatch::new();
    batch.put(Role::Meta.cf(), vec![0], b"legacy-user".to_vec());
    engine.write_batch(batch).unwrap();
    assert_eq!(
        engine
            .get_cf(
                &ColumnFamily(Role::Meta.cf().into()),
                &[0],
                engine.snapshot()
            )
            .unwrap()
            .unwrap()
            .as_ref(),
        b"legacy-user"
    );
    drop(engine);
    assert!(PraxisEngine::open(config).is_ok());
}

#[test]
fn review_unknown_reserved_segment_cf_is_not_silently_retired() {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    database.kv().flush().unwrap();
    drop(database);
    let mut manifest = manifest(temp.path());
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    raw.blocks
        .last_mut()
        .unwrap()
        .push(crate::segments::codec::RawEntry {
            entry: crate::segments::block::SegmentEntry {
                cf: ColumnFamily("__praxor_record_unknown".into()),
                key: vec![255].into(),
                version: crate::types::VersionedValue {
                    sequence: 1,
                    value: crate::types::StoredValue::Put(b"must-not-filter".to_vec()),
                },
            },
            blob_expiry: None,
        });
    metadata.entries += 1;
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(temp.path().join("MANIFEST"))
        .save(&manifest)
        .unwrap();
    unfinished(temp.path());
    denied_unchanged(temp.path(), &config);
}

fn reordered_flushed_wal_is_not_backup_evidence(duplicate_bootstrap: bool) {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let database = CoreDatabase::create_fresh(PraxisConfig::new(source.path()), options()).unwrap();
    let kv = database.kv();
    kv.put("first", "one").unwrap();
    kv.put("second", "two").unwrap();
    let path = source.path().join("wal/00000000000000000001.wal");
    let bytes = std::fs::read(&path).unwrap();
    let mut frames = Vec::new();
    let mut offset = 16;
    while offset < bytes.len() {
        let CoreRecordPrefix::Complete { encoded_len, .. } =
            crate::wal::record::parse_core_record_prefix(&bytes[offset..], &path).unwrap()
        else {
            panic!("complete fixture")
        };
        frames.push(bytes[offset..offset + encoded_len].to_vec());
        offset += encoded_len;
    }
    assert_eq!(frames.len(), 3);
    kv.flush().unwrap();
    drop(kv);
    drop(database);
    let order = if duplicate_bootstrap {
        vec![0, 0, 1, 2]
    } else {
        vec![0, 2, 1]
    };
    let mut malformed = bytes[..16].to_vec();
    for index in order {
        malformed.extend(&frames[index]);
    }
    std::fs::write(path, malformed).unwrap();
    let destination = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    destination.put("preserve", "old-authority").unwrap();
    drop(destination);
    let before = tree(target.path());
    let source_before = tree(source.path());
    assert!(
        PraxisEngine::restore_from_backup(source.path(), target.path()).is_err(),
        "backup accepted reordered complete flushed authority records"
    );
    assert_eq!(tree(target.path()), before);
    assert_eq!(tree(source.path()), source_before);
}

#[test]
fn review_duplicate_flushed_bootstrap_cannot_pass_offline_backup_validation() {
    reordered_flushed_wal_is_not_backup_evidence(true);
}

#[test]
fn review_reversed_flushed_user_records_cannot_pass_offline_backup_validation() {
    reordered_flushed_wal_is_not_backup_evidence(false);
}

fn ordinary_segment_row_cannot_share_bootstrap(sequence: u64, cf: &str) {
    let temp = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(temp.path());
    let database = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    database.kv().flush().unwrap();
    drop(database);
    let mut manifest = manifest(temp.path());
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    raw.blocks
        .last_mut()
        .unwrap()
        .push(crate::segments::codec::RawEntry {
            entry: crate::segments::block::SegmentEntry {
                cf: ColumnFamily(cf.into()),
                key: vec![255].into(),
                version: crate::types::VersionedValue {
                    sequence,
                    value: crate::types::StoredValue::Put(b"forged-user-bootstrap".to_vec()),
                },
            },
            blob_expiry: None,
        });
    metadata.entries += 1;
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(temp.path().join("MANIFEST"))
        .save(&manifest)
        .unwrap();
    unfinished(temp.path());
    denied_unchanged(temp.path(), &config);
    let target = tempfile::tempdir().unwrap();
    let target_owner = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    target_owner.put("preserve", "target").unwrap();
    drop(target_owner);
    let before = tree(target.path());
    let source_before = tree(temp.path());
    assert!(PraxisEngine::restore_from_backup(temp.path(), target.path()).is_err());
    assert_eq!(tree(target.path()), before);
    assert_eq!(tree(temp.path()), source_before);
}

#[test]
fn review_ordinary_segment_row_cannot_use_sequence_zero() {
    ordinary_segment_row_cannot_share_bootstrap(0, "default");
}
#[test]
fn review_ordinary_segment_row_cannot_use_sequence_one() {
    ordinary_segment_row_cannot_share_bootstrap(1, "default");
}
#[test]
fn review_retired_segment_cf_cannot_hide_a_bootstrap_sequence_row() {
    ordinary_segment_row_cannot_share_bootstrap(1, "retired");
}
#[test]
fn review_ordinary_segment_row_cannot_exceed_the_installed_flush_cutoff() {
    ordinary_segment_row_cannot_share_bootstrap(100, "default");
}

#[test]
fn canonical_nonbootstrap_create_recovers_through_existing_owner_and_backup_apis() {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), options()).unwrap();
    let id = db.authority().identity(dir.path()).unwrap();
    drop(db);
    let mut batch = WriteBatch::new();
    for (role, key, row) in [
        (Role::Payload, Key::Payload(1), Row::Payload(b"actual")),
        (
            Role::State,
            Key::State(1),
            Row::State {
                live: true,
                payload_length: 6,
            },
        ),
        (
            Role::Meta,
            Key::Allocator,
            Row::Allocator(Allocator {
                last_rid: 1,
                compatibility_sequence: 1,
                append_ordinal: 1,
                live_count: 1,
                dead_count: 0,
                live_payload_bytes: 6,
            }),
        ),
    ] {
        batch.put(role.cf(), key.encode().unwrap(), row.encode().unwrap());
    }
    append(
        dir.path(),
        &CoreWalRecord::Record {
            sequence: 2,
            batch,
            envelope: Envelope {
                kind: Kind::Create,
                database_id: id,
                prior_rid: 0,
                new_rid: 1,
                prior_compatibility_sequence: 0,
                new_compatibility_sequence: 1,
                prior_append_ordinal: 0,
                new_append_ordinal: 1,
                record_count: 1,
                logical_entry_count: 1,
            },
        }
        .try_encode()
        .unwrap(),
    );
    let db =
        CoreDatabase::open(config.clone()).expect("valid complete canonical create is supported");
    assert_eq!(db.kv().snapshot().sequence, 2);
    db.kv().flush().unwrap();
    let backup = tempfile::tempdir().unwrap();
    db.kv().backup_to(backup.path()).unwrap();
    drop(db);
    CoreDatabase::open(config).unwrap();
}
