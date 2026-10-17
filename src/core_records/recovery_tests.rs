use super::codec::*;
use super::intent::*;
use super::*;
use crate::manifest::{Manifest, ManifestStore};
use crate::types::StoredValue;
use crate::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == crate::writer_lease::LOCK_FILE_NAME {
                continue;
            }
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().into();
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
fn malformed_segment(mutation: u8) {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "review".into(),
            }],
        },
    )
    .unwrap();
    for key in [b"k", b"j"] {
        db.kv()
            .commit_record(
                RecordIntent::new(IntentKind::Create(vec![NewRecord {
                    payload: b"v".to_vec(),
                    mappings: vec![Mapping {
                        index: 1,
                        key: key.to_vec(),
                    }],
                }]))
                .unwrap(),
            )
            .unwrap();
    }
    db.kv().flush().unwrap();
    drop(db);
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    match mutation {
        0 => {
            // A second key claims the SAME globally allocated logical event.
            let mut additions = Vec::new();
            for row in raw.blocks.iter().flatten() {
                if row.entry.cf.0 != Role::Index.cf() {
                    continue;
                }
                let key = Key::decode(Role::Index, &row.entry.key, path).unwrap();
                let changed = match key {
                    Key::Fact {
                        key: b"k",
                        raw_sequence,
                        ..
                    } => Some(Key::Fact {
                        index: 1,
                        incarnation: 1,
                        key: b"evil",
                        raw_sequence,
                    }),
                    Key::Head { key: b"k", .. } => Some(Key::Head {
                        index: 1,
                        incarnation: 1,
                        key: b"evil",
                    }),
                    _ => None,
                };
                if let Some(key) = changed {
                    let mut row = crate::segments::codec::RawEntry {
                        entry: row.entry.clone(),
                        blob_expiry: row.blob_expiry,
                    };
                    row.entry.key = key.encode().unwrap().into();
                    additions.push(row);
                }
            }
            metadata.entries += additions.len() as u64;
            raw.blocks[0].extend(additions);
        }
        1 => {
            // Rewrite an existing immutable fact at a later core sequence,
            // with a matching latest head so a latest-only check cannot see it.
            let mut additions = Vec::new();
            for row in raw.blocks.iter().flatten() {
                if row.entry.cf.0 != Role::Index.cf() {
                    continue;
                }
                let key = Key::decode(Role::Index, &row.entry.key, path).unwrap();
                let value = match key {
                    Key::Fact { key: b"k", .. } => Some(Row::Fact {
                        append_ordinal: 2,
                        decision: Decision::Delete,
                    }),
                    Key::Head { key: b"k", .. } => Some(Row::Head {
                        raw_sequence: 2,
                        append_ordinal: 2,
                        decision: Decision::Delete,
                    }),
                    _ => None,
                };
                if let Some(value) = value {
                    let mut row = crate::segments::codec::RawEntry {
                        entry: row.entry.clone(),
                        blob_expiry: row.blob_expiry,
                    };
                    row.entry.version.sequence = 3;
                    row.entry.version.value = StoredValue::Put(value.encode().unwrap());
                    additions.push(row);
                }
            }
            metadata.entries += additions.len() as u64;
            raw.blocks[0].extend(additions);
        }
        2 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::Meta.cf()
                        && row.entry.key.as_ref() == [1]
                        && row.entry.version.sequence == 1
                })
                .unwrap();
            old.entry.version.value = StoredValue::Put(
                Row::Allocator(Allocator {
                    last_rid: 100,
                    compatibility_sequence: 100,
                    append_ordinal: 100,
                    live_count: 100,
                    dead_count: 0,
                    live_payload_bytes: 100,
                })
                .encode()
                .unwrap(),
            );
        }
        3 => {
            let old = raw
                .blocks
                .iter()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::Index.cf()
                        && matches!(
                            Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                            Key::Fact { .. }
                        )
                })
                .unwrap();
            let copied = crate::segments::codec::RawEntry {
                entry: old.entry.clone(),
                blob_expiry: old.blob_expiry,
            };
            raw.blocks[0].push(copied);
            metadata.entries += 1;
        }
        4 => {
            for block in &mut raw.blocks {
                block.retain(|row| {
                    !(row.entry.cf.0 == Role::State.cf()
                        && row.entry.key.as_ref() == Key::State(1).encode().unwrap())
                });
            }
            metadata.entries -= 1;
        }
        5 => {
            for block in &mut raw.blocks {
                block.retain(|row| {
                    !(row.entry.cf.0 == Role::Payload.cf()
                        && row.entry.key.as_ref() == Key::Payload(1).encode().unwrap())
                });
            }
            metadata.entries -= 1;
        }
        6 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::Meta.cf()
                        && row.entry.key.as_ref() == [1]
                        && row.entry.version.sequence == 3
                })
                .unwrap();
            old.entry.version.value = StoredValue::Put(
                Row::Allocator(Allocator {
                    last_rid: 2,
                    compatibility_sequence: 4,
                    append_ordinal: 4,
                    live_count: 2,
                    dead_count: 0,
                    live_payload_bytes: 99,
                })
                .encode()
                .unwrap(),
            );
        }
        7 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::Index.cf()
                        && matches!(
                            Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                            Key::Head { key: b"k", .. }
                        )
                })
                .unwrap();
            old.entry.version.value = StoredValue::Put(
                Row::Head {
                    raw_sequence: 2,
                    append_ordinal: 2,
                    decision: Decision::Put(2),
                }
                .encode()
                .unwrap(),
            );
        }
        8 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| row.entry.cf.0 == Role::Payload.cf())
                .unwrap();
            old.entry.version.value = StoredValue::Merge(b"bad".to_vec());
        }
        9 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| row.entry.cf.0 == Role::State.cf())
                .unwrap();
            old.entry.version.value = StoredValue::Delete;
        }
        10 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::State.cf()
                        && row.entry.key.as_ref() == Key::State(1).encode().unwrap()
                })
                .unwrap();
            let mut live = crate::segments::codec::RawEntry {
                entry: old.entry.clone(),
                blob_expiry: None,
            };
            live.entry.version.sequence = 3;
            old.entry.version.value = StoredValue::Put(
                Row::State {
                    live: false,
                    payload_length: 0,
                }
                .encode()
                .unwrap(),
            );
            raw.blocks[0].push(live);
            metadata.entries += 1;
        }
        11 | 12 => {
            let old = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == Role::Payload.cf()
                        && row.entry.key.as_ref() == Key::Payload(1).encode().unwrap()
                })
                .unwrap();
            let mut latest = crate::segments::codec::RawEntry {
                entry: old.entry.clone(),
                blob_expiry: None,
            };
            latest.entry.version.sequence = 3;
            old.entry.version.value = if mutation == 11 {
                StoredValue::Put(Row::Payload(b"changed-old-bytes").encode().unwrap())
            } else {
                StoredValue::Delete
            };
            raw.blocks[0].push(latest);
            metadata.entries += 1;
        }
        14 => {
            for row in raw.blocks.iter_mut().flatten() {
                if row.entry.cf.0 != Role::Index.cf() {
                    continue;
                }
                match Key::decode(Role::Index, &row.entry.key, path).unwrap() {
                    Key::Fact { key: b"k", .. } => {
                        row.entry.key = Key::Fact {
                            index: 1,
                            incarnation: 1,
                            key: b"k",
                            raw_sequence: 1,
                        }
                        .encode()
                        .unwrap()
                        .into();
                        row.entry.version.value = StoredValue::Put(
                            Row::Fact {
                                append_ordinal: 1,
                                decision: Decision::Put(1),
                            }
                            .encode()
                            .unwrap(),
                        );
                    }
                    Key::Head { key: b"k", .. } => {
                        row.entry.version.value = StoredValue::Put(
                            Row::Head {
                                raw_sequence: 1,
                                append_ordinal: 1,
                                decision: Decision::Put(1),
                            }
                            .encode()
                            .unwrap(),
                        );
                    }
                    _ => {}
                }
            }
        }
        _ => unreachable!(),
    }
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    if mutation == 3 {
        drop(
            CoreDatabase::open(config).expect("equivalent same-coreseq copied fact remains valid"),
        );
    } else {
        assert!(
            CoreDatabase::open(config).is_err(),
            "malformed protected segment must be refused"
        );
    }
    assert_eq!(tree(dir.path()), before);
    let destination = tempfile::tempdir().unwrap();
    let destination_config = PraxisConfig::new(destination.path());
    let healthy = PraxisEngine::open(destination_config).unwrap();
    healthy.put("keep", "bytes").unwrap();
    drop(healthy);
    let target_before = tree(destination.path());
    let restored = PraxisEngine::restore_from_backup(dir.path(), destination.path());
    if mutation == 3 {
        restored.unwrap();
        CoreDatabase::open(PraxisConfig::new(destination.path())).unwrap();
    } else {
        assert!(restored.is_err());
        assert_eq!(tree(destination.path()), target_before);
    }
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn review_fact_ordinals_have_one_global_owner() {
    malformed_segment(0);
}
#[test]
fn review_fact_cannot_be_rewritten_at_a_later_core_sequence() {
    malformed_segment(1);
}
#[test]
fn review_old_allocator_cannot_exceed_installed_floors() {
    malformed_segment(2);
}
#[test]
fn equivalent_same_sequence_fact_copy_is_not_a_rewrite() {
    malformed_segment(3);
}
#[test]
fn installed_state_requires_payloads_states_counters_heads_and_allowed_operations() {
    for mutation in 4..10 {
        malformed_segment(mutation);
    }
}

#[test]
fn review_retained_state_cannot_resurrect_a_dead_rid() {
    malformed_segment(10);
}
#[test]
fn review_retained_payload_cannot_change_its_bytes() {
    malformed_segment(11);
}
#[test]
fn review_retained_payload_cannot_reappear_after_tombstone() {
    malformed_segment(12);
}

fn old_wal_relationship(mutation: u8) {
    use crate::wal::record::CoreWalRecord;
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    for payload in [b"v", b"w"] {
        db.kv()
            .commit_record(
                RecordIntent::new(IntentKind::Create(vec![NewRecord {
                    payload: payload.to_vec(),
                    mappings: vec![],
                }]))
                .unwrap(),
            )
            .unwrap();
    }
    for _ in 0..2 {
        db.kv()
            .commit_record(
                RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                    .unwrap(),
            )
            .unwrap();
    }
    let path = dir.path().join("wal").join("00000000000000000001.wal");
    let original = std::fs::read(&path).unwrap();
    db.kv().flush().unwrap();
    drop(db);
    // Retired evidence is optional. Restore the exact captured old file so this
    // test exercises validation below C, not a missing-path fixture error.
    std::fs::write(&path, &original).unwrap();
    drop(CoreDatabase::open(config.clone()).unwrap());
    let (mut records, _) = crate::wal::writer::replay_core_records(&original, &path).unwrap();
    if mutation == 1 {
        let mut reused = records
            .iter()
            .find(|record| record.sequence() == 2)
            .unwrap()
            .clone();
        let CoreWalRecord::Record { sequence, .. } = &mut reused else {
            panic!()
        };
        *sequence = 3;
        records.retain(|record| record.sequence() <= 3);
        *records.last_mut().unwrap() = reused;
    } else if mutation == 2 {
        records.retain(|record| record.sequence() != 2);
    } else {
        if mutation == 3 {
            records.retain(|record| record.sequence() <= 3);
        }
        for record in &mut records {
            if let CoreWalRecord::Record {
                sequence,
                envelope,
                batch,
            } = record
            {
                if *sequence != if mutation == 0 { 2 } else { 3 } {
                    continue;
                }
                if mutation == 3 {
                    envelope.prior_compatibility_sequence = 2;
                    envelope.new_compatibility_sequence = 3;
                    envelope.prior_append_ordinal = 2;
                    envelope.new_append_ordinal = 3;
                }
                let mut changed = crate::transactions::WriteBatch::new();
                for op in batch.ops() {
                    let op = match op {
                        crate::transactions::BatchOp::Put { cf, key, value }
                            if cf.0 == Role::Meta.cf() && key == &[1] =>
                        {
                            let Row::Allocator(mut allocator) =
                                Row::decode(&Key::Allocator, value, &path).unwrap()
                            else {
                                panic!()
                            };
                            if mutation == 0 {
                                allocator.live_payload_bytes = 100;
                            } else {
                                allocator.compatibility_sequence = 3;
                                allocator.append_ordinal = 3;
                            }
                            crate::transactions::BatchOp::Put {
                                cf: cf.clone(),
                                key: key.clone(),
                                value: Row::Allocator(allocator).encode().unwrap(),
                            }
                        }
                        _ => op.clone(),
                    };
                    changed.push_op(op);
                }
                *batch = changed;
            }
        }
    }
    let mut changed = original[..16].to_vec();
    for record in records {
        changed.extend(record.try_encode().unwrap());
    }
    std::fs::write(&path, changed).unwrap();
    let before = tree(dir.path());
    if mutation == 2 {
        drop(
            CoreDatabase::open(config)
                .expect("missing old core sequence resets equality, not monotone bounds"),
        );
    } else {
        assert!(
            CoreDatabase::open(config).is_err(),
            "old typed frame relationships must be proved without latest-liveness equality"
        );
    }
    assert_eq!(tree(dir.path()), before);
}
#[test]
fn historical_first_create_cannot_invent_prior_payload_bytes() {
    old_wal_relationship(0);
}
#[test]
fn historical_typed_frames_cannot_reuse_rid_or_raw_floors() {
    old_wal_relationship(1);
}
#[test]
fn historical_counter_equality_resets_only_across_missing_core_sequences() {
    old_wal_relationship(2);
}
#[test]
fn historical_contiguous_chain_cannot_invent_counter_gaps() {
    old_wal_relationship(3);
}

fn impossible_counter_lower_bound(mutation: u8) {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "bounds".into(),
            }],
        },
    )
    .unwrap();
    let engine = db.kv();
    for _ in 0..3 {
        engine
            .commit_record(
                RecordIntent::new(IntentKind::Create(vec![NewRecord {
                    payload: b"v".to_vec(),
                    mappings: vec![],
                }]))
                .unwrap(),
            )
            .unwrap();
    }
    if mutation == 1 {
        engine
            .commit_record(
                RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                    .unwrap(),
            )
            .unwrap();
    }
    engine.flush().unwrap();
    engine.put("second-segment", "marker").unwrap();
    engine.flush().unwrap();
    assert_ne!(engine.compact().unwrap(), 0);
    engine.garbage_collect().unwrap();
    drop(engine);
    drop(db);
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    let row = raw
        .blocks
        .iter_mut()
        .flatten()
        .find(|row| row.entry.cf.0 == Role::Meta.cf() && row.entry.key.as_ref() == [1])
        .unwrap();
    let StoredValue::Put(bytes) = &row.entry.version.value else {
        panic!()
    };
    let Row::Allocator(mut allocator) = Row::decode(&Key::Allocator, bytes, path).unwrap() else {
        panic!()
    };
    allocator.compatibility_sequence = if mutation == 0 { 1 } else { 3 };
    allocator.append_ordinal = allocator.compatibility_sequence;
    row.entry.version.value = StoredValue::Put(Row::Allocator(allocator).encode().unwrap());
    if mutation == 2 {
        for (key, value) in [
            (
                Key::Fact {
                    index: 1,
                    incarnation: 1,
                    key: b"fake",
                    raw_sequence: 1,
                },
                Row::Fact {
                    append_ordinal: 1,
                    decision: Decision::Put(1),
                },
            ),
            (
                Key::Head {
                    index: 1,
                    incarnation: 1,
                    key: b"fake",
                },
                Row::Head {
                    raw_sequence: 1,
                    append_ordinal: 1,
                    decision: Decision::Put(1),
                },
            ),
        ] {
            raw.blocks[0].push(crate::segments::codec::RawEntry {
                entry: crate::segments::block::SegmentEntry {
                    cf: crate::types::ColumnFamily(Role::Index.cf().into()),
                    key: key.encode().unwrap().into(),
                    version: crate::types::VersionedValue {
                        sequence: 2,
                        value: StoredValue::Put(value.encode().unwrap()),
                    },
                },
                blob_expiry: None,
            });
            metadata.entries += 1;
        }
    }
    let encoded = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &encoded).unwrap();
    metadata.file_digest = blake3::hash(&encoded).to_hex().to_string();
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    assert!(
        CoreDatabase::open(config).is_err(),
        "actual rows require minimum distinct logical events"
    );
    assert_eq!(tree(dir.path()), before);
}
#[test]
fn review_counter_must_cover_every_allocated_rid() {
    impossible_counter_lower_bound(0);
}
#[test]
fn review_counter_must_cover_first_deletes() {
    impossible_counter_lower_bound(1);
}
#[test]
fn review_counter_must_cover_distinct_mapping_facts() {
    impossible_counter_lower_bound(2);
}

fn planned_frame(db: &CoreDatabase, sequence: u64) -> crate::wal::record::CoreWalRecord {
    let engine = db.kv();
    let authority = db.authority();
    let source = Path::new("frame-cuts");
    let intent = RecordIntent::new(IntentKind::Create(vec![
        NewRecord {
            payload: b"a".to_vec(),
            mappings: vec![],
        },
        NewRecord {
            payload: b"b".to_vec(),
            mappings: vec![],
        },
    ]))
    .unwrap();
    super::transition::plan(
        &intent,
        sequence,
        &super::transition::Context {
            id: authority.identity(source).unwrap(),
            descriptors: 0,
            source,
        },
        &mut |role, key| {
            engine
                .resolve_value_at_snapshot(
                    &crate::types::ColumnFamily(role.cf().into()),
                    key,
                    engine.snapshot().sequence,
                )?
                .map(|bytes| super::transition::Summary::decode(role, key, &bytes, source))
                .transpose()
        },
    )
    .unwrap()
    .record
}

#[test]
fn every_valid_record_frame_cut_recovers_none_or_the_whole_create_batch() {
    // Every byte position, with real framing/checksums and writable owner open.
    let mut cut = 0;
    loop {
        let dir = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(dir.path());
        let db =
            CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
                .unwrap();
        let encoded = planned_frame(&db, 2).try_encode().unwrap();
        let path = db.kv().inner.wal.lock().path().to_path_buf();
        let original = std::fs::read(&path).unwrap();
        drop(db);
        let mut bytes = original.clone();
        bytes.extend_from_slice(&encoded[..cut]);
        std::fs::write(&path, &bytes).unwrap();
        let recovered = CoreDatabase::open(config).unwrap();
        assert_eq!(
            recovered.kv().snapshot().sequence,
            if cut == encoded.len() { 2 } else { 1 }
        );
        let allocator = recovered
            .kv()
            .resolve_value_at_snapshot(
                &crate::types::ColumnFamily(Role::Meta.cf().into()),
                &[1],
                recovered.kv().snapshot().sequence,
            )
            .unwrap()
            .unwrap();
        let Row::Allocator(allocator) = Row::decode(&Key::Allocator, &allocator, &path).unwrap()
        else {
            panic!()
        };
        assert_eq!(allocator.last_rid, if cut == encoded.len() { 2 } else { 0 });
        assert_eq!(
            std::fs::read(&path).unwrap(),
            if cut == encoded.len() {
                bytes
            } else {
                original
            }
        );
        if cut == encoded.len() {
            break;
        }
        cut += 1;
    }
}

#[test]
fn suffix_counter_validation_precedes_repair_of_a_later_torn_tail() {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    db.kv()
        .commit_record(
            RecordIntent::new(IntentKind::Create(vec![NewRecord {
                payload: b"prior".to_vec(),
                mappings: vec![],
            }]))
            .unwrap(),
        )
        .unwrap();
    let mut record = planned_frame(&db, 3);
    let crate::wal::record::CoreWalRecord::Record { batch, .. } = &mut record else {
        panic!()
    };
    let mut changed = crate::transactions::WriteBatch::new();
    for op in batch.ops() {
        let mut op = op.clone();
        if let crate::transactions::BatchOp::Put { cf, key, value } = &mut op
            && cf.0 == Role::Meta.cf()
            && key == &[1]
        {
            let Row::Allocator(mut allocator) =
                Row::decode(&Key::Allocator, value, Path::new("counter")).unwrap()
            else {
                panic!()
            };
            allocator.live_payload_bytes += 1;
            *value = Row::Allocator(allocator).encode().unwrap();
        }
        changed.push_op(op);
    }
    *batch = changed;
    let path = db.kv().inner.wal.lock().path().to_path_buf();
    drop(db);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend(record.try_encode().unwrap());
    bytes.push(0x32);
    std::fs::write(&path, bytes).unwrap();
    let before = tree(dir.path());
    assert!(CoreDatabase::open(config).is_err());
    assert_eq!(tree(dir.path()), before);
}

fn cross_evidence(mutation: u8) {
    use crate::segments::codec::{RawEntry, RawSegment};
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    let engine = db.kv();
    let mut created = vec![NewRecord {
        payload: b"v".to_vec(),
        mappings: vec![],
    }];
    if mutation == 10 || mutation == 12 {
        created.push(created[0].clone());
    }
    engine
        .commit_record(RecordIntent::new(IntentKind::Create(created)).unwrap())
        .unwrap();
    engine
        .commit_record(
            RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(
                if mutation == 10 || mutation == 12 {
                    2
                } else {
                    1
                },
            )]))
            .unwrap(),
        )
        .unwrap();
    if mutation == 11 {
        engine.put("ordinary", "marker").unwrap();
    }
    if mutation == 8 || mutation == 11 {
        engine
            .commit_record(
                RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                    .unwrap(),
            )
            .unwrap();
    }
    let wal_path = engine.inner.wal.lock().path().to_path_buf();
    let wal = std::fs::read(&wal_path).unwrap();
    engine.flush().unwrap();
    if mutation == 12 {
        engine
            .commit_record(
                RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                    .unwrap(),
            )
            .unwrap();
    }
    drop(engine);
    drop(db);
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    if mutation == 12 {
        // Mirror the actual committed suffix in an offline capture. R1 is
        // live at C3 and dead at S4; checking only final rows would mask the
        // forged old-WAL death of R1 at S3.
        manifest.last_sequence = 4;
    }
    let metadata = manifest.segments[0].clone();
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    match mutation {
        0 => {
            let state = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| row.entry.cf.0 == Role::State.cf() && row.entry.version.sequence == 2)
                .unwrap();
            state.entry.version.value = StoredValue::Put(
                Row::State {
                    live: true,
                    payload_length: 2,
                }
                .encode()
                .unwrap(),
            );
            let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
            std::fs::write(path, &bytes).unwrap();
            manifest.segments[0].file_digest = blake3::hash(&bytes).to_hex().to_string();
        }
        1 | 2 | 4 | 5 => {
            let role = if mutation == 1 || mutation == 4 {
                Role::State
            } else {
                Role::Payload
            };
            let old = raw
                .blocks
                .iter()
                .flatten()
                .find(|row| row.entry.cf.0 == role.cf() && row.entry.version.sequence == 2)
                .unwrap();
            let mut conflicting = RawEntry {
                entry: old.entry.clone(),
                blob_expiry: None,
            };
            conflicting.entry.version.value = if mutation == 1 {
                StoredValue::Put(
                    Row::State {
                        live: false,
                        payload_length: 0,
                    }
                    .encode()
                    .unwrap(),
                )
            } else if mutation == 2 {
                StoredValue::Delete
            } else {
                conflicting.entry.version.value
            };
            let id = manifest.next_segment_id;
            manifest.next_segment_id += 1;
            let path = path.parent().unwrap().join(format!("{id:020}.tseg"));
            let bytes = RawSegment {
                id,
                level: 0,
                compression: crate::Compression::None,
                blocks: vec![vec![conflicting]],
            }
            .encode(&crate::accel::CpuAccelerator)
            .unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let mut metadata = metadata;
            metadata.id = id;
            metadata.path = path.to_string_lossy().into_owned();
            metadata.entries = 1;
            metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
            manifest.segments.push(metadata);
        }
        3 => {
            let (mut records, _) =
                crate::wal::writer::replay_core_records(&wal, &wal_path).unwrap();
            for record in &mut records {
                if let crate::wal::record::CoreWalRecord::Record {
                    sequence: 2, batch, ..
                } = record
                {
                    let mut changed = crate::transactions::WriteBatch::new();
                    for op in batch.ops() {
                        let mut op = op.clone();
                        if let crate::transactions::BatchOp::Put { cf, value, .. } = &mut op
                            && cf.0 == Role::Payload.cf()
                        {
                            *value = Row::Payload(b"x").encode().unwrap();
                        }
                        changed.push_op(op);
                    }
                    *batch = changed;
                }
            }
            let mut bytes = wal[..16].to_vec();
            for record in records {
                bytes.extend(record.try_encode().unwrap());
            }
            std::fs::write(&wal_path, bytes).unwrap();
        }
        6 => {
            // A legitimate compacted dead RID need not retain old payload/state
            // versions. Available old WAL still validates without current liveness.
            for block in &mut raw.blocks {
                let old = block.len();
                block.retain(|row| {
                    !(row.entry.version.sequence == 2
                        && matches!(
                            Role::from_cf(&row.entry.cf.0),
                            Some(Role::State | Role::Payload)
                        ))
                });
                manifest.segments[0].entries -= (old - block.len()) as u64;
            }
            let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
            std::fs::write(path, &bytes).unwrap();
            manifest.segments[0].file_digest = blake3::hash(&bytes).to_hex().to_string();
            std::fs::write(&wal_path, &wal).unwrap();
        }
        7..=9 => {
            // The latest dead state/counters remain valid. Only one older
            // installed version contradicts the complete retained WAL commit.
            let role = match mutation {
                7 => Role::State,
                8 => Role::Payload,
                _ => Role::Meta,
            };
            let sequence = if mutation == 8 { 3 } else { 2 };
            let row = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| {
                    row.entry.cf.0 == role.cf()
                        && row.entry.version.sequence == sequence
                        && (role != Role::Meta || row.entry.key.as_ref() == [1])
                })
                .unwrap();
            row.entry.version.value = StoredValue::Put(match mutation {
                7 => Row::State {
                    live: false,
                    payload_length: 0,
                }
                .encode()
                .unwrap(),
                8 => Row::Payload(b"v").encode().unwrap(),
                _ => {
                    let StoredValue::Put(bytes) = &row.entry.version.value else {
                        panic!()
                    };
                    let Row::Allocator(mut allocator) =
                        Row::decode(&Key::Allocator, bytes, path).unwrap()
                    else {
                        panic!()
                    };
                    allocator.live_payload_bytes = 2;
                    Row::Allocator(allocator).encode().unwrap()
                }
            });
            let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
            std::fs::write(path, &bytes).unwrap();
            manifest.segments[0].file_digest = blake3::hash(&bytes).to_hex().to_string();
            std::fs::write(&wal_path, &wal).unwrap();
        }
        10 | 12 => {
            let (mut records, _) =
                crate::wal::writer::replay_core_records(&wal, &wal_path).unwrap();
            for record in &mut records {
                if let crate::wal::record::CoreWalRecord::Record {
                    sequence: 3, batch, ..
                } = record
                {
                    let mut changed = crate::transactions::WriteBatch::new();
                    for op in batch.ops() {
                        let mut op = op.clone();
                        match &mut op {
                            crate::transactions::BatchOp::Put { cf, key, .. }
                                if cf.0 == Role::State.cf() =>
                            {
                                *key = Key::State(1).encode().unwrap();
                            }
                            crate::transactions::BatchOp::Delete { cf, key }
                                if cf.0 == Role::Payload.cf() =>
                            {
                                *key = Key::Payload(1).encode().unwrap();
                            }
                            _ => {}
                        }
                        changed.push_op(op);
                    }
                    *batch = changed;
                }
            }
            let mut bytes = wal[..16].to_vec();
            for record in records {
                bytes.extend(record.try_encode().unwrap());
            }
            std::fs::write(&wal_path, bytes).unwrap();
        }
        11 => {
            // Both latest primary rows remain dead at S5. The segment's state
            // chain alone looks like live2/live4/dead5, while the real old WAL
            // and payload tombstone prove permanent death at S3.
            let row = raw
                .blocks
                .iter_mut()
                .flatten()
                .find(|row| row.entry.cf.0 == Role::State.cf() && row.entry.version.sequence == 3)
                .unwrap();
            row.entry.version.sequence = 4;
            row.entry.version.value = StoredValue::Put(
                Row::State {
                    live: true,
                    payload_length: 1,
                }
                .encode()
                .unwrap(),
            );
            let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
            std::fs::write(path, &bytes).unwrap();
            manifest.segments[0].file_digest = blake3::hash(&bytes).to_hex().to_string();
            std::fs::write(&wal_path, &wal).unwrap();
        }
        _ => unreachable!(),
    }
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    if (4..=6).contains(&mutation) {
        drop(
            CoreDatabase::open(config)
                .expect("equivalent primary copies and absent compacted history remain supported"),
        );
    } else {
        assert!(
            CoreDatabase::open(config).is_err(),
            "contradictory available primary evidence must be refused"
        );
    }
    assert_eq!(tree(dir.path()), before);
    let target = tempfile::tempdir().unwrap();
    let existing = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    existing.put("keep", "value").unwrap();
    drop(existing);
    let target_before = tree(target.path());
    let restored = PraxisEngine::restore_from_backup(dir.path(), target.path());
    if (4..=6).contains(&mutation) {
        restored.unwrap();
        CoreDatabase::open(PraxisConfig::new(target.path())).unwrap();
    } else {
        assert!(restored.is_err());
        assert_eq!(tree(target.path()), target_before);
    }
    assert_eq!(tree(dir.path()), before);
}
#[test]
fn final_review_old_live_state_length_matches_retained_payload() {
    cross_evidence(0);
}
#[test]
fn final_review_same_sequence_state_source_groups_cannot_conflict() {
    cross_evidence(1);
}
#[test]
fn final_review_same_sequence_payload_source_groups_cannot_conflict() {
    cross_evidence(2);
}
#[test]
fn final_review_old_wal_payload_matches_retained_segment_payload() {
    cross_evidence(3);
}
#[test]
fn final_review_mapping_put_must_follow_its_rid_allocation() {
    malformed_segment(14);
}
#[test]
fn final_review_equivalent_same_sequence_state_source_groups_are_valid() {
    cross_evidence(4);
}
#[test]
fn final_review_equivalent_same_sequence_payload_source_groups_are_valid() {
    cross_evidence(5);
}
#[test]
fn final_review_old_payload_need_not_survive_compaction_for_a_dead_rid() {
    cross_evidence(6);
}

#[test]
fn final_review_same_commit_wal_and_segment_state_must_agree() {
    cross_evidence(7);
}

#[test]
fn final_review_same_commit_wal_and_segment_payload_tombstone_must_agree() {
    cross_evidence(8);
}

#[test]
fn final_review_same_commit_wal_and_segment_allocator_must_agree() {
    cross_evidence(9);
}

#[test]
fn final_review_available_old_death_cannot_leave_current_rid_live() {
    cross_evidence(10);
}

#[test]
fn final_review_live_primary_evidence_must_precede_any_available_death() {
    cross_evidence(11);
}

#[test]
fn final_review_suffix_delete_cannot_mask_corrupt_installed_liveness() {
    cross_evidence(12);
}

fn causal_evidence(mutation: u8) {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "causal".into(),
            }],
        },
    )
    .unwrap();
    let engine = db.kv();
    let create = |count| {
        RecordIntent::new(IntentKind::Create(
            (0..count)
                .map(|_| NewRecord {
                    payload: b"v".to_vec(),
                    mappings: if mutation >= 4 {
                        vec![Mapping {
                            index: 1,
                            key: b"created".to_vec(),
                        }]
                    } else {
                        vec![]
                    },
                })
                .collect(),
        ))
        .unwrap()
    };
    let index_put = |rid| {
        RecordIntent::new(IntentKind::IndexPut(
            Mapping {
                index: 1,
                key: b"k".to_vec(),
            },
            crate::store::RecordId(rid),
        ))
        .unwrap()
    };
    engine
        .commit_record(create(if mutation == 0 { 2 } else { 1 }))
        .unwrap();
    match mutation {
        0 => {
            engine
                .commit_record(
                    RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                        .unwrap(),
                )
                .unwrap();
            engine.commit_record(index_put(2)).unwrap();
        }
        1 => {
            engine.put("ordinary", "marker").unwrap();
        }
        2 => {
            engine
                .commit_record(
                    RecordIntent::new(IntentKind::IndexDelete(Mapping {
                        index: 1,
                        key: b"gap".to_vec(),
                    }))
                    .unwrap(),
                )
                .unwrap();
            engine.commit_record(index_put(1)).unwrap();
            engine.commit_record(create(1)).unwrap();
        }
        3 => {
            engine.commit_record(create(1)).unwrap();
        }
        4 | 5 => {
            engine.commit_record(index_put(1)).unwrap();
            engine
                .commit_record(
                    RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(1)]))
                        .unwrap(),
                )
                .unwrap();
        }
        _ => unreachable!(),
    }
    let wal_path = engine.inner.wal.lock().path().to_path_buf();
    let wal = std::fs::read(&wal_path).unwrap();
    engine.flush().unwrap();
    drop(engine);
    drop(db);
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    let remap = |key: &Key<'_>, bytes: &[u8]| match Row::decode(key, bytes, path).unwrap() {
        Row::Fact {
            append_ordinal,
            decision: Decision::Put(_),
        } => Some(
            Row::Fact {
                append_ordinal,
                decision: Decision::Put(if mutation == 0 { 1 } else { 2 }),
            }
            .encode()
            .unwrap(),
        ),
        Row::Head {
            raw_sequence,
            append_ordinal,
            decision: Decision::Put(_),
        } => Some(
            Row::Head {
                raw_sequence,
                append_ordinal,
                decision: Decision::Put(if mutation == 0 { 1 } else { 2 }),
            }
            .encode()
            .unwrap(),
        ),
        _ => None,
    };
    if mutation == 1 {
        let mut copies = Vec::new();
        for row in raw.blocks.iter().flatten() {
            if matches!(
                Role::from_cf(&row.entry.cf.0),
                Some(Role::State | Role::Payload)
            ) {
                let mut copy = crate::segments::codec::RawEntry {
                    entry: row.entry.clone(),
                    blob_expiry: row.blob_expiry,
                };
                copy.entry.version.sequence = 3;
                copies.push(copy);
            }
        }
        metadata.entries += copies.len() as u64;
        raw.blocks[0].extend(copies);
    } else if mutation == 3 {
        // Births of two actual RIDs are swapped without changing current
        // payloads/counters or either RID's internally consistent birth.
        for row in raw.blocks.iter_mut().flatten() {
            if matches!(
                Role::from_cf(&row.entry.cf.0),
                Some(Role::State | Role::Payload)
            ) {
                row.entry.version.sequence = if row.entry.version.sequence == 2 {
                    3
                } else {
                    2
                };
            }
        }
    } else if mutation == 5 {
        for block in &mut raw.blocks {
            let old = block.len();
            block.retain(|row| {
                !(row.entry.version.sequence == 2
                    && matches!(
                        Role::from_cf(&row.entry.cf.0),
                        Some(Role::State | Role::Payload)
                    ))
            });
            metadata.entries -= (old - block.len()) as u64;
        }
    } else if mutation <= 2 {
        for row in raw.blocks.iter_mut().flatten() {
            if row.entry.cf.0 == Role::Index.cf()
                && let StoredValue::Put(bytes) = &mut row.entry.version.value
                && let Some(changed) = remap(
                    &Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                    bytes,
                )
            {
                *bytes = changed;
            }
        }
    }
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    if mutation == 4 {
        std::fs::write(&wal_path, &wal).unwrap();
    } else if mutation == 0 {
        let (mut records, _) = crate::wal::writer::replay_core_records(&wal, &wal_path).unwrap();
        for record in &mut records {
            if let crate::wal::record::CoreWalRecord::Record {
                sequence: 4, batch, ..
            } = record
            {
                let mut changed = crate::transactions::WriteBatch::new();
                for op in batch.ops() {
                    let mut op = op.clone();
                    if let crate::transactions::BatchOp::Put { cf, key, value } = &mut op
                        && cf.0 == Role::Index.cf()
                        && let Some(bytes) =
                            remap(&Key::decode(Role::Index, key, path).unwrap(), value)
                    {
                        *value = bytes;
                    }
                    changed.push_op(op);
                }
                *batch = changed;
            }
        }
        let mut bytes = wal[..16].to_vec();
        for record in records {
            bytes.extend(record.try_encode().unwrap());
        }
        std::fs::write(&wal_path, bytes).unwrap();
    }
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    if mutation >= 4 {
        drop(
            CoreDatabase::open(config).expect(
                "same-S create mappings, old live mapping and missing birth remain supported",
            ),
        );
    } else {
        assert!(
            CoreDatabase::open(config).is_err(),
            "available fresh causal evidence must agree"
        );
    }
    assert_eq!(tree(dir.path()), before);
    let target = tempfile::tempdir().unwrap();
    let existing = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    existing.put("keep", "value").unwrap();
    drop(existing);
    let target_before = tree(target.path());
    let restored = PraxisEngine::restore_from_backup(dir.path(), target.path());
    if mutation >= 4 {
        restored.unwrap();
        CoreDatabase::open(PraxisConfig::new(target.path())).unwrap();
    } else {
        assert!(restored.is_err());
        assert_eq!(tree(target.path()), target_before);
    }
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn final_review_fact_put_cannot_follow_available_rid_death() {
    causal_evidence(0);
}

#[test]
fn final_review_all_primary_live_copies_share_one_fresh_birth() {
    causal_evidence(1);
}

#[test]
fn final_review_fact_put_cannot_precede_available_rid_birth() {
    causal_evidence(2);
}

#[test]
fn final_review_known_births_follow_actual_rid_allocation_order() {
    causal_evidence(3);
}

#[test]
fn final_review_same_birth_mapping_and_old_put_before_death_remain_valid() {
    causal_evidence(4);
}

#[test]
fn final_review_mapping_fact_does_not_require_pruned_birth_evidence() {
    causal_evidence(5);
}

fn retained_head_evidence(mutation: u8) {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "heads".into(),
            }],
        },
    )
    .unwrap();
    let mapping = Mapping {
        index: 1,
        key: b"k".to_vec(),
    };
    db.kv()
        .commit_record(
            RecordIntent::new(IntentKind::Create(vec![NewRecord {
                payload: b"v".to_vec(),
                mappings: vec![mapping.clone()],
            }]))
            .unwrap(),
        )
        .unwrap();
    db.kv().put("ordinary", "marker").unwrap();
    db.kv()
        .commit_record(
            RecordIntent::new(IntentKind::IndexPut(mapping, crate::store::RecordId(1))).unwrap(),
        )
        .unwrap();
    let wal_path = db.kv().inner.wal.lock().path().to_path_buf();
    let wal = std::fs::read(&wal_path).unwrap();
    db.kv().flush().unwrap();
    drop(db);
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    let row = raw
        .blocks
        .iter_mut()
        .flatten()
        .find(|row| {
            row.entry.cf.0 == Role::Index.cf()
                && row.entry.version.sequence == 2
                && matches!(
                    Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                    Key::Head { .. }
                )
        })
        .unwrap();
    if mutation != 0 {
        row.entry.version.sequence = 3;
    } else {
        row.entry.version.value = StoredValue::Put(
            Row::Head {
                raw_sequence: 2,
                append_ordinal: 2,
                decision: Decision::Delete,
            }
            .encode()
            .unwrap(),
        );
    }
    if mutation == 2 {
        for row in raw.blocks.iter_mut().flatten() {
            if row.entry.cf.0 == Role::Index.cf() && row.entry.version.sequence == 2 {
                row.entry.version.sequence = 3;
            }
        }
        std::fs::write(&wal_path, wal).unwrap();
    }
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    assert!(
        CoreDatabase::open(config).is_err(),
        "every available Head must match its immutable Fact at the same core sequence"
    );
    assert_eq!(tree(dir.path()), before);
    let target = tempfile::tempdir().unwrap();
    let existing = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    existing.put("keep", "value").unwrap();
    drop(existing);
    let target_before = tree(target.path());
    assert!(PraxisEngine::restore_from_backup(dir.path(), target.path()).is_err());
    assert_eq!(tree(target.path()), target_before);
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn final_review_retained_head_decision_matches_its_immutable_fact() {
    retained_head_evidence(0);
}

#[test]
fn final_review_retained_head_core_sequence_matches_its_immutable_fact() {
    retained_head_evidence(1);
}

#[test]
fn final_review_immutable_fact_core_sequence_agrees_across_wal_and_segments() {
    retained_head_evidence(2);
}

fn cutoff_evidence(mutation: u8) {
    let dir = tempfile::tempdir().unwrap();
    let config = PraxisConfig::new(dir.path());
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "cutoffs".into(),
            }],
        },
    )
    .unwrap();
    let engine = db.kv();
    let create = |count| {
        RecordIntent::new(IntentKind::Create(
            (0..count)
                .map(|_| NewRecord {
                    payload: b"v".to_vec(),
                    mappings: vec![],
                })
                .collect(),
        ))
        .unwrap()
    };
    let index_delete = |key: &[u8]| {
        RecordIntent::new(IntentKind::IndexDelete(Mapping {
            index: 1,
            key: key.to_vec(),
        }))
        .unwrap()
    };
    let index_put = || {
        RecordIntent::new(IntentKind::IndexPut(
            Mapping {
                index: 1,
                key: b"k".to_vec(),
            },
            crate::store::RecordId(1),
        ))
        .unwrap()
    };
    let delete = |rid| {
        RecordIntent::new(IntentKind::DeleteRecords(vec![crate::store::RecordId(rid)])).unwrap()
    };
    engine
        .commit_record(create(if mutation >= 4 { 2 } else { 1 }))
        .unwrap();
    match mutation {
        0 => {
            engine.commit_record(index_delete(b"gap")).unwrap();
            engine.commit_record(create(1)).unwrap();
        }
        1 => {
            engine.commit_record(create(1)).unwrap();
            engine.commit_record(index_delete(b"gap")).unwrap();
        }
        2 => {
            engine.commit_record(index_delete(b"gap")).unwrap();
            engine.commit_record(index_put()).unwrap();
            engine.commit_record(index_delete(b"end")).unwrap();
        }
        3 => {
            engine.commit_record(index_put()).unwrap();
            engine.commit_record(index_delete(b"gap")).unwrap();
        }
        4 => {
            engine.commit_record(delete(1)).unwrap();
            engine.commit_record(index_delete(b"gap")).unwrap();
            engine.commit_record(delete(2)).unwrap();
        }
        5 => {
            engine.commit_record(delete(2)).unwrap();
            engine.commit_record(index_delete(b"gap")).unwrap();
            engine.commit_record(delete(1)).unwrap();
        }
        6 | 7 => {
            for (key, rid) in [(b"a", 1), (b"b", 2)] {
                engine
                    .commit_record(
                        RecordIntent::new(IntentKind::IndexPut(
                            Mapping {
                                index: 1,
                                key: key.to_vec(),
                            },
                            crate::store::RecordId(rid),
                        ))
                        .unwrap(),
                    )
                    .unwrap();
            }
            engine.commit_record(delete(1)).unwrap();
        }
        _ => unreachable!(),
    }
    let wal_path = engine.inner.wal.lock().path().to_path_buf();
    let wal = std::fs::read(&wal_path).unwrap();
    engine.flush().unwrap();
    drop(engine);
    drop(db);
    // Prove the genuine post-flush baseline with no retained complete frames.
    drop(CoreDatabase::open(config.clone()).unwrap());
    let wal_files = std::fs::read_dir(dir.path().join("wal"))
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(wal_files.len(), 1);
    assert_eq!(std::fs::metadata(wal_files[0].path()).unwrap().len(), 16);
    if mutation == 4 {
        // Complete old prefix through DeleteS3 is available, but later old
        // frames were retired. This valid gap must not imply lost authority.
        let (records, _) = crate::wal::writer::replay_core_records(&wal, &wal_path).unwrap();
        let mut prefix = wal[..16].to_vec();
        for record in records.into_iter().filter(|record| record.sequence() <= 3) {
            prefix.extend(record.try_encode().unwrap());
        }
        std::fs::write(&wal_path, prefix).unwrap();
        drop(CoreDatabase::open(config.clone()).unwrap());
    }
    let manifest_path = dir.path().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&std::fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let metadata = &mut manifest.segments[0];
    let path = Path::new(&metadata.path);
    let mut raw = crate::segments::codec::decode_segment(
        &std::fs::read(path).unwrap(),
        path,
        &crate::accel::CpuAccelerator,
    )
    .unwrap();
    for block in &mut raw.blocks {
        if mutation >= 4 {
            let old = block.len();
            block.retain(|row| {
                let sequence = row.entry.version.sequence;
                let allocator = row.entry.cf.0 == Role::Meta.cf() && row.entry.key.as_ref() == [1];
                let removed_allocator = allocator
                    && match mutation {
                        4 => sequence == 3,
                        5 => sequence == 2 || sequence == 3,
                        _ => sequence == 3 || sequence == 4,
                    };
                let pruned_birth = mutation == 5
                    && sequence == 2
                    && matches!(
                        Role::from_cf(&row.entry.cf.0).and_then(|role| Key::decode(
                            role,
                            &row.entry.key,
                            path
                        )
                        .ok()),
                        Some(Key::State(2) | Key::Payload(2))
                    );
                !(removed_allocator || pruned_birth)
            });
            metadata.entries -= (old - block.len()) as u64;
        }
        for row in block {
            if mutation <= 1 || mutation == 4 || mutation == 5 {
                let sequence = if mutation >= 4 { 4 } else { 3 };
                if row.entry.cf.0 == Role::Meta.cf()
                    && row.entry.key.as_ref() == [1]
                    && row.entry.version.sequence == sequence
                {
                    let StoredValue::Put(bytes) = &mut row.entry.version.value else {
                        panic!()
                    };
                    let Row::Allocator(mut allocator) =
                        Row::decode(&Key::Allocator, bytes, path).unwrap()
                    else {
                        panic!()
                    };
                    allocator.last_rid = if mutation == 1 || mutation == 5 { 1 } else { 2 };
                    allocator.dead_count = if mutation == 5 { 1 } else { 0 };
                    allocator.live_count = allocator.last_rid - allocator.dead_count;
                    allocator.live_payload_bytes = allocator.live_count;
                    *bytes = Row::Allocator(allocator).encode().unwrap();
                }
            } else if mutation == 6 && row.entry.cf.0 == Role::Index.cf() {
                let key = Key::decode(Role::Index, &row.entry.key, path).unwrap();
                let StoredValue::Put(bytes) = &mut row.entry.version.value else {
                    panic!()
                };
                let swapped = |raw| if raw == 3 { 4 } else { 3 };
                match (
                    key,
                    Row::decode(
                        &Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                        bytes,
                        path,
                    )
                    .unwrap(),
                ) {
                    (
                        Key::Fact {
                            index,
                            incarnation,
                            key,
                            raw_sequence,
                        },
                        Row::Fact {
                            append_ordinal,
                            decision,
                        },
                    ) => {
                        let encoded = Key::Fact {
                            index,
                            incarnation,
                            key,
                            raw_sequence: swapped(raw_sequence),
                        }
                        .encode()
                        .unwrap();
                        *bytes = Row::Fact {
                            append_ordinal: swapped(append_ordinal),
                            decision,
                        }
                        .encode()
                        .unwrap();
                        row.entry.key = encoded.into();
                    }
                    (
                        Key::Head { .. },
                        Row::Head {
                            raw_sequence,
                            append_ordinal,
                            decision,
                        },
                    ) => {
                        *bytes = Row::Head {
                            raw_sequence: swapped(raw_sequence),
                            append_ordinal: swapped(append_ordinal),
                            decision,
                        }
                        .encode()
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
            } else if row.entry.cf.0 == Role::Index.cf()
                && matches!(
                    Key::decode(Role::Index, &row.entry.key, path).unwrap(),
                    Key::Fact { key: b"k", .. } | Key::Head { key: b"k", .. }
                )
            {
                row.entry.version.sequence = if mutation == 2 { 3 } else { 4 };
            }
        }
    }
    let bytes = raw.encode(&crate::accel::CpuAccelerator).unwrap();
    std::fs::write(path, &bytes).unwrap();
    metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = tree(dir.path());
    if mutation == 7 {
        drop(CoreDatabase::open(config).expect("missing intermediate cuts remain supported"));
    } else {
        assert!(
            CoreDatabase::open(config).is_err(),
            "available counter cutoffs must agree with actual event positions"
        );
    }
    assert_eq!(tree(dir.path()), before);
    let target = tempfile::tempdir().unwrap();
    let existing = PraxisEngine::open(PraxisConfig::new(target.path())).unwrap();
    existing.put("keep", "value").unwrap();
    drop(existing);
    let target_before = tree(target.path());
    let restored = PraxisEngine::restore_from_backup(dir.path(), target.path());
    if mutation == 7 {
        restored.unwrap();
        CoreDatabase::open(PraxisConfig::new(target.path())).unwrap();
    } else {
        assert!(restored.is_err());
        assert_eq!(tree(target.path()), target_before);
    }
    assert_eq!(tree(dir.path()), before);
}

#[test]
fn final_review_cutoff_allocator_cannot_allocate_a_known_future_birth() {
    cutoff_evidence(0);
}
#[test]
fn final_review_cutoff_allocator_covers_known_earlier_birth() {
    cutoff_evidence(1);
}
#[test]
fn final_review_cutoff_allocator_covers_known_earlier_fact_raw() {
    cutoff_evidence(2);
}
#[test]
fn final_review_cutoff_allocator_cannot_cover_known_future_fact_raw() {
    cutoff_evidence(3);
}
#[test]
fn final_review_cutoff_allocator_dead_count_cannot_decrease_across_sources() {
    cutoff_evidence(4);
}

#[test]
fn final_review_cutoff_covers_actual_death_even_with_pruned_birth() {
    cutoff_evidence(5);
}

#[test]
fn final_review_cutoff_fact_intervals_order_when_inbetween_cuts_are_pruned() {
    cutoff_evidence(6);
}

#[test]
fn final_review_cutoff_pruned_intermediate_cuts_remain_valid() {
    cutoff_evidence(7);
}
