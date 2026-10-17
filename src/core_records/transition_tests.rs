use super::codec::*;
use super::intent::*;
use super::transition::*;
use crate::store::RecordId;
use std::path::Path;

fn context() -> Context<'static> {
    Context {
        id: [7; 16],
        descriptors: 1,
        source: Path::new("model"),
    }
}
fn initial() -> Rows {
    [
        (
            Role::Meta,
            Key::Binding,
            Row::Binding {
                database_id: [7; 16],
                descriptor_count: 1,
            },
        ),
        (
            Role::Meta,
            Key::Allocator,
            Row::Allocator(Allocator::default()),
        ),
        (
            Role::Meta,
            Key::Descriptor(1),
            Row::Descriptor {
                name: "kv",
                namespace: "model",
            },
        ),
    ]
    .into_iter()
    .map(|(role, key, row)| {
        let key = key.encode().unwrap();
        let value =
            Summary::decode(role, &key, &row.encode().unwrap(), Path::new("model")).unwrap();
        ((role, key), Some(value))
    })
    .collect()
}
fn mapping() -> Mapping {
    Mapping {
        index: 1,
        key: b"k".to_vec(),
    }
}
fn intent(kind: IntentKind) -> RecordIntent {
    RecordIntent::new(kind).unwrap()
}
fn create(bytes: &[u8], mappings: usize) -> IntentKind {
    IntentKind::Create(vec![NewRecord {
        payload: bytes.into(),
        mappings: vec![mapping(); mappings],
    }])
}
fn plan_on(rows: &Rows, kind: IntentKind, sequence: u64) -> crate::Result<PlannedRecord> {
    plan(&intent(kind), sequence, &context(), &mut |role, key| {
        Ok(rows.get(&(role, key.to_vec())).cloned().flatten())
    })
}
fn counters(rows: &Rows) -> Allocator {
    validate_installed(rows, &context()).unwrap()
}

/// Independent logical tables, not codec/parser-derived expected counters.
#[derive(Clone, Default)]
struct Model {
    records: Vec<Option<Vec<u8>>>,
    raw: u64,
    mappings: Vec<(u64, Option<u64>)>,
}
impl Model {
    fn apply(&mut self, kind: &IntentKind) -> bool {
        let known = |rid: RecordId| rid.0 > 0 && rid.0 <= self.records.len() as u64;
        match kind {
            IntentKind::Create(records) => {
                if records
                    .iter()
                    .flat_map(|r| &r.mappings)
                    .any(|m| m.index != 1)
                {
                    return false;
                }
                for record in records {
                    self.records.push(Some(record.payload.clone()));
                    self.raw += 1;
                    let rid = self.records.len() as u64;
                    for _ in &record.mappings {
                        self.raw += 1;
                        self.mappings.push((self.raw, Some(rid)));
                    }
                }
            }
            IntentKind::DeleteRecords(ids) => {
                if !ids.iter().copied().all(known) {
                    return false;
                }
                for rid in ids {
                    self.records[rid.0 as usize - 1] = None;
                    self.raw += 1;
                }
            }
            IntentKind::IndexPut(m, rid) => {
                if m.index != 1 || !known(*rid) || self.records[rid.0 as usize - 1].is_none() {
                    return false;
                }
                self.raw += 1;
                self.mappings.push((self.raw, Some(rid.0)));
            }
            IntentKind::IndexDelete(m) => {
                if m.index != 1 {
                    return false;
                }
                self.raw += 1;
                self.mappings.push((self.raw, None));
            }
            IntentKind::Cleanup(rid, keys) => {
                if !known(*rid) || keys.iter().any(|m| m.index != 1) {
                    return false;
                }
                for _ in keys {
                    self.raw += 1;
                    self.mappings.push((self.raw, None));
                }
                self.raw += 1;
                self.records[rid.0 as usize - 1] = None;
            }
            IntentKind::DeleteByIndex(m) => {
                if m.index != 1 {
                    return false;
                }
                let rid = self.mappings.last().and_then(|(_, rid)| *rid);
                self.raw += 1;
                self.mappings.push((self.raw, None));
                if let Some(rid) = rid {
                    self.raw += 1;
                    self.records[rid as usize - 1] = None;
                }
            }
        }
        true
    }
    fn check(&self, rows: &Rows) {
        let value = counters(rows);
        let live = self.records.iter().filter(|v| v.is_some()).count() as u64;
        assert_eq!(
            value,
            Allocator {
                last_rid: self.records.len() as u64,
                compatibility_sequence: self.raw,
                append_ordinal: self.raw,
                live_count: live,
                dead_count: self.records.len() as u64 - live,
                live_payload_bytes: self.records.iter().flatten().map(|v| v.len() as u64).sum()
            }
        );
        for (index, expected) in self.records.iter().enumerate() {
            let key = (
                Role::Payload,
                Key::Payload(index as u64 + 1).encode().unwrap(),
            );
            assert_eq!(
                rows.get(&key).and_then(Option::as_ref),
                expected
                    .as_ref()
                    .map(|v| Summary::Payload {
                        len: v.len() as u64,
                        digest: *blake3::hash(v).as_bytes()
                    })
                    .as_ref()
            );
        }
        let mut actual = Vec::new();
        for ((role, key), value) in rows {
            if *role != Role::Index {
                continue;
            }
            if let Key::Fact { raw_sequence, .. } =
                Key::decode(*role, key, context().source).unwrap()
            {
                let Row::Fact {
                    append_ordinal,
                    decision,
                } = Row::decode(
                    &Key::decode(*role, key, context().source).unwrap(),
                    value.as_ref().unwrap().bytes(context().source).unwrap(),
                    context().source,
                )
                .unwrap()
                else {
                    panic!()
                };
                assert_eq!(append_ordinal, raw_sequence);
                actual.push((
                    raw_sequence,
                    match decision {
                        Decision::Put(rid) => Some(rid),
                        Decision::Delete => None,
                    },
                ));
            }
        }
        assert_eq!(actual, self.mappings);
    }
}

#[test]
fn exhaustive_short_logical_traces_match_independent_tables() {
    let choices = [
        create(b"a", 2),
        create(b"bc", 0),
        IntentKind::DeleteRecords(vec![RecordId(1), RecordId(1)]),
        IntentKind::DeleteRecords(vec![RecordId(1), RecordId(99)]),
        IntentKind::IndexPut(mapping(), RecordId(1)),
        IntentKind::IndexDelete(mapping()),
        IntentKind::Cleanup(RecordId(1), vec![mapping(), mapping()]),
        IntentKind::DeleteByIndex(mapping()),
    ];
    for trace in 0..choices.len().pow(4) {
        let mut rows = initial();
        let mut model = Model::default();
        let mut sequence = 1;
        let mut code = trace;
        for _ in 0..4 {
            let kind = choices[code % choices.len()].clone();
            code /= choices.len();
            let before = rows.clone();
            let mut next_model = model.clone();
            let accepted = next_model.apply(&kind);
            match plan_on(&rows, kind, sequence + 1) {
                Ok(planned) => {
                    assert!(accepted);
                    rows.extend(planned.updates);
                    model = next_model;
                    sequence += 1;
                }
                Err(_) => {
                    assert!(!accepted);
                    assert_eq!(rows, before);
                }
            }
            model.check(&rows);
        }
    }
}

#[test]
fn old_frame_validation_uses_its_own_rid_range_not_latest_liveness() {
    let mut rows = initial();
    let created = plan_on(&rows, create(b"a", 2), 2).unwrap();
    rows.extend(created.updates);
    let deleted = plan_on(&rows, IntentKind::DeleteRecords(vec![RecordId(1)]), 3).unwrap();
    rows.extend(deleted.updates);
    let crate::wal::record::CoreWalRecord::Record {
        sequence,
        envelope,
        batch,
    } = created.record
    else {
        panic!()
    };
    validate(sequence, &envelope, &batch, &context(), None).unwrap();
    assert!(
        validate(
            sequence,
            &envelope,
            &batch,
            &context(),
            Some(&mut |role, key| Ok(rows.get(&(role, key.to_vec())).cloned().flatten()))
        )
        .is_err()
    );
}

#[test]
fn huge_allocator_and_envelope_claims_are_bounded_by_actual_rows_and_ops() {
    let mut rows = initial();
    let huge = Allocator {
        last_rid: u64::MAX,
        live_count: 0,
        dead_count: u64::MAX,
        ..Allocator::default()
    };
    rows.insert(
        (Role::Meta, vec![1]),
        Some(Summary::Bytes(Row::Allocator(huge).encode().unwrap())),
    );
    assert!(validate_installed(&rows, &context()).is_err());
    assert!(plan_on(&rows, create(b"x", 0), 2).is_err());
    let planned = plan_on(&initial(), create(b"x", 0), 2).unwrap();
    let crate::wal::record::CoreWalRecord::Record {
        sequence,
        mut envelope,
        batch,
    } = planned.record
    else {
        panic!()
    };
    envelope.record_count = u32::MAX;
    envelope.logical_entry_count = u32::MAX;
    envelope.new_rid = u32::MAX as u64;
    envelope.new_compatibility_sequence = u32::MAX as u64;
    envelope.new_append_ordinal = u32::MAX as u64;
    assert!(validate(sequence, &envelope, &batch, &context(), None).is_err());
}

#[test]
fn exhausted_and_invalid_intents_leave_the_touched_state_unchanged() {
    let mut rows = initial();
    rows.insert(
        (Role::Meta, vec![1]),
        Some(Summary::Bytes(
            Row::Allocator(Allocator {
                compatibility_sequence: u64::MAX,
                append_ordinal: u64::MAX,
                ..Allocator::default()
            })
            .encode()
            .unwrap(),
        )),
    );
    let before = rows.clone();
    assert!(plan_on(&rows, create(b"x", 0), 2).is_err());
    assert_eq!(rows, before);
    assert!(matches!(
        plan_on(
            &initial(),
            IntentKind::DeleteRecords(vec![RecordId::NULL]),
            2
        ),
        Err(crate::PraxisError::KeyNotFound)
    ));
}

#[test]
fn ratified_legacy_trace_has_exact_34_logical_entries_without_physical_relocation() {
    let context = Context {
        id: [7; 16],
        descriptors: 2,
        source: Path::new("legacy-contract"),
    };
    let mut rows = Rows::new();
    for (key, row) in [
        (
            Key::Binding,
            Row::Binding {
                database_id: [7; 16],
                descriptor_count: 2,
            },
        ),
        (Key::Allocator, Row::Allocator(Allocator::default())),
        (
            Key::Descriptor(1),
            Row::Descriptor {
                name: "aux",
                namespace: "model",
            },
        ),
        (
            Key::Descriptor(2),
            Row::Descriptor {
                name: "kv",
                namespace: "model",
            },
        ),
    ] {
        rows.insert(
            (Role::Meta, key.encode().unwrap()),
            Some(Summary::Bytes(row.encode().unwrap())),
        );
    }
    let mapping = |index, key: &str| Mapping {
        index,
        key: key.as_bytes().to_vec(),
    };
    let record = |payload: &[u8], mappings| NewRecord {
        payload: payload.to_vec(),
        mappings,
    };
    let steps = vec![
        (
            IntentKind::Create(vec![
                record(
                    b"one",
                    vec![mapping(2, "same"), mapping(2, "same"), mapping(1, "left")],
                ),
                record(
                    b"two",
                    vec![mapping(2, "same"), mapping(2, "other"), mapping(1, "same")],
                ),
            ]),
            8,
        ),
        (
            IntentKind::Create(vec![record(
                b"three",
                vec![mapping(2, "third"), mapping(1, "right")],
            )]),
            11,
        ),
        (IntentKind::DeleteRecords(vec![RecordId(2)]), 12),
        (IntentKind::DeleteRecords(vec![RecordId(2)]), 13),
        (
            IntentKind::DeleteRecords(vec![RecordId(2), RecordId(2)]),
            15,
        ),
        (
            IntentKind::Cleanup(
                RecordId(1),
                vec![mapping(1, "left"), mapping(2, "third"), mapping(1, "left")],
            ),
            19,
        ),
        (IntentKind::DeleteByIndex(mapping(2, "absent")), 20),
        (IntentKind::DeleteByIndex(mapping(2, "same")), 22),
        (IntentKind::DeleteByIndex(mapping(1, "right")), 24),
        (
            IntentKind::Create(vec![record(b"four", vec![mapping(2, "keep")])]),
            26,
        ),
        (IntentKind::IndexPut(mapping(2, "only"), RecordId(4)), 27),
        (IntentKind::IndexDelete(mapping(2, "only")), 28),
        (IntentKind::IndexDelete(mapping(2, "missing")), 29),
        // No fabricated primary relocation event between29 and30.
        (
            IntentKind::Create(vec![record(b"fives", vec![mapping(2, "after")])]),
            31,
        ),
        (IntentKind::DeleteRecords(vec![RecordId(1)]), 32),
        (
            IntentKind::DeleteRecords(vec![RecordId(1), RecordId(1)]),
            34,
        ),
    ];
    let mut events = Vec::new();
    for (index, (kind, raw)) in steps.into_iter().enumerate() {
        let planned = plan(
            &intent(kind),
            index as u64 + 2,
            &context,
            &mut |role, key| Ok(rows.get(&(role, key.to_vec())).cloned().flatten()),
        )
        .unwrap();
        assert_eq!(planned.receipt.compatibility_sequence, raw);
        if raw == 22 {
            assert_eq!(
                planned.receipt.result,
                RecordResult::DeletedByIndex(Some(RecordId(2)))
            );
        }
        for op in planned.record.batch().ops() {
            let crate::transactions::BatchOp::Put { cf, key, value } = op else {
                continue;
            };
            let role = Role::from_cf(&cf.0).unwrap();
            let key = Key::decode(role, key, context.source).unwrap();
            match (&key, Row::decode(&key, value, context.source).unwrap()) {
                (Key::State(rid), Row::State { live, .. }) => {
                    events.push(format!("primary{}{}", if live { "+" } else { "-" }, rid))
                }
                (
                    Key::Fact {
                        index,
                        key,
                        raw_sequence,
                        ..
                    },
                    Row::Fact {
                        append_ordinal,
                        decision,
                    },
                ) => {
                    assert_eq!(*raw_sequence, events.len() as u64 + 1);
                    assert_eq!(append_ordinal, *raw_sequence);
                    events.push(format!(
                        "{}/{}{}",
                        if *index == 1 { "aux" } else { "kv" },
                        String::from_utf8_lossy(key),
                        match decision {
                            Decision::Put(rid) => format!("+{rid}"),
                            Decision::Delete => "-".into(),
                        }
                    ));
                }
                _ => {}
            }
        }
        rows.extend(planned.updates);
        validate_installed(&rows, &context).unwrap();
        // A mixed unknown batch cannot alter accepted state or consume a number.
        let before = rows.clone();
        assert!(
            plan(
                &intent(IntentKind::DeleteRecords(vec![RecordId(1), RecordId(999)])),
                99,
                &context,
                &mut |role, key| Ok(rows.get(&(role, key.to_vec())).cloned().flatten())
            )
            .is_err()
        );
        assert_eq!(rows, before);
    }
    assert_eq!(
        events,
        [
            "primary+1",
            "kv/same+1",
            "kv/same+1",
            "aux/left+1",
            "primary+2",
            "kv/same+2",
            "kv/other+2",
            "aux/same+2",
            "primary+3",
            "kv/third+3",
            "aux/right+3",
            "primary-2",
            "primary-2",
            "primary-2",
            "primary-2",
            "aux/left-",
            "kv/third-",
            "aux/left-",
            "primary-1",
            "kv/absent-",
            "kv/same-",
            "primary-2",
            "aux/right-",
            "primary-3",
            "primary+4",
            "kv/keep+4",
            "kv/only+4",
            "kv/only-",
            "kv/missing-",
            "primary+5",
            "kv/after+5",
            "primary-1",
            "primary-1",
            "primary-1"
        ]
    );
    assert_eq!(
        validate_installed(&rows, &context).unwrap(),
        Allocator {
            last_rid: 5,
            compatibility_sequence: 34,
            append_ordinal: 34,
            live_count: 2,
            dead_count: 3,
            live_payload_bytes: 9
        }
    );
}
