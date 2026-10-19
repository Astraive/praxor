use super::frame::{
    FrameContext, PriorCatalog, ValidatedCatalogFrame, validate_bootstrap, validate_create,
};
use super::{CatalogAuthorityV1, CatalogBindingV1};
use crate::core_catalog::CatalogControl;
use crate::core_catalog::codec::Head;
use crate::core_records::RecordAuthority;
use crate::core_records::codec::{Allocator, Key, Role, Row};
use crate::core_records::transition::{self, Context as RecordContext, Rows, Summary};
use crate::errors::{PraxisError, Result};
use crate::transactions::{BatchOp, WriteBatch};
use crate::wal::record::{CoreRecordPrefix, CoreWalRecord, parse_core_record_prefix};
use std::path::Path;

const BOOTSTRAP: &[u8; 563] = include_bytes!("../../tests/fixtures/catalog_tag6_bootstrap_s1.bin");
const CREATE: &[u8; 424] = include_bytes!("../../tests/fixtures/catalog_tag7_create_s2.bin");
const ORACLE: &str = include_str!("../../tests/fixtures/catalog_v4_wal_oracle.json");
const ID: [u8; 16] = [0x11; 16];

fn source() -> &'static Path {
    Path::new("literal-v4-frame-relation")
}

fn context(descriptors: u32) -> FrameContext<'static> {
    let record = RecordAuthority::new(ID, descriptors);
    let catalog = CatalogAuthorityV1 {
        kind: "core_catalog".into(),
        schema_version: 1,
        codec_version: 1,
        database_id: "11111111111111111111111111111111".into(),
        epoch: 1,
        bootstrap_sequence: 1,
        binding: CatalogBindingV1 {
            role: "catalog".into(),
            column_family: "__praxor_record_catalog_v1".into(),
            generation: 5,
        },
    };
    FrameContext::new(&record, &catalog, source()).unwrap()
}

fn parsed(bytes: &[u8]) -> CoreWalRecord {
    match parse_core_record_prefix(bytes, source()).unwrap() {
        CoreRecordPrefix::Complete {
            record,
            encoded_len,
        } => {
            assert_eq!(encoded_len, bytes.len());
            assert!(matches!(record, CoreWalRecord::Catalog { .. }));
            record
        }
        CoreRecordPrefix::Torn => panic!("literal complete frame was torn"),
    }
}

fn unhex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn assert_literal_effects(frame: ValidatedCatalogFrame<'_>, section: &str, sequence: u64) {
    assert_eq!(frame.sequence(), sequence);
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let expected = oracle[section]["operations"].as_array().unwrap();
    assert_eq!(frame.ops().len(), expected.len());
    for (op, expected) in frame.ops().iter().zip(expected) {
        let BatchOp::Put { cf, key, value } = op else {
            panic!("literal frame effect was not an ordinary Put");
        };
        assert_eq!(cf.0, expected["cf_utf8"].as_str().unwrap());
        assert_eq!(*key, unhex(expected["key_hex"].as_str().unwrap()));
        assert_eq!(*value, unhex(expected["value_hex"].as_str().unwrap()));
    }
}

#[derive(Clone)]
struct Prior {
    head: Head,
    names: Vec<Vec<u8>>,
    queried: Vec<Vec<u8>>,
}

impl PriorCatalog for Prior {
    fn head_and_name_presence(&mut self, exact_key: &[u8]) -> Result<(Head, bool)> {
        self.queried.push(exact_key.to_vec());
        Ok((self.head, self.names.iter().any(|name| name == exact_key)))
    }
}

#[test]
fn literal_tag6_bootstrap_has_one_valid_complete_relation() {
    let record = parsed(BOOTSTRAP);
    let effect = validate_bootstrap(&record, &context(0)).unwrap();
    assert_literal_effects(effect, "bootstrap_tag6", 1);
}

#[test]
fn literal_tag7_create_uses_same_prior_head_and_exact_name_endpoint() {
    let record = parsed(CREATE);
    let mut prior = Prior {
        head: Head {
            database_id: ID,
            revision: 1,
            collection_count: 0,
        },
        names: Vec::new(),
        queried: Vec::new(),
    };
    let effect = validate_create(&record, &context(0), &mut prior).unwrap();
    assert_literal_effects(effect, "create_tag7", 2);
    assert_eq!(prior.queried, [unhex("0100086163636f756e7473")]);
}

fn record_subbatch(batch: &WriteBatch, count: usize) -> WriteBatch {
    let mut result = WriteBatch::new();
    for op in &batch.ops()[..count] {
        result.push_op(op.clone());
    }
    result
}

fn descriptor_bootstrap(descriptors: u32) -> CoreWalRecord {
    let CoreWalRecord::Catalog { control, batch, .. } = parsed(BOOTSTRAP) else {
        unreachable!()
    };
    let mut result = WriteBatch::new();
    result.put(
        Role::Meta.cf(),
        Key::Binding.encode().unwrap(),
        Row::Binding {
            database_id: ID,
            descriptor_count: descriptors,
        }
        .encode()
        .unwrap(),
    );
    result.put(
        Role::Meta.cf(),
        Key::Allocator.encode().unwrap(),
        Row::Allocator(Allocator::default()).encode().unwrap(),
    );
    for id in 1..=descriptors {
        let name = format!("index-{id:04}");
        result.put(
            Role::Meta.cf(),
            Key::Descriptor(id).encode().unwrap(),
            Row::Descriptor {
                name: &name,
                namespace: "model",
            }
            .encode()
            .unwrap(),
        );
    }
    for op in &batch.ops()[2..] {
        result.push_op(op.clone());
    }
    CoreWalRecord::Catalog {
        sequence: 1,
        control,
        batch: result,
    }
}

fn frozen_record_rows(descriptors: u32) -> Rows {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let rows = oracle["bootstrap_tag6"]["operations"].as_array().unwrap();
    let mut binding = unhex(rows[0]["value_hex"].as_str().unwrap());
    // PRM1 descriptor_count is u32LE at 36..40, as fixed by codec 1.
    binding[36..40].copy_from_slice(&descriptors.to_le_bytes());
    let mut expected = Rows::new();
    expected.insert(
        (Role::Meta, unhex(rows[0]["key_hex"].as_str().unwrap())),
        Some(Summary::Bytes(binding)),
    );
    expected.insert(
        (Role::Meta, unhex(rows[1]["key_hex"].as_str().unwrap())),
        Some(Summary::Bytes(unhex(
            rows[1]["value_hex"].as_str().unwrap(),
        ))),
    );
    for (id, key, value) in [
        (
            1,
            "0200000001",
            "50524431010000000101010001000000000000000a000000696e6465782d30303031050000006d6f64656c00000000",
        ),
        (
            2,
            "0200000002",
            "50524431010000000101010001000000000000000a000000696e6465782d30303032050000006d6f64656c00000000",
        ),
    ] {
        if id <= descriptors {
            expected.insert((Role::Meta, unhex(key)), Some(Summary::Bytes(unhex(value))));
        }
    }
    expected
}

#[test]
fn v3_bootstrap_keeps_exact_literal_record_updates() {
    let CoreWalRecord::Catalog {
        control: CatalogControl::Bootstrap { envelope, .. },
        batch,
        ..
    } = parsed(BOOTSTRAP)
    else {
        unreachable!()
    };
    let record_batch = record_subbatch(&batch, 2);
    let relation_context = RecordContext {
        id: ID,
        descriptors: 0,
        source: source(),
    };
    let updates =
        transition::validate(1, &envelope, &record_batch, &relation_context, None).unwrap();
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let expected: Rows = oracle["bootstrap_tag6"]["operations"].as_array().unwrap()[..2]
        .iter()
        .map(|row| {
            (
                (Role::Meta, unhex(row["key_hex"].as_str().unwrap())),
                Some(Summary::Bytes(unhex(row["value_hex"].as_str().unwrap()))),
            )
        })
        .collect();
    assert_eq!(updates, expected);
}

#[test]
fn one_and_two_descriptors_share_borrowed_bootstrap_rules_with_v3() {
    for descriptors in [1, 2] {
        let record = descriptor_bootstrap(descriptors);
        let encoded = record.try_encode().unwrap();
        assert!(encoded.len() <= 1_048_576);
        let reparsed = parsed(&encoded);
        let effect = validate_bootstrap(&reparsed, &context(descriptors)).unwrap();
        assert_eq!(effect.ops().len(), descriptors as usize + 4);
        let CoreWalRecord::Catalog {
            control: CatalogControl::Bootstrap { envelope, .. },
            batch,
            ..
        } = reparsed
        else {
            unreachable!()
        };
        let record_batch = record_subbatch(&batch, descriptors as usize + 2);
        let relation_context = RecordContext {
            id: ID,
            descriptors,
            source: source(),
        };
        transition::validate_bootstrap_ops(1, &envelope, record_batch.ops(), &relation_context)
            .unwrap();
        let updates =
            transition::validate(1, &envelope, &record_batch, &relation_context, None).unwrap();
        let expected = frozen_record_rows(descriptors);
        assert_eq!(updates, expected);
    }
}

#[test]
fn near_one_mib_descriptor_bootstrap_uses_borrowed_record_prefix() {
    const DESCRIPTORS: u32 = 3_800;
    let CoreWalRecord::Catalog { control, batch, .. } = descriptor_bootstrap(0) else {
        unreachable!()
    };
    let mut enlarged = WriteBatch::new();
    enlarged.put(
        Role::Meta.cf(),
        Key::Binding.encode().unwrap(),
        Row::Binding {
            database_id: ID,
            descriptor_count: DESCRIPTORS,
        }
        .encode()
        .unwrap(),
    );
    enlarged.put(
        Role::Meta.cf(),
        Key::Allocator.encode().unwrap(),
        Row::Allocator(Allocator::default()).encode().unwrap(),
    );
    for id in 1..=DESCRIPTORS {
        let name = format!("{id:05}{}", "x".repeat(195));
        assert_eq!(name.len(), 200);
        enlarged.put(
            Role::Meta.cf(),
            Key::Descriptor(id).encode().unwrap(),
            Row::Descriptor {
                name: &name,
                namespace: "n",
            }
            .encode()
            .unwrap(),
        );
    }
    for op in &batch.ops()[2..] {
        enlarged.push_op(op.clone());
    }
    let record = CoreWalRecord::Catalog {
        sequence: 1,
        control,
        batch: enlarged,
    };
    let encoded = record.try_encode().unwrap();
    assert!((1_040_000..=1_048_576).contains(&encoded.len()));
    let reparsed = parsed(&encoded);
    let effect = validate_bootstrap(&reparsed, &context(DESCRIPTORS)).unwrap();
    assert_eq!(effect.ops().len(), DESCRIPTORS as usize + 4);
}

fn corrupt_reason(error: PraxisError) -> String {
    let PraxisError::Corrupt { path, reason } = error else {
        panic!("expected source-addressed corruption, got {error:?}")
    };
    assert_eq!(path, source());
    reason
}

fn oracle_mutation(name: &str) -> Vec<u8> {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let mutation = oracle["semantic_mutations_rechecksummed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .unwrap();
    unhex(mutation["frame_hex"].as_str().unwrap())
}

#[test]
fn unchecked_oracle_flip_fails_crc_before_control_or_relation() {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let bytes = unhex(
        oracle["unchecked_payload_crc_flip"]["frame_hex"]
            .as_str()
            .unwrap(),
    );
    let error = match parse_core_record_prefix(&bytes, source()) {
        Err(error) => error,
        Ok(_) => panic!("unchecked mutation reached catalog control"),
    };
    assert!(corrupt_reason(error).contains("WAL checksum mismatch"));
}

#[test]
fn rechecksummed_outer_id_mutation_fails_control_before_typed_catalog() {
    let bytes = oracle_mutation("bootstrap_outer_database_id_only");
    let error = match parse_core_record_prefix(&bytes, source()) {
        Err(error) => error,
        Ok(_) => panic!("outer ID mismatch produced a typed catalog frame"),
    };
    assert!(corrupt_reason(error).contains("catalog bootstrap envelope mismatch"));
}

#[test]
fn rechecksummed_anchor_digest_mutation_fails_row_decode_inside_relation() {
    let bytes = oracle_mutation("bootstrap_anchor_digest_only");
    let record = parsed(&bytes);
    let error = match validate_bootstrap(&record, &context(0)) {
        Err(error) => error,
        Ok(_) => panic!("mutated Anchor produced a validated effect"),
    };
    assert!(corrupt_reason(error).contains("catalog Anchor digest does not match Head@1"));
}

#[test]
fn rechecksummed_prior_revision_mutation_fails_create_relation() {
    let bytes = oracle_mutation("create_prior_revision_only");
    let record = parsed(&bytes);
    let mut prior = Prior {
        head: Head {
            database_id: ID,
            revision: 1,
            collection_count: 0,
        },
        names: Vec::new(),
        queried: Vec::new(),
    };
    let error = match validate_create(&record, &context(0), &mut prior) {
        Err(error) => error,
        Ok(_) => panic!("stale prior revision produced a validated effect"),
    };
    assert!(corrupt_reason(error).contains("catalog CREATE frame relation mismatch"));
}

#[test]
fn rechecksummed_schema_id_mutation_fails_row_decode_inside_relation() {
    let bytes = oracle_mutation("create_schema_collection_id_only");
    let record = parsed(&bytes);
    let mut prior = Prior {
        head: Head {
            database_id: ID,
            revision: 1,
            collection_count: 0,
        },
        names: Vec::new(),
        queried: Vec::new(),
    };
    let error = match validate_create(&record, &context(0), &mut prior) {
        Err(error) => error,
        Ok(_) => panic!("mutated Schema ID produced a validated effect"),
    };
    assert!(corrupt_reason(error).contains("catalog schema key/namespace ID mismatch"));
}

fn mutate_put(
    record: &mut CoreWalRecord,
    index: usize,
    change: impl FnOnce(&mut String, &mut Vec<u8>, &mut Vec<u8>),
) {
    let CoreWalRecord::Catalog { batch, .. } = record else {
        panic!("expected typed Catalog record")
    };
    let mut ops = batch.ops().to_vec();
    let BatchOp::Put { cf, key, value } = &mut ops[index] else {
        panic!("fixture operation was not Put")
    };
    change(&mut cf.0, key, value);
    let mut changed = WriteBatch::new();
    for op in ops {
        changed.push_op(op);
    }
    *batch = changed;
}

fn replace_op(record: &mut CoreWalRecord, index: usize, replacement: BatchOp) {
    let CoreWalRecord::Catalog { batch, .. } = record else {
        panic!("expected typed Catalog record")
    };
    let mut ops = batch.ops().to_vec();
    ops[index] = replacement;
    let mut changed = WriteBatch::new();
    for op in ops {
        changed.push_op(op);
    }
    *batch = changed;
}

fn bootstrap_corrupt(record: &CoreWalRecord, descriptors: u32, expected: &str) {
    let error = match validate_bootstrap(record, &context(descriptors)) {
        Err(error) => error,
        Ok(_) => panic!("invalid bootstrap yielded a validated effect: {expected}"),
    };
    assert!(corrupt_reason(error).contains(expected));
}

#[test]
fn bootstrap_record_prefix_rejects_binding_allocator_and_descriptor_mismatches() {
    let base = descriptor_bootstrap(2);
    let mut binding_id = base.clone();
    mutate_put(&mut binding_id, 0, |_, _, value| value[8] ^= 1);
    bootstrap_corrupt(&binding_id, 2, "bootstrap binding mismatch");

    let mut binding_count = base.clone();
    mutate_put(&mut binding_count, 0, |_, _, value| {
        value[36..40].copy_from_slice(&3u32.to_le_bytes())
    });
    bootstrap_corrupt(&binding_count, 2, "bootstrap binding mismatch");

    let mut allocator = base.clone();
    mutate_put(&mut allocator, 1, |_, _, value| {
        *value = Row::Allocator(Allocator {
            last_rid: 1,
            dead_count: 1,
            ..Allocator::default()
        })
        .encode()
        .unwrap();
    });
    bootstrap_corrupt(&allocator, 2, "bootstrap allocator mismatch");

    let mut descriptor_id = base.clone();
    mutate_put(&mut descriptor_id, 2, |_, key, _| {
        *key = Key::Descriptor(2).encode().unwrap()
    });
    bootstrap_corrupt(&descriptor_id, 2, "bootstrap descriptor order");

    let mut descriptor_name = base.clone();
    mutate_put(&mut descriptor_name, 3, |_, _, value| {
        *value = Row::Descriptor {
            name: "index-0000",
            namespace: "model",
        }
        .encode()
        .unwrap();
    });
    bootstrap_corrupt(&descriptor_name, 2, "bootstrap descriptor order");

    for (candidate, expected) in [
        (binding_id, "bootstrap binding mismatch"),
        (allocator, "bootstrap allocator mismatch"),
        (descriptor_id, "bootstrap descriptor order"),
    ] {
        let CoreWalRecord::Catalog {
            control: CatalogControl::Bootstrap { envelope, .. },
            batch,
            ..
        } = candidate
        else {
            unreachable!()
        };
        let record_batch = record_subbatch(&batch, 4);
        let record_context = RecordContext {
            id: ID,
            descriptors: 2,
            source: source(),
        };
        let error = match transition::validate(1, &envelope, &record_batch, &record_context, None) {
            Err(error) => error,
            Ok(_) => panic!("invalid record bootstrap materialized rows"),
        };
        assert!(corrupt_reason(error).contains(expected));
    }
}

#[test]
fn bootstrap_rejects_wrong_tail_count_order_role_and_operation_kind() {
    let base = descriptor_bootstrap(2);
    let mut missing = base.clone();
    let CoreWalRecord::Catalog { batch, .. } = &mut missing else {
        unreachable!()
    };
    batch.truncate(5);
    bootstrap_corrupt(&missing, 2, "catalog bootstrap operation count mismatch");

    let mut extra = base.clone();
    let CoreWalRecord::Catalog { batch, .. } = &mut extra else {
        unreachable!()
    };
    batch.push_op(batch.ops()[5].clone());
    bootstrap_corrupt(&extra, 2, "catalog bootstrap operation count mismatch");

    let mut swapped = base.clone();
    let CoreWalRecord::Catalog { batch, .. } = &mut swapped else {
        unreachable!()
    };
    let mut ops = batch.ops().to_vec();
    ops.swap(4, 5);
    let mut changed = WriteBatch::new();
    for op in ops {
        changed.push_op(op);
    }
    *batch = changed;
    bootstrap_corrupt(&swapped, 2, "catalog bootstrap Head key mismatch");

    let mut wrong_record_role = base.clone();
    mutate_put(&mut wrong_record_role, 0, |cf, _, _| {
        *cf = Role::Payload.cf().into()
    });
    bootstrap_corrupt(&wrong_record_role, 2, "bootstrap record role mismatch");

    let mut wrong_catalog_role = base.clone();
    mutate_put(&mut wrong_catalog_role, 4, |cf, _, _| {
        *cf = Role::Meta.cf().into()
    });
    bootstrap_corrupt(
        &wrong_catalog_role,
        2,
        "catalog frame column family mismatch",
    );

    let mut delete = base.clone();
    replace_op(
        &mut delete,
        5,
        BatchOp::Delete {
            cf: "__praxor_record_catalog_v1".into(),
            key: vec![4],
        },
    );
    bootstrap_corrupt(&delete, 2, "catalog frame requires plain Put");

    let mut expiry = base;
    replace_op(
        &mut expiry,
        5,
        BatchOp::PutWithExpiry {
            cf: "__praxor_record_catalog_v1".into(),
            key: vec![4],
            value: vec![0],
            expires_at_ms: 5,
        },
    );
    bootstrap_corrupt(&expiry, 2, "catalog frame requires plain Put");
}

#[test]
fn bootstrap_checks_canonical_head_and_anchor_against_manifest_identity() {
    let base = parsed(BOOTSTRAP);
    let mut changed_head = base.clone();
    mutate_put(&mut changed_head, 2, |_, _, value| value[8] ^= 1);
    bootstrap_corrupt(&changed_head, 0, "catalog bootstrap Head value mismatch");

    let mut changed_revision = base.clone();
    mutate_put(&mut changed_revision, 2, |_, _, value| {
        value[32..40].copy_from_slice(&2u64.to_le_bytes())
    });
    bootstrap_corrupt(
        &changed_revision,
        0,
        "catalog bootstrap Head value mismatch",
    );

    let mut changed_anchor = base.clone();
    mutate_put(&mut changed_anchor, 3, |_, _, value| {
        let other_id = [0x22; 16];
        value[8..24].copy_from_slice(&other_id);
        value[40..72].copy_from_slice(&super::codec::anchor_digest(other_id).unwrap());
    });
    bootstrap_corrupt(
        &changed_anchor,
        0,
        "catalog bootstrap Anchor value mismatch",
    );

    let mut wrong_control_id = base.clone();
    let CoreWalRecord::Catalog {
        control: CatalogControl::Bootstrap { database_id, .. },
        ..
    } = &mut wrong_control_id
    else {
        unreachable!()
    };
    *database_id = [0x22; 16];
    bootstrap_corrupt(
        &wrong_control_id,
        0,
        "catalog bootstrap identity or sequence mismatch",
    );
}

struct ChangingPrior {
    current_head: Head,
    queried: Vec<Vec<u8>>,
}

impl PriorCatalog for ChangingPrior {
    fn head_and_name_presence(&mut self, exact_key: &[u8]) -> Result<(Head, bool)> {
        self.queried.push(exact_key.to_vec());
        // A different CREATE committed after the caller bound its old intent.
        // The adapter's one endpoint sees the new Head and absent target name.
        self.current_head.revision = 2;
        self.current_head.collection_count = 1;
        Ok((self.current_head, false))
    }
}

#[test]
fn create_cannot_mix_old_head_with_newer_name_endpoint() {
    let record = parsed(CREATE);
    let mut changing = ChangingPrior {
        current_head: Head {
            database_id: ID,
            revision: 1,
            collection_count: 0,
        },
        queried: Vec::new(),
    };
    assert!(
        validate_create(&record, &context(0), &mut changing).is_err(),
        "a mixed-cut prior must not validate the older S=2 frame"
    );
    assert_eq!(changing.queried, [unhex("0100086163636f756e7473")]);
}

#[test]
fn create_rejects_zero_revision_prior_even_when_control_agrees() {
    let mut record = parsed(CREATE);
    let CoreWalRecord::Catalog {
        control: CatalogControl::Create { prior_revision, .. },
        ..
    } = &mut record
    else {
        unreachable!()
    };
    *prior_revision = 0;
    let mut prior = Prior {
        head: Head {
            database_id: ID,
            revision: 0,
            collection_count: 0,
        },
        names: Vec::new(),
        queried: Vec::new(),
    };
    assert!(
        validate_create(&record, &context(0), &mut prior).is_err(),
        "revision-zero prior is not a valid codec-1 Head"
    );
}

fn create_at(
    sequence: u64,
    prior_revision: u64,
    prior_count: u64,
    name: &[u8; 8],
) -> CoreWalRecord {
    let mut record = parsed(CREATE);
    let CoreWalRecord::Catalog {
        sequence: actual_sequence,
        control:
            CatalogControl::Create {
                prior_revision: actual_prior_revision,
                prior_count: actual_prior_count,
                new_revision,
                new_count,
                ..
            },
        ..
    } = &mut record
    else {
        unreachable!()
    };
    *actual_sequence = sequence;
    *actual_prior_revision = prior_revision;
    *actual_prior_count = prior_count;
    *new_revision = sequence;
    *new_count = prior_count + 1;
    mutate_put(&mut record, 0, |_, _, value| {
        value[32..40].copy_from_slice(&sequence.to_le_bytes());
        value[40..48].copy_from_slice(&(prior_count + 1).to_le_bytes());
    });
    mutate_put(&mut record, 1, |_, key, value| {
        key[3..11].copy_from_slice(name);
        value[4..12].copy_from_slice(&sequence.to_le_bytes());
    });
    mutate_put(&mut record, 2, |_, key, value| {
        key[1..9].copy_from_slice(&sequence.to_be_bytes());
        value[8..16].copy_from_slice(&sequence.to_le_bytes());
        value[16..24].copy_from_slice(&sequence.to_le_bytes());
        value[26..34].copy_from_slice(name);
    });
    mutate_put(&mut record, 3, |_, key, value| {
        key[1..9].copy_from_slice(&sequence.to_be_bytes());
        value[8..16].copy_from_slice(&sequence.to_le_bytes());
    });
    record
}

fn prior(revision: u64, count: u64) -> Prior {
    Prior {
        head: Head {
            database_id: ID,
            revision,
            collection_count: count,
        },
        names: Vec::new(),
        queried: Vec::new(),
    }
}

fn create_corrupt(record: &CoreWalRecord, prior: &mut Prior, expected: &str) {
    let error = match validate_create(record, &context(0), prior) {
        Err(error) => error,
        Ok(_) => panic!("invalid CREATE yielded a validated effect: {expected}"),
    };
    assert!(corrupt_reason(error).contains(expected));
}

#[test]
fn create_revision_can_jump_over_ordinary_sequences_while_count_increments_once() {
    let first = create_at(3, 1, 0, b"accounts");
    let first = parsed(&first.try_encode().unwrap());
    let mut first_prior = prior(1, 0);
    let effect = validate_create(&first, &context(0), &mut first_prior).unwrap();
    assert_eq!(effect.sequence(), 3);
    assert_eq!(effect.ops().len(), 4);
    assert_eq!(first_prior.queried, [unhex("0100086163636f756e7473")]);

    let second = create_at(5, 3, 1, b"ledger00");
    let second = parsed(&second.try_encode().unwrap());
    let mut second_prior = prior(3, 1);
    second_prior.names.push(unhex("0100086163636f756e7473"));
    let effect = validate_create(&second, &context(0), &mut second_prior).unwrap();
    assert_eq!(effect.sequence(), 5);
    assert_eq!(effect.ops().len(), 4);
    assert_eq!(second_prior.queried, [unhex("0100086c65646765723030")]);
}

#[test]
fn create_refuses_stale_duplicate_foreign_and_overflowed_prior() {
    let base = parsed(CREATE);
    let mut stale = prior(3, 1);
    create_corrupt(&base, &mut stale, "catalog CREATE frame relation mismatch");

    let mut duplicate = prior(1, 0);
    duplicate.names.push(unhex("0100086163636f756e7473"));
    create_corrupt(&base, &mut duplicate, "catalog CREATE name already exists");
    assert_eq!(duplicate.queried, [unhex("0100086163636f756e7473")]);

    let mut foreign = prior(1, 0);
    foreign.head.database_id = [0x22; 16];
    create_corrupt(
        &base,
        &mut foreign,
        "catalog CREATE frame relation mismatch",
    );

    let mut count_overflow = base;
    let CoreWalRecord::Catalog {
        control: CatalogControl::Create { prior_count, .. },
        ..
    } = &mut count_overflow
    else {
        unreachable!()
    };
    *prior_count = u64::MAX;
    let mut max_prior = prior(1, u64::MAX);
    create_corrupt(
        &count_overflow,
        &mut max_prior,
        "catalog collection count overflow",
    );
}

#[test]
fn create_rejects_control_and_head_identity_revision_count_drift() {
    let base = parsed(CREATE);
    let mut wrong_sequence = base.clone();
    let CoreWalRecord::Catalog { sequence, .. } = &mut wrong_sequence else {
        unreachable!()
    };
    *sequence = 1;
    create_corrupt(
        &wrong_sequence,
        &mut prior(1, 0),
        "catalog CREATE identity or sequence mismatch",
    );

    for change in [
        "control ID",
        "control epoch",
        "control revision",
        "control count",
    ] {
        let mut candidate = base.clone();
        let CoreWalRecord::Catalog {
            control:
                CatalogControl::Create {
                    database_id,
                    catalog_epoch,
                    new_revision,
                    new_count,
                    ..
                },
            ..
        } = &mut candidate
        else {
            unreachable!()
        };
        match change {
            "control ID" => *database_id = [0x22; 16],
            "control epoch" => *catalog_epoch = 2,
            "control revision" => *new_revision = 3,
            "control count" => *new_count = 2,
            _ => unreachable!(),
        }
        let reason = if change.starts_with("control I") || change.starts_with("control e") {
            "catalog CREATE identity or sequence mismatch"
        } else {
            "catalog CREATE frame relation mismatch"
        };
        create_corrupt(&candidate, &mut prior(1, 0), reason);
    }

    for (offset, replacement) in [
        (8, vec![0x22]),
        (32, 3u64.to_le_bytes().to_vec()),
        (40, 2u64.to_le_bytes().to_vec()),
    ] {
        let mut candidate = base.clone();
        mutate_put(&mut candidate, 0, |_, _, value| {
            value[offset..offset + replacement.len()].copy_from_slice(&replacement)
        });
        create_corrupt(
            &candidate,
            &mut prior(1, 0),
            "catalog CREATE frame relation mismatch",
        );
    }
}

#[test]
fn create_rejects_cross_row_name_schema_namespace_drift() {
    let base = parsed(CREATE);
    let mut name_value = base.clone();
    mutate_put(&mut name_value, 1, |_, _, value| {
        value[4..12].copy_from_slice(&3u64.to_le_bytes())
    });
    create_corrupt(
        &name_value,
        &mut prior(1, 0),
        "catalog CREATE frame relation mismatch",
    );

    let mut name_key = base.clone();
    mutate_put(&mut name_key, 1, |_, key, _| key[3] = b'b');
    create_corrupt(
        &name_key,
        &mut prior(1, 0),
        "catalog CREATE frame relation mismatch",
    );

    let mut schema_name = base.clone();
    mutate_put(&mut schema_name, 2, |_, _, value| value[26] = b'b');
    create_corrupt(
        &schema_name,
        &mut prior(1, 0),
        "catalog CREATE frame relation mismatch",
    );

    let mut schema_id = base.clone();
    mutate_put(&mut schema_id, 2, |_, key, value| {
        key[1..9].copy_from_slice(&3u64.to_be_bytes());
        value[8..16].copy_from_slice(&3u64.to_le_bytes());
        value[16..24].copy_from_slice(&3u64.to_le_bytes());
    });
    create_corrupt(
        &schema_id,
        &mut prior(1, 0),
        "catalog CREATE frame relation mismatch",
    );

    let mut namespace_id = base;
    mutate_put(&mut namespace_id, 3, |_, key, value| {
        key[1..9].copy_from_slice(&3u64.to_be_bytes());
        value[8..16].copy_from_slice(&3u64.to_le_bytes());
    });
    create_corrupt(
        &namespace_id,
        &mut prior(1, 0),
        "catalog CREATE frame relation mismatch",
    );
}

#[test]
fn create_rejects_noncanonical_order_role_and_operation_kind() {
    let base = parsed(CREATE);
    let mut wrong_cf = base.clone();
    mutate_put(&mut wrong_cf, 1, |cf, _, _| *cf = Role::Meta.cf().into());
    create_corrupt(
        &wrong_cf,
        &mut prior(1, 0),
        "catalog frame column family mismatch",
    );

    let mut wrong_order = base.clone();
    let CoreWalRecord::Catalog { batch, .. } = &mut wrong_order else {
        unreachable!()
    };
    let mut ops = batch.ops().to_vec();
    ops.swap(1, 2);
    let mut changed = WriteBatch::new();
    for op in ops {
        changed.push_op(op);
    }
    *batch = changed;
    create_corrupt(
        &wrong_order,
        &mut prior(1, 0),
        "catalog CREATE Name key mismatch",
    );

    let mut missing = base.clone();
    let CoreWalRecord::Catalog { batch, .. } = &mut missing else {
        unreachable!()
    };
    batch.truncate(3);
    create_corrupt(
        &missing,
        &mut prior(1, 0),
        "catalog CREATE operation count mismatch",
    );

    let mut anchor_rewrite = base.clone();
    mutate_put(&mut anchor_rewrite, 3, |_, key, _| *key = vec![4]);
    create_corrupt(
        &anchor_rewrite,
        &mut prior(1, 0),
        "catalog CREATE Namespace key mismatch",
    );

    for replacement in [
        BatchOp::Delete {
            cf: "__praxor_record_catalog_v1".into(),
            key: vec![0],
        },
        BatchOp::Merge {
            cf: "__praxor_record_catalog_v1".into(),
            key: vec![0],
            value: vec![0],
        },
        BatchOp::PutWithExpiry {
            cf: "__praxor_record_catalog_v1".into(),
            key: vec![0],
            value: vec![0],
            expires_at_ms: 1,
        },
    ] {
        let mut candidate = base.clone();
        replace_op(&mut candidate, 0, replacement);
        create_corrupt(
            &candidate,
            &mut prior(1, 0),
            "catalog frame requires plain Put",
        );
    }
}
