use super::{
    FrameContext, FrameError, FrameKind, H64Inspection, UntrustedFrame, UntrustedH64,
    decode_complete_frame, inspect_h64_prefix,
};
use serde_json::Value;

// Byte-for-byte copy of the frozen, independently reviewed R6 vectors.
// The decoder must not generate its own expected wire bytes.
const R6_VECTORS: &str = include_str!("../../../tests/fixtures/wal_v5_r6.json");

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("fixed hex"))
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex_bytes(text).try_into().expect("fixed array width")
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect("frozen vector field")
}

fn case(name: &str) -> (Vec<u8>, FrameContext, UntrustedFrame) {
    let vectors: Value = serde_json::from_str(R6_VECTORS).expect("frozen vectors JSON");
    let frame = &vectors["frames"][name];
    let (kind, sequence, ordinary_operations, prior) = match name {
        "record_bootstrap" => (FrameKind::Record, 1, 0, None),
        "user_put" => (FrameKind::User, 2, 1, Some("record_bootstrap")),
        "catalog_bootstrap" => (FrameKind::CatalogBootstrap, 1, 0, None),
        "catalog_create" => (FrameKind::CatalogCreate, 2, 0, Some("catalog_bootstrap")),
        _ => panic!("unknown frozen frame"),
    };
    let context = FrameContext {
        header_digest: hex_array(field(&vectors, "header_digest")),
        previous_hash: prior.map_or_else(
            || hex_array(field(&vectors, "header_digest")),
            |prior| hex_array(field(&vectors["frames"][prior], "trailer")),
        ),
        expected_sequence: sequence,
        database_id: hex_array(field(&vectors, "database_id")),
    };
    let bytes = hex_bytes(field(frame, "hex"));
    let payload_len = frame["payload_len"].as_u64().expect("payload length") as u32;
    let expected = UntrustedFrame {
        header: UntrustedH64 {
            kind,
            sequence,
            ordinary_operations,
            payload_len,
            total_len: payload_len + 100,
        },
        trailer: hex_array(field(frame, "trailer")),
    };
    (bytes, context, expected)
}

fn crc32c_reference(bytes: &[u8]) -> u32 {
    // Bitwise Castagnoli oracle, checked against the R6 external vectors.
    let mut state = !0_u32;
    for &byte in bytes {
        state ^= u32::from(byte);
        for _ in 0..8 {
            state = (state >> 1) ^ (0_u32.wrapping_sub(state & 1) & 0x82f6_3b78);
        }
    }
    !state
}

fn trailer_reference(frame_through_crc: &[u8], context: &FrameContext) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"praxor/wal-frame/v5");
    hasher.update(&context.header_digest);
    hasher.update(&context.previous_hash);
    hasher.update(frame_through_crc);
    *hasher.finalize().as_bytes()
}

fn reseal(frame: &mut [u8], context: &FrameContext) {
    let crc_at = frame.len() - 36;
    let crc = crc32c_reference(&frame[..crc_at]);
    frame[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
    let trailer = trailer_reference(&frame[..crc_at + 4], context);
    frame[crc_at + 4..].copy_from_slice(&trailer);
}

fn set_lengths(header: &mut [u8], payload_len: u32) {
    header[8..12].copy_from_slice(&(payload_len + 100).to_le_bytes());
    header[28..32].copy_from_slice(&payload_len.to_le_bytes());
}

fn expected_frame(
    frame: &[u8],
    context: &FrameContext,
    kind: FrameKind,
    ordinary_operations: u32,
) -> UntrustedFrame {
    UntrustedFrame {
        header: UntrustedH64 {
            kind,
            sequence: context.expected_sequence,
            ordinary_operations,
            payload_len: u32::try_from(frame.len() - 100).expect("bounded synthetic frame"),
            total_len: u32::try_from(frame.len()).expect("bounded synthetic frame"),
        },
        trailer: frame[frame.len() - 32..].try_into().expect("trailer"),
    }
}

fn rewrite_payload(
    source: &[u8],
    context: &FrameContext,
    payload: &[u8],
    ordinary_operations: u32,
) -> Vec<u8> {
    let mut frame = source[..64].to_vec();
    frame[24..28].copy_from_slice(&ordinary_operations.to_le_bytes());
    set_lengths(
        &mut frame,
        u32::try_from(payload.len()).expect("bounded synthetic payload"),
    );
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&[0; 36]);
    reseal(&mut frame, context);
    frame
}

fn reject_resealed(
    source: &[u8],
    context: &FrameContext,
    name: &str,
    edit: impl FnOnce(&mut [u8]),
) {
    let mut frame = source.to_vec();
    edit(&mut frame);
    reseal(&mut frame, context);
    assert_eq!(
        decode_complete_frame(&frame, context),
        Err(FrameError::Corrupt),
        "{name} with a valid CRC and domain trailer"
    );
}

fn record_kind_frame(kind: u8, records: u32, logical: u32) -> (Vec<u8>, FrameContext) {
    let (mut frame, mut context, _) = case("record_bootstrap");
    if kind != 1 {
        let (previous, _, _) = case("record_bootstrap");
        context.expected_sequence = 2;
        context.previous_hash = previous[previous.len() - 32..]
            .try_into()
            .expect("previous trailer");
        frame[12..20].copy_from_slice(&2_u64.to_le_bytes());
        frame[32..64].copy_from_slice(&context.previous_hash);
        frame[74] = kind;
        frame[100..108].copy_from_slice(&10_u64.to_le_bytes());
        let new_rid = if kind == 2 {
            10 + u64::from(records)
        } else {
            10
        };
        frame[108..116].copy_from_slice(&new_rid.to_le_bytes());
        frame[116..124].copy_from_slice(&20_u64.to_le_bytes());
        frame[124..132].copy_from_slice(&(20 + u64::from(logical)).to_le_bytes());
        frame[132..140].copy_from_slice(&40_u64.to_le_bytes());
        frame[140..148].copy_from_slice(&(40 + u64::from(logical)).to_le_bytes());
        frame[148..152].copy_from_slice(&records.to_le_bytes());
        frame[152..156].copy_from_slice(&logical.to_le_bytes());
        reseal(&mut frame, &context);
    }
    (frame, context)
}

fn user_operation(tag: u8, cf_name: &[u8]) -> Vec<u8> {
    let mut operation = Vec::new();
    operation.extend_from_slice(&0_u32.to_le_bytes()); // first physical ordinal
    operation.push(tag);
    operation.extend_from_slice(&1_u64.to_le_bytes());
    operation.extend_from_slice(
        &u16::try_from(cf_name.len())
            .expect("bounded synthetic name")
            .to_le_bytes(),
    );
    operation.extend_from_slice(cf_name);
    operation.extend_from_slice(&1_u32.to_le_bytes());
    operation.push(b'k');
    if tag != 2 {
        operation.extend_from_slice(&1_u32.to_le_bytes());
        operation.push(b'v');
    }
    if tag == 3 {
        operation.extend_from_slice(&123_u64.to_le_bytes());
    }
    operation
}

fn user_frame(operation: Option<&[u8]>, context: &FrameContext) -> Vec<u8> {
    let (source, _, _) = case("user_put");
    let mut payload = 0_u32.to_le_bytes().to_vec();
    if let Some(operation) = operation {
        payload.extend_from_slice(operation);
    }
    rewrite_payload(
        &source,
        context,
        &payload,
        if operation.is_some() { 1 } else { 0 },
    )
}

#[test]
fn frozen_bytes_have_independent_crc32c_and_exact_frame_domain() {
    assert_eq!(crc32c_reference(b"123456789"), 0xe306_9283);
    assert_eq!(crate::io::crc32c(b"123456789"), 0xcbf4_3926);
    for name in [
        "record_bootstrap",
        "user_put",
        "catalog_bootstrap",
        "catalog_create",
    ] {
        let (frame, context, expected) = case(name);
        assert_eq!(frame.len(), expected.header.total_len as usize, "{name}");
        assert_eq!(&frame[..4], b"PWF5", "{name}");
        let crc_at = frame.len() - 36;
        assert_eq!(
            &frame[crc_at..crc_at + 4],
            &crc32c_reference(&frame[..crc_at]).to_le_bytes(),
            "{name} Castagnoli CRC"
        );
        assert_eq!(
            &frame[crc_at + 4..],
            &trailer_reference(&frame[..crc_at + 4], &context),
            "{name} exact frame-domain trailer"
        );
        assert_eq!(&frame[crc_at + 4..], &expected.trailer, "{name}");
    }
}

#[test]
fn four_typed_goldens_decode_only_as_untrusted_frames() {
    for name in [
        "record_bootstrap",
        "user_put",
        "catalog_bootstrap",
        "catalog_create",
    ] {
        let (frame, context, expected) = case(name);
        assert_eq!(
            inspect_h64_prefix(&frame[..64], &context),
            Ok(H64Inspection::Complete(expected.header)),
            "{name} H64"
        );
        assert_eq!(
            decode_complete_frame(&frame, &context),
            Ok(expected),
            "{name}"
        );
    }
}

#[test]
fn every_golden_h64_cut_is_incomplete_without_tail_authority() {
    for name in [
        "record_bootstrap",
        "user_put",
        "catalog_bootstrap",
        "catalog_create",
    ] {
        let (frame, context, _) = case(name);
        for cut in 0..64 {
            assert_eq!(
                inspect_h64_prefix(&frame[..cut], &context),
                Ok(H64Inspection::IncompleteUnclassified),
                "{name} H64 cut {cut}"
            );
        }
    }
}

#[test]
fn partial_little_endian_and_cross_field_impossibilities_refuse() {
    let (frame, context, _) = case("user_put");
    for (name, offset, replacement, cut) in [
        ("version low", 4, 0, 5),
        ("version high", 5, 1, 6),
        ("flags low", 6, 1, 7),
        ("flags high", 7, 1, 8),
        ("known sequence", 12, 3, 13),
        ("unknown kind", 20, 5, 21),
        ("reserved", 21, 1, 22),
        ("wrong previous hash", 32, 0, 33),
        ("total/payload equation", 28, 31, 29),
    ] {
        let mut prefix = frame[..cut].to_vec();
        prefix[offset] = replacement;
        assert_eq!(
            inspect_h64_prefix(&prefix, &context),
            Err(FrameError::Corrupt),
            "{name} at cut {cut}"
        );
    }

    // Two visible low bytes 0xffff cannot complete a count in 0..=4096.
    let mut too_many = frame[..26].to_vec();
    too_many[24..26].copy_from_slice(&[0xff, 0xff]);
    assert_eq!(
        inspect_h64_prefix(&too_many, &context),
        Err(FrameError::Corrupt)
    );

    // R6 review corrected this literal cut: total_len is complete at [8,12),
    // and the first payload_len byte is visible only at cut 29.
    let mut inconsistent = frame[..29].to_vec();
    inconsistent[8..12].copy_from_slice(&104_u32.to_le_bytes());
    inconsistent[28] = 5;
    assert_eq!(
        inspect_h64_prefix(&inconsistent, &context),
        Err(FrameError::Corrupt)
    );
}

#[test]
fn h64_enforces_closed_kind_counts_and_bounded_lengths_before_body_reads() {
    for name in [
        "record_bootstrap",
        "user_put",
        "catalog_bootstrap",
        "catalog_create",
    ] {
        let (frame, context, expected) = case(name);
        let mut header = frame[..64].to_vec();
        header[20] = 0;
        assert_eq!(
            inspect_h64_prefix(&header, &context),
            Err(FrameError::Corrupt)
        );
        header[20] = 5;
        assert_eq!(
            inspect_h64_prefix(&header, &context),
            Err(FrameError::Corrupt)
        );

        let mut header = frame[..64].to_vec();
        header[24..28].copy_from_slice(&4097_u32.to_le_bytes());
        assert_eq!(
            inspect_h64_prefix(&header, &context),
            Err(FrameError::Corrupt)
        );

        let min_payload = match expected.header.kind {
            FrameKind::User => 4 + 20 * expected.header.ordinary_operations,
            FrameKind::Record => 92 + 20 * expected.header.ordinary_operations,
            FrameKind::CatalogBootstrap => 124 + 20 * expected.header.ordinary_operations,
            FrameKind::CatalogCreate => 68 + 20 * expected.header.ordinary_operations,
        };
        let mut header = frame[..64].to_vec();
        set_lengths(&mut header, min_payload - 1);
        assert_eq!(
            inspect_h64_prefix(&header, &context),
            Err(FrameError::Corrupt)
        );

        let mut header = frame[..64].to_vec();
        header[8..12].copy_from_slice(&(expected.header.total_len + 1).to_le_bytes());
        assert_eq!(
            inspect_h64_prefix(&header, &context),
            Err(FrameError::Corrupt)
        );
    }

    let (user, context, _) = case("user_put");
    let mut oversized = user[..64].to_vec();
    set_lengths(&mut oversized, 67_108_865);
    assert_eq!(
        inspect_h64_prefix(&oversized, &context),
        Err(FrameError::Corrupt)
    );
    set_lengths(&mut oversized, 67_108_864);
    assert_eq!(
        inspect_h64_prefix(&oversized, &context),
        Ok(H64Inspection::Complete(UntrustedH64 {
            kind: FrameKind::User,
            sequence: 2,
            ordinary_operations: 1,
            payload_len: 67_108_864,
            total_len: 67_108_964,
        }))
    );

    let (catalog, context, _) = case("catalog_create");
    let mut oversized = catalog[..64].to_vec();
    set_lengths(&mut oversized, 1_048_477);
    assert_eq!(
        inspect_h64_prefix(&oversized, &context),
        Err(FrameError::Corrupt)
    );
    set_lengths(&mut oversized, 1_048_476);
    assert!(matches!(
        inspect_h64_prefix(&oversized, &context),
        Ok(H64Inspection::Complete(_))
    ));

    let mut impossible_user = user[..64].to_vec();
    set_lengths(&mut impossible_user, 4);
    assert_eq!(
        inspect_h64_prefix(&impossible_user, &case("user_put").1),
        Err(FrameError::Corrupt)
    );
}

#[test]
fn changed_context_or_corrupted_complete_integrity_is_not_a_torn_frame() {
    let (frame, context, _) = case("user_put");
    let mut wrong_sequence = context;
    wrong_sequence.expected_sequence = 3;
    assert_eq!(
        decode_complete_frame(&frame, &wrong_sequence),
        Err(FrameError::Corrupt)
    );
    let mut wrong_header_digest = context;
    wrong_header_digest.header_digest[0] ^= 1;
    assert_eq!(
        decode_complete_frame(&frame, &wrong_header_digest),
        Err(FrameError::Corrupt)
    );

    let mut bad_crc = frame.clone();
    let crc_at = bad_crc.len() - 36;
    bad_crc[crc_at] ^= 1;
    assert_eq!(
        decode_complete_frame(&bad_crc, &context),
        Err(FrameError::Corrupt)
    );
    let mut bad_trailer = frame.clone();
    *bad_trailer.last_mut().expect("trailer") ^= 1;
    assert_eq!(
        decode_complete_frame(&bad_trailer, &context),
        Err(FrameError::Corrupt)
    );

    let mut ieee = frame.clone();
    let ieee_crc = crate::io::crc32c(&ieee[..crc_at]);
    assert_ne!(ieee_crc, crc32c_reference(&ieee[..crc_at]));
    ieee[crc_at..crc_at + 4].copy_from_slice(&ieee_crc.to_le_bytes());
    let ieee_trailer = trailer_reference(&ieee[..crc_at + 4], &context);
    ieee[crc_at + 4..].copy_from_slice(&ieee_trailer);
    assert_eq!(
        decode_complete_frame(&ieee, &context),
        Err(FrameError::Corrupt)
    );

    for cut in [0, 1, 63, 64, 93, 94, 95, 98, 99, 129] {
        assert_eq!(
            decode_complete_frame(&frame[..cut], &context),
            Err(FrameError::Corrupt),
            "complete decoder cut {cut}"
        );
    }
    let mut suffix = frame;
    suffix.push(b'P');
    assert_eq!(
        decode_complete_frame(&suffix, &context),
        Err(FrameError::Corrupt)
    );
}

#[test]
fn typed_payload_checks_control_and_ordinary_operation_fields() {
    let (user, context, _) = case("user_put");
    for (name, offset, replacement) in [
        ("User control length", 64, 1),
        ("first ordinal", 68, 1),
        ("unknown op tag", 72, 5),
        ("zero CF generation", 73, 0),
        ("empty CF", 81, 0),
        ("NUL CF", 83, 0),
        ("invalid UTF-8 CF", 83, 0xff),
    ] {
        let mut changed = user.clone();
        changed[offset] = replacement;
        reseal(&mut changed, &context);
        assert_eq!(
            decode_complete_frame(&changed, &context),
            Err(FrameError::Corrupt),
            "{name} with valid CRC and trailer"
        );
    }

    let mut too_long_key = user.clone();
    too_long_key[84..88].copy_from_slice(&1_048_577_u32.to_le_bytes());
    reseal(&mut too_long_key, &context);
    assert_eq!(
        decode_complete_frame(&too_long_key, &context),
        Err(FrameError::Corrupt)
    );
    let mut too_long_value = user.clone();
    too_long_value[89..93].copy_from_slice(&67_108_865_u32.to_le_bytes());
    reseal(&mut too_long_value, &context);
    assert_eq!(
        decode_complete_frame(&too_long_value, &context),
        Err(FrameError::Corrupt)
    );

    let (record, context, _) = case("record_bootstrap");
    let mut wrong_control = record;
    wrong_control[68] = b'X';
    reseal(&mut wrong_control, &context);
    assert_eq!(
        decode_complete_frame(&wrong_control, &context),
        Err(FrameError::Corrupt)
    );

    let (catalog, context, _) = case("catalog_create");
    let mut wrong_revision = catalog;
    wrong_revision[68 + 48..68 + 56].copy_from_slice(&3_u64.to_le_bytes());
    reseal(&mut wrong_revision, &context);
    assert_eq!(
        decode_complete_frame(&wrong_revision, &context),
        Err(FrameError::Corrupt)
    );
}

#[test]
fn each_typed_control_binds_both_wire_and_context_database_identity() {
    for name in ["record_bootstrap", "catalog_bootstrap", "catalog_create"] {
        let (frame, context, _) = case(name);
        let mut wrong_context = context;
        wrong_context.database_id[0] ^= 1;
        assert_eq!(
            decode_complete_frame(&frame, &wrong_context),
            Err(FrameError::Corrupt),
            "{name} versus separately checked H80 identity"
        );
        reject_resealed(&frame, &context, &format!("{name} outer DB ID"), |bytes| {
            bytes[76] ^= 1;
        });
        if name == "catalog_bootstrap" {
            reject_resealed(&frame, &context, "PCB1 nested PRR1 DB ID", |bytes| {
                bytes[108] ^= 1;
            });
        }
    }
}

#[test]
fn prr1_all_six_kinds_have_closed_static_counter_patterns() {
    // Nonbootstrap counter values are structurally canonical but have no
    // claimed #84 predecessor or physical row effect in this codec test.
    for (kind, records, logical) in [
        (1, 0, 0), // Bootstrap S1
        (2, 2, 3), // Create permits extra logical effects
        (3, 2, 2), // DeleteRecords
        (4, 0, 1), // IndexPut
        (5, 0, 1), // IndexDelete
        (6, 1, 2), // DeleteWithIndexCleanup
    ] {
        let (frame, context) = record_kind_frame(kind, records, logical);
        assert_eq!(frame[74], kind);
        assert_eq!(
            u32::from_le_bytes(frame[148..152].try_into().expect("records")),
            records
        );
        assert_eq!(
            u32::from_le_bytes(frame[152..156].try_into().expect("logical")),
            logical
        );
        assert_eq!(
            decode_complete_frame(&frame, &context),
            Ok(expected_frame(&frame, &context, FrameKind::Record, 0)),
            "PRR1 kind {kind}"
        );
    }
}

#[test]
fn prr1_rejects_unknown_version_flags_epoch_kind_and_bootstrap_counters() {
    let (bootstrap, context) = record_kind_frame(1, 0, 0);
    for (name, offset, replacement) in [
        ("codec", 72, 2),
        ("codec high", 73, 1),
        ("flags", 75, 1),
        ("epoch", 92, 2),
        ("kind zero", 74, 0),
        ("kind seven", 74, 7),
    ] {
        reject_resealed(&bootstrap, &context, name, |bytes| {
            bytes[offset] = replacement;
        });
    }
    for (name, offset) in [
        ("prior RID", 100),
        ("new RID", 108),
        ("prior compatibility sequence", 116),
        ("new compatibility sequence", 124),
        ("prior append ordinal", 132),
        ("new append ordinal", 140),
        ("record count", 148),
        ("logical entry count", 152),
    ] {
        reject_resealed(&bootstrap, &context, name, |bytes| {
            bytes[offset] = 1;
        });
    }

    let (mut late_bootstrap, mut late_context) = record_kind_frame(1, 0, 0);
    let (previous, _, _) = case("record_bootstrap");
    late_context.expected_sequence = 2;
    late_context.previous_hash = previous[previous.len() - 32..]
        .try_into()
        .expect("previous trailer");
    late_bootstrap[12..20].copy_from_slice(&2_u64.to_le_bytes());
    late_bootstrap[32..64].copy_from_slice(&late_context.previous_hash);
    reseal(&mut late_bootstrap, &late_context);
    assert_eq!(
        decode_complete_frame(&late_bootstrap, &late_context),
        Err(FrameError::Corrupt),
        "PRR1 Bootstrap requires S1"
    );
}

#[test]
fn prr1_nonbootstrap_arithmetic_and_kind_specific_counts_refuse_when_resealed() {
    let (create, context) = record_kind_frame(2, 2, 3);
    reject_resealed(&create, &context, "nonbootstrap PRR1 epoch", |bytes| {
        bytes[92] = 2;
    });
    let mut wrong_context = context;
    wrong_context.database_id[0] ^= 1;
    assert_eq!(
        decode_complete_frame(&create, &wrong_context),
        Err(FrameError::Corrupt),
        "nonbootstrap PRR1 also binds H80 database identity"
    );
    let mut first_create = create.clone();
    let mut first_context = context;
    first_context.expected_sequence = 1;
    first_context.previous_hash = context.header_digest;
    first_create[12..20].copy_from_slice(&1_u64.to_le_bytes());
    first_create[32..64].copy_from_slice(&first_context.previous_hash);
    reseal(&mut first_create, &first_context);
    assert_eq!(
        decode_complete_frame(&first_create, &first_context),
        Err(FrameError::Corrupt),
        "nonbootstrap PRR1 requires S>1"
    );
    reject_resealed(&create, &context, "Create RID addition", |bytes| {
        bytes[108..116].copy_from_slice(&13_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "Create logical below records", |bytes| {
        bytes[152..156].copy_from_slice(&1_u32.to_le_bytes());
        bytes[124..132].copy_from_slice(&21_u64.to_le_bytes());
        bytes[140..148].copy_from_slice(&41_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "Create requires records", |bytes| {
        // prior RID 10 + zero records == new RID 10; only the
        // Create-specific positive record_count rule is violated.
        bytes[148..152].copy_from_slice(&0_u32.to_le_bytes());
        bytes[108..116].copy_from_slice(&10_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "compatibility arithmetic", |bytes| {
        bytes[124..132].copy_from_slice(&24_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "append arithmetic", |bytes| {
        bytes[140..148].copy_from_slice(&44_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "compatibility overflow", |bytes| {
        bytes[116..124].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[124..132].copy_from_slice(&2_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "append overflow", |bytes| {
        bytes[132..140].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[140..148].copy_from_slice(&2_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "Create RID overflow", |bytes| {
        bytes[100..108].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[108..116].copy_from_slice(&1_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "nonbootstrap logical zero", |bytes| {
        bytes[152..156].copy_from_slice(&0_u32.to_le_bytes());
        bytes[124..132].copy_from_slice(&20_u64.to_le_bytes());
        bytes[140..148].copy_from_slice(&40_u64.to_le_bytes());
    });

    let (delete, context) = record_kind_frame(3, 2, 2);
    reject_resealed(&delete, &context, "DeleteRecords unchanged RID", |bytes| {
        bytes[108..116].copy_from_slice(&11_u64.to_le_bytes());
    });
    reject_resealed(&delete, &context, "DeleteRecords equal counts", |bytes| {
        bytes[148..152].copy_from_slice(&1_u32.to_le_bytes());
    });
    for kind in [4, 5] {
        let (index, context) = record_kind_frame(kind, 0, 1);
        reject_resealed(&index, &context, "Index kind record count", |bytes| {
            bytes[148..152].copy_from_slice(&1_u32.to_le_bytes());
        });
        reject_resealed(&index, &context, "Index kind logical count", |bytes| {
            bytes[152..156].copy_from_slice(&2_u32.to_le_bytes());
            bytes[124..132].copy_from_slice(&22_u64.to_le_bytes());
            bytes[140..148].copy_from_slice(&42_u64.to_le_bytes());
        });
        reject_resealed(&index, &context, "Index kind unchanged RID", |bytes| {
            bytes[108..116].copy_from_slice(&11_u64.to_le_bytes());
        });
    }
    let (cleanup, context) = record_kind_frame(6, 1, 2);
    reject_resealed(&cleanup, &context, "cleanup requires one record", |bytes| {
        bytes[148..152].copy_from_slice(&0_u32.to_le_bytes());
    });
    reject_resealed(&cleanup, &context, "cleanup needs two effects", |bytes| {
        bytes[152..156].copy_from_slice(&1_u32.to_le_bytes());
        bytes[124..132].copy_from_slice(&21_u64.to_le_bytes());
        bytes[140..148].copy_from_slice(&41_u64.to_le_bytes());
    });
    reject_resealed(&cleanup, &context, "cleanup unchanged RID", |bytes| {
        bytes[108..116].copy_from_slice(&11_u64.to_le_bytes());
    });
}

#[test]
fn catalog_controls_close_outer_nested_and_static_revision_fields() {
    let (bootstrap, context, _) = case("catalog_bootstrap");
    let mut late_bootstrap = bootstrap.clone();
    let mut late_context = context;
    late_context.expected_sequence = 2;
    late_context.previous_hash = bootstrap[bootstrap.len() - 32..]
        .try_into()
        .expect("previous trailer");
    late_bootstrap[12..20].copy_from_slice(&2_u64.to_le_bytes());
    late_bootstrap[32..64].copy_from_slice(&late_context.previous_hash);
    reseal(&mut late_bootstrap, &late_context);
    assert_eq!(
        decode_complete_frame(&late_bootstrap, &late_context),
        Err(FrameError::Corrupt),
        "PCB1 Bootstrap requires S1"
    );
    for (name, offset, replacement) in [
        ("PCB1 magic", 68, b'X'),
        ("PCB1 codec", 72, 2),
        ("PCB1 codec high", 73, 1),
        ("PCB1 flags", 74, 1),
        ("PCB1 flags high", 75, 1),
        ("PCB1 epoch", 92, 2),
        ("nested PRR1 magic", 100, b'X'),
        ("nested PRR1 codec", 104, 2),
        ("nested PRR1 codec high", 105, 1),
        ("nested PRR1 kind", 106, 2),
        ("nested PRR1 flags", 107, 1),
        ("nested PRR1 epoch", 124, 2),
    ] {
        reject_resealed(&bootstrap, &context, name, |bytes| {
            bytes[offset] = replacement;
        });
    }
    for (name, offset) in [
        ("nested prior RID", 132),
        ("nested new RID", 140),
        ("nested prior compatibility sequence", 148),
        ("nested new compatibility sequence", 156),
        ("nested prior append ordinal", 164),
        ("nested new append ordinal", 172),
        ("nested record count", 180),
        ("nested logical count", 184),
    ] {
        reject_resealed(&bootstrap, &context, name, |bytes| {
            bytes[offset] = 1;
        });
    }

    let (create, context, _) = case("catalog_create");
    for (name, offset, replacement) in [
        ("PCC1 magic", 68, b'X'),
        ("PCC1 codec", 72, 2),
        ("PCC1 codec high", 73, 1),
        ("PCC1 flags", 74, 1),
        ("PCC1 flags high", 75, 1),
        ("PCC1 epoch", 92, 2),
    ] {
        reject_resealed(&create, &context, name, |bytes| {
            bytes[offset] = replacement;
        });
    }
    reject_resealed(&create, &context, "prior revision nonzero", |bytes| {
        bytes[100..108].copy_from_slice(&0_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "new revision equals S", |bytes| {
        bytes[116..124].copy_from_slice(&3_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "new revision increases", |bytes| {
        // S and new revision remain 2; prior revision becomes 2, so only
        // the strict new_revision > prior_revision rule is violated.
        bytes[100..108].copy_from_slice(&2_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "collection count plus one", |bytes| {
        bytes[108..116].copy_from_slice(&1_u64.to_le_bytes());
    });
    reject_resealed(&create, &context, "collection count overflow", |bytes| {
        bytes[108..116].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[124..132].copy_from_slice(&0_u64.to_le_bytes());
    });
}

#[test]
fn typed_control_lengths_are_closed_even_when_total_frame_bytes_still_match() {
    for name in ["record_bootstrap", "catalog_bootstrap", "catalog_create"] {
        let (frame, context, _) = case(name);
        let declared = u32::from_le_bytes(frame[64..68].try_into().expect("control length"));
        reject_resealed(&frame, &context, name, |bytes| {
            bytes[64..68].copy_from_slice(&(declared + 1).to_le_bytes());
        });
    }
}

#[test]
fn ordinary_ordinals_follow_physical_order_without_a_control_slot() {
    let (user, context, _) = case("user_put");
    let mut two = user[..94].to_vec(); // H64 + control_len + one 26-byte Put.
    let mut second = user[68..94].to_vec();
    second[..4].copy_from_slice(&1_u32.to_le_bytes());
    two.extend_from_slice(&second);
    two[24..28].copy_from_slice(&2_u32.to_le_bytes());
    set_lengths(&mut two[..64], 56);
    two.extend_from_slice(&[0; 36]);
    reseal(&mut two, &context);
    assert_eq!(
        decode_complete_frame(&two, &context),
        Ok(UntrustedFrame {
            header: UntrustedH64 {
                kind: FrameKind::User,
                sequence: 2,
                ordinary_operations: 2,
                payload_len: 56,
                total_len: 156,
            },
            trailer: two[124..156].try_into().expect("trailer"),
        })
    );
    let mut duplicate = two.clone();
    duplicate[94..98].copy_from_slice(&0_u32.to_le_bytes());
    reseal(&mut duplicate, &context);
    assert_eq!(
        decode_complete_frame(&duplicate, &context),
        Err(FrameError::Corrupt)
    );
    let mut reversed = two;
    reversed[68..72].copy_from_slice(&1_u32.to_le_bytes());
    reversed[94..98].copy_from_slice(&0_u32.to_le_bytes());
    reseal(&mut reversed, &context);
    assert_eq!(
        decode_complete_frame(&reversed, &context),
        Err(FrameError::Corrupt)
    );
}

#[test]
fn zero_op_user_and_each_closed_operation_tag_decode_with_exact_lengths() {
    let (_, context, _) = case("user_put");
    let empty = user_frame(None, &context);
    assert_eq!(empty.len(), 104);
    assert_eq!(&empty[64..68], &0_u32.to_le_bytes());
    assert_eq!(
        decode_complete_frame(&empty, &context),
        Ok(expected_frame(&empty, &context, FrameKind::User, 0)),
        "zero-operation User is legal wire grammar"
    );

    for tag in [1, 2, 3, 4] {
        let operation = user_operation(tag, b"x");
        let frame = user_frame(Some(&operation), &context);
        assert_eq!(frame[72], tag);
        assert_eq!(&frame[68..72], &0_u32.to_le_bytes());
        assert_eq!(frame.len(), 104 + operation.len());
        assert_eq!(
            decode_complete_frame(&frame, &context),
            Ok(expected_frame(&frame, &context, FrameKind::User, 1)),
            "ordinary op tag {tag}"
        );
        let mut zero_generation = operation;
        zero_generation[5..13].copy_from_slice(&0_u64.to_le_bytes());
        let frame = user_frame(Some(&zero_generation), &context);
        assert_eq!(
            decode_complete_frame(&frame, &context),
            Err(FrameError::Corrupt),
            "op tag {tag} cannot use generation zero"
        );
    }

    let max_cf = user_operation(1, &[b'x'; 255]);
    let frame = user_frame(Some(&max_cf), &context);
    assert_eq!(&frame[81..83], &255_u16.to_le_bytes());
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Ok(expected_frame(&frame, &context, FrameKind::User, 1)),
        "255-byte UTF-8 CF boundary"
    );

    let utf8_cf = user_operation(1, "é".as_bytes());
    let frame = user_frame(Some(&utf8_cf), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Ok(expected_frame(&frame, &context, FrameKind::User, 1)),
        "well-formed multibyte CF name"
    );

    let mut empty_key_value = Vec::new();
    empty_key_value.extend_from_slice(&0_u32.to_le_bytes());
    empty_key_value.push(1); // Put
    empty_key_value.extend_from_slice(&1_u64.to_le_bytes());
    empty_key_value.extend_from_slice(&1_u16.to_le_bytes());
    empty_key_value.push(b'x');
    empty_key_value.extend_from_slice(&0_u32.to_le_bytes()); // empty key
    empty_key_value.extend_from_slice(&0_u32.to_le_bytes()); // empty value
    let frame = user_frame(Some(&empty_key_value), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Ok(expected_frame(&frame, &context, FrameKind::User, 1)),
        "zero-length key and value are legal"
    );
}

#[test]
fn tag_specific_fields_and_exact_payload_consumption_refuse_resealed_alternates() {
    let (source, context, _) = case("user_put");
    let put = user_operation(1, b"x");
    let delete = user_operation(2, b"x");
    let expiry = user_operation(3, b"x");
    let merge = user_operation(4, b"x");

    let mut missing_value_length = put.clone();
    missing_value_length.truncate(missing_value_length.len() - 5);
    let frame = user_frame(Some(&missing_value_length), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let mut missing_value_byte = put.clone();
    missing_value_byte.pop();
    let frame = user_frame(Some(&missing_value_byte), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let mut delete_with_value = delete.clone();
    delete_with_value.extend_from_slice(&1_u32.to_le_bytes());
    delete_with_value.push(b'v');
    let frame = user_frame(Some(&delete_with_value), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    assert_eq!(delete.len(), 21);
    let mut delete_with_expiry = delete;
    delete_with_expiry.extend_from_slice(&123_u64.to_le_bytes());
    assert_eq!(delete_with_expiry.len(), 29);
    let frame = user_frame(Some(&delete_with_expiry), &context);
    assert_eq!(frame.len(), 133);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt),
        "Delete has no expiry field"
    );

    let mut missing_expiry = expiry.clone();
    missing_expiry.truncate(missing_expiry.len() - 8);
    let frame = user_frame(Some(&missing_expiry), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    assert_eq!(expiry.len(), 34);
    let mut expiry_without_value = expiry;
    // For CF x/key k, the value length plus value is operation [21,26).
    // Retain the eight expiry bytes at [26,34), so only the value is absent.
    expiry_without_value.drain(21..26);
    assert_eq!(expiry_without_value.len(), 29);
    assert_eq!(&expiry_without_value[21..29], &123_u64.to_le_bytes());
    let frame = user_frame(Some(&expiry_without_value), &context);
    assert_eq!(frame.len(), 133);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt),
        "PutWithExpiry requires value before expiry"
    );

    let mut put_with_expiry = put.clone();
    put_with_expiry.extend_from_slice(&123_u64.to_le_bytes());
    let frame = user_frame(Some(&put_with_expiry), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let mut merge_without_value = merge.clone();
    merge_without_value.truncate(merge_without_value.len() - 5);
    let frame = user_frame(Some(&merge_without_value), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let mut merge_with_expiry = merge;
    merge_with_expiry.extend_from_slice(&123_u64.to_le_bytes());
    let frame = user_frame(Some(&merge_with_expiry), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let overlong_cf = user_operation(1, &[b'x'; 256]);
    let frame = user_frame(Some(&overlong_cf), &context);
    assert_eq!(&frame[81..83], &256_u16.to_le_bytes());
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let mut unknown_zero = put;
    unknown_zero[4] = 0;
    let frame = user_frame(Some(&unknown_zero), &context);
    assert_eq!(
        decode_complete_frame(&frame, &context),
        Err(FrameError::Corrupt)
    );

    let trailing = rewrite_payload(&source, &context, &[0, 0, 0, 0, 0xff], 0);
    assert_eq!(
        decode_complete_frame(&trailing, &context),
        Err(FrameError::Corrupt)
    );
    let mut put_with_trailing = source[64..94].to_vec();
    put_with_trailing.push(0xff);
    let trailing_after_put = rewrite_payload(&source, &context, &put_with_trailing, 1);
    assert_eq!(
        decode_complete_frame(&trailing_after_put, &context),
        Err(FrameError::Corrupt)
    );
    let second_user_control = rewrite_payload(&source, &context, &[0; 8], 0);
    assert_eq!(
        decode_complete_frame(&second_user_control, &context),
        Err(FrameError::Corrupt)
    );

    let (record, record_context, _) = case("record_bootstrap");
    let mut second_record_payload = record[64..156].to_vec();
    second_record_payload.extend_from_slice(&88_u32.to_le_bytes());
    second_record_payload.extend_from_slice(&record[68..156]);
    let second_record_control =
        rewrite_payload(&record, &record_context, &second_record_payload, 0);
    assert_eq!(
        decode_complete_frame(&second_record_control, &record_context),
        Err(FrameError::Corrupt),
        "a second typed control cannot be an ordinary operation"
    );
}
