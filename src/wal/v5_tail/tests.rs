use super::{InstalledWalState, TailInspection, inspect_installed_v5_wal};
use crate::wal::v5_frame::{FrameContext, H64Inspection, inspect_h64_prefix};
use crate::wal::v5_header::{
    H80Descriptor, H80Error, PendingH80Inspection, inspect_pending_h80_file,
};
use serde_json::Value;

// Frozen R6 wire bytes. The classifier must not manufacture its own oracle.
const R6_VECTORS: &str = include_str!("../../../tests/fixtures/wal_v5_r6.json");
const GOLDEN_PATH: &str = "wal/00000000000000000001.wal";

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "frozen hex has whole bytes");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("frozen hex"))
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex_bytes(text).try_into().expect("frozen field width")
}

fn text_field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().expect("frozen vector field")
}

fn vectors() -> Value {
    serde_json::from_str(R6_VECTORS).expect("frozen R6 JSON")
}

fn descriptor(vectors: &Value) -> H80Descriptor<'static> {
    assert_eq!(text_field(vectors, "path"), GOLDEN_PATH);
    H80Descriptor {
        relative_path: GOLDEN_PATH,
        database_id: hex_array(text_field(vectors, "database_id")),
        writer_incarnation: hex_array(text_field(vectors, "writer_incarnation")),
        wal_id: 1,
        creation_nonce: hex_array(text_field(vectors, "nonce")),
        start_after_sequence: 0,
        header_digest: hex_array(text_field(vectors, "header_digest")),
    }
}

fn header(vectors: &Value) -> Vec<u8> {
    let bytes = hex_bytes(text_field(vectors, "header_hex"));
    assert_eq!(bytes.len(), 80);
    bytes
}

fn frame(vectors: &Value, name: &str) -> Vec<u8> {
    let bytes = hex_bytes(text_field(&vectors["frames"][name], "hex"));
    assert_eq!(
        bytes.len() as u64,
        vectors["frames"][name]["len"]
            .as_u64()
            .expect("frame length")
    );
    bytes
}

fn image(header: &[u8], complete_prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(header.len() + complete_prefix.len() + suffix.len());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(complete_prefix);
    bytes.extend_from_slice(suffix);
    bytes
}

fn inspect(
    image: &[u8],
    descriptor: &H80Descriptor<'_>,
    state: InstalledWalState,
    required_sequence_through: u64,
) -> TailInspection {
    inspect_installed_v5_wal(image, descriptor, state, required_sequence_through)
}

fn set_frame_payload_len(frame: &mut [u8], payload_len: u32) {
    frame[8..12].copy_from_slice(&(payload_len + 100).to_le_bytes());
    frame[28..32].copy_from_slice(&payload_len.to_le_bytes());
}

// Independent bitwise reference, not the historical IEEE checksum alias.
fn crc32c_reference(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn reseal_frame(frame: &mut [u8], context: &FrameContext) {
    let crc_at = frame.len() - 36;
    let crc = crc32c_reference(&frame[..crc_at]);
    frame[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"praxor/wal-frame/v5");
    hasher.update(&context.header_digest);
    hasher.update(&context.previous_hash);
    hasher.update(&frame[..crc_at + 4]);
    frame[crc_at + 4..].copy_from_slice(hasher.finalize().as_bytes());
}

#[test]
fn every_cut_of_all_four_frozen_frames_has_exact_active_status() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);

    for (name, prior) in [
        ("record_bootstrap", None),
        ("user_put", Some("record_bootstrap")),
        ("catalog_bootstrap", None),
        ("catalog_create", Some("catalog_bootstrap")),
    ] {
        let full = frame(&vectors, name);
        let complete_prefix = prior.map_or_else(Vec::new, |prior| frame(&vectors, prior));
        let prior_count = usize::from(prior.is_some());
        let prior_sequence = prior_count as u64;
        let at_boundary = image(&header, &complete_prefix, &[]);
        assert_eq!(
            inspect(
                &at_boundary,
                &descriptor,
                InstalledWalState::Active,
                prior_sequence,
            ),
            TailInspection::Complete {
                complete_frames: prior_count,
                last_sequence: prior_sequence,
            },
            "{name}: empty terminal suffix is complete, not a tear"
        );

        for cut in 1..full.len() {
            let visible = image(&header, &complete_prefix, &full[..cut]);
            assert_eq!(
                inspect(
                    &visible,
                    &descriptor,
                    InstalledWalState::Active,
                    prior_sequence,
                ),
                TailInspection::EligibleTerminalPrefix {
                    complete_frames: prior_count,
                    prefix_len: cut,
                },
                "{name}: canonical proper cut {cut} of {} bytes",
                full.len()
            );
        }

        let whole = image(&header, &complete_prefix, &full);
        assert_eq!(
            inspect(
                &whole,
                &descriptor,
                InstalledWalState::Active,
                prior_sequence,
            ),
            TailInspection::Complete {
                complete_frames: prior_count + 1,
                last_sequence: prior_sequence + 1,
            },
            "{name}: all frame bytes are complete, not a tear"
        );
    }
}

#[test]
fn active_sealed_and_pending_images_have_distinct_terminal_rules() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");

    assert!(matches!(
        inspect_pending_h80_file(Some(&header), &descriptor),
        Ok(PendingH80Inspection::Complete(_))
    ));
    for cut in 0..80 {
        assert_eq!(
            inspect_pending_h80_file(Some(&header[..cut]), &descriptor),
            Ok(PendingH80Inspection::ExactPrefix(cut)),
            "pending H80 cut {cut} is a header prefix only"
        );
        assert_eq!(
            inspect(&header[..cut], &descriptor, InstalledWalState::Active, 0),
            TailInspection::Corrupt,
            "installed active H80 cut {cut} cannot borrow pending rules"
        );
    }

    let header_only = image(&header, &[], &[]);
    assert_eq!(
        inspect(&header_only, &descriptor, InstalledWalState::Active, 0),
        TailInspection::Complete {
            complete_frames: 0,
            last_sequence: 0,
        }
    );
    assert_eq!(
        inspect(&header_only, &descriptor, InstalledWalState::Sealed, 0),
        TailInspection::Complete {
            complete_frames: 0,
            last_sequence: 0,
        }
    );

    let p = image(&header, &[], b"P");
    assert_eq!(
        inspect(&p, &descriptor, InstalledWalState::Active, 0),
        TailInspection::EligibleTerminalPrefix {
            complete_frames: 0,
            prefix_len: 1,
        },
        "P can begin the canonical next frame in an active WAL"
    );
    assert_eq!(
        inspect(&p, &descriptor, InstalledWalState::Sealed, 0),
        TailInspection::Corrupt,
        "sealed WALs have no tail allowance"
    );
    assert_eq!(
        inspect_pending_h80_file(Some(&p), &descriptor),
        Err(H80Error::Corrupt),
        "a pending WalCreate/Rotate file permits no frame byte after H80"
    );
    let whole = image(&header, &[], &record);
    assert_eq!(
        inspect_pending_h80_file(Some(&whole), &descriptor),
        Err(H80Error::Corrupt),
        "an entire frame is still forbidden in the pending file"
    );

    for cut in 1..record.len() {
        let partial = image(&header, &[], &record[..cut]);
        assert_eq!(
            inspect(&partial, &descriptor, InstalledWalState::Sealed, 0),
            TailInspection::Corrupt,
            "sealed Record frame cut {cut}"
        );
    }
    assert_eq!(
        inspect(&whole, &descriptor, InstalledWalState::Sealed, 0),
        TailInspection::Complete {
            complete_frames: 1,
            last_sequence: 1,
        }
    );
}

#[test]
fn impossible_prefixes_refuse_before_eof_even_when_h64_is_incomplete() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");

    let first = image(&header, &[], b"X");
    assert_eq!(
        inspect(&first, &descriptor, InstalledWalState::Active, 0),
        TailInspection::Corrupt,
        "X cannot begin a canonical PWF5 frame"
    );

    let mut wrong_version = record[..5].to_vec();
    wrong_version[4] = 0;
    assert_eq!(
        inspect(
            &image(&header, &[], &wrong_version),
            &descriptor,
            InstalledWalState::Active,
            0
        ),
        TailInspection::Corrupt,
        "visible version low byte 00 cannot complete to v5"
    );

    // Isolate R6's cut-29 joint equation: with zero ordinary operations,
    // total_len=104 permits payload_len=4, but visible low byte 05 does not.
    let mut inconsistent = user[..29].to_vec();
    inconsistent[8..12].copy_from_slice(&104_u32.to_le_bytes());
    inconsistent[24..28].copy_from_slice(&0_u32.to_le_bytes());
    inconsistent[28] = 5;
    assert_eq!(
        inspect(
            &image(&header, &record, &inconsistent),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "cut 29 has no payload length congruent with total_len=104"
    );

    // The first visible cf_len byte at [81] fixes the LE16 residue to 0
    // modulo 256. No value in the closed 1..=255 range can complete it.
    let mut impossible_name_len = user[..82].to_vec();
    assert_eq!(impossible_name_len[81], 1);
    impossible_name_len[81] = 0;
    assert_eq!(
        inspect(
            &image(&header, &record, &impossible_name_len),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "LE16 name-length residue zero has no legal completion"
    );

    let mut impossible_control_len = record[..65].to_vec();
    assert_eq!(impossible_control_len[64], 88);
    impossible_control_len[64] = 0;
    assert_eq!(
        inspect(
            &image(&header, &[], &impossible_control_len),
            &descriptor,
            InstalledWalState::Active,
            0,
        ),
        TailInspection::Corrupt,
        "Record control length is exactly 88, even as a partial LE32"
    );

    let context = FrameContext {
        header_digest: descriptor.header_digest,
        previous_hash: descriptor.header_digest,
        expected_sequence: 1,
        database_id: descriptor.database_id,
    };
    assert_eq!(
        inspect_h64_prefix(&record[..1], &context),
        Ok(H64Inspection::IncompleteUnclassified),
        "the H64 seam does not classify a terminal tear"
    );
}

#[test]
fn visible_crc_trailer_and_next_frame_conflicts_are_corrupt() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");

    let crc_at = record.len() - 36;
    let mut bad_crc = record[..crc_at + 1].to_vec();
    bad_crc[crc_at] ^= 1;
    assert_eq!(
        inspect(
            &image(&header, &[], &bad_crc),
            &descriptor,
            InstalledWalState::Active,
            0
        ),
        TailInspection::Corrupt,
        "the first visible CRC byte is already determined by complete H64+payload"
    );
    let mut bad_trailer = record[..crc_at + 5].to_vec();
    bad_trailer[crc_at + 4] ^= 1;
    assert_eq!(
        inspect(
            &image(&header, &[], &bad_trailer),
            &descriptor,
            InstalledWalState::Active,
            0
        ),
        TailInspection::Corrupt,
        "the first visible trailer byte is already determined after CRC"
    );
    let mut complete_bad_crc = record.clone();
    complete_bad_crc[crc_at] ^= 1;
    assert_eq!(
        inspect(
            &image(&header, &[], &complete_bad_crc),
            &descriptor,
            InstalledWalState::Active,
            0,
        ),
        TailInspection::Corrupt,
        "a complete bad frame is not a tear"
    );

    assert_eq!(
        inspect(
            &image(&header, &record, b"X"),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "a malformed next-frame byte cannot be hidden by the prior valid frame"
    );
}

#[test]
fn required_retained_sequence_cannot_be_hidden_by_a_terminal_prefix() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");

    assert_eq!(
        inspect(
            &image(&header, &[], &record[..1]),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "required S1 cannot be replaced by its one-byte prefix"
    );
    assert_eq!(
        inspect(
            &image(&header, &record, &user[..1]),
            &descriptor,
            InstalledWalState::Active,
            2,
        ),
        TailInspection::Corrupt,
        "required S2 cannot be hidden by a terminal suffix after S1"
    );
    assert_eq!(
        inspect(
            &image(&header, &record, &[]),
            &descriptor,
            InstalledWalState::Active,
            2,
        ),
        TailInspection::Corrupt,
        "required S2 cannot disappear at a clean EOF either"
    );
}

#[test]
fn visible_h64_chain_kind_and_reserved_conflicts_refuse_as_prefixes() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");

    for (name, source, cut, offset, replacement, prior, required) in [
        ("version", &record, 5, 4, 0, None, 0),
        ("flags", &record, 7, 6, 1, None, 0),
        ("kind", &record, 21, 20, 0xff, None, 0),
        ("reserved", &record, 22, 21, 1, None, 0),
        ("sequence", &user, 13, 12, 3, Some(&record), 1),
        ("previous hash", &user, 33, 32, 0, Some(&record), 1),
    ] {
        let mut bad = source[..cut].to_vec();
        assert_ne!(bad[offset], replacement, "{name} mutation is effective");
        bad[offset] = replacement;
        let prior = prior.map_or(&[][..], Vec::as_slice);
        assert_eq!(
            inspect(
                &image(&header, prior, &bad),
                &descriptor,
                InstalledWalState::Active,
                required,
            ),
            TailInspection::Corrupt,
            "{name} visible at cut {cut} cannot become a canonical H64"
        );
    }
}

#[test]
fn operation_prefix_residues_and_utf8_feasibility_are_decided_jointly() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");

    for (name, cut, start, bytes) in [
        ("wrong first ordinal", 69, 68, &[1][..]),
        ("unknown operation tag", 73, 72, &[0xff][..]),
        ("zero generation", 81, 73, &[0; 8][..]),
        ("invalid UTF-8 lead", 84, 83, &[0xff][..]),
    ] {
        let mut bad = user[..cut].to_vec();
        bad[start..start + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            inspect(
                &image(&header, &record, &bad),
                &descriptor,
                InstalledWalState::Active,
                1,
            ),
            TailInspection::Corrupt,
            "{name} cannot be completed even before the payload ends"
        );
    }

    let mut unfinishable_utf8 = user[..84].to_vec();
    assert_eq!(&unfinishable_utf8[81..83], &1_u16.to_le_bytes());
    unfinishable_utf8[83] = 0xc3;
    assert_eq!(
        inspect(
            &image(&header, &record, &unfinishable_utf8),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "a valid UTF-8 lead cannot finish within a one-byte name"
    );

    let mut extendable_utf8 = user[..84].to_vec();
    set_frame_payload_len(&mut extendable_utf8, 31);
    extendable_utf8[81..83].copy_from_slice(&2_u16.to_le_bytes());
    extendable_utf8[83] = 0xc3;
    assert_eq!(
        inspect(
            &image(&header, &record, &extendable_utf8),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::EligibleTerminalPrefix {
            complete_frames: 1,
            prefix_len: 84,
        },
        "one visible multibyte lead can be completed within the name length"
    );

    let mut impossible_key_len = user[..87].to_vec();
    set_frame_payload_len(&mut impossible_key_len, 1_048_606);
    impossible_key_len[84..87].copy_from_slice(&[1, 0, 16]);
    assert_eq!(
        inspect(
            &image(&header, &record, &impossible_key_len),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "LE key-length residue 1,048,577 exceeds the 1-MiB cap"
    );

    let mut impossible_value_budget = user[..93].to_vec();
    set_frame_payload_len(&mut impossible_value_budget, 67_108_864);
    impossible_value_budget[89..93].copy_from_slice(&67_108_865_u32.to_le_bytes());
    assert_eq!(
        inspect(
            &image(&header, &record, &impossible_value_budget),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "visible value length cannot fit inside the 64-MiB payload cap"
    );
}

#[test]
fn complete_resealed_bad_control_and_operation_never_become_terminal_tears() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");
    let first_context = FrameContext {
        header_digest: descriptor.header_digest,
        previous_hash: descriptor.header_digest,
        expected_sequence: 1,
        database_id: descriptor.database_id,
    };
    let next_context = FrameContext {
        header_digest: descriptor.header_digest,
        previous_hash: record[record.len() - 32..].try_into().expect("trailer"),
        expected_sequence: 2,
        database_id: descriptor.database_id,
    };

    let mut unchanged_record = record.clone();
    reseal_frame(&mut unchanged_record, &first_context);
    assert_eq!(unchanged_record, record, "resealer matches frozen S1 bytes");
    let mut unchanged_user = user.clone();
    reseal_frame(&mut unchanged_user, &next_context);
    assert_eq!(unchanged_user, user, "resealer matches frozen S2 bytes");

    let mut bad_control = record.clone();
    bad_control[74] = 0xff; // PRR1 control kind is closed.
    reseal_frame(&mut bad_control, &first_context);
    assert_eq!(
        inspect(
            &image(&header, &[], &bad_control),
            &descriptor,
            InstalledWalState::Active,
            0,
        ),
        TailInspection::Corrupt,
        "a complete hash-valid frame with unknown control kind is corrupt"
    );

    let mut bad_operation = user.clone();
    bad_operation[72] = 0xff; // Ordinary operation tag is closed.
    reseal_frame(&mut bad_operation, &next_context);
    assert_eq!(
        inspect(
            &image(&header, &record, &bad_operation),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "a complete hash-valid frame with unknown operation is corrupt"
    );

    let mut bad_trailer = record;
    let trailer_at = bad_trailer.len() - 32;
    bad_trailer[trailer_at] ^= 1;
    assert_eq!(
        inspect(
            &image(&header, &[], &bad_trailer),
            &descriptor,
            InstalledWalState::Active,
            0,
        ),
        TailInspection::Corrupt,
        "a complete bad trailer is not an eligible prefix"
    );
}

#[test]
fn impossible_h64_count_and_payload_cap_refuse_without_body_allocation() {
    let vectors = vectors();
    let descriptor = descriptor(&vectors);
    let header = header(&vectors);
    let record = frame(&vectors, "record_bootstrap");
    let user = frame(&vectors, "user_put");

    let mut impossible_count = user[..64].to_vec();
    set_frame_payload_len(&mut impossible_count, 4);
    assert_eq!(
        inspect(
            &image(&header, &record, &impossible_count),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "one ordinary operation cannot fit in a four-byte payload"
    );

    let mut oversized = user[..64].to_vec();
    set_frame_payload_len(&mut oversized, 67_108_865);
    assert_eq!(
        inspect(
            &image(&header, &record, &oversized),
            &descriptor,
            InstalledWalState::Active,
            1,
        ),
        TailInspection::Corrupt,
        "a 64-MiB-plus-one payload is impossible without allocating it"
    );
}
