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
