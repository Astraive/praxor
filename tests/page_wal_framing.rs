use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::io::crc32_ieee;
use praxis::wal::page::{PageWalFileFormat, PageWalScanStop};
use praxis::wal::{PageWal, PageWalMutation, PageWalRecord};

fn delete(sequence: u64) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Delete {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(sequence.max(1)),
        },
    }
}

// An independent legacy byte constructor: public encode changes to v2 in #39.
fn legacy_payload(payload: &[u8]) -> Vec<u8> {
    let mut bytes = 0x5450_5752_u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn legacy_delete(sequence: u64) -> Vec<u8> {
    let mut payload = sequence.to_le_bytes().to_vec();
    payload.push(2);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&2_u32.to_le_bytes());
    payload.extend_from_slice(&sequence.max(1).to_le_bytes());
    legacy_payload(&payload)
}

fn legacy_file(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = 0x5450_5746_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    for frame in frames {
        bytes.extend_from_slice(frame);
    }
    bytes
}

fn assert_strict_refusal(bytes: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("page.wal");
    std::fs::write(&path, bytes).unwrap();
    assert!(
        PageWal::replay(&path).is_err(),
        "strict replay accepted an incomplete or invalid {}-byte file",
        bytes.len()
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn public_replay_refuses_final_and_middle_crc_corruption() {
    for count in [2, 3] {
        let mut bytes = legacy_file(&(1..=count).map(legacy_delete).collect::<Vec<_>>());
        bytes[16 + 38 + 9] ^= 1;
        assert_strict_refusal(&bytes);
    }
}

#[test]
fn intact_legacy_body_does_not_allow_an_increased_outer_length() {
    let mut bytes = legacy_file(&[legacy_delete(1), legacy_delete(2)]);
    assert_eq!(bytes.len(), 92);
    bytes[16 + 38 + 5..16 + 38 + 9].copy_from_slice(&153_u32.to_le_bytes());
    assert_strict_refusal(&bytes);
}

#[test]
fn exact_record_decode_refuses_trailing_frame_bytes() {
    let mut bytes = legacy_delete(1);
    bytes.push(0x42);
    assert!(PageWalRecord::decode(&bytes, "legacy-frame").is_err());
}

#[test]
fn short_garbage_is_not_an_empty_headerless_wal() {
    assert_strict_refusal(&[0x42]);
}

#[test]
fn legacy_file_reserved_bytes_must_be_zero() {
    let mut bytes = legacy_file(&[legacy_delete(1)]);
    bytes[8] = 1;
    assert_strict_refusal(&bytes);
}

#[test]
fn public_replay_enforces_identity_and_monotone_sequences() {
    for frames in [
        vec![legacy_delete(0)],
        vec![legacy_delete(1), legacy_delete(1)],
        vec![legacy_delete(2), legacy_delete(1)],
    ] {
        assert_strict_refusal(&legacy_file(&frames));
    }
}

#[test]
fn public_encode_checks_the_new_write_cap_before_encoding() {
    // Modest actual allocation, not a forged Vec or a multi-GiB claimed count.
    let record = PageWalRecord {
        sequence: 1,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(1),
            fields: vec![(FieldId::Fixed(Aid(1)), vec![7; 64 * 1024 * 1024])],
        },
    };
    assert!(
        std::panic::catch_unwind(|| record.encode()).is_err(),
        "source-compatible encode wrapper accepted an oversized new record"
    );
}

#[test]
fn valid_legacy_files_and_headerless_records_still_decode() {
    let frames = [legacy_delete(1), legacy_delete(3)];
    let expected = vec![delete(1), delete(3)];
    assert_eq!(
        PageWalRecord::decode(&frames[0], "legacy-frame").unwrap(),
        expected[0]
    );
    for bytes in [legacy_file(&frames), frames.concat()] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.wal");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(PageWal::replay(&path).unwrap(), expected);
    }
}

#[test]
fn already_fixed_count_narrowing_and_payload_consumption_stay_rejected() {
    let mut base = 1_u64.to_le_bytes().to_vec();
    base.push(1);
    base.extend_from_slice(&1_u32.to_le_bytes());
    base.extend_from_slice(&2_u32.to_le_bytes());
    base.extend_from_slice(&1_u64.to_le_bytes());
    let mut count = base.clone();
    count.extend_from_slice(&65_536_u32.to_le_bytes());
    assert!(PageWalRecord::decode(&legacy_payload(&count), "legacy-frame").is_err());
    for tag in [1, 2] {
        let mut field = base.clone();
        field.extend_from_slice(&1_u32.to_le_bytes());
        field.push(tag);
        field.extend_from_slice(&0x1_0001_u32.to_le_bytes());
        field.extend_from_slice(&0_u32.to_le_bytes());
        assert!(PageWalRecord::decode(&legacy_payload(&field), "legacy-frame").is_err());
    }
    let mut trailing = legacy_delete(1)[13..].to_vec();
    trailing.push(0x42);
    assert!(PageWalRecord::decode(&legacy_payload(&trailing), "legacy-frame").is_err());
}

fn v2_file(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = 0x5450_5746_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(&bytes).to_le_bytes());
    for frame in frames {
        bytes.extend_from_slice(frame);
    }
    bytes
}

fn report(bytes: &[u8]) -> praxis::wal::page::PageWalReplayReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("page.wal");
    std::fs::write(&path, bytes).unwrap();
    let report = PageWal::replay_prefix(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    report
}

#[test]
fn forensic_report_distinguishes_a_valid_prefix_from_complete_history() {
    let mut bytes = legacy_file(&[legacy_delete(1), legacy_delete(2)]);
    bytes[16 + 38 + 9] ^= 1;
    let report = report(&bytes);
    assert_eq!(report.records, vec![delete(1)]);
    assert_eq!(report.valid_len, 54);
    assert_eq!(report.physical_len, 92);
    assert_eq!(report.file_format, PageWalFileFormat::LegacyV1);
    assert!(matches!(
        report.stop,
        PageWalScanStop::Corrupt { offset: 54, .. }
    ));
}

#[test]
fn unresolved_legacy_suffix_is_ambiguous_but_intact_wrong_length_is_corrupt() {
    let mut bytes = legacy_file(&[legacy_delete(1)]);
    let second = legacy_delete(2);
    bytes.extend_from_slice(&second[..20]);
    let partial = report(&bytes);
    assert!(matches!(
        partial.stop,
        PageWalScanStop::LegacyAmbiguousTail { offset: 54, .. }
    ));
    assert_eq!(partial.valid_len, 54);
    let mut wrong = legacy_file(&[legacy_delete(1), second]);
    wrong[59..63].copy_from_slice(&153_u32.to_le_bytes());
    assert!(matches!(
        report(&wrong).stop,
        PageWalScanStop::Corrupt { offset: 54, .. }
    ));
}

#[test]
fn v2_encode_authenticates_its_header_and_preserves_binary_payload() {
    let record = PageWalRecord {
        sequence: 3,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(9),
            fields: vec![(FieldId::Fixed(Aid(u16::MAX)), vec![0xff, 0, 0x80])],
        },
    };
    let bytes = record.try_encode().unwrap();
    assert_eq!(bytes.len(), record.checked_encoded_len().unwrap());
    assert_eq!(&bytes[..4], &0x5450_5732_u32.to_le_bytes());
    assert_eq!(bytes[4], 2);
    assert_eq!(
        u32::from_le_bytes(bytes[13..17].try_into().unwrap()),
        crc32_ieee(&bytes[..13])
    );
    assert_eq!(PageWalRecord::decode(&bytes, "v2").unwrap(), record);
    for index in 0..17 {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1;
        let bad = report(&v2_file(&[damaged]));
        assert!(
            !matches!(
                bad.stop,
                PageWalScanStop::Clean | PageWalScanStop::ProvenV2Torn { .. }
            ),
            "header byte {index}: {:?}",
            bad.stop
        );
    }
}

#[test]
fn every_v2_frame_cut_is_classified_without_strict_success_or_mutation() {
    let frame = delete(1).try_encode().unwrap();
    for cut in 1..frame.len() {
        let bytes = v2_file(&[frame[..cut].to_vec()]);
        let partial = report(&bytes);
        assert_eq!(partial.valid_len, 16);
        assert!(
            matches!(
                partial.stop,
                PageWalScanStop::ProvenV2Torn { offset: 16, .. }
            ),
            "cut {cut}: {:?}",
            partial.stop
        );
        assert_strict_refusal(&bytes);
    }
    assert!(matches!(
        report(&v2_file(&[frame])).stop,
        PageWalScanStop::Clean
    ));
}

#[test]
fn partial_v2_header_crc_contradictions_are_corrupt_not_torn() {
    let frame = delete(1).try_encode().unwrap();
    for cut in 14..17 {
        for damaged_at in 13..cut {
            let mut prefix = frame[..cut].to_vec();
            prefix[damaged_at] ^= 1;
            let report = report(&v2_file(&[prefix]));
            assert!(
                matches!(report.stop, PageWalScanStop::Corrupt { offset: 16, .. }),
                "cut {cut}, CRC byte {damaged_at}: {:?}",
                report.stop
            );
        }
    }
}

// Authenticate the complete extent before exposing only the supplied body prefix.
// The omitted bytes are concrete zeros, so no fixture depends on a forged buffer.
fn partial_v2_payload(payload: &[u8], declared_len: usize) -> Vec<u8> {
    assert!(payload.len() < declared_len);
    let mut complete = payload.to_vec();
    complete.resize(declared_len, 0);
    let mut frame = 0x5450_5732_u32.to_le_bytes().to_vec();
    frame.push(2);
    frame.extend_from_slice(&u32::try_from(declared_len).unwrap().to_le_bytes());
    frame.extend_from_slice(&crc32_ieee(&complete).to_le_bytes());
    frame.extend_from_slice(&crc32_ieee(&frame).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn binary_put(sequence: u64) -> PageWalRecord {
    PageWalRecord {
        sequence,
        mutation: PageWalMutation::Put {
            cid: Cid(1),
            eid: Eid(2),
            rid: Rid(3),
            fields: vec![
                (FieldId::Fixed(Aid(u16::MAX)), vec![0xff, 0, 0x80, 7]),
                (FieldId::Dynamic(praxis::identity::Did(2)), vec![0xfe, 0]),
            ],
        },
    }
}

#[test]
fn incomplete_v2_impossible_metadata_is_corrupt_at_each_complete_field() {
    let payload = binary_put(7).try_encode().unwrap()[17..].to_vec();
    let cases = [
        ("zero sequence", 0, 8, 0_u64.to_le_bytes().to_vec()),
        ("mutation tag", 8, 9, vec![3]),
        ("zero cid", 9, 13, 0_u32.to_le_bytes().to_vec()),
        ("zero eid", 13, 17, 0_u32.to_le_bytes().to_vec()),
        ("zero rid", 17, 25, 0_u64.to_le_bytes().to_vec()),
        ("field tag", 29, 30, vec![3]),
        ("fixed field id", 30, 34, 65_536_u32.to_le_bytes().to_vec()),
        (
            "dynamic field id",
            30,
            34,
            65_537_u32.to_le_bytes().to_vec(),
        ),
    ];
    let mut wrong = Vec::new();
    for (label, at, cut, value) in cases {
        let mut damaged = payload.clone();
        damaged[at..at + value.len()].copy_from_slice(&value);
        if label == "dynamic field id" {
            damaged[29] = 2;
        }
        let bytes = v2_file(&[partial_v2_payload(&damaged[..cut], payload.len())]);
        let found = report(&bytes);
        if !matches!(found.stop, PageWalScanStop::Corrupt { offset: 16, .. }) {
            wrong.push(format!("{label}: {:?}", found.stop));
        }
        assert_strict_refusal(&bytes);
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn incomplete_v2_extent_must_allow_an_exact_semantic_completion() {
    let payload = binary_put(7).try_encode().unwrap()[17..].to_vec();
    let mut impossible_count = payload[..29].to_vec();
    impossible_count[25..29].copy_from_slice(&4_u32.to_le_bytes());
    let mut impossible_value = payload[..38].to_vec();
    impossible_value[34..38].copy_from_slice(&5_u32.to_le_bytes());
    let mut empty_put = payload[..29].to_vec();
    empty_put[25..29].copy_from_slice(&0_u32.to_le_bytes());
    let cases = [
        ("count cannot fit", impossible_count, 55),
        // Five value bytes fit the immediate remaining extent, but leave only
        // eight bytes for the second field's mandatory nine-byte header.
        ("value leaves no next header", impossible_value, 51),
        (
            "delete has extra extent",
            legacy_delete(7)[13..22].to_vec(),
            26,
        ),
        ("complete put before declared end", empty_put, 30),
        ("put cannot fit fixed prefix", payload[..9].to_vec(), 25),
    ];
    let mut wrong = Vec::new();
    for (label, prefix, declared) in cases {
        let bytes = v2_file(&[partial_v2_payload(&prefix, declared)]);
        let found = report(&bytes);
        if !matches!(found.stop, PageWalScanStop::Corrupt { offset: 16, .. }) {
            wrong.push(format!("{label}: {:?}", found.stop));
        }
        assert_strict_refusal(&bytes);
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn incomplete_v2_complete_sequence_must_follow_the_valid_prefix() {
    let first = delete(7).try_encode().unwrap();
    for sequence in [1, 7] {
        let frame = binary_put(sequence).try_encode().unwrap();
        let bytes = v2_file(&[first.clone(), frame[..25].to_vec()]);
        let found = report(&bytes);
        assert_eq!(found.records, vec![delete(7)]);
        assert_eq!(found.valid_len, 58);
        assert!(
            matches!(found.stop, PageWalScanStop::Corrupt { offset: 58, .. }),
            "sequence {sequence}: {:?}",
            found.stop
        );
        assert_strict_refusal(&bytes);
    }
}

#[test]
fn every_true_v2_put_cut_including_binary_values_remains_torn() {
    // Include high-byte-only sequence/identities so incomplete all-zero integer
    // prefixes remain eligible for a nonzero completion.
    let mut record = binary_put(1 << 56);
    let PageWalMutation::Put { cid, eid, rid, .. } = &mut record.mutation else {
        unreachable!()
    };
    *cid = Cid(1 << 24);
    *eid = Eid(1 << 24);
    *rid = Rid(1 << 56);
    let frame = record.try_encode().unwrap();
    for cut in 1..frame.len() {
        let bytes = v2_file(&[frame[..cut].to_vec()]);
        let found = report(&bytes);
        assert!(
            matches!(found.stop, PageWalScanStop::ProvenV2Torn { offset: 16, .. }),
            "cut {cut}: {:?}",
            found.stop
        );
        assert_strict_refusal(&bytes);
    }
    assert_eq!(report(&v2_file(&[frame])).records, vec![record]);
}

#[test]
fn unauthenticated_legacy_invalid_prefixes_remain_ambiguous() {
    let payload = binary_put(7).try_encode().unwrap()[17..].to_vec();
    let mut zero_sequence = payload[..8].to_vec();
    zero_sequence.fill(0);
    let mut bad_tag = payload[..9].to_vec();
    bad_tag[8] = 3;
    let mut bad_count = payload[..29].to_vec();
    bad_count[25..29].copy_from_slice(&u32::MAX.to_le_bytes());
    for prefix in [zero_sequence, bad_tag, bad_count] {
        let mut frame = legacy_payload(&prefix);
        frame[5..9].copy_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        for bytes in [legacy_file(&[frame.clone()]), frame] {
            let found = report(&bytes);
            assert!(
                matches!(found.stop, PageWalScanStop::LegacyAmbiguousTail { .. }),
                "{:?}",
                found.stop
            );
            assert_strict_refusal(&bytes);
        }
    }
}

#[test]
fn file_header_cuts_preserve_v1_v2_ambiguity_until_version_is_known() {
    let header = v2_file(&[]);
    for cut in 1..header.len() {
        let partial = report(&header[..cut]);
        if cut <= 4 {
            assert!(matches!(
                partial.stop,
                PageWalScanStop::LegacyAmbiguousTail { .. }
            ));
        } else {
            assert!(matches!(partial.stop, PageWalScanStop::ProvenV2Torn { .. }));
        }
    }
    for cut in 1..16 {
        assert!(matches!(
            report(&legacy_file(&[])[..cut]).stop,
            PageWalScanStop::LegacyAmbiguousTail { .. }
        ));
    }
    let mut flags = header;
    flags[8] = 1;
    let crc = crc32_ieee(&flags[..12]);
    flags[12..16].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(
        report(&flags).stop,
        PageWalScanStop::Unsupported { .. }
    ));
}

#[test]
fn v2_barrier_allows_legacy_prefix_but_never_v1_after_v2() {
    let frames = [legacy_delete(1), delete(2).try_encode().unwrap()];
    let mixed = report(&v2_file(&frames));
    assert!(matches!(mixed.stop, PageWalScanStop::Clean));
    assert_eq!(mixed.records, vec![delete(1), delete(2)]);
    let mut invalid = frames.to_vec();
    invalid.push(legacy_delete(3));
    assert!(matches!(
        report(&v2_file(&invalid)).stop,
        PageWalScanStop::Corrupt { .. }
    ));
    invalid.pop();
    invalid.push(legacy_delete(3)[..7].to_vec());
    assert!(matches!(
        report(&v2_file(&invalid)).stop,
        PageWalScanStop::Corrupt { .. }
    ));
    assert_strict_refusal(&legacy_file(&[delete(1).try_encode().unwrap()]));
    assert_strict_refusal(&delete(1).try_encode().unwrap());
}

#[test]
fn missing_and_existing_empty_reports_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.wal");
    assert!(PageWal::replay(&path).unwrap().is_empty());
    let missing = PageWal::replay_prefix(&path).unwrap();
    assert_eq!(missing.file_format, PageWalFileFormat::Missing);
    assert!(!path.exists());
    assert_eq!(report(&[]).file_format, PageWalFileFormat::Empty);
}

#[test]
fn v2_length_is_authenticated_before_limit_or_tail_classification() {
    let mut frame = delete(1).try_encode().unwrap();
    assert_eq!(&frame[17..], &legacy_delete(1)[13..]);
    frame[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    let corrupt_header = report(&v2_file(&[frame.clone()]));
    let PageWalScanStop::Corrupt { reason, .. } = corrupt_header.stop else {
        panic!("header corruption expected")
    };
    assert!(reason.contains("header checksum"));
    let crc = crc32_ieee(&frame[..13]);
    frame[13..17].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(
        report(&v2_file(&[frame])).stop,
        PageWalScanStop::Corrupt { .. }
    ));
}

#[test]
fn valid_legacy_payload_above_new_cap_remains_readable() {
    let mut payload = 1_u64.to_le_bytes().to_vec();
    payload.push(1);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&2_u32.to_le_bytes());
    payload.extend_from_slice(&1_u64.to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.push(1);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    let len = 64 * 1024 * 1024;
    payload.extend_from_slice(&(len as u32).to_le_bytes());
    payload.resize(payload.len() + len, 7);
    let frame = legacy_payload(&payload);
    drop(payload);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.wal");
    std::fs::write(&path, &frame).unwrap();
    drop(frame);
    let records = PageWal::replay(&path).unwrap();
    let PageWalMutation::Put { fields, .. } = &records[0].mutation else {
        panic!("put expected")
    };
    assert_eq!(fields[0].1.len(), len);
    assert!(records[0].try_encode().is_err());
}
