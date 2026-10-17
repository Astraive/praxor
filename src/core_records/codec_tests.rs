use super::*;

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn source() -> &'static Path {
    Path::new("golden")
}

#[test]
fn exact_key_goldens_and_all_truncated_or_trailing_inputs() {
    let cases = [
        (Role::Meta, Key::Binding, "00"),
        (Role::Meta, Key::Allocator, "01"),
        (Role::Meta, Key::Descriptor(u32::MAX), "02 ffffffff"),
        (Role::Payload, Key::Payload(u64::MAX), "01 ffffffffffffffff"),
        (Role::State, Key::State(1), "01 0000000000000001"),
        (
            Role::Index,
            Key::Fact {
                index: 1,
                incarnation: 1,
                key: b"\0/x",
                raw_sequence: u64::MAX,
            },
            "01 00000001 0000000000000001 03000000 002f78 ffffffffffffffff",
        ),
        (
            Role::Index,
            Key::Head {
                index: u32::MAX,
                incarnation: 1,
                key: b"",
            },
            "02 ffffffff 0000000000000001 00000000",
        ),
    ];
    for (role, key, expected) in cases {
        let bytes = hex(expected);
        assert_eq!(key.encode().unwrap(), bytes);
        assert_eq!(Key::decode(role, &bytes, source()).unwrap(), key);
        for cut in 0..bytes.len() {
            assert!(
                Key::decode(role, &bytes[..cut], source()).is_err(),
                "{key:?} cut{cut}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Key::decode(role, &trailing, source()).is_err());
    }
    assert_eq!(Role::from_cf(Role::Meta.cf()), Some(Role::Meta));
    assert_eq!(Role::from_cf("default"), None);
    assert!(Key::decode(Role::Meta, &[3], source()).is_err());
    assert!(Key::Payload(0).encode().is_err());
    assert!(Key::Descriptor(0).encode().is_err());
    assert!(Key::decode(Role::Payload, &hex("01 0000000000000000"), source()).is_err());
    assert!(
        Key::decode(
            Role::Index,
            &hex("02 00000001 0000000000000001 ffffffff"),
            source()
        )
        .is_err()
    );
    assert!(
        Key::Head {
            index: 1,
            incarnation: 2,
            key: b""
        }
        .encode()
        .is_err()
    );
}

#[test]
fn exact_row_goldens_and_all_truncated_trailing_schema_or_flag_inputs() {
    let cases = [
        (
            Key::Binding,
            Row::Binding {
                database_id: [0x11; 16],
                descriptor_count: 2,
            },
            "50524d31 01000000 11111111111111111111111111111111 0100000000000000 01000000 02000000 04000000 01 0100000000000000 02 0200000000000000 03 0300000000000000 04 0400000000000000",
        ),
        (
            Key::Allocator,
            Row::Allocator(Allocator {
                last_rid: 3,
                compatibility_sequence: u64::MAX,
                append_ordinal: 7,
                live_count: 1,
                dead_count: 2,
                live_payload_bytes: 9,
            }),
            "50524131 01000000 0300000000000000 ffffffffffffffff 0700000000000000 0100000000000000 0200000000000000 0900000000000000",
        ),
        (
            Key::Descriptor(1),
            Row::Descriptor {
                name: "é",
                namespace: "",
            },
            "50524431 01000000 01010100 0100000000000000 02000000 c3a9 00000000 00000000",
        ),
        (
            Key::Payload(1),
            Row::Payload(b"\0/x"),
            "50525031 01000000 03000000 002f78",
        ),
        (
            Key::State(1),
            Row::State {
                live: true,
                payload_length: u64::MAX,
            },
            "50525331 01000000 01 00000000000000 ffffffffffffffff",
        ),
        (
            Key::State(1),
            Row::State {
                live: false,
                payload_length: 0,
            },
            "50525331 01000000 02 00000000000000 0000000000000000",
        ),
        (
            Key::Fact {
                index: 1,
                incarnation: 1,
                key: b"",
                raw_sequence: 0,
            },
            Row::Fact {
                append_ordinal: u64::MAX,
                decision: Decision::Put(u64::MAX),
            },
            "50524631 01000000 ffffffffffffffff 01 00000000000000 ffffffffffffffff",
        ),
        (
            Key::Head {
                index: 1,
                incarnation: 1,
                key: b"",
            },
            Row::Head {
                raw_sequence: 0,
                append_ordinal: 1,
                decision: Decision::Delete,
            },
            "50524831 01000000 0000000000000000 0100000000000000 02 00000000000000 0000000000000000",
        ),
    ];
    for (key, row, expected) in cases {
        let bytes = hex(expected);
        assert_eq!(row.encode().unwrap(), bytes);
        assert_eq!(Row::decode(&key, &bytes, source()).unwrap(), row);
        for cut in 0..bytes.len() {
            assert!(
                Row::decode(&key, &bytes[..cut], source()).is_err(),
                "{key:?} cut{cut}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Row::decode(&key, &trailing, source()).is_err());
        for offset in [0, 4, 6, 7] {
            let mut bad = bytes.clone();
            bad[offset] ^= 0x80;
            assert!(Row::decode(&key, &bad, source()).is_err());
        }
    }
}

#[test]
fn row_claims_utf8_reserved_and_counter_overflow_refuse_without_claimed_allocations() {
    assert!(
        Row::decode(
            &Key::Payload(1),
            &hex("50525031 01000000 ffffffff"),
            source()
        )
        .is_err()
    );
    assert!(
        Row::decode(
            &Key::Descriptor(1),
            &hex("50524431 01000000 01010100 0100000000000000 ffffffff"),
            source()
        )
        .is_err()
    );
    let mut row = Row::Descriptor {
        name: "x",
        namespace: "y",
    }
    .encode()
    .unwrap();
    row[24] = 0xff;
    assert!(Row::decode(&Key::Descriptor(1), &row, source()).is_err());
    let mut row = Row::State {
        live: true,
        payload_length: 0,
    }
    .encode()
    .unwrap();
    row[9] = 1;
    assert!(Row::decode(&Key::State(1), &row, source()).is_err());
    assert!(
        Row::State {
            live: false,
            payload_length: 1
        }
        .encode()
        .is_err()
    );
    assert!(
        Row::Fact {
            append_ordinal: 1,
            decision: Decision::Put(0)
        }
        .encode()
        .is_err()
    );
    assert!(
        Row::Allocator(Allocator {
            last_rid: 0,
            live_count: u64::MAX,
            dead_count: 1,
            ..Allocator::default()
        })
        .encode()
        .is_err()
    );
    let mut binding = Row::Binding {
        database_id: [1; 16],
        descriptor_count: 0,
    }
    .encode()
    .unwrap();
    binding[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Row::decode(&Key::Binding, &binding, source()).is_err());
}

fn bootstrap() -> Envelope {
    Envelope {
        kind: Kind::Bootstrap,
        database_id: [0x11; 16],
        prior_rid: 0,
        new_rid: 0,
        prior_compatibility_sequence: 0,
        new_compatibility_sequence: 0,
        prior_append_ordinal: 0,
        new_append_ordinal: 0,
        record_count: 0,
        logical_entry_count: 0,
    }
}

#[test]
fn exact_envelope_golden_and_all_cuts_reserved_unknown_or_overflow() {
    let value = bootstrap();
    let bytes = hex(
        "50525231 0100 01 00 11111111111111111111111111111111 0100000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 00000000 00000000",
    );
    assert_eq!(bytes.len(), Envelope::LEN);
    assert_eq!(value.encode(1).unwrap(), bytes);
    assert_eq!(Envelope::decode(&bytes, 1, source()).unwrap(), value);
    for cut in 0..bytes.len() {
        assert!(Envelope::decode(&bytes[..cut], 1, source()).is_err());
    }
    for offset in [0, 4, 6, 7, 24, 80, 84] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0x80;
        assert!(Envelope::decode(&bad, 1, source()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Envelope::decode(&trailing, 1, source()).is_err());
    assert!(value.encode(2).is_err());
    let mut value = value;
    value.kind = Kind::Create;
    value.new_rid = 1;
    value.record_count = 1;
    value.logical_entry_count = 1;
    value.new_compatibility_sequence = 1;
    value.new_append_ordinal = 1;
    assert_eq!(
        Envelope::decode(&value.encode(2).unwrap(), 2, source()).unwrap(),
        value
    );
    value.prior_compatibility_sequence = u64::MAX;
    value.new_compatibility_sequence = 0;
    assert!(value.encode(2).is_err());
    value.prior_compatibility_sequence = 0;
    value.new_compatibility_sequence = 1;
    value.prior_rid = u64::MAX;
    value.new_rid = 0;
    assert!(value.encode(2).is_err());
}

#[test]
fn each_nonbootstrap_kind_has_exact_count_and_delta_rules() {
    for kind in [
        Kind::Create,
        Kind::DeleteRecords,
        Kind::IndexPut,
        Kind::IndexDelete,
        Kind::DeleteWithIndexCleanup,
    ] {
        let primary = matches!(
            kind,
            Kind::Create | Kind::DeleteRecords | Kind::DeleteWithIndexCleanup
        );
        let logical = if kind == Kind::DeleteWithIndexCleanup {
            2
        } else {
            1
        };
        let value = Envelope {
            kind,
            database_id: [1; 16],
            prior_rid: 1,
            new_rid: if kind == Kind::Create { 2 } else { 1 },
            prior_compatibility_sequence: u64::MAX - logical,
            new_compatibility_sequence: u64::MAX,
            prior_append_ordinal: u64::MAX - logical,
            new_append_ordinal: u64::MAX,
            record_count: u32::from(primary),
            logical_entry_count: logical as u32,
        };
        assert_eq!(
            Envelope::decode(&value.encode(u64::MAX).unwrap(), u64::MAX, source()).unwrap(),
            value
        );
        let mut bad = value.clone();
        bad.logical_entry_count = 0;
        assert!(bad.encode(2).is_err());
        let mut bad = value;
        bad.new_append_ordinal -= 1;
        assert!(bad.encode(2).is_err());
    }
}
