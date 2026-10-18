use super::{
    FixtureBudgetDecodeError as BudgetError, FixtureDecodeReason as Reason, FixtureEncodeError,
    decode_document, decode_document_with_attribute_budget, encode_document,
};
use serde_json::{Number, Value};
use std::collections::BTreeMap;

// Independent, full-frame wire oracles. Never derive these from encode_document.
const A: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x03a:b\x00\x01c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
const B: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x01a\x00\x03b:c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
const C: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x19\x00\x01u\x00\x02\xc3\xa9\x00\x00";
const D: &[u8] =
    b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x17\x00\x01u\x00\x00\x00\x00";

fn attributes() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("n".into(), Value::Null),
        ("v".into(), Value::Number(Number::from(7_u64))),
    ])
}

#[test]
fn budget_decoder_accepts_exact_allowance_and_zero_attribute_frames() {
    for (wire, collection, key, allowance, count) in [
        (A, "a:b", "c", 2, 2),
        (B, "a", "b:c", 2, 2),
        (C, "u", "é", 0, 0),
        (D, "u", "", 0, 0),
    ] {
        let (record, used) = decode_document_with_attribute_budget(wire, allowance).unwrap();
        assert_eq!(used, count);
        assert_eq!(record.attributes.len(), count);
        assert_eq!(
            (record.id.collection.as_str(), record.id.key.as_str()),
            (collection, key)
        );
    }
    for wire in [A, B] {
        assert_eq!(
            decode_document_with_attribute_budget(wire, 1),
            Err(BudgetError::AttributeBudget)
        );
        assert_eq!(
            decode_document_with_attribute_budget(wire, 0),
            Err(BudgetError::AttributeBudget)
        );
    }
    // The unbudgeted codec's behavior remains unchanged.
    assert_eq!(decode_document(A).unwrap().attributes, attributes());
}

#[test]
fn budget_decoder_retains_outer_count_and_later_entry_precedence() {
    let mut wrong_declared_length = A.to_vec();
    wrong_declared_length[15] = 43;
    assert_eq!(
        decode_document_with_attribute_budget(&wrong_declared_length, 0),
        Err(BudgetError::Document(Reason::FrameLength))
    );
    let mut excessive_count = A.to_vec();
    excessive_count[24..26].copy_from_slice(&257_u16.to_be_bytes());
    assert_eq!(
        decode_document_with_attribute_budget(&excessive_count, 0),
        Err(BudgetError::Document(Reason::InvalidAttributeCount))
    );
    let mut malformed_entry = A.to_vec();
    malformed_entry[33] = 6;
    assert_eq!(
        decode_document_with_attribute_budget(&malformed_entry, 1),
        Err(BudgetError::AttributeBudget)
    );
    assert_eq!(
        decode_document_with_attribute_budget(&malformed_entry, 2),
        Err(BudgetError::Document(Reason::UnknownValueTag))
    );
    assert_eq!(
        decode_document_with_attribute_budget(&A[..15], 0),
        Err(BudgetError::Document(Reason::Truncated))
    );
}

#[test]
fn literal_frames_decode_distinct_pairs_and_deterministic_records() {
    for (wire, collection, key, expected) in [
        (A, "a:b", "c", attributes()),
        (B, "a", "b:c", attributes()),
        (C, "u", "é", BTreeMap::new()),
        (D, "u", "", BTreeMap::new()),
    ] {
        let record = decode_document(wire).unwrap();
        assert_eq!(
            (record.id.collection.as_str(), record.id.key.as_str()),
            (collection, key)
        );
        assert_eq!(record.attributes, expected);
        assert!(record.labels.is_empty());
        assert!(record.vectors.is_empty());
        assert!(record.edges.is_empty());
        assert_eq!((record.created_at_ms, record.updated_at_ms), (0, 0));
    }
}

#[test]
fn fixture_writer_matches_independent_full_frame_oracles() {
    for (collection, key, fields, wire) in [
        ("a:b", "c", attributes(), A),
        ("a", "b:c", attributes(), B),
        ("u", "é", BTreeMap::new(), C),
        ("u", "", BTreeMap::new(), D),
    ] {
        assert_eq!(encode_document(collection, key, &fields).unwrap(), wire);
    }
    let signed_origin = BTreeMap::from([("v".into(), Value::Number(Number::from(7_i64)))]);
    let encoded = encode_document("u", "", &signed_origin).unwrap();
    assert_eq!(
        encoded[26], 0x04,
        "nonnegative integers use the unsigned tag"
    );
}

#[test]
fn independently_mutated_frames_refuse_with_finite_reasons() {
    let mut cases: Vec<(Vec<u8>, Reason)> = Vec::new();
    let mut mutated = A.to_vec();
    mutated[0] = 0;
    cases.push((mutated, Reason::InvalidMagic));
    let mut mutated = A.to_vec();
    mutated[9] = 2;
    cases.push((mutated, Reason::UnsupportedVersion));
    let mut mutated = A.to_vec();
    mutated[11] = 1;
    cases.push((mutated, Reason::UnsupportedFlags));
    let mut mutated = A.to_vec();
    mutated[15] = 43;
    cases.push((mutated, Reason::FrameLength));
    let mut mutated = A.to_vec();
    mutated.push(0);
    cases.push((mutated, Reason::FrameLength));
    cases.push((A[..41].to_vec(), Reason::FrameLength));
    let mut mutated = A.to_vec();
    mutated[15] = 43;
    mutated.push(0);
    cases.push((mutated, Reason::TrailingBytes));
    let mut mutated = A.to_vec();
    mutated[25] = 3;
    cases.push((mutated, Reason::Truncated));
    let mut mutated = C.to_vec();
    mutated[22] = 0;
    cases.push((mutated, Reason::InvalidUtf8));
    let mut mutated = A.to_vec();
    mutated[33] = 6;
    cases.push((mutated, Reason::UnknownValueTag));
    let mut mutated = A.to_vec();
    mutated[33] = 3;
    cases.push((mutated, Reason::NonCanonicalInteger));
    let mut mutated = A.to_vec();
    mutated[32] = b'n';
    cases.push((mutated, Reason::DuplicateAttribute));
    let mut mutated = A.to_vec();
    mutated.swap(28, 32);
    cases.push((mutated, Reason::NonCanonicalAttributeOrder));
    let mut mutated = A.to_vec();
    mutated.resize(1_048_577, 0);
    cases.push((mutated, Reason::FrameTooLarge));
    let mut mutated = A.to_vec();
    mutated[12..16].copy_from_slice(&[0, 16, 0, 1]);
    cases.push((mutated, Reason::FrameTooLarge));

    for (wire, want) in cases {
        assert_eq!(
            decode_document(&wire),
            Err(want),
            "wire length {}",
            wire.len()
        );
    }
}

#[test]
fn outer_and_inner_precedence_refuse_before_payload_access() {
    assert_eq!(decode_document(&A[..15]), Err(Reason::Truncated));
    let mut sixteen = A[..16].to_vec();
    sixteen[15] = 16;
    assert_eq!(decode_document(&sixteen), Err(Reason::FrameLength));

    let mut excessive = A.to_vec();
    excessive[33] = 5;
    excessive[34..38].copy_from_slice(&[0, 1, 0, 1]);
    assert_eq!(decode_document(&excessive), Err(Reason::TextTooLong));

    let mut short = A.to_vec();
    short[33] = 5;
    short[34..38].copy_from_slice(&[0, 0, 0, 8]);
    assert_eq!(decode_document(&short), Err(Reason::Truncated));
}

#[test]
fn fixture_writer_rejects_unsupported_values_without_coercion() {
    for value in [
        serde_json::json!(7.0),
        serde_json::json!([1]),
        serde_json::json!({"x": 1}),
    ] {
        let fields = BTreeMap::from([("v".into(), value)]);
        assert_eq!(
            encode_document("u", "", &fields),
            Err(FixtureEncodeError::UnsupportedFixtureValue)
        );
    }
}

// This hand-built fixture helper is only for boundary inputs. The A/B/C/D
// byte oracles above remain fixed literals independent of the production writer.
fn manual_empty(collection: &[u8], key: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from(&b"PRXQDOC\0\0\x01\0\0\0\0\0\0"[..]);
    frame.extend_from_slice(&(collection.len() as u16).to_be_bytes());
    frame.extend_from_slice(collection);
    frame.extend_from_slice(&(key.len() as u16).to_be_bytes());
    frame.extend_from_slice(key);
    frame.extend_from_slice(&[0, 0]);
    let len = frame.len() as u32;
    frame[12..16].copy_from_slice(&len.to_be_bytes());
    frame
}

fn manual_single(name: &[u8], tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = D.to_vec();
    frame[22] = 1;
    frame.extend_from_slice(&(name.len() as u16).to_be_bytes());
    frame.extend_from_slice(name);
    frame.push(tag);
    frame.extend_from_slice(payload);
    let len = frame.len() as u32;
    frame[12..16].copy_from_slice(&len.to_be_bytes());
    frame
}

#[test]
fn literal_scalar_tags_preserve_bool_negative_and_full_unsigned_range() {
    let cases = [
        (0, Vec::new(), Value::Null),
        (1, Vec::new(), Value::Bool(false)),
        (2, Vec::new(), Value::Bool(true)),
        (
            3,
            vec![0x80, 0, 0, 0, 0, 0, 0, 0],
            Value::Number(Number::from(i64::MIN)),
        ),
        (4, vec![0xff; 8], Value::Number(Number::from(u64::MAX))),
        (5, vec![0, 0, 0, 0], Value::String(String::new())),
    ];
    for (tag, payload, expected) in cases {
        let frame = manual_single(b"v", tag, &payload);
        let decoded = decode_document(&frame).unwrap();
        assert_eq!(decoded.attributes.get("v"), Some(&expected));
        let fields = BTreeMap::from([("v".into(), expected)]);
        assert_eq!(encode_document("u", "", &fields).unwrap(), frame);
    }

    for signed in [0_i64, 7_i64] {
        let frame = manual_single(b"v", 3, &signed.to_be_bytes());
        assert_eq!(decode_document(&frame), Err(Reason::NonCanonicalInteger));
    }
}

#[test]
fn field_limits_refuse_before_slicing_and_utf8_is_strict_without_normalization() {
    let collection = vec![b'c'; 255];
    let key = vec![b'k'; 1024];
    let valid = manual_empty(&collection, &key);
    let decoded = decode_document(&valid).unwrap();
    assert_eq!(decoded.id.collection.as_bytes(), collection);
    assert_eq!(decoded.id.key.as_bytes(), key);
    assert_eq!(
        encode_document(&decoded.id.collection, &decoded.id.key, &BTreeMap::new()).unwrap(),
        valid
    );

    assert_eq!(
        decode_document(&manual_empty(&vec![b'c'; 256], b"k")),
        Err(Reason::InvalidCollectionLength)
    );
    assert_eq!(
        decode_document(&manual_empty(b"", b"k")),
        Err(Reason::InvalidCollectionLength)
    );
    assert_eq!(
        decode_document(&manual_empty(b"c", &vec![b'k'; 1025])),
        Err(Reason::InvalidKeyLength)
    );
    assert_eq!(
        decode_document(&manual_empty(&[0xc3, 0], b"")),
        Err(Reason::InvalidUtf8)
    );
    assert_eq!(
        decode_document(&manual_single(&[0xc3, 0], 0, &[])),
        Err(Reason::InvalidUtf8)
    );
    assert_eq!(
        decode_document(&manual_single(b"", 0, &[])),
        Err(Reason::InvalidAttributeNameLength)
    );
    assert_eq!(
        decode_document(&manual_single(&[b'n'; 129], 0, &[])),
        Err(Reason::InvalidAttributeNameLength)
    );
    assert_eq!(
        decode_document(&manual_single(b"v", 5, &[0, 0, 0, 2, 0xc3, 0])),
        Err(Reason::InvalidUtf8)
    );

    let name = "n".repeat(128);
    let frame = manual_single(name.as_bytes(), 0, &[]);
    assert!(
        decode_document(&frame)
            .unwrap()
            .attributes
            .contains_key(&name)
    );
    assert_eq!(
        encode_document("u", "", &BTreeMap::from([(name, Value::Null)])).unwrap(),
        frame
    );

    let composed = decode_document(&manual_empty(b"u", "é".as_bytes())).unwrap();
    let combining = decode_document(&manual_empty(b"u", "e\u{301}".as_bytes())).unwrap();
    assert_ne!(composed.id.key, combining.id.key);

    for (collection, key, fields, code) in [
        ("", "k", BTreeMap::new(), "collection_bytes"),
        (&"c".repeat(256), "", BTreeMap::new(), "collection_bytes"),
        ("u", &"k".repeat(1025), BTreeMap::new(), "key_bytes"),
    ] {
        assert_eq!(
            encode_document(collection, key, &fields),
            Err(FixtureEncodeError::Limit { code })
        );
    }
    assert_eq!(
        encode_document("u", "", &BTreeMap::from([("n".repeat(129), Value::Null)])),
        Err(FixtureEncodeError::Limit {
            code: "attribute_name_bytes"
        })
    );
}

#[test]
fn text_count_and_total_frame_caps_accept_maxima_and_refuse_one_over() {
    let text_payload = [vec![0, 1, 0, 0], vec![b'x'; 65_536]].concat();
    let text_frame = manual_single(b"v", 5, &text_payload);
    assert_eq!(
        decode_document(&text_frame).unwrap().attributes["v"],
        Value::String("x".repeat(65_536))
    );
    assert_eq!(
        encode_document(
            "u",
            "",
            &BTreeMap::from([("v".into(), Value::String("x".repeat(65_536)))])
        )
        .unwrap(),
        text_frame
    );
    assert_eq!(
        decode_document(&manual_single(b"v", 5, &[0, 1, 0, 1])),
        Err(Reason::TextTooLong)
    );
    assert_eq!(
        decode_document(&manual_single(b"v", 5, &[0, 0, 0, 8])),
        Err(Reason::Truncated)
    );
    assert_eq!(
        encode_document(
            "u",
            "",
            &BTreeMap::from([("v".into(), Value::String("x".repeat(65_537)))])
        ),
        Err(FixtureEncodeError::Limit { code: "text_bytes" })
    );

    let mut count_frame = D.to_vec();
    count_frame[21..23].copy_from_slice(&[1, 0]);
    let mut count_fields = BTreeMap::new();
    for i in 0..256 {
        let name = format!("a{i:03}");
        count_frame.extend_from_slice(&[0, 4]);
        count_frame.extend_from_slice(name.as_bytes());
        count_frame.push(0);
        count_fields.insert(name, Value::Null);
    }
    count_frame[12..16].copy_from_slice(&(1815_u32).to_be_bytes());
    assert_eq!(count_frame.len(), 1815);
    assert_eq!(decode_document(&count_frame).unwrap().attributes.len(), 256);
    let (budgeted, used) = decode_document_with_attribute_budget(&count_frame, 256).unwrap();
    assert_eq!(used, 256);
    assert_eq!(budgeted.attributes.len(), 256);
    assert_eq!(
        decode_document_with_attribute_budget(&count_frame, 255),
        Err(BudgetError::AttributeBudget)
    );
    assert_eq!(
        encode_document("u", "", &count_fields).unwrap(),
        count_frame
    );
    count_frame[21..23].copy_from_slice(&[1, 1]);
    assert_eq!(
        decode_document(&count_frame),
        Err(Reason::InvalidAttributeCount)
    );
    count_fields.insert("a256".into(), Value::Null);
    assert_eq!(
        encode_document("u", "", &count_fields),
        Err(FixtureEncodeError::Limit {
            code: "attribute_count"
        })
    );

    let mut exact = D.to_vec();
    exact[22] = 16;
    let mut fields = BTreeMap::new();
    for index in 0..16 {
        let name = (b'a' + index) as char;
        let size = if index == 15 { 65_385 } else { 65_536 };
        exact.extend_from_slice(&[0, 1, name as u8, 5]);
        exact.extend_from_slice(&(size as u32).to_be_bytes());
        exact.extend(std::iter::repeat_n(b'x', size));
        fields.insert(name.to_string(), Value::String("x".repeat(size)));
    }
    assert_eq!(exact.len(), 1_048_576);
    exact[12..16].copy_from_slice(&(1_048_576_u32).to_be_bytes());
    assert_eq!(decode_document(&exact).unwrap().attributes.len(), 16);
    assert_eq!(encode_document("u", "", &fields).unwrap(), exact);
    exact.push(0);
    assert_eq!(decode_document(&exact), Err(Reason::FrameTooLarge));
    fields.insert("p".into(), Value::String("x".repeat(65_386)));
    assert_eq!(
        encode_document("u", "", &fields),
        Err(FixtureEncodeError::Limit {
            code: "frame_bytes"
        })
    );
}
