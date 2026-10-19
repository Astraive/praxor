use super::*;
use std::path::Path;

// Exact copy: D:/poiesis-benchmarks/query-q3-v4-wal-oracle-fixtures.json
// SHA-256 aca1ca058bae136f11c1f24cbed30e337f6c7f5635105bd71556b96847c2eb56.
const ORACLE: &str = include_str!("../../tests/fixtures/catalog_v4_wal_oracle.json");
const SOURCE: &str = "literal-v4-catalog-row";
const DATABASE_ID: [u8; 16] = [0x11; 16];

fn source() -> &'static Path {
    Path::new(SOURCE)
}

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn oracle() -> serde_json::Value {
    serde_json::from_str(ORACLE).unwrap()
}

fn literal_row(name: &str) -> (Vec<u8>, Vec<u8>) {
    let fixture = oracle();
    let mut rows = fixture["bootstrap_tag6"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .chain(fixture["create_tag7"]["operations"].as_array().unwrap());
    let row = rows.find(|row| row["name"].as_str() == Some(name)).unwrap();
    (
        bytes(row["key_hex"].as_str().unwrap()),
        bytes(row["value_hex"].as_str().unwrap()),
    )
}

#[test]
fn frozen_catalog_keys_decode_and_encode_exactly() {
    let examples = [
        ("catalog_head_at_1", CatalogKey::Head),
        ("catalog_anchor_at_1", CatalogKey::Anchor),
        ("catalog_name_accounts", CatalogKey::Name("accounts")),
        (
            "catalog_schema_id_2",
            CatalogKey::Schema(CollectionId::new(2).unwrap()),
        ),
        (
            "catalog_namespace_id_2",
            CatalogKey::Namespace(NamespaceId::new(2).unwrap()),
        ),
    ];
    for (name, expected) in examples {
        let (key, _) = literal_row(name);
        assert_eq!(
            CatalogKey::decode(&key, source()).unwrap(),
            expected,
            "{name}"
        );
        assert_eq!(expected.encode().unwrap(), key, "{name}");
    }
}

#[test]
fn frozen_catalog_values_decode_and_encode_exactly() {
    for name in [
        "catalog_head_at_1",
        "catalog_anchor_at_1",
        "catalog_head_at_2",
        "catalog_name_accounts",
        "catalog_schema_id_2",
        "catalog_namespace_id_2",
    ] {
        let (key, value) = literal_row(name);
        let key = CatalogKey::decode(&key, source()).unwrap();
        let decoded = CatalogValue::decode(&key, &value, source()).unwrap();
        assert_eq!(decoded.encode().unwrap(), value, "{name}");
    }
    let (schema_key, schema_value) = literal_row("catalog_schema_id_2");
    let key = CatalogKey::decode(&schema_key, source()).unwrap();
    let CatalogValue::Schema(schema) = CatalogValue::decode(&key, &schema_value, source()).unwrap()
    else {
        panic!("literal schema decoded as a different value");
    };
    assert_eq!(schema.collection_id.get(), 2);
    assert_eq!(schema.namespace_id.get(), 2);
    assert_eq!(schema.name, "accounts");
    assert_eq!(schema.fields.len(), 2);
    assert_eq!(schema.fields[0].id, 1);
    assert_eq!(schema.fields[0].name, "active");
    assert_eq!(schema.fields[0].scalar, ScalarType::Boolean);
    assert!(!schema.fields[0].nullable);
    assert_eq!(schema.fields[1].id, 2);
    assert_eq!(schema.fields[1].name, "balance");
    assert_eq!(schema.fields[1].scalar, ScalarType::Int8);
    assert!(schema.fields[1].nullable);
}

#[test]
fn constructed_values_match_independent_literal_bytes() {
    let id = CollectionId::new(2).unwrap();
    let namespace = NamespaceId::new(2).unwrap();
    let head_at_1 = CatalogValue::Head(Head {
        database_id: DATABASE_ID,
        revision: 1,
        collection_count: 0,
    });
    let head_at_2 = CatalogValue::Head(Head {
        database_id: DATABASE_ID,
        revision: 2,
        collection_count: 1,
    });
    let anchor = CatalogValue::Anchor(Anchor {
        database_id: DATABASE_ID,
        head_at_1_digest: bytes("70fc8bc46f645195e91ca8b2fe01bd1f41abc222b166d40c8f0dbeaba7fe8c49")
            .try_into()
            .unwrap(),
    });
    let schema = CatalogValue::Schema(Schema {
        collection_id: id,
        namespace_id: namespace,
        name: "accounts",
        fields: vec![
            Field {
                id: 1,
                name: "active",
                scalar: ScalarType::Boolean,
                nullable: false,
            },
            Field {
                id: 2,
                name: "balance",
                scalar: ScalarType::Int8,
                nullable: true,
            },
        ],
    });
    for (name, expected) in [
        ("catalog_head_at_1", head_at_1),
        ("catalog_anchor_at_1", anchor),
        ("catalog_head_at_2", head_at_2),
        ("catalog_name_accounts", CatalogValue::Name(id)),
        ("catalog_schema_id_2", schema),
        ("catalog_namespace_id_2", CatalogValue::Namespace(id)),
    ] {
        let (key, literal) = literal_row(name);
        assert_eq!(expected.encode().unwrap(), literal, "{name}");
        let decoded = CatalogValue::decode(
            &CatalogKey::decode(&key, source()).unwrap(),
            &literal,
            source(),
        )
        .unwrap();
        assert_eq!(decoded, expected, "{name}");
    }
}

#[test]
fn anchor_hash_is_the_frozen_85_byte_preimage_and_full_value() {
    let fixture = oracle();
    let preimage = bytes(fixture["anchor_digest_preimage_hex"].as_str().unwrap());
    let domain = bytes(fixture["anchor_digest_domain_hex"].as_str().unwrap());
    assert_eq!(domain.len(), 33);
    assert_eq!(preimage.len(), 85);
    assert_eq!(&preimage[..33], domain);
    assert_eq!(&preimage[33..37], &48u32.to_le_bytes());
    let head = canonical_head_at_1(DATABASE_ID).unwrap();
    assert_eq!(head.as_slice(), &preimage[37..]);
    assert_eq!(
        head.to_vec(),
        bytes(fixture["head_at_1_value_hex"].as_str().unwrap())
    );
    let digest = anchor_digest(DATABASE_ID).unwrap();
    assert_eq!(
        digest.to_vec(),
        bytes("70fc8bc46f645195e91ca8b2fe01bd1f41abc222b166d40c8f0dbeaba7fe8c49")
    );
    let (key, value) = literal_row("catalog_anchor_at_1");
    assert_eq!(key, [4]);
    assert_eq!(
        value,
        bytes(fixture["anchor_at_1_value_hex"].as_str().unwrap())
    );
    assert_eq!(&value[40..], &digest);
}

#[test]
fn fixed_rows_reject_every_truncation_and_trailing_byte() {
    for name in [
        "catalog_head_at_1",
        "catalog_anchor_at_1",
        "catalog_name_accounts",
        "catalog_namespace_id_2",
    ] {
        let (key, value) = literal_row(name);
        let key = CatalogKey::decode(&key, source()).unwrap();
        for len in 0..value.len() {
            assert!(
                CatalogValue::decode(&key, &value[..len], source()).is_err(),
                "{name}:{len}"
            );
        }
        let mut trailing = value;
        trailing.push(0);
        assert!(
            CatalogValue::decode(&key, &trailing, source()).is_err(),
            "{name}:trailing"
        );
    }
}

#[test]
fn catalog_keys_reject_zero_ids_wrong_lengths_and_noncanonical_names() {
    let bad: &[&[u8]] = &[
        &[],
        &[0, 0],
        &[4, 0],
        &[2],
        &[3, 0, 0, 0],
        &[2, 0, 0, 0, 0, 0, 0, 0, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 0],
        &[1, 0, 2, b'a'],
        &[1, 0, 1, 0],
        &[1, 0, 1, 0x1f],
        &[1, 0, 1, 0x7f],
        &[1, 0, 1, 0xff],
        &[5],
    ];
    for key in bad {
        assert!(CatalogKey::decode(key, source()).is_err(), "{key:?}");
    }
    assert!(CatalogKey::Name(&"x".repeat(256)).encode().is_err());
    assert!(CatalogKey::Name("a\u{0001}b").encode().is_err());
    assert!(CollectionId::new(0).is_none());
    assert!(NamespaceId::new(0).is_none());
    assert_ne!(
        CatalogKey::Name("é").encode().unwrap(),
        CatalogKey::Name("e\u{301}").encode().unwrap()
    );
}

#[test]
fn schema_rejects_every_cut_and_noncanonical_field_encoding() {
    let (key, value) = literal_row("catalog_schema_id_2");
    let key = CatalogKey::decode(&key, source()).unwrap();
    for len in 0..value.len() {
        assert!(
            CatalogValue::decode(&key, &value[..len], source()).is_err(),
            "cut {len}"
        );
    }
    let mutate = |offset: usize, bytes: &[u8]| {
        let mut changed = value.clone();
        changed[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert!(
            CatalogValue::decode(&key, &changed, source()).is_err(),
            "offset {offset}"
        );
    };
    // PCS1[4]+codec[2]+flags[2]+collection[8]+namespace[8]+name_len[2]
    // +accounts[8]+field_count[2] => first field at byte 36.
    mutate(34, &0u16.to_le_bytes());
    mutate(34, &129u16.to_le_bytes());
    mutate(8, &3u64.to_le_bytes()); // key/value collection mismatch
    mutate(16, &3u64.to_le_bytes()); // namespace != collection
    mutate(36, &2u16.to_le_bytes()); // first ID must be 1
    mutate(50, &1u16.to_le_bytes()); // second ID must be 2
    mutate(36, &0u16.to_le_bytes());
    mutate(46, &[7]); // scalar code outside codec 1
    mutate(47, &[2]); // nullable must be Boolean byte
    mutate(48, &[1, 0]); // reserved nonzero
    mutate(24, &0u16.to_le_bytes()); // empty collection name
    mutate(36 + 2, &0u16.to_le_bytes()); // empty field name
    mutate(40, b"zctive"); // sorted names are exact UTF-8 byte order
    mutate(40, &[0x61, 0x63, 0x00, 0x69, 0x76, 0x65]);
    mutate(40, &[0xff, 0x63, 0x74, 0x69, 0x76, 0x65]);
    let mut trailing = value.clone();
    trailing.push(0);
    assert!(CatalogValue::decode(&key, &trailing, source()).is_err());
}

#[test]
fn fixed_rows_reject_wrong_codec_flags_epoch_and_anchor_hash() {
    for name in [
        "catalog_head_at_1",
        "catalog_anchor_at_1",
        "catalog_namespace_id_2",
    ] {
        let (key, value) = literal_row(name);
        let key = CatalogKey::decode(&key, source()).unwrap();
        for (offset, byte) in [(4, 2), (6, 1)] {
            let mut changed = value.clone();
            changed[offset] = byte;
            assert!(
                CatalogValue::decode(&key, &changed, source()).is_err(),
                "{name}:{offset}"
            );
        }
    }
    for (name, offset) in [("catalog_head_at_1", 24), ("catalog_anchor_at_1", 24)] {
        let (key, mut value) = literal_row(name);
        value[offset] = 2;
        let key = CatalogKey::decode(&key, source()).unwrap();
        assert!(
            CatalogValue::decode(&key, &value, source()).is_err(),
            "{name}"
        );
    }
    let (key, mut anchor) = literal_row("catalog_anchor_at_1");
    anchor[40] ^= 1;
    assert!(
        CatalogValue::decode(
            &CatalogKey::decode(&key, source()).unwrap(),
            &anchor,
            source()
        )
        .is_err()
    );
}

#[test]
fn schema_accepts_all_scalar_codes_and_bounded_canonical_fields() {
    let collection_id = CollectionId::new(3).unwrap();
    let namespace_id = NamespaceId::new(3).unwrap();
    let scalars = [
        ScalarType::Int2,
        ScalarType::Int4,
        ScalarType::Int8,
        ScalarType::Uint8,
        ScalarType::Boolean,
        ScalarType::Text,
    ];
    let names = ["a", "b", "c", "d", "e", "f"];
    let long_name = "x".repeat(255);
    let schema = Schema {
        collection_id,
        namespace_id,
        name: &long_name,
        fields: names
            .iter()
            .enumerate()
            .map(|(index, name)| Field {
                id: (index + 1) as u16,
                name,
                scalar: scalars[index],
                nullable: index % 2 == 0,
            })
            .collect(),
    };
    let key = CatalogKey::Schema(collection_id);
    let value = CatalogValue::Schema(schema);
    let encoded = value.encode().unwrap();
    assert_eq!(
        CatalogValue::decode(&key, &encoded, source()).unwrap(),
        value
    );
    let field_names: Vec<_> = (1..=128).map(|index| format!("f{index:03}")).collect();
    let fields: Vec<_> = field_names
        .iter()
        .enumerate()
        .map(|(index, name)| Field {
            id: (index + 1) as u16,
            name,
            scalar: ScalarType::Text,
            nullable: false,
        })
        .collect();
    let max = CatalogValue::Schema(Schema {
        collection_id,
        namespace_id,
        name: "accounts",
        fields,
    });
    let encoded = max.encode().unwrap();
    assert_eq!(CatalogValue::decode(&key, &encoded, source()).unwrap(), max);
}

#[test]
fn schema_encoder_rejects_unsorted_or_overfull_fields() {
    let (key, value) = literal_row("catalog_schema_id_2");
    let key = CatalogKey::decode(&key, source()).unwrap();
    let CatalogValue::Schema(mut schema) = CatalogValue::decode(&key, &value, source()).unwrap()
    else {
        unreachable!()
    };
    schema.fields.swap(0, 1);
    assert!(CatalogValue::Schema(schema.clone()).encode().is_err());
    schema.fields.swap(0, 1);
    schema.fields.resize(129, schema.fields[0].clone());
    assert!(CatalogValue::Schema(schema).encode().is_err());
}
