use praxis::io::{crc32_ieee, crc32c};

#[test]
fn historical_checksum_name_preserves_ieee_check_values() {
    assert_eq!(crc32c(b""), 0);
    assert_eq!(crc32c(b"123456789"), 0xcbf4_3926);
}

#[test]
fn accurately_named_entry_point_matches_the_existing_wire_contract() {
    assert_eq!(crc32_ieee(b""), 0);
    assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    let binary = (0..=255).collect::<Vec<u8>>();
    assert_eq!(crc32_ieee(&binary), crc32c(&binary));
}
