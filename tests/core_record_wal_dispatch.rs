use praxis::io::crc32_ieee;
use praxis::wal::WalRecord;

#[test]
fn ordinary_wal_decoder_reports_typed_authority_dispatch_instead_of_unknown_op() {
    let mut envelope = b"PRR1\x01\x00\x01\x00".to_vec();
    envelope.extend([0x11; 16]);
    envelope.extend(1u64.to_le_bytes());
    envelope.extend([0; 56]);
    assert_eq!(envelope.len(), 88);
    let mut payload = 1u64.to_le_bytes().to_vec();
    payload.extend(1u32.to_le_bytes());
    payload.push(5);
    payload.extend(88u32.to_le_bytes());
    payload.extend(envelope);
    let mut bytes = 0x5457_4132u32.to_le_bytes().to_vec();
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(crc32_ieee(&payload).to_le_bytes());
    bytes.extend(crc32_ieee(&bytes).to_le_bytes());
    bytes.extend(payload);
    let error = WalRecord::decode(&bytes, "typed-core-wal").unwrap_err();
    assert!(
        error.to_string().contains("record-authority WAL requires"),
        "{error}"
    );
}
