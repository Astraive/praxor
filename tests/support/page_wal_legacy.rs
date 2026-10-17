//! Independent historical v1 fixture writer; never a product writer API.
use praxis::identity::FieldId;
use praxis::io::{BinaryWriter, crc32_ieee};
use praxis::wal::{PageWalMutation, PageWalRecord};

pub fn encode(record: &PageWalRecord) -> Vec<u8> {
    let mut body = BinaryWriter::new();
    body.write_u64(record.sequence);
    let (tag, cid, eid, rid, fields) = match &record.mutation {
        PageWalMutation::Put {
            cid,
            eid,
            rid,
            fields,
        } => (1, *cid, *eid, *rid, Some(fields)),
        PageWalMutation::Delete { cid, eid, rid } => (2, *cid, *eid, *rid, None),
    };
    body.write_u8(tag);
    body.write_u32(cid.0);
    body.write_u32(eid.0);
    body.write_u64(rid.0);
    if let Some(fields) = fields {
        body.write_u32(u32::try_from(fields.len()).unwrap());
        for (field, bytes) in fields {
            match field {
                FieldId::Fixed(id) => {
                    body.write_u8(1);
                    body.write_u32(id.0.into());
                }
                FieldId::Dynamic(id) => {
                    body.write_u8(2);
                    body.write_u32(id.0.into());
                }
            }
            body.write_len_bytes(bytes);
        }
    }
    let body = body.into_inner();
    let mut frame = BinaryWriter::new();
    frame.write_u32(0x5450_5752);
    frame.write_u8(1);
    frame.write_u32(u32::try_from(body.len()).unwrap());
    frame.write_u32(crc32_ieee(&body));
    frame.write_bytes(&body);
    frame.into_inner()
}
