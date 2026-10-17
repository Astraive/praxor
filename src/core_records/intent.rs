//! Owned logical requests. Only the core coordinator can turn these into WAL
//! capabilities; no public batch or decoded envelope becomes an intent.
use crate::errors::{PraxisError, Result};
use crate::store::RecordId;

#[derive(Clone, Debug)]
pub(crate) struct Mapping {
    pub(crate) index: u32,
    pub(crate) key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct NewRecord {
    pub(crate) payload: Vec<u8>,
    pub(crate) mappings: Vec<Mapping>,
}

#[derive(Clone)]
pub(crate) enum IntentKind {
    Create(Vec<NewRecord>),
    DeleteRecords(Vec<RecordId>),
    IndexPut(Mapping, RecordId),
    IndexDelete(Mapping),
    Cleanup(RecordId, Vec<Mapping>),
    DeleteByIndex(Mapping),
}

pub(crate) struct RecordIntent {
    kind: IntentKind,
    admission_bytes: usize,
}

impl RecordIntent {
    pub(crate) fn new(kind: IntentKind) -> Result<Self> {
        // Include owned input, generated operations, touched-key overlay and
        // receipts. This is a memory/admission charge, NOT a wire-size limit.
        let mut charge = 2048usize;
        let mut add = |bytes: usize, items: usize| -> Result<()> {
            u32::try_from(bytes).map_err(|_| invalid("record field exceeds u32"))?;
            u32::try_from(items).map_err(|_| invalid("record count exceeds u32"))?;
            charge = charge
                .checked_add(
                    bytes
                        .checked_mul(4)
                        .ok_or_else(|| invalid("record size overflow"))?,
                )
                .and_then(|n| n.checked_add(items.checked_mul(2048)?))
                .ok_or_else(|| invalid("record admission overflow"))?;
            Ok(())
        };
        let mut mappings = Vec::new();
        match &kind {
            IntentKind::Create(records) => {
                add(0, records.len())?;
                for record in records {
                    add(record.payload.len(), record.mappings.len())?;
                    mappings.extend(record.mappings.iter());
                }
            }
            IntentKind::DeleteRecords(ids) => add(0, ids.len())?,
            IntentKind::IndexPut(mapping, _)
            | IntentKind::IndexDelete(mapping)
            | IntentKind::DeleteByIndex(mapping) => mappings.push(mapping),
            IntentKind::Cleanup(_, inserts) => {
                add(0, inserts.len() + 1)?;
                mappings.extend(inserts);
            }
        }
        for mapping in mappings {
            if mapping.index == 0 {
                return Err(invalid("null mapping descriptor"));
            }
            add(mapping.key.len(), 1)?;
            // One key appears in both fact/head operations, their touched-key
            // overlay and the temporary final frame/publication copies.
            add(mapping.key.len(), 0)?;
        }
        Ok(Self {
            kind,
            admission_bytes: charge,
        })
    }

    pub(crate) fn kind(&self) -> &IntentKind {
        &self.kind
    }
    pub(crate) fn admission_bytes(&self) -> usize {
        self.admission_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecordResult {
    Created(Vec<RecordId>),
    Unit,
    DeletedByIndex(Option<RecordId>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordReceipt {
    pub(crate) core_sequence: u64,
    pub(crate) compatibility_sequence: u64,
    pub(crate) result: RecordResult,
}

fn invalid(reason: &str) -> PraxisError {
    PraxisError::InvalidConfig(reason.into())
}
