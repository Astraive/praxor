//! Private PCB1/PCC1 WAL controls. These authenticate a control's bytes;
//! the relation between its protected operations belongs to later recovery.
use crate::core_records::codec::{Envelope, Kind};
use crate::errors::{PraxisError, Result};
use std::path::Path;

const EPOCH: u64 = 1;
const CODEC: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatalogControl {
    Bootstrap {
        database_id: [u8; 16],
        catalog_epoch: u64,
        envelope: Envelope,
    },
    Create {
        database_id: [u8; 16],
        catalog_epoch: u64,
        prior_revision: u64,
        prior_count: u64,
        new_revision: u64,
        new_count: u64,
    },
}

impl CatalogControl {
    pub(crate) const BOOTSTRAP_LEN: usize = 120;
    pub(crate) const CREATE_LEN: usize = 64;

    pub(crate) fn tag(&self) -> u8 {
        match self {
            Self::Bootstrap { .. } => 6,
            Self::Create { .. } => 7,
        }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            Self::Bootstrap { .. } => Self::BOOTSTRAP_LEN,
            Self::Create { .. } => Self::CREATE_LEN,
        }
    }

    pub(crate) fn decode(tag: u8, bytes: &[u8], sequence: u64, source: &Path) -> Result<Self> {
        let (len, magic) = match tag {
            6 => (Self::BOOTSTRAP_LEN, b"PCB1".as_slice()),
            7 => (Self::CREATE_LEN, b"PCC1".as_slice()),
            _ => return Err(corrupt(source, "unknown catalog WAL control tag")),
        };
        if bytes.len() != len || &bytes[..4] != magic {
            return Err(corrupt(
                source,
                "catalog WAL control length or magic mismatch",
            ));
        }
        if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != CODEC
            || u16::from_le_bytes(bytes[6..8].try_into().unwrap()) != 0
        {
            return Err(corrupt(
                source,
                "unsupported catalog WAL control codec or flags",
            ));
        }
        let database_id: [u8; 16] = bytes[8..24].try_into().unwrap();
        let catalog_epoch = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        if database_id == [0; 16] || catalog_epoch != EPOCH {
            return Err(corrupt(
                source,
                "invalid catalog WAL control identity or epoch",
            ));
        }
        match tag {
            6 => {
                let envelope = Envelope::decode(&bytes[32..120], sequence, source)?;
                if envelope.kind != Kind::Bootstrap || envelope.database_id != database_id {
                    return Err(corrupt(source, "catalog bootstrap envelope mismatch"));
                }
                Ok(Self::Bootstrap {
                    database_id,
                    catalog_epoch,
                    envelope,
                })
            }
            7 => Ok(Self::Create {
                database_id,
                catalog_epoch,
                prior_revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
                prior_count: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
                new_revision: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
                new_count: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            }),
            _ => unreachable!("tag checked above"),
        }
    }

    pub(crate) fn encode_into(&self, sequence: u64, out: &mut Vec<u8>) -> Result<()> {
        let (database_id, catalog_epoch, magic) = match self {
            Self::Bootstrap {
                database_id,
                catalog_epoch,
                ..
            } => (database_id, catalog_epoch, b"PCB1".as_slice()),
            Self::Create {
                database_id,
                catalog_epoch,
                ..
            } => (database_id, catalog_epoch, b"PCC1".as_slice()),
        };
        if *database_id == [0; 16] || *catalog_epoch != EPOCH {
            return Err(PraxisError::InvalidConfig(
                "invalid catalog WAL control identity or epoch".into(),
            ));
        }
        out.extend(magic);
        out.extend(CODEC.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(database_id);
        out.extend(catalog_epoch.to_le_bytes());
        match self {
            Self::Bootstrap { envelope, .. } => {
                if envelope.kind != Kind::Bootstrap || envelope.database_id != *database_id {
                    return Err(PraxisError::InvalidConfig(
                        "catalog bootstrap envelope mismatch".into(),
                    ));
                }
                envelope.encode_into(sequence, out)?;
            }
            Self::Create {
                prior_revision,
                prior_count,
                new_revision,
                new_count,
                ..
            } => {
                for value in [prior_revision, prior_count, new_revision, new_count] {
                    out.extend(value.to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

fn corrupt(source: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: reason.into(),
    }
}
