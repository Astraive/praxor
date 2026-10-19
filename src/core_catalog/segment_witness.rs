//! Provisional, read-only evidence for every physical v4 segment row.
//!
//! No caller may turn these observations into an owner proof until the later
//! protected-copy, installed-relation, and WAL-history proofs are complete.

use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::types::ValuePointer;
use crate::wal::catalog_witness::PhysicalWitnessBudget;
use std::path::{Path, PathBuf};

/// This position is from the original, unsorted MANIFEST segment vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentSource {
    pub(crate) level: u32,
    pub(crate) id: u64,
    pub(crate) manifest_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedRole {
    Meta,
    Payload,
    State,
    Index,
    Catalog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalRowClass {
    BoundProtected(ProtectedRole),
    ReservedUnbound,
    Other,
}

/// This retains the wire tag, including unresolved pointer expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObservedSegmentValue {
    Put(Vec<u8>),
    Delete,
    Pointer {
        pointer: ValuePointer,
        expires_at_ms: Option<u64>,
    },
    PutWithExpiry {
        value: Vec<u8>,
        expires_at_ms: u64,
    },
    Merge(Vec<u8>),
}

/// All fields are owned; no borrowed bytes can outlive a file buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedSegmentRow {
    pub(crate) source: SegmentSource,
    pub(crate) block_offset: u64,
    /// Zero-based position within this block.
    pub(crate) row_ordinal: u32,
    pub(crate) classification: PhysicalRowClass,
    pub(crate) cf: String,
    pub(crate) key: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) value: ObservedSegmentValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentPhysicalId {
    pub(crate) volume: u64,
    pub(crate) file: [u8; 16],
}

/// Witnesses are only candidates until a complete final namespace recheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentFileWitness {
    pub(crate) source: SegmentSource,
    pub(crate) path: PathBuf,
    pub(crate) identity: SegmentPhysicalId,
    pub(crate) len: u64,
    pub(crate) digest: blake3::Hash,
    pub(crate) observed_rows: u64,
}

pub(crate) fn visit_v4_segments(
    _root: &Path,
    _manifest: &Manifest,
    _budget: &mut PhysicalWitnessBudget,
    _visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<Vec<SegmentFileWitness>> {
    Err(PraxisError::UnsupportedCatalogFeature {
        feature: "bounded v4 physical segment visitor is not yet admitted",
    })
}
