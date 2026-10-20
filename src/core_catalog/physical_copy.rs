//! Private physical-copy admission seam for protected installed rows.
//!
//! The bounded segment visitor and its witnesses precede this ledger. Until
//! equality proof exists, this entrypoint never grants copy admission.

use super::segment_witness::{ObservedSegmentRow, SegmentFileWitness, SegmentSource};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::wal::catalog_witness::PhysicalWitnessBudget;
use std::path::Path;

/// A source locator stays tied to a physical row, before any version fold.
#[allow(dead_code)] // Deliberately unconstructed until the #82 GREEN admission proof.
#[derive(Debug)]
pub(crate) struct PhysicalCopySource {
    pub(crate) source: SegmentSource,
    pub(crate) block_offset: u64,
    pub(crate) row_ordinal: u32,
    pub(crate) cf: String,
    pub(crate) key: Vec<u8>,
    pub(crate) sequence: u64,
}

/// Admitted copy locations and their authenticated source-file receipts.
#[allow(dead_code)] // The RED stub cannot construct a ledger before equivalence proof.
#[derive(Debug)]
pub(crate) struct ProtectedCopyLedger {
    pub(crate) copies: Vec<PhysicalCopySource>,
    pub(crate) segment_witnesses: Vec<SegmentFileWitness>,
}

/// The future ledger must prove every same-(CF,key,S) physical source before
/// selecting a current version. It does not expose public owner authority.
#[allow(dead_code)] // Called only by the focused RED until private admission exists.
pub(crate) fn admit_protected_physical_copies(
    _root: &Path,
    _manifest: &Manifest,
    _observed: &[ObservedSegmentRow],
    _witnesses: &[SegmentFileWitness],
    _budget: &mut PhysicalWitnessBudget,
) -> Result<ProtectedCopyLedger> {
    Err(PraxisError::UnsupportedCatalogFeature {
        feature: "protected physical-copy ledger not implemented",
    })
}
