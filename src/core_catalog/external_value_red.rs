//! Test-only seam for the first protected external-value RED.
//! The private resolver and its I/O probes replace this stub in the GREEN slice.

use super::segment_witness::ObservedSegmentRow;
use crate::errors::{PraxisError, Result};
use std::path::Path;

#[derive(Default)]
pub(super) struct ValuePayloadProbe {
    pub(super) open_attempts: usize,
    pub(super) reserve_attempts: usize,
    pub(super) read_attempts: usize,
}

pub(super) fn resolve_catalog_head_external(
    _root: &Path,
    _row: &ObservedSegmentRow,
    _probe: &mut ValuePayloadProbe,
) -> Result<Vec<u8>> {
    Err(PraxisError::UnsupportedCatalogFeature {
        feature: "protected external-value resolver is not implemented",
    })
}
