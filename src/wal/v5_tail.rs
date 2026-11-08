//! Read-only classification of a synthetic v5 WAL image. No result from this
//! module grants a writer, truncation, record effect, or provenance authority.

use super::v5_header::H80Descriptor;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstalledWalState {
    Active,
    Sealed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TailInspection {
    Complete {
        complete_frames: usize,
        last_sequence: u64,
    },
    // This has no repair authority. It is intentionally distinct from an
    // existentially proven canonical terminal prefix.
    IncompleteUnclassified,
    EligibleTerminalPrefix {
        complete_frames: usize,
        prefix_len: usize,
    },
    Corrupt,
    Unsupported,
}

/// Inspect a synthetic installed WAL image under a separately supplied
/// descriptor and retained-history watermark. The implementation must check
/// H80, every complete frame and the final suffix before returning eligibility.
/// Dynamic row and owner validation remain separate responsibilities.
pub(crate) fn inspect_installed_v5_wal(
    _image: &[u8],
    _descriptor: &H80Descriptor<'_>,
    _state: InstalledWalState,
    _required_sequence_through: u64,
) -> TailInspection {
    TailInspection::Unsupported
}

#[cfg(test)]
mod tests;
