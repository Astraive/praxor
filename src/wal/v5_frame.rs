//! Read-only v5 typed-frame inspection. Parsed bytes remain untrusted and
//! grant no WAL owner, tail repair, row effect, or provenance authority.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameKind {
    User,
    Record,
    CatalogBootstrap,
    CatalogCreate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameContext {
    pub header_digest: [u8; 32],
    pub previous_hash: [u8; 32],
    pub expected_sequence: u64,
    pub database_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UntrustedH64 {
    pub kind: FrameKind,
    pub sequence: u64,
    pub ordinary_operations: u32,
    pub payload_len: u32,
    pub total_len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UntrustedFrame {
    pub header: UntrustedH64,
    pub trailer: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H64Inspection {
    // This does not assert a valid terminal tear or permit truncation.
    IncompleteUnclassified,
    Complete(UntrustedH64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameError {
    Corrupt,
    Unsupported,
}

/// Inspect up to one 64-byte frame header. An incomplete header cannot grant
/// tail-repair authority; the full existential classifier is a later slice.
pub(crate) fn inspect_h64_prefix(
    _bytes: &[u8],
    _context: &FrameContext,
) -> Result<H64Inspection, FrameError> {
    Err(FrameError::Unsupported)
}

/// Decode one complete synthetic frame image after a separately checked H80.
/// This is not an installed-WAL scan or proof of a relational effect.
pub(crate) fn decode_complete_frame(
    _bytes: &[u8],
    _context: &FrameContext,
) -> Result<UntrustedFrame, FrameError> {
    Err(FrameError::Unsupported)
}

#[cfg(test)]
mod tests;
