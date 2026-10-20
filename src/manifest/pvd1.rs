//! Standalone PVD1 directory seam. Parsing bytes never authenticates a pack,
//! MANIFEST reference, owner or ancestry claim. Live v3/v4 paths do not use it.

const MAGIC: &[u8; 4] = b"PVD1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 24;
const ENTRY_LEN: u64 = 45;
const TRAILER_LEN: u64 = 4;
const MAX_ENTRIES: u64 = 131_072;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pvd1Kind {
    Birth,
    Edge,
    InstallDelta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pvd1Entry {
    pub node_id: [u8; 32],
    pub pack_id: u64,
    pub record_index: u32,
    pub kind: Pvd1Kind,
}

/// Syntactically decoded bytes only. The future MANIFEST/pack verification
/// layer must authenticate this entire file before using a routing entry.
#[derive(Debug)]
pub(crate) struct UntrustedPvd1<'a> {
    raw: &'a [u8],
    entries: Vec<Pvd1Entry>,
}

impl<'a> UntrustedPvd1<'a> {
    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub(crate) fn entries(&self) -> &[Pvd1Entry] {
        &self.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pvd1Error {
    BadMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    Truncated,
    Trailing,
    CountOverflow,
    CountLimit,
    LengthLimit,
    LengthMismatch,
    ChecksumMismatch,
    ZeroNodeId,
    DuplicateNodeId,
    UnsortedNodeId,
    ZeroPackId,
    InvalidRecordIndex,
    UnknownKind,
    /// Entry/CRC parsing is intentionally not implemented in the RED slice.
    Unsupported(&'static str),
}

/// Preflight the fixed header with no allocation. The entry decoder and
/// Castagnoli CRC check are intentionally missing at this test-first head.
pub(crate) fn decode_pvd1(bytes: &[u8]) -> Result<UntrustedPvd1<'_>, Pvd1Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Pvd1Error::Truncated);
    }
    if &bytes[..4] != MAGIC {
        return Err(Pvd1Error::BadMagic);
    }
    if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION {
        return Err(Pvd1Error::UnsupportedVersion);
    }
    if u16::from_le_bytes([bytes[6], bytes[7]]) != 0 {
        return Err(Pvd1Error::UnsupportedFlags);
    }

    let count = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed header checked"));
    let declared_payload =
        u64::from_le_bytes(bytes[16..24].try_into().expect("fixed header checked"));
    let entry_bytes = count
        .checked_mul(ENTRY_LEN)
        .ok_or(Pvd1Error::CountOverflow)?;
    let expected_total = (HEADER_LEN as u64)
        .checked_add(entry_bytes)
        .and_then(|length| length.checked_add(TRAILER_LEN))
        .ok_or(Pvd1Error::CountOverflow)?;
    if count > MAX_ENTRIES {
        return Err(Pvd1Error::CountLimit);
    }
    if declared_payload > MAX_BYTES || expected_total > MAX_BYTES || bytes.len() as u64 > MAX_BYTES
    {
        return Err(Pvd1Error::LengthLimit);
    }
    if declared_payload != entry_bytes {
        return Err(Pvd1Error::LengthMismatch);
    }
    let actual = bytes.len() as u64;
    if actual < expected_total {
        return Err(Pvd1Error::Truncated);
    }
    if actual > expected_total {
        return Err(Pvd1Error::Trailing);
    }

    Err(Pvd1Error::Unsupported(
        "PVD1 CRC and entries await strict decoding",
    ))
}
