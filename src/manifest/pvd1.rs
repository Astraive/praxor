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
    AllocationFailure,
}

/// Parse a bounded directory without granting provenance authority. No
/// allocation occurs until the full length and checksum have been checked.
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

    let payload_end = bytes.len() - TRAILER_LEN as usize;
    let expected_crc = u32::from_le_bytes(
        bytes[payload_end..]
            .try_into()
            .expect("exact trailer length checked"),
    );
    if castagnoli_crc32c(&bytes[..payload_end]) != expected_crc {
        return Err(Pvd1Error::ChecksumMismatch);
    }

    let entry_count = usize::try_from(count).map_err(|_| Pvd1Error::CountLimit)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| Pvd1Error::AllocationFailure)?;
    let mut previous_node_id: Option<[u8; 32]> = None;
    for entry in bytes[HEADER_LEN..payload_end]
        .as_chunks::<{ ENTRY_LEN as usize }>()
        .0
    {
        let node_id: [u8; 32] = entry[..32].try_into().expect("fixed entry width checked");
        if node_id == [0; 32] {
            return Err(Pvd1Error::ZeroNodeId);
        }
        if let Some(previous) = previous_node_id {
            if node_id == previous {
                return Err(Pvd1Error::DuplicateNodeId);
            }
            if node_id < previous {
                return Err(Pvd1Error::UnsortedNodeId);
            }
        }
        let pack_id = u64::from_le_bytes(entry[32..40].try_into().expect("fixed entry width"));
        if pack_id == 0 {
            return Err(Pvd1Error::ZeroPackId);
        }
        let record_index = u32::from_le_bytes(entry[40..44].try_into().expect("fixed entry width"));
        if record_index == 0 || u64::from(record_index) > MAX_ENTRIES {
            return Err(Pvd1Error::InvalidRecordIndex);
        }
        let kind = match entry[44] {
            1 => Pvd1Kind::Birth,
            2 => Pvd1Kind::Edge,
            3 => Pvd1Kind::InstallDelta,
            _ => return Err(Pvd1Error::UnknownKind),
        };
        entries.push(Pvd1Entry {
            node_id,
            pack_id,
            record_index,
            kind,
        });
        previous_node_id = Some(node_id);
    }
    Ok(UntrustedPvd1 {
        raw: bytes,
        entries,
    })
}

// This is true CRC32C/Castagnoli. `crate::io::crc32c` is a historical alias
// for IEEE CRC32 and must not be used for PVD1. The MANIFEST-bound full-file
// BLAKE3 check belongs to a later layer, not this standalone parser.
fn castagnoli_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
