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

const H64_LEN: usize = 64;
const FRAME_OVERHEAD: u32 = 100;
const MAX_PAYLOAD: u32 = 67_108_864;
const MAX_CATALOG_FRAME: u32 = 1_048_576;
const MAX_OPERATIONS: u32 = 4_096;
const MAX_KEY_LEN: u32 = 1_048_576;

// The existing crate::io::crc32c name denotes the historical IEEE CRC. V5
// uses the reflected Castagnoli polynomial, including for frame trailers.
const fn castagnoli_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0_u32.wrapping_sub(crc & 1) & 0x82f6_3b78);
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

const CASTAGNOLI_TABLE: [u32; 256] = castagnoli_table();

fn castagnoli_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        let index = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ CASTAGNOLI_TABLE[index];
    }
    !crc
}

fn matches_visible(bytes: &[u8], offset: usize, fixed: &[u8]) -> bool {
    if bytes.len() <= offset {
        return true;
    }
    let visible = bytes.len().saturating_sub(offset).min(fixed.len());
    bytes.get(offset..offset + visible) == Some(&fixed[..visible])
}

// A truncated little-endian integer admits exactly one residue class. The
// modulus is 2^(8 * visible bytes), including 2^32 for a complete u32.
fn visible_u32_residue(bytes: &[u8], offset: usize) -> (u64, u64) {
    let visible = bytes.len().saturating_sub(offset).min(4);
    let mut residue = 0_u64;
    for index in 0..visible {
        residue |= u64::from(bytes[offset + index]) << (8 * index);
    }
    (residue, 1_u64 << (8 * visible))
}

fn first_in_range(residue: u64, modulus: u64, lower: u64, upper: u64) -> Option<u64> {
    let first = if residue >= lower {
        residue
    } else {
        let steps = (lower - residue).div_ceil(modulus);
        residue.checked_add(steps.checked_mul(modulus)?)?
    };
    (first <= upper).then_some(first)
}

fn kind_byte(kind: FrameKind) -> u8 {
    match kind {
        FrameKind::User => 1,
        FrameKind::Record => 2,
        FrameKind::CatalogBootstrap => 3,
        FrameKind::CatalogCreate => 4,
    }
}

fn min_payload(kind: FrameKind, count: u32) -> u64 {
    let control = match kind {
        FrameKind::User => 0,
        FrameKind::Record => 88,
        FrameKind::CatalogBootstrap => 120,
        FrameKind::CatalogCreate => 64,
    };
    4 + control + 20 * u64::from(count)
}

fn max_payload(kind: FrameKind) -> u64 {
    match kind {
        FrameKind::User | FrameKind::Record => u64::from(MAX_PAYLOAD),
        FrameKind::CatalogBootstrap | FrameKind::CatalogCreate => {
            u64::from(MAX_CATALOG_FRAME - FRAME_OVERHEAD)
        }
    }
}

// `total_len = payload_len + 100` couples the two visible little-endian
// residues. Both moduli are powers of 256, so one contains the other; testing
// only their independent interval envelopes would accept impossible prefixes.
fn lengths_can_complete(bytes: &[u8], kind: FrameKind, count: u32) -> bool {
    let (payload, payload_step) = visible_u32_residue(bytes, 28);
    let (total, total_step) = visible_u32_residue(bytes, 8);
    let payload_from_total =
        (total + total_step - u64::from(FRAME_OVERHEAD) % total_step) % total_step;
    let common_step = payload_step.min(total_step);
    if payload % common_step != payload_from_total % common_step {
        return false;
    }
    let (residue, step) = if payload_step >= total_step {
        (payload, payload_step)
    } else {
        (payload_from_total, total_step)
    };
    first_in_range(residue, step, min_payload(kind, count), max_payload(kind)).is_some()
}

/// Inspect up to one 64-byte frame header. An incomplete header cannot grant
/// tail-repair authority; the full existential classifier is a later slice.
pub(crate) fn inspect_h64_prefix(
    bytes: &[u8],
    context: &FrameContext,
) -> Result<H64Inspection, FrameError> {
    if bytes.len() > H64_LEN
        || context.expected_sequence == 0
        || !matches_visible(bytes, 0, b"PWF5")
        || !matches_visible(bytes, 4, &5_u16.to_le_bytes())
        || !matches_visible(bytes, 6, &[0, 0])
        || !matches_visible(bytes, 12, &context.expected_sequence.to_le_bytes())
        || !matches_visible(bytes, 21, &[0, 0, 0])
        || !matches_visible(bytes, 32, &context.previous_hash)
    {
        return Err(FrameError::Corrupt);
    }

    let (count_residue, count_step) = visible_u32_residue(bytes, 24);
    let Some(min_count) = first_in_range(count_residue, count_step, 0, u64::from(MAX_OPERATIONS))
    else {
        return Err(FrameError::Corrupt);
    };
    let count = u32::try_from(min_count).map_err(|_| FrameError::Corrupt)?;
    let possible_kind = [
        FrameKind::User,
        FrameKind::Record,
        FrameKind::CatalogBootstrap,
        FrameKind::CatalogCreate,
    ]
    .into_iter()
    .find(|&kind| {
        matches_visible(bytes, 20, &[kind_byte(kind)]) && lengths_can_complete(bytes, kind, count)
    });
    let Some(kind) = possible_kind else {
        return Err(FrameError::Corrupt);
    };
    if bytes.len() < H64_LEN {
        return Ok(H64Inspection::IncompleteUnclassified);
    }
    let total_len = u32::from_le_bytes(bytes[8..12].try_into().expect("complete H64"));
    let payload_len = u32::from_le_bytes(bytes[28..32].try_into().expect("complete H64"));
    Ok(H64Inspection::Complete(UntrustedH64 {
        kind,
        sequence: context.expected_sequence,
        ordinary_operations: count,
        payload_len,
        total_len,
    }))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FrameError> {
        let end = self.offset.checked_add(len).ok_or(FrameError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FrameError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn control_identity(body: &[u8], magic: &[u8; 4], database_id: &[u8; 16]) -> bool {
    body.len() >= 32
        && body[..4] == magic[..]
        && body[4] == 1
        && body[5] == 0
        && body[8..24] == database_id[..]
        && database_id.iter().any(|&byte| byte != 0)
        && read_u64(body, 24) == 1
}

fn read_u64(body: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        body[offset..offset + 8]
            .try_into()
            .expect("fixed control width"),
    )
}

fn read_u32(body: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        body[offset..offset + 4]
            .try_into()
            .expect("fixed control width"),
    )
}

fn valid_prr1(body: &[u8], sequence: u64, database_id: &[u8; 16]) -> bool {
    if body.len() != 88 || !control_identity(body, b"PRR1", database_id) || body[7] != 0 {
        return false;
    }
    let prior_rid = read_u64(body, 32);
    let new_rid = read_u64(body, 40);
    let prior_compat = read_u64(body, 48);
    let new_compat = read_u64(body, 56);
    let prior_append = read_u64(body, 64);
    let new_append = read_u64(body, 72);
    let records = read_u32(body, 80);
    let logical = read_u32(body, 84);
    match body[6] {
        1 => {
            sequence == 1
                && [
                    prior_rid,
                    new_rid,
                    prior_compat,
                    new_compat,
                    prior_append,
                    new_append,
                ]
                .iter()
                .all(|&value| value == 0)
                && records == 0
                && logical == 0
        }
        kind @ 2..=6 => {
            if sequence <= 1 || logical == 0 {
                return false;
            }
            let logical = u64::from(logical);
            if prior_compat.checked_add(logical) != Some(new_compat)
                || prior_append.checked_add(logical) != Some(new_append)
            {
                return false;
            }
            match kind {
                2 => {
                    records > 0
                        && logical >= u64::from(records)
                        && prior_rid.checked_add(u64::from(records)) == Some(new_rid)
                }
                3 => records > 0 && logical == u64::from(records) && new_rid == prior_rid,
                4 | 5 => records == 0 && logical == 1 && new_rid == prior_rid,
                6 => records == 1 && logical >= 2 && new_rid == prior_rid,
                _ => false,
            }
        }
        _ => false,
    }
}

fn valid_control(kind: FrameKind, sequence: u64, database_id: &[u8; 16], body: &[u8]) -> bool {
    match kind {
        FrameKind::User => body.is_empty(),
        FrameKind::Record => valid_prr1(body, sequence, database_id),
        FrameKind::CatalogBootstrap => {
            body.len() == 120
                && control_identity(body, b"PCB1", database_id)
                && body[6..8] == [0, 0]
                && sequence == 1
                && valid_prr1(&body[32..120], sequence, database_id)
        }
        FrameKind::CatalogCreate => {
            if body.len() != 64
                || !control_identity(body, b"PCC1", database_id)
                || body[6..8] != [0, 0]
            {
                return false;
            }
            let prior_revision = read_u64(body, 32);
            let prior_count = read_u64(body, 40);
            let new_revision = read_u64(body, 48);
            let new_count = read_u64(body, 56);
            prior_revision > 0
                && new_revision == sequence
                && new_revision > prior_revision
                && prior_count.checked_add(1) == Some(new_count)
        }
    }
}

fn valid_payload(header: &UntrustedH64, database_id: &[u8; 16], payload: &[u8]) -> bool {
    let mut cursor = Cursor::new(payload);
    let Ok(control_len) = cursor.u32() else {
        return false;
    };
    let expected_control_len = match header.kind {
        FrameKind::User => 0,
        FrameKind::Record => 88,
        FrameKind::CatalogBootstrap => 120,
        FrameKind::CatalogCreate => 64,
    };
    if control_len != expected_control_len {
        return false;
    }
    let Ok(control) = cursor.take(control_len as usize) else {
        return false;
    };
    if !valid_control(header.kind, header.sequence, database_id, control) {
        return false;
    }
    for expected_ordinal in 0..header.ordinary_operations {
        let Ok(ordinal) = cursor.u32() else {
            return false;
        };
        let Ok(tag) = cursor.u8() else {
            return false;
        };
        let Ok(generation) = cursor.u64() else {
            return false;
        };
        let Ok(name_len) = cursor.u16() else {
            return false;
        };
        if ordinal != expected_ordinal
            || !(1..=4).contains(&tag)
            || generation == 0
            || !(1..=255).contains(&name_len)
        {
            return false;
        }
        let Ok(name) = cursor.take(usize::from(name_len)) else {
            return false;
        };
        if name.contains(&0) || std::str::from_utf8(name).is_err() {
            return false;
        }
        let Ok(key_len) = cursor.u32() else {
            return false;
        };
        if key_len > MAX_KEY_LEN || cursor.take(key_len as usize).is_err() {
            return false;
        }
        if tag != 2 {
            let Ok(value_len) = cursor.u32() else {
                return false;
            };
            if value_len > MAX_PAYLOAD || cursor.take(value_len as usize).is_err() {
                return false;
            }
        }
        if tag == 3 && cursor.u64().is_err() {
            return false;
        }
    }
    cursor.finished()
}

/// Decode one complete synthetic frame image after a separately checked H80.
/// This is not an installed-WAL scan or proof of a relational effect.
pub(crate) fn decode_complete_frame(
    bytes: &[u8],
    context: &FrameContext,
) -> Result<UntrustedFrame, FrameError> {
    let Some(h64) = bytes.get(..H64_LEN) else {
        return Err(FrameError::Corrupt);
    };
    let H64Inspection::Complete(header) = inspect_h64_prefix(h64, context)? else {
        return Err(FrameError::Corrupt);
    };
    if bytes.len() != header.total_len as usize {
        return Err(FrameError::Corrupt);
    }
    let crc_at = H64_LEN + header.payload_len as usize;
    let expected_crc = castagnoli_crc32c(&bytes[..crc_at]);
    if bytes[crc_at..crc_at + 4] != expected_crc.to_le_bytes() {
        return Err(FrameError::Corrupt);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"praxor/wal-frame/v5");
    hasher.update(&context.header_digest);
    hasher.update(&context.previous_hash);
    hasher.update(&bytes[..crc_at + 4]);
    let trailer = *hasher.finalize().as_bytes();
    if bytes[crc_at + 4..] != trailer {
        return Err(FrameError::Corrupt);
    }
    if !valid_payload(&header, &context.database_id, &bytes[H64_LEN..crc_at]) {
        return Err(FrameError::Corrupt);
    }
    Ok(UntrustedFrame { header, trailer })
}

#[cfg(test)]
mod tests;
