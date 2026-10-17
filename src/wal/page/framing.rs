//! Read-only framing authority. A report is evidence, never permission to repair.
use super::{PageWalMutation, PageWalRecord, validate_identity};
use crate::errors::{PraxisError, Result};
use crate::identity::{Aid, Cid, Did, Eid, FieldId, Rid};
use crate::io::{BinaryReader, crc32_ieee};
use std::path::Path;

pub const MAX_PAGE_WAL_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub(super) const FILE_MAGIC: u32 = 0x5450_5746;
const V1_MAGIC: u32 = 0x5450_5752;
const V2_MAGIC: u32 = 0x5450_5732;
const V1_HEADER: usize = 13;
const V2_HEADER: usize = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageWalFileFormat {
    Missing,
    Empty,
    HeaderlessV1,
    LegacyV1,
    V2,
    Undetermined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageWalIncompleteKind {
    FileHeader,
    RecordHeader,
    Payload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageWalScanStop {
    Clean,
    ProvenV2Torn {
        offset: u64,
        kind: PageWalIncompleteKind,
        available: u64,
        expected: u64,
    },
    LegacyAmbiguousTail {
        offset: u64,
        kind: PageWalIncompleteKind,
        available: u64,
        expected: u64,
        reason: String,
    },
    Corrupt {
        offset: u64,
        reason: String,
    },
    Unsupported {
        offset: u64,
        reason: String,
    },
}

/// A forensic prefix and its stop evidence; it does not certify complete history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageWalReplayReport {
    pub records: Vec<PageWalRecord>,
    pub valid_len: u64,
    pub physical_len: u64,
    pub file_format: PageWalFileFormat,
    pub stop: PageWalScanStop,
}

impl PageWalReplayReport {
    pub(super) fn into_strict(self, source: &Path) -> Result<Vec<PageWalRecord>> {
        if self.stop == PageWalScanStop::Clean {
            Ok(self.records)
        } else {
            Err(PraxisError::Corrupt {
                path: source.to_path_buf(),
                reason: format!("incomplete page WAL scan: {:?}", self.stop),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Version {
    V1,
    V2,
}

enum Prefix {
    Complete {
        record: PageWalRecord,
        consumed: usize,
        version: Version,
    },
    Incomplete {
        version: Version,
        kind: PageWalIncompleteKind,
        available: usize,
        expected: usize,
    },
}

#[derive(Debug)]
struct Issue {
    unsupported: bool,
    reason: String,
}

impl Issue {
    fn corrupt(reason: impl Into<String>) -> Self {
        Self {
            unsupported: false,
            reason: reason.into(),
        }
    }
    fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            unsupported: true,
            reason: reason.into(),
        }
    }
    fn stop(self, offset: usize) -> PageWalScanStop {
        if self.unsupported {
            PageWalScanStop::Unsupported {
                offset: offset as u64,
                reason: self.reason,
            }
        } else {
            PageWalScanStop::Corrupt {
                offset: offset as u64,
                reason: self.reason,
            }
        }
    }
}

fn invalid(reason: impl Into<String>) -> PraxisError {
    PraxisError::InvalidConfig(reason.into())
}

pub(super) fn checked_put_len(
    count: usize,
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize> {
    u32::try_from(count).map_err(|_| invalid("page WAL field count exceeds u32"))?;
    let mut payload = 29_usize;
    let mut actual = 0_usize;
    for len in lengths {
        u32::try_from(len).map_err(|_| invalid("page WAL field length exceeds u32"))?;
        payload = payload
            .checked_add(9)
            .and_then(|sum| sum.checked_add(len))
            .ok_or_else(|| invalid("page WAL payload length overflow"))?;
        if payload > MAX_PAGE_WAL_PAYLOAD_BYTES {
            return Err(invalid("page WAL payload exceeds 64 MiB"));
        }
        actual = actual
            .checked_add(1)
            .ok_or_else(|| invalid("page WAL field count overflow"))?;
    }
    if actual != count {
        return Err(invalid("page WAL field count does not match fields"));
    }
    payload
        .checked_add(V2_HEADER)
        .ok_or_else(|| invalid("page WAL frame length overflow"))
}

pub(super) fn checked_len(record: &PageWalRecord) -> Result<usize> {
    validate_identity(record, Path::new("page-wal-input"))?;
    match &record.mutation {
        PageWalMutation::Put { fields, .. } => {
            checked_put_len(fields.len(), fields.iter().map(|(_, bytes)| bytes.len()))
        }
        PageWalMutation::Delete { .. } => Ok(V2_HEADER + 25),
    }
}

pub(super) fn encode(record: &PageWalRecord) -> Result<Vec<u8>> {
    let len = checked_len(record)?;
    let header_len = V2_HEADER;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| invalid("cannot reserve checked page WAL frame"))?;
    out.resize(header_len, 0);
    out.extend_from_slice(&record.sequence.to_le_bytes());
    let (cid, eid, rid, fields) = match &record.mutation {
        PageWalMutation::Put {
            cid,
            eid,
            rid,
            fields,
        } => {
            out.push(1);
            (*cid, *eid, *rid, Some(fields))
        }
        PageWalMutation::Delete { cid, eid, rid } => {
            out.push(2);
            (*cid, *eid, *rid, None)
        }
    };
    out.extend_from_slice(&cid.0.to_le_bytes());
    out.extend_from_slice(&eid.0.to_le_bytes());
    out.extend_from_slice(&rid.0.to_le_bytes());
    if let Some(fields) = fields {
        out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        for (field, bytes) in fields {
            let (tag, id) = match field {
                FieldId::Fixed(aid) => (1, aid.0),
                FieldId::Dynamic(did) => (2, did.0),
            };
            out.push(tag);
            out.extend_from_slice(&u32::from(id).to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
    out[..4].copy_from_slice(&V2_MAGIC.to_le_bytes());
    out[4] = 2;
    out[5..9].copy_from_slice(&((len - header_len) as u32).to_le_bytes());
    let payload_crc = crc32_ieee(&out[header_len..]);
    out[9..13].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32_ieee(&out[..13]);
    out[13..17].copy_from_slice(&header_crc.to_le_bytes());
    Ok(out)
}

pub(super) fn exact(bytes: &[u8], source: &Path) -> Result<PageWalRecord> {
    match frame(bytes, source, None).map_err(|issue| PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: issue.reason,
    })? {
        Prefix::Complete {
            record, consumed, ..
        } if consumed == bytes.len() => Ok(record),
        Prefix::Complete { .. } => Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "trailing page WAL frame bytes".into(),
        }),
        Prefix::Incomplete { .. } => Err(PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: "incomplete page WAL frame".into(),
        }),
    }
}

pub(super) fn file_header_v2() -> [u8; 16] {
    let mut out = [0; 16];
    out[..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&2_u32.to_le_bytes());
    let crc = crc32_ieee(&out[..12]);
    out[12..].copy_from_slice(&crc.to_le_bytes());
    out
}

fn file_start(bytes: &[u8]) -> (PageWalFileFormat, usize, Option<PageWalScanStop>) {
    use PageWalFileFormat as F;
    if bytes.is_empty() {
        return (F::Empty, 0, None);
    }
    let mut v1 = [0; 16];
    v1[..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
    v1[4..8].copy_from_slice(&1_u32.to_le_bytes());
    let v2 = file_header_v2();
    if bytes.len() < 4 && FILE_MAGIC.to_le_bytes().starts_with(bytes)
        || bytes.len() >= 4 && bytes[..4] == FILE_MAGIC.to_le_bytes()
    {
        if bytes.len() < 16 {
            let known_v1 = v1.starts_with(bytes);
            let known_v2 = v2.starts_with(bytes);
            if known_v2 && !known_v1 {
                return (
                    F::V2,
                    0,
                    Some(PageWalScanStop::ProvenV2Torn {
                        offset: 0,
                        kind: PageWalIncompleteKind::FileHeader,
                        available: bytes.len() as u64,
                        expected: 16,
                    }),
                );
            }
            if known_v1 || known_v2 {
                let format = if known_v1 && !known_v2 {
                    F::LegacyV1
                } else {
                    F::Undetermined
                };
                return (
                    format,
                    0,
                    Some(PageWalScanStop::LegacyAmbiguousTail {
                        offset: 0,
                        kind: PageWalIncompleteKind::FileHeader,
                        available: bytes.len() as u64,
                        expected: 16,
                        reason: "incomplete file identity has no proven v2 repair boundary".into(),
                    }),
                );
            }
            return (
                F::Undetermined,
                0,
                Some(Issue::corrupt("invalid partial page WAL file header").stop(0)),
            );
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        match version {
            1 if bytes[8..16] == [0; 8] => (F::LegacyV1, 16, None),
            1 => (
                F::LegacyV1,
                0,
                Some(Issue::corrupt("nonzero legacy file reserved bytes").stop(0)),
            ),
            2 => {
                let expected = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                if crc32_ieee(&bytes[..12]) != expected {
                    return (
                        F::V2,
                        0,
                        Some(Issue::corrupt("page WAL file header checksum mismatch").stop(0)),
                    );
                }
                if bytes[8..12] != [0; 4] {
                    return (
                        F::V2,
                        0,
                        Some(Issue::unsupported("unsupported page WAL file flags").stop(0)),
                    );
                }
                (F::V2, 16, None)
            }
            _ => (
                F::Undetermined,
                0,
                Some(
                    Issue::unsupported(format!("unsupported page WAL file version {version}"))
                        .stop(0),
                ),
            ),
        }
    } else if (bytes.len() < 4 && V1_MAGIC.to_le_bytes().starts_with(bytes))
        || (bytes.len() >= 4 && bytes[..4] == V1_MAGIC.to_le_bytes())
    {
        (F::HeaderlessV1, 0, None)
    } else {
        (
            F::Undetermined,
            0,
            Some(Issue::corrupt("unrecognized page WAL file identity").stop(0)),
        )
    }
}

pub(super) fn scan(bytes: &[u8], source: &Path) -> PageWalReplayReport {
    let (format, mut offset, stop) = file_start(bytes);
    let mut report = PageWalReplayReport {
        records: Vec::new(),
        valid_len: offset as u64,
        physical_len: bytes.len() as u64,
        file_format: format,
        stop: stop.unwrap_or(PageWalScanStop::Clean),
    };
    if report.stop != PageWalScanStop::Clean {
        return report;
    }
    let mut previous = 0;
    let mut seen_v2 = false;
    while offset < bytes.len() {
        match frame(&bytes[offset..], source, Some(previous)) {
            Ok(Prefix::Complete {
                record,
                consumed,
                version,
            }) => {
                if version == Version::V2 && format != PageWalFileFormat::V2
                    || version == Version::V1 && seen_v2
                {
                    report.stop =
                        Issue::corrupt("page WAL frame violates its file-version transition")
                            .stop(offset);
                    break;
                }
                if record.sequence <= previous {
                    report.stop =
                        Issue::corrupt("page WAL sequences must strictly increase").stop(offset);
                    break;
                }
                previous = record.sequence;
                seen_v2 |= version == Version::V2;
                if report.records.try_reserve(1).is_err() {
                    report.stop =
                        Issue::corrupt("cannot reserve actual page WAL history").stop(offset);
                    break;
                }
                report.records.push(record);
                offset += consumed;
                report.valid_len = offset as u64;
            }
            Ok(Prefix::Incomplete {
                version: Version::V2,
                kind,
                available,
                expected,
            }) if format == PageWalFileFormat::V2 => {
                report.stop = PageWalScanStop::ProvenV2Torn {
                    offset: offset as u64,
                    kind,
                    available: available as u64,
                    expected: expected as u64,
                };
                break;
            }
            Ok(Prefix::Incomplete {
                version: Version::V1,
                ..
            }) if seen_v2 => {
                report.stop = Issue::corrupt("legacy frame prefix after a v2 record").stop(offset);
                break;
            }
            Ok(Prefix::Incomplete {
                version: Version::V1,
                kind,
                available,
                expected,
            }) => {
                report.stop = PageWalScanStop::LegacyAmbiguousTail {
                    offset: offset as u64,
                    kind,
                    available: available as u64,
                    expected: expected as u64,
                    reason: "legacy length/header cannot authenticate a discarded suffix".into(),
                };
                break;
            }
            Ok(Prefix::Incomplete { .. }) => {
                report.stop = Issue::corrupt("v2 frame requires a v2 file barrier").stop(offset);
                break;
            }
            Err(issue) => {
                report.stop = issue.stop(offset);
                break;
            }
        }
    }
    report
}

fn frame(
    bytes: &[u8],
    source: &Path,
    previous_sequence: Option<u64>,
) -> std::result::Result<Prefix, Issue> {
    let version = if bytes.len() < 4 {
        if V1_MAGIC.to_le_bytes().starts_with(bytes) {
            Version::V1
        } else if V2_MAGIC.to_le_bytes().starts_with(bytes) {
            Version::V2
        } else {
            return Err(Issue::corrupt("unrecognized short page WAL frame"));
        }
    } else {
        match u32::from_le_bytes(bytes[..4].try_into().unwrap()) {
            V1_MAGIC => Version::V1,
            V2_MAGIC => Version::V2,
            _ => return Err(Issue::corrupt("bad page WAL record magic")),
        }
    };
    let expected_version = if version == Version::V1 { 1 } else { 2 };
    if bytes.len() >= 5 && bytes[4] != expected_version {
        return Err(Issue::unsupported(format!(
            "unsupported page WAL record version {}",
            bytes[4]
        )));
    }
    let header_len = if version == Version::V1 {
        V1_HEADER
    } else {
        V2_HEADER
    };
    if bytes.len() < header_len {
        // Once the first 13 bytes exist, every present checksum byte is a
        // verifiable part of the append prefix, even before the header is whole.
        if version == Version::V2 && bytes.len() > V1_HEADER {
            let expected = crc32_ieee(&bytes[..V1_HEADER]).to_le_bytes();
            if bytes[V1_HEADER..] != expected[..bytes.len() - V1_HEADER] {
                return Err(Issue::corrupt("partial page WAL header checksum mismatch"));
            }
        }
        return Ok(Prefix::Incomplete {
            version,
            kind: PageWalIncompleteKind::RecordHeader,
            available: bytes.len(),
            expected: header_len,
        });
    }
    if version == Version::V2
        && crc32_ieee(&bytes[..13]) != u32::from_le_bytes(bytes[13..17].try_into().unwrap())
    {
        return Err(Issue::corrupt("page WAL record header checksum mismatch"));
    }
    let len = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let expected_crc = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
    if version == Version::V2 && !(25..=MAX_PAGE_WAL_PAYLOAD_BYTES).contains(&len) {
        return Err(Issue::corrupt("invalid v2 page WAL payload length"));
    }
    let end = header_len
        .checked_add(len)
        .ok_or_else(|| Issue::corrupt("page WAL frame length overflow"))?;
    if end > bytes.len() {
        if version == Version::V1
            && let PayloadProbe::Complete(consumed) =
                probe_payload(&bytes[header_len..], None, None)
            && crc32_ieee(&bytes[header_len..header_len + consumed]) == expected_crc
        {
            return Err(Issue::corrupt(
                "legacy page WAL length disagrees with intact payload",
            ));
        }
        if version == Version::V2
            && let PayloadProbe::Invalid(reason) =
                probe_payload(&bytes[header_len..], Some(len), previous_sequence)
        {
            return Err(Issue::corrupt(reason));
        }
        return Ok(Prefix::Incomplete {
            version,
            kind: PageWalIncompleteKind::Payload,
            available: bytes.len(),
            expected: end,
        });
    }
    let payload = &bytes[header_len..end];
    if crc32_ieee(payload) != expected_crc {
        return Err(Issue::corrupt("page WAL payload checksum mismatch"));
    }
    match probe_payload(payload, Some(payload.len()), previous_sequence) {
        PayloadProbe::Complete(_) => {}
        PayloadProbe::NeedMore => return Err(Issue::corrupt("incomplete page WAL payload")),
        PayloadProbe::Invalid(reason) => return Err(Issue::corrupt(reason)),
    }
    let record =
        decode_payload(payload, source).map_err(|error| Issue::corrupt(error.to_string()))?;
    Ok(Prefix::Complete {
        record,
        consumed: end,
        version,
    })
}

enum PayloadProbe {
    NeedMore,
    Invalid(&'static str),
    Complete(usize),
}

enum ProbeFailure {
    NeedMore,
    Invalid(&'static str),
}

// Probe only borrowed slices. A v2 prefix uses its authenticated total rather
// than the available bytes to establish whether a valid completion can fit.
// A legacy length is unauthenticated, so its intact-body probe has no total and
// may finish before subsequent frames. No legacy failure authorizes repair.
fn probe_payload(
    bytes: &[u8],
    total: Option<usize>,
    previous_sequence: Option<u64>,
) -> PayloadProbe {
    match probe_payload_inner(bytes, total, previous_sequence) {
        Ok(consumed) => PayloadProbe::Complete(consumed),
        Err(ProbeFailure::NeedMore) => PayloadProbe::NeedMore,
        Err(ProbeFailure::Invalid(reason)) => PayloadProbe::Invalid(reason),
    }
}

fn probe_payload_inner(
    bytes: &[u8],
    total: Option<usize>,
    previous_sequence: Option<u64>,
) -> std::result::Result<usize, ProbeFailure> {
    use ProbeFailure::{Invalid, NeedMore};
    struct Probe<'a> {
        bytes: &'a [u8],
        at: usize,
        total: Option<usize>,
    }
    impl<'a> Probe<'a> {
        fn fits(&self, len: usize) -> std::result::Result<(), ProbeFailure> {
            let end = self
                .at
                .checked_add(len)
                .ok_or(Invalid("page WAL payload offset overflow"))?;
            if self.total.is_some_and(|total| end > total) {
                return Err(Invalid("page WAL fields exceed declared payload extent"));
            }
            Ok(())
        }
        fn take(&mut self, len: usize) -> std::result::Result<&'a [u8], ProbeFailure> {
            self.fits(len)?;
            let end = self.at + len;
            let bytes = self.bytes.get(self.at..end).ok_or(NeedMore)?;
            self.at = end;
            Ok(bytes)
        }
        fn u32(&mut self) -> std::result::Result<u32, ProbeFailure> {
            Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
        }
        fn u64(&mut self) -> std::result::Result<u64, ProbeFailure> {
            Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
        }
    }
    let mut reader = Probe {
        bytes,
        at: 0,
        total,
    };
    let sequence = reader.u64()?;
    if sequence == 0 {
        return Err(Invalid("reserved zero sequence in page WAL record"));
    }
    if previous_sequence.is_some_and(|previous| sequence <= previous) {
        return Err(Invalid("page WAL sequences must strictly increase"));
    }
    let mutation = reader.take(1)?[0];
    match mutation {
        1 if total.is_some_and(|total| total < 29) => {
            return Err(Invalid("page WAL put cannot fit declared payload extent"));
        }
        2 if total.is_some_and(|total| total != 25) => {
            return Err(Invalid(
                "page WAL delete has invalid declared payload extent",
            ));
        }
        1 | 2 => {}
        _ => return Err(Invalid("unknown page WAL mutation tag")),
    }
    if reader.u32()? == 0 {
        return Err(Invalid("reserved zero cid in page WAL record"));
    }
    if reader.u32()? == 0 {
        return Err(Invalid("reserved zero eid in page WAL record"));
    }
    if reader.u64()? == 0 {
        return Err(Invalid("reserved zero rid in page WAL record"));
    }
    match mutation {
        1 => {
            let count = reader.u32()? as usize;
            let minimum = count
                .checked_mul(9)
                .ok_or(Invalid("page WAL field count overflows payload extent"))?;
            reader.fits(minimum)?;
            for index in 0..count {
                let tag = reader.take(1)?[0];
                if !matches!(tag, 1 | 2) {
                    return Err(Invalid("unknown page WAL field tag"));
                }
                u16::try_from(reader.u32()?)
                    .map_err(|_| Invalid("page WAL field ID exceeds u16"))?;
                let len = reader.u32()? as usize;
                let remaining = (count - index - 1)
                    .checked_mul(9)
                    .and_then(|minimum| minimum.checked_add(len))
                    .ok_or(Invalid("page WAL field length overflows payload extent"))?;
                reader.fits(remaining)?;
                reader.take(len)?;
            }
        }
        2 => {}
        _ => unreachable!("validated mutation tag"),
    }
    if total.is_some_and(|total| reader.at != total) {
        return Err(Invalid("trailing bytes in page WAL mutation"));
    }
    Ok(reader.at)
}

fn decode_payload(bytes: &[u8], source: &Path) -> Result<PageWalRecord> {
    let mut reader = BinaryReader::new(bytes, source);
    let sequence = reader.read_u64()?;
    let tag = reader.read_u8()?;
    let cid = Cid(reader.read_u32()?);
    let eid = Eid(reader.read_u32()?);
    let rid = Rid(reader.read_u64()?);
    let mutation = if tag == 1 {
        let count = reader.read_u32()? as usize;
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(count)
            .map_err(|_| invalid("cannot reserve validated page WAL fields"))?;
        for _ in 0..count {
            let tag = reader.read_u8()?;
            let id = u16::try_from(reader.read_u32()?)
                .map_err(|_| invalid("invalid field after page WAL probe"))?;
            let field = if tag == 1 {
                FieldId::Fixed(Aid(id))
            } else {
                FieldId::Dynamic(Did(id))
            };
            let bytes = reader.read_len_slice()?;
            let mut copied = Vec::new();
            copied
                .try_reserve_exact(bytes.len())
                .map_err(|_| invalid("cannot reserve validated page WAL field"))?;
            copied.extend_from_slice(bytes);
            fields.push((field, copied));
        }
        PageWalMutation::Put {
            cid,
            eid,
            rid,
            fields,
        }
    } else {
        PageWalMutation::Delete { cid, eid, rid }
    };
    Ok(PageWalRecord { sequence, mutation })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_writer_open_preserves_a_complete_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("page.wal");
        let bytes = file_header_v2();
        std::fs::write(&path, bytes).unwrap();
        let _writer = super::super::PageWalWriter::open(
            &path,
            crate::config::WalSyncPolicy::EveryBatch,
            &mut super::super::owned::WalLifecycle::default(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn checked_sizing_boundaries_need_no_large_allocations() {
        let max_value = MAX_PAGE_WAL_PAYLOAD_BYTES - 29 - 9;
        assert_eq!(
            checked_put_len(1, [max_value]).unwrap(),
            MAX_PAGE_WAL_PAYLOAD_BYTES + V2_HEADER
        );
        assert!(checked_put_len(1, [max_value + 1]).is_err());
        assert!(checked_put_len(1, [usize::MAX]).is_err());
        assert!(checked_put_len(usize::MAX, []).is_err());
        assert!(checked_put_len(2, [0]).is_err());
        assert_eq!(checked_put_len(0, []).unwrap(), 29 + V2_HEADER);
    }
}
