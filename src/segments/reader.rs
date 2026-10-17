use crate::accel::Accelerator;
use crate::errors::Result;
use crate::io::read_file_with_policy;
use crate::segments::block::SegmentEntry;
use crate::segments::codec::decode_segment;
use crate::types::StoredValue;
use std::path::Path;

pub struct SegmentReader;

impl SegmentReader {
    pub fn read(
        path: &Path,
        accelerator: &dyn Accelerator,
        requested_direct_io: bool,
    ) -> Result<Vec<SegmentEntry>> {
        let (bytes, _) = read_file_with_policy(path, requested_direct_io)?;
        let raw = decode_segment(&bytes, path, accelerator)?;
        raw.blocks
            .into_iter()
            .flatten()
            .map(|mut raw| {
                if let Some(expires_at_ms) = raw.blob_expiry
                    && let StoredValue::BlobPointer(pointer) = &raw.entry.version.value
                {
                    raw.entry.version.value = StoredValue::PutWithExpiry {
                        value: crate::values::ValueLog::read_pointer(pointer)?,
                        expires_at_ms,
                    };
                }
                Ok(raw.entry)
            })
            .collect()
    }
}
