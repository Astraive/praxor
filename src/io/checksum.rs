use crate::errors::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// IEEE CRC32 (CRC-32/ISO-HDLC), used by the existing storage formats.
///
/// The check value for `b"123456789"` is `0xcbf4_3926`.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Historical name for [`crc32_ieee`]. This computes IEEE CRC32, not CRC32C
/// (Castagnoli). Retained without deprecation to preserve source and wire
/// compatibility; new callers should use the accurately named entry point.
#[inline]
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32_ieee(bytes)
}

pub fn file_digest(path: &Path) -> Result<blake3::Hash> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize())
}
