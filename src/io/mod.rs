pub mod binary;
pub mod capability;
pub mod checksum;
pub mod compression;
pub mod hardware;
pub mod rate_limiter;

pub use binary::{BinaryReader, BinaryWriter};
pub use capability::{
    IoCapability, IoExecution, detect_io_capability, read_file_with_policy, resolve_io_execution,
    write_file_with_policy,
};
pub(crate) use capability::{create_dir_all_durable, sync_parent_dir};
pub use checksum::{crc32_ieee, crc32c, file_digest};
pub use compression::{decode_block, encode_block};
pub use hardware::{HardwareBackend, HardwareCapability, HardwareIoProfile, HardwareOperation};
pub use rate_limiter::IoRateLimiter;
