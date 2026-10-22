#[allow(dead_code)] // Private v4 physical witness is built behind a fenced owner.
pub(crate) mod catalog_witness;
pub mod durability;
pub mod page;
pub mod record;
pub mod writer;
// Read-only v5 wire decoding is staged behind a synthetic, untrusted seam.
#[allow(dead_code)]
pub(crate) mod v5_header;

#[cfg(test)]
mod catalog_witness_tests;

pub use durability::{DurabilitySource, WalDurability, WalVisibilityRule};
pub use page::{PageWal, PageWalMutation, PageWalRecord};
pub(crate) use page::{
    PageWalWriter, read_records_strict as read_page_wal_strict,
    validate_identity as validate_page_wal_identity,
};
pub use record::WalRecord;
pub use writer::Wal;
