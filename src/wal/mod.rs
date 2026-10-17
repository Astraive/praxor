pub mod durability;
pub mod page;
pub mod record;
pub mod writer;

pub use durability::{DurabilitySource, WalDurability, WalVisibilityRule};
pub use page::{PageWal, PageWalMutation, PageWalRecord};
pub(crate) use page::{
    PageWalWriter, read_records_strict as read_page_wal_strict,
    validate_identity as validate_page_wal_identity,
};
pub use record::WalRecord;
pub use writer::Wal;
