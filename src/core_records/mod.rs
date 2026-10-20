//! Explicit core-backed record authority. Legacy storage constructors never activate it.
pub(crate) mod codec;
mod database;
pub(crate) mod intent;
pub(crate) mod recovery;
mod schema;
mod snapshot;
mod store;
pub(crate) mod transition;
pub(crate) mod variable_stream;

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod transition_tests;

pub use database::CoreDatabase;
pub use schema::{MappingDescriptor, RecordAuthority, RecordAuthorityOptions, RecordRoleBinding};
pub use snapshot::CoreRecordSnapshot;
pub(crate) use store::{CoreRecordScanError, RecordScanLimits};
pub use store::{CoreRecordStore, RecordHistoryReclaimReport};

pub(crate) fn ensure_public_cf(
    manifest: &crate::manifest::Manifest,
    name: &str,
) -> crate::Result<()> {
    if manifest.record_authority.is_some() && name.starts_with(schema::RESERVED_PREFIX) {
        Err(crate::PraxisError::ProtectedRecordColumnFamily(name.into()))
    } else {
        Ok(())
    }
}
