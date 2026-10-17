//! Explicit core-backed record authority. Legacy storage constructors never activate it.
pub(crate) mod codec;
mod database;
pub(crate) mod recovery;
mod schema;

pub use database::CoreDatabase;
pub use schema::{MappingDescriptor, RecordAuthority, RecordAuthorityOptions, RecordRoleBinding};

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
