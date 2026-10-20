//! Provisional entry point for the separately versioned core catalog owner.
//!
//! The v4 owner is unavailable until its bootstrap and recovery contract is
//! durable. This module never hands out a writable owner on partial evidence.

mod authority;
#[allow(dead_code)] // The private format codec is wired into WAL relations in the next B1 slice.
mod codec;
mod control;
mod database;
#[allow(dead_code)] // The pure relation is wired into admission in the B2 slice.
mod frame;
#[allow(dead_code)] // Private read-only physical proof is not yet a public owner.
mod physical;
#[allow(dead_code)] // #80 starts with a compiling behavioral RED for this private reader.
mod segment_witness;

#[allow(dead_code)] // Private external Head bytes are not owner authority until #81 is complete.
mod external_value;

#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod physical_tests;
#[cfg(test)]
mod segment_witness_tests;

pub(crate) use control::CatalogControl;

pub use authority::{CatalogAuthorityV1, CatalogBindingV1};
pub use database::CatalogDatabase;
