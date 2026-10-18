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

#[cfg(test)]
mod frame_tests;

pub(crate) use control::CatalogControl;

pub use authority::{CatalogAuthorityV1, CatalogBindingV1};
pub use database::CatalogDatabase;
