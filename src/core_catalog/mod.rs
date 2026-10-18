//! Provisional entry point for the separately versioned core catalog owner.
//!
//! The v4 owner is unavailable until its bootstrap and recovery contract is
//! durable. This module never hands out a writable owner on partial evidence.

mod database;

pub use database::CatalogDatabase;
