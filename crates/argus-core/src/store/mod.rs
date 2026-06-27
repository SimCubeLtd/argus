//! Triage-state persistence.
//!
//! All access to stored findings and the last-run marker goes through the
//! [`FindingStore`] trait, so the JSON backend can be swapped (for SQLite, say)
//! without touching the scanner. [`JsonFindingStore`] is the production backend;
//! [`MemoryFindingStore`] backs unit tests with no filesystem.

mod json_store;
mod memory_store;
#[allow(clippy::module_inception)]
mod store;

pub use json_store::JsonFindingStore;
pub use memory_store::MemoryFindingStore;
pub use store::{Counts, FindingStore, LastRun};
