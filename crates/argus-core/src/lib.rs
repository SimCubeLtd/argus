//! Argus core — local LLM-driven security triage.
//!
//! This crate holds all the scanning logic with no CLI/terminal concerns, so it
//! is unit-testable without a network, a TTY, or the LadybugDB (C++) build. The
//! seams that touch the outside world — the LLM endpoint and the Synapse context
//! engine — are traits ([`llm::LlmClient`], [`context::ContextProvider`]) with
//! real implementations and test doubles, so the orchestration in [`scan`] can
//! be exercised end to end against in-memory fakes.
//!
//! The `synapse` cargo feature (off by default) compiles the real
//! [`context::SynapseContextProvider`]; the binary turns it on.

pub mod chunk;
pub mod config;
pub mod context;
pub mod errors;
pub mod llm;
pub mod report;
pub mod scan;
pub mod store;

pub use errors::ArgusError;
