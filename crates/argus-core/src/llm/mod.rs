//! The LLM seam: a trait over an OpenAI-compatible chat endpoint, the real
//! SGLang-targeting client, and the two-pass prompt builders.

mod client;
pub mod prompts;

pub use client::{Completion, LlmClient, MockLlmClient, OpenAiClient, TokenUsage};
