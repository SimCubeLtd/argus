//! Argus error type.
//!
//! Most fallible paths use `anyhow::Result` for ergonomic context chaining;
//! [`ArgusError`] names the handful of failure modes callers may want to match
//! on (a missing workspace, a bad fingerprint) rather than treat as opaque.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArgusError {
    /// `.triage-state/argus.toml` was not found — `argus init` hasn't been run.
    #[error("no Argus workspace at {0} — run `argus init` first")]
    NotInitialized(String),

    /// A fingerprint passed to `dismiss`/`confirm` matches no known finding.
    #[error("no finding with fingerprint `{0}`")]
    UnknownFingerprint(String),

    /// The model returned non-JSON output even after the one retry.
    #[error("model did not return parseable JSON for {context} (after retry)")]
    LlmJsonParse { context: String },
}
