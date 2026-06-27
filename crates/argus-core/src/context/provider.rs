//! The [`ContextProvider`] contract.

use anyhow::Result;

/// Supplies the scanner with its file set, git change information, and per-file
/// cross-file context packs. Implementations decide whether a real code graph
/// backs them; the scanner is agnostic.
pub trait ContextProvider: Send + Sync {
    /// Build or refresh the underlying graph. `changed_only` restricts the
    /// refresh to git-changed files. A no-op for providers with no graph.
    fn refresh(&self, changed_only: bool) -> Result<()>;

    /// All repo-relative candidate files to triage (already filtered to the
    /// configured extensions and exclude-dirs), in deterministic order.
    fn candidate_files(&self) -> Result<Vec<String>>;

    /// Files changed since `sha` (repo-relative), narrowed to triage candidates.
    /// `Ok(None)` means "can't compute an incremental set" (first run, not a git
    /// repo, or an unknown SHA) — the scanner then does a full scan.
    fn changed_files_since(&self, sha: Option<&str>) -> Result<Option<Vec<String>>>;

    /// The current HEAD SHA to persist as this run's marker, if available.
    fn head_sha(&self) -> Option<String>;

    /// A token-budgeted context pack (Markdown) for `file`: its callers, base
    /// types, and project siblings. Returns an empty string when no context is
    /// available (the scanner then reasons file-only).
    fn context_pack(&self, file: &str, budget: usize) -> Result<String>;
}
