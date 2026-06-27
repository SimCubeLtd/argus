//! clap definitions for the `argus` CLI.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "argus",
    version,
    about = "Local daily LLM security triage for any codebase.",
    long_about = "Argus scans a codebase with a self-hosted SGLang endpoint, \
enriching each file with cross-file context from a Synapse code graph, and \
produces a daily Markdown triage report for human or AI review."
)]
pub struct Cli {
    /// Repo root to operate on (defaults to the current directory).
    #[arg(long, global = true)]
    pub root: Option<String>,

    /// OpenAI-compatible base URL (overrides config / $ARGUS_BASE_URL).
    #[arg(long, global = true)]
    pub base_url: Option<String>,

    /// Model name (overrides config / $ARGUS_MODEL).
    #[arg(long, global = true)]
    pub model: Option<String>,

    /// Max in-flight LLM requests (overrides config / $ARGUS_CONCURRENCY).
    #[arg(long, global = true)]
    pub concurrency: Option<usize>,

    /// Per-chunk token ceiling (overrides config / $ARGUS_MAX_TOKENS).
    #[arg(long, global = true)]
    pub max_tokens: Option<usize>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Write a default `.triage-state/argus.toml` config.
    Init {
        /// Overwrite an existing config.
        #[arg(long)]
        force: bool,
    },
    /// Run a scan and produce today's report.
    Scan,
    /// Mark a finding as dismissed (suppressed from reports forever).
    Dismiss {
        /// The finding's fingerprint (shown in the report).
        fingerprint: String,
    },
    /// Mark a finding as confirmed (kept in reports).
    Confirm {
        /// The finding's fingerprint (shown in the report).
        fingerprint: String,
    },
    /// Regenerate today's report from current state without rescanning.
    Report,
    /// Show counts of pending/confirmed/dismissed findings.
    Status {
        /// Emit JSON instead of a human table.
        #[arg(long)]
        json: bool,
    },
}
