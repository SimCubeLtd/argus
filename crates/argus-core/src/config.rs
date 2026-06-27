//! Loading and saving of `.triage-state/argus.toml`.
//!
//! Mirrors Synapse's config module: this is the *only* place that reads or
//! writes the TOML, and the struct shape round-trips a freshly `init`-ed file
//! without surprises. Every section field has a serde default so partial /
//! older config files still load.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Directory holding all Argus state, relative to the repo root.
pub const TRIAGE_DIR: &str = ".triage-state";
/// Config file name within [`TRIAGE_DIR`].
pub const CONFIG_FILE: &str = "argus.toml";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ArgusConfig {
    #[serde(default)]
    pub endpoint: EndpointConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub report: ReportConfig,
}

/// SGLang / OpenAI-compatible endpoint settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// OpenAI-compatible base URL, e.g. `http://ippex-inference:8000/v1`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Model name served by the endpoint.
    #[serde(default = "default_model")]
    pub model: String,
    /// Bearer token. SGLang requires no auth, so this is a dummy by default.
    /// Never commit a real key here.
    #[serde(default = "default_api_key")]
    pub api_key: String,
    /// Per-request timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Max in-flight LLM requests, so a first full scan can't overwhelm SGLang.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Send `chat_template_kwargs: {"enable_thinking": false}` on each request so
    /// reasoning-capable models (Qwen3.x, GLM, ...) answer in `content` instead
    /// of emitting chain-of-thought. Harmless for non-thinking models. Set false
    /// only if an endpoint rejects the field.
    #[serde(default = "default_true")]
    pub disable_thinking: bool,
}

/// What to scan and how to bound chunk size.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanConfig {
    /// File extensions to triage (with leading dot).
    #[serde(default = "default_include_extensions")]
    pub include_extensions: Vec<String>,
    /// Directory *names* to prune anywhere in the tree.
    #[serde(default = "default_exclude_dirs")]
    pub exclude_dirs: Vec<String>,
    /// Per-chunk token ceiling (estimated as chars / 4).
    #[serde(default = "default_max_tokens_per_chunk")]
    pub max_tokens_per_chunk: usize,
    /// Token budget for the per-file Synapse context pack.
    #[serde(default = "default_context_budget")]
    pub context_budget: usize,
}

/// Report output settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Directory (repo-relative) for the dated Markdown reports.
    #[serde(default = "default_report_dir")]
    pub output_dir: String,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        EndpointConfig {
            base_url: default_base_url(),
            model: default_model(),
            api_key: default_api_key(),
            timeout_secs: default_timeout_secs(),
            concurrency: default_concurrency(),
            disable_thinking: default_true(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            include_extensions: default_include_extensions(),
            exclude_dirs: default_exclude_dirs(),
            max_tokens_per_chunk: default_max_tokens_per_chunk(),
            context_budget: default_context_budget(),
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        ReportConfig {
            output_dir: default_report_dir(),
        }
    }
}

fn default_base_url() -> String {
    "http://ippex-inference:8000/v1".to_string()
}
fn default_model() -> String {
    "default".to_string()
}
fn default_api_key() -> String {
    // Dummy value — SGLang needs no auth, and committing a real key is a bug.
    "sglang".to_string()
}
fn default_timeout_secs() -> u64 {
    300
}
fn default_true() -> bool {
    true
}
fn default_concurrency() -> usize {
    4
}
fn default_include_extensions() -> Vec<String> {
    [".cs", ".svelte", ".ts", ".js", ".json", ".yaml", ".yml"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_exclude_dirs() -> Vec<String> {
    ["bin", "obj", ".git", "node_modules", "migrations"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_max_tokens_per_chunk() -> usize {
    8000
}
fn default_context_budget() -> usize {
    8000
}
fn default_report_dir() -> String {
    format!("{TRIAGE_DIR}/reports")
}

impl ArgusConfig {
    /// Load config from a repo root (expects `<root>/.triage-state/argus.toml`).
    pub fn load(root: &Path) -> Result<ArgusConfig> {
        let path = config_path(root);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading config at {}", path.display()))?;
        let cfg: ArgusConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    /// Serialize this config to TOML text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing config")
    }

    /// Write config to `<root>/.triage-state/argus.toml`, creating the dir.
    pub fn save(&self, root: &Path) -> Result<()> {
        let path = config_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, self.to_toml()?)
            .with_context(|| format!("writing config to {}", path.display()))?;
        Ok(())
    }
}

/// Path to the config file given a repo root.
pub fn config_path(root: &Path) -> PathBuf {
    root.join(TRIAGE_DIR).join(CONFIG_FILE)
}

/// Absolute path to the `.triage-state` directory for a repo root.
pub fn triage_dir(root: &Path) -> PathBuf {
    root.join(TRIAGE_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_round_trips_through_toml() {
        let cfg = ArgusConfig::default();
        let text = cfg.to_toml().unwrap();
        let parsed: ArgusConfig = toml::from_str(&text).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn empty_toml_yields_defaults() {
        // Every section is `#[serde(default)]`, so an empty file is valid and
        // produces the documented defaults — important for forward-compat.
        let parsed: ArgusConfig = toml::from_str("").unwrap();
        assert_eq!(parsed, ArgusConfig::default());
        assert_eq!(parsed.endpoint.base_url, "http://ippex-inference:8000/v1");
        assert_eq!(parsed.endpoint.api_key, "sglang");
        assert_eq!(parsed.scan.max_tokens_per_chunk, 8000);
    }

    #[test]
    fn partial_toml_fills_missing_with_defaults() {
        let parsed: ArgusConfig = toml::from_str("[endpoint]\nmodel = \"qwen\"\n").unwrap();
        assert_eq!(parsed.endpoint.model, "qwen");
        // Untouched fields keep their defaults.
        assert_eq!(parsed.endpoint.concurrency, 4);
        assert_eq!(parsed.scan.include_extensions[0], ".cs");
    }

    #[test]
    fn save_then_load_is_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ArgusConfig::default();
        cfg.save(dir.path()).unwrap();
        assert!(config_path(dir.path()).is_file());
        let loaded = ArgusConfig::load(dir.path()).unwrap();
        assert_eq!(cfg, loaded);
    }
}
