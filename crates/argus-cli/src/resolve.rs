//! Resolve effective settings with precedence: CLI args > env vars > config
//! file > built-in defaults.
//!
//! This is the *only* place env vars are read, so `argus-core` stays pure and
//! testable. The resolved values flow into the scan as an explicit struct.

use crate::cli::Cli;
use argus_core::config::ArgusConfig;

/// Effective, fully-resolved settings for a run.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub disable_thinking: bool,
    pub concurrency: usize,
    pub max_tokens_per_chunk: usize,
    pub context_budget: usize,
    pub include_extensions: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub report_dir: String,
}

impl Resolved {
    /// Layer CLI > env > config. `cfg` already carries the file/default values.
    pub fn from(cli: &Cli, cfg: &ArgusConfig) -> Self {
        let base_url = pick_str(
            cli.base_url.clone(),
            env("ARGUS_BASE_URL"),
            cfg.endpoint.base_url.clone(),
        );
        let model = pick_str(
            cli.model.clone(),
            env("ARGUS_MODEL"),
            cfg.endpoint.model.clone(),
        );
        let api_key = pick_str(None, env("ARGUS_API_KEY"), cfg.endpoint.api_key.clone());
        let concurrency = pick_usize(
            cli.concurrency,
            env_usize("ARGUS_CONCURRENCY"),
            cfg.endpoint.concurrency,
        );
        let max_tokens_per_chunk = pick_usize(
            cli.max_tokens,
            env_usize("ARGUS_MAX_TOKENS"),
            cfg.scan.max_tokens_per_chunk,
        );

        Resolved {
            base_url,
            model,
            api_key,
            timeout_secs: cfg.endpoint.timeout_secs,
            disable_thinking: cfg.endpoint.disable_thinking,
            concurrency,
            max_tokens_per_chunk,
            context_budget: cfg.scan.context_budget,
            include_extensions: cfg.scan.include_extensions.clone(),
            exclude_dirs: cfg.scan.exclude_dirs.clone(),
            report_dir: cfg.report.output_dir.clone(),
        }
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_usize(key: &str) -> Option<usize> {
    env(key).and_then(|v| v.parse().ok())
}

fn pick_str(cli: Option<String>, env: Option<String>, cfg: String) -> String {
    cli.or(env).unwrap_or(cfg)
}

fn pick_usize(cli: Option<usize>, env: Option<usize>, cfg: usize) -> usize {
    cli.or(env).unwrap_or(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        let mut full = vec!["argus"];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    #[test]
    fn cli_arg_beats_config() {
        let c = cli(&["--base-url", "http://cli:9/v1", "scan"]);
        let r = Resolved::from(&c, &ArgusConfig::default());
        assert_eq!(r.base_url, "http://cli:9/v1");
    }

    #[test]
    fn config_is_the_fallback() {
        let c = cli(&["scan"]);
        let mut cfg = ArgusConfig::default();
        cfg.endpoint.model = "from-config".into();
        let r = Resolved::from(&c, &cfg);
        assert_eq!(r.model, "from-config");
        assert_eq!(r.concurrency, 4); // default
    }
}
