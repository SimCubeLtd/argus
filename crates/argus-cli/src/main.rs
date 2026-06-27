//! `argus` — the CLI binary. Thin wiring over `argus-core`: parse args, resolve
//! settings, dispatch to a command. Data goes to stdout, diagnostics to stderr.

mod cli;
mod commands;
mod resolve;

use anyhow::{Context, Result};
use argus_core::config::{ArgusConfig, config_path};
use argus_core::scan::model::TriageState;
use chrono::Local;
use clap::Parser;
use cli::{Cli, Command};
use resolve::Resolved;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    // Diagnostics via tracing; level from $RUST_LOG (default: warn).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let root = resolve_root(&cli)?;

    match &cli.command {
        Command::Init { force } => commands::init(&root, *force),
        Command::Scan => {
            let cfg = load_config(&root)?;
            let settings = Resolved::from(&cli, &cfg);
            let date = Local::now().format("%Y-%m-%d").to_string();
            let now = Local::now().to_rfc3339();
            commands::scan(&root, &settings, &date, &now).await
        }
        Command::Dismiss { fingerprint } => {
            commands::set_state(&root, fingerprint, TriageState::Dismissed)
        }
        Command::Confirm { fingerprint } => {
            commands::set_state(&root, fingerprint, TriageState::Confirmed)
        }
        Command::Report => {
            let cfg = load_config(&root)?;
            let settings = Resolved::from(&cli, &cfg);
            let date = Local::now().format("%Y-%m-%d").to_string();
            commands::report(&root, &settings, &date)
        }
        Command::Status { json } => commands::status(&root, *json),
    }
}

/// The repo root: `--root` if given, else the current directory.
fn resolve_root(cli: &Cli) -> Result<PathBuf> {
    let p = match &cli.root {
        Some(r) => PathBuf::from(r),
        None => std::env::current_dir().context("getting current directory")?,
    };
    Ok(p)
}

/// Load config, with a clear "run `argus init`" error if it's missing.
fn load_config(root: &std::path::Path) -> Result<ArgusConfig> {
    if !config_path(root).is_file() {
        anyhow::bail!(
            "no Argus workspace at {} — run `argus init` first",
            root.display()
        );
    }
    ArgusConfig::load(root)
}
