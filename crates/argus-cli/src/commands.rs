//! Subcommand implementations. Each takes the resolved repo root and settings,
//! and writes data to stdout / diagnostics to stderr (via `tracing`).

use crate::resolve::Resolved;
use anyhow::{Context, Result};
use argus_core::config::{ArgusConfig, config_path};
use argus_core::context::{ContextProvider, StubContextProvider, SynapseContextProvider};
use argus_core::llm::{LlmClient, OpenAiClient};
use argus_core::report::{ReportMeta, write_report};
use argus_core::scan::model::TriageState;
use argus_core::scan::{ScanParams, run_scan};
use argus_core::store::{FindingStore, JsonFindingStore};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// `argus init` — write a default config.
pub fn init(root: &Path, force: bool) -> Result<()> {
    let path = config_path(root);
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists (use --force to overwrite)",
            path.display()
        );
    }
    ArgusConfig::default().save(root)?;
    println!("Initialized Argus at {}", path.display());
    println!(
        "Edit the [endpoint] section (or set $ARGUS_BASE_URL) to point at your SGLang server."
    );
    Ok(())
}

/// `argus scan` — refresh context, scan, persist, write today's report.
pub async fn scan(root: &Path, settings: &Resolved, date: &str, now: &str) -> Result<()> {
    let (provider, using_synapse) = build_provider(root, settings);

    let llm: Arc<dyn LlmClient> = Arc::new(
        OpenAiClient::new(
            &settings.base_url,
            &settings.model,
            &settings.api_key,
            Duration::from_secs(settings.timeout_secs),
        )
        .context("building LLM client")?,
    );

    let mut store = JsonFindingStore::open(root)?;
    let params = ScanParams {
        max_tokens_per_chunk: settings.max_tokens_per_chunk,
        context_budget: settings.context_budget,
        concurrency: settings.concurrency,
    };

    eprintln!(
        "Scanning via {} (model: {})...",
        settings.base_url, settings.model
    );
    let outcome = run_scan(root, provider, llm, &mut store, &params, now).await?;

    eprintln!(
        "Scanned {} file(s) [{}], {} new finding(s).",
        outcome.files_scanned,
        outcome.mode.label(),
        outcome.new_findings
    );
    if using_synapse && !outcome.context_available {
        eprintln!("warning: Synapse graph produced no context packs — scanned file-only.");
    }

    let meta = ReportMeta {
        scan_mode: outcome.mode.label().to_string(),
        commit: outcome.head_sha.clone(),
        context_available: outcome.context_available,
    };
    let path = write_report(root, &settings.report_dir, date, &store, &meta)?;
    println!("{}", path.display());
    Ok(())
}

/// `argus dismiss <fp>` / `argus confirm <fp>`.
pub fn set_state(root: &Path, fingerprint: &str, state: TriageState) -> Result<()> {
    let mut store = JsonFindingStore::open(root)?;
    store.set_state(fingerprint, state)?;
    println!("{} -> {}", fingerprint, state.label());
    Ok(())
}

/// `argus report` — regenerate today's report without rescanning.
pub fn report(root: &Path, settings: &Resolved, date: &str) -> Result<()> {
    let store = JsonFindingStore::open(root)?;
    // Recover scan-mode/commit hints from the last-run marker if present.
    let last = store.last_run()?;
    let meta = ReportMeta {
        scan_mode: "regenerated".into(),
        commit: last.and_then(|l| l.sha),
        // Unknown at report time — leave conservative.
        context_available: false,
    };
    let path = write_report(root, &settings.report_dir, date, &store, &meta)?;
    println!("{}", path.display());
    Ok(())
}

/// `argus status` — print triage-state counts.
pub fn status(root: &Path, json: bool) -> Result<()> {
    let store = JsonFindingStore::open(root)?;
    let c = store.counts()?;
    if json {
        let v = serde_json::json!({
            "pending": c.pending,
            "confirmed": c.confirmed,
            "dismissed": c.dismissed,
            "total": c.total(),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("pending:   {}", c.pending);
        println!("confirmed: {}", c.confirmed);
        println!("dismissed: {}", c.dismissed);
        println!("total:     {}", c.total());
    }
    Ok(())
}

/// Build the real Synapse-backed provider, falling back to the file-only stub if
/// the graph can't be opened (so a missing C++ build or a graph error never
/// blocks the daily scan). The bool is whether the real Synapse provider is in
/// use (used only to phrase the "graph yielded no context" warning).
fn build_provider(root: &Path, settings: &Resolved) -> (Arc<dyn ContextProvider>, bool) {
    match SynapseContextProvider::open(
        root,
        settings.include_extensions.clone(),
        settings.exclude_dirs.clone(),
    ) {
        Ok(p) => (Arc::new(p), true),
        Err(e) => {
            eprintln!("warning: could not open Synapse context graph ({e}); scanning file-only.");
            (
                Arc::new(StubContextProvider::new(
                    root,
                    settings.include_extensions.clone(),
                    settings.exclude_dirs.clone(),
                )),
                false,
            )
        }
    }
}
