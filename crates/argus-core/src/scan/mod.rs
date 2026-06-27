//! Scan orchestration: discover -> context -> chunk -> two-pass LLM -> merge ->
//! reconcile -> persist.
//!
//! The flow is async with a bounded concurrency limit so a first full scan can't
//! overwhelm the SGLang endpoint. Every external dependency is a trait
//! ([`ContextProvider`], [`LlmClient`], [`FindingStore`]) so this whole pipeline
//! runs against in-memory fakes in tests.

pub mod fingerprint;
pub mod model;

use crate::chunk::{self, Chunk};
use crate::context::ContextProvider;
use crate::llm::LlmClient;
use crate::llm::prompts::{self, SYSTEM_PROMPT};
use crate::scan::model::{Finding, RawFinding, Severity, TriageState};
use crate::store::{FindingStore, LastRun};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// How the file set for this scan was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// No prior marker (or unknown SHA / not a git repo) — every candidate.
    Full,
    /// Only files git reports changed since the stored last-run SHA.
    Incremental,
}

impl ScanMode {
    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Full => "full",
            ScanMode::Incremental => "incremental",
        }
    }
}

/// Summary of a completed scan (for the CLI to print).
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub mode: ScanMode,
    pub files_scanned: usize,
    pub new_findings: usize,
    pub context_available: bool,
    pub head_sha: Option<String>,
}

/// Knobs resolved by the caller (CLI), passed in explicitly so core never reads
/// env/config itself.
#[derive(Debug, Clone)]
pub struct ScanParams {
    pub max_tokens_per_chunk: usize,
    pub context_budget: usize,
    pub concurrency: usize,
}

/// Run a full scan: refresh the graph, resolve the file set, triage each file,
/// reconcile against the store, and persist findings + the new last-run marker.
///
/// `now` is the RFC3339 timestamp to stamp on findings/marker (injected so tests
/// are deterministic). Returns the outcome; the report is rendered separately.
pub async fn run_scan(
    root: &Path,
    provider: Arc<dyn ContextProvider>,
    llm: Arc<dyn LlmClient>,
    store: &mut dyn FindingStore,
    params: &ScanParams,
    now: &str,
) -> Result<ScanOutcome> {
    // 1. Decide incremental vs full from the stored marker, then refresh.
    let last_sha = store
        .last_run()?
        .and_then(|lr| lr.sha)
        .filter(|s| !s.is_empty());

    let changed = provider.changed_files_since(last_sha.as_deref())?;
    let (mode, files) = match changed {
        Some(list) => (ScanMode::Incremental, list),
        None => (ScanMode::Full, provider.candidate_files()?),
    };

    provider.refresh(mode == ScanMode::Incremental)?;

    // 2. Probe whether context is available at all (purely for reporting; the
    //    scan proceeds either way). The first non-empty pack flips this true.
    let mut context_available = false;

    // 3. Triage each file under a concurrency cap.
    let sem = Arc::new(Semaphore::new(params.concurrency.max(1)));
    let mut handles = Vec::new();
    for rel in &files {
        let rel = rel.clone();
        let provider = Arc::clone(&provider);
        let llm = Arc::clone(&llm);
        let sem = Arc::clone(&sem);
        let params = params.clone();
        let now = now.to_string();
        let root = root.to_path_buf();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            triage_file(&root, &rel, provider.as_ref(), llm.as_ref(), &params, &now).await
        }));
    }

    let mut detected: Vec<Finding> = Vec::new();
    for h in handles {
        let (findings, had_context) = h.await.expect("scan task panicked")?;
        if had_context {
            context_available = true;
        }
        detected.extend(findings);
    }

    // 4. Reconcile: which fingerprints are genuinely new (for the count).
    let new_findings = detected
        .iter()
        .filter(|f| matches!(store.get(&f.fingerprint), Ok(None)))
        .count();

    // 5. Persist findings (upsert preserves prior triage state) and the marker.
    store.upsert(detected)?;
    let head_sha = provider.head_sha();
    store.set_last_run(LastRun {
        sha: head_sha.clone(),
        ran_at: now.to_string(),
    })?;

    Ok(ScanOutcome {
        mode,
        files_scanned: files.len(),
        new_findings,
        context_available,
        head_sha,
    })
}

/// Triage a single file: fetch its context pack, chunk it, run the two-pass LLM
/// per chunk, map lines back, and merge into fingerprinted findings. Returns the
/// findings plus whether a non-empty context pack was used.
async fn triage_file(
    root: &Path,
    rel: &str,
    provider: &dyn ContextProvider,
    llm: &dyn LlmClient,
    params: &ScanParams,
    now: &str,
) -> Result<(Vec<Finding>, bool)> {
    let abs = root.join(rel);
    let code = match std::fs::read_to_string(&abs) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(file = rel, error = %e, "skipping unreadable file");
            return Ok((Vec::new(), false));
        }
    };

    let context_pack = provider
        .context_pack(rel, params.context_budget)
        .unwrap_or_default();
    let had_context = !context_pack.trim().is_empty();

    let chunks = chunk::chunk_file(&code, params.max_tokens_per_chunk);

    // Merge chunk findings into one map per (vuln_type, mapped first line) so the
    // same issue reported in overlapping chunks doesn't double up.
    let mut merged: BTreeMap<String, Finding> = BTreeMap::new();
    for chunk in &chunks {
        let raws = scan_chunk(rel, chunk, &context_pack, llm).await?;
        for raw in raws {
            let finding = build_finding(rel, &raw, chunk, now);
            merged.entry(finding.fingerprint.clone()).or_insert(finding);
        }
    }

    Ok((merged.into_values().collect(), had_context))
}

/// Run the two-pass prompt sequence for one chunk and parse the final findings.
/// A pass that returns unparseable JSON is retried once; a second failure yields
/// no findings for that pass (logged), never an error that aborts the scan.
async fn scan_chunk(
    file: &str,
    chunk: &Chunk,
    context_pack: &str,
    llm: &dyn LlmClient,
) -> Result<Vec<RawFinding>> {
    // Pass 1 — discover candidates. We don't strictly need to parse them; the
    // raw JSON text is fed straight into pass 2, so a malformed pass-1 reply
    // still lets pass 2 run with whatever the model produced.
    let discover = prompts::discover_prompt(file, &chunk.text, context_pack);
    let candidates_raw = llm.complete(SYSTEM_PROMPT, &discover).await?;
    let candidates_json =
        prompts::extract_json_array(&candidates_raw).unwrap_or_else(|| "[]".to_string());

    // Pass 2 — evaluate into final findings, with a single parse retry.
    let evaluate = prompts::evaluate_prompt(file, &chunk.text, context_pack, &candidates_json);
    let raws = match complete_and_parse(llm, &evaluate).await? {
        Some(r) => r,
        None => {
            // One retry with an explicit "JSON only" nudge.
            let retry = format!("{evaluate}\n\nIMPORTANT: respond with the JSON array ONLY.");
            match complete_and_parse(llm, &retry).await? {
                Some(r) => r,
                None => {
                    tracing::warn!(
                        file,
                        "model returned no parseable JSON after retry; 0 findings for this chunk"
                    );
                    Vec::new()
                }
            }
        }
    };
    Ok(raws)
}

/// Send a prompt and parse the reply into `RawFinding`s. Returns `Ok(None)` when
/// no JSON array could be extracted/deserialized (the caller decides on retry).
async fn complete_and_parse(llm: &dyn LlmClient, user: &str) -> Result<Option<Vec<RawFinding>>> {
    let reply = llm.complete(SYSTEM_PROMPT, user).await?;
    let Some(json) = prompts::extract_json_array(&reply) else {
        return Ok(None);
    };
    match serde_json::from_str::<Vec<RawFinding>>(&json) {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

/// Convert a chunk-relative [`RawFinding`] into a stored [`Finding`], mapping
/// reported lines back to true file lines and computing the fingerprint.
fn build_finding(file: &str, raw: &RawFinding, chunk: &Chunk, now: &str) -> Finding {
    let line_numbers: Vec<u32> = raw
        .line_numbers
        .iter()
        .map(|&l| chunk.map_line(l))
        .collect();
    let first_line = line_numbers.first().copied().unwrap_or(0);
    let fingerprint = fingerprint::fingerprint(file, &raw.vulnerability_type, first_line);

    Finding {
        fingerprint,
        file: file.to_string(),
        vulnerability_type: raw.vulnerability_type.clone(),
        description: raw.description.clone(),
        severity: Severity::parse(&raw.severity),
        line_numbers,
        impact: raw.impact.clone(),
        recommendation: raw.recommendation.clone(),
        fix_example: raw.fix_example.clone(),
        state: TriageState::Pending,
        first_seen: now.to_string(),
        last_seen: now.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Chunk;
    use crate::scan::model::RawFinding;

    #[test]
    fn build_finding_maps_lines_back_to_file() {
        let chunk = Chunk {
            start_line: 100,
            text: "irrelevant".into(),
        };
        let raw = RawFinding {
            vulnerability_type: "SQLi".into(),
            description: "d".into(),
            severity: "High".into(),
            line_numbers: vec![3, 5],
            impact: "i".into(),
            recommendation: "r".into(),
            fix_example: String::new(),
        };
        let f = build_finding("src/Foo.cs", &raw, &chunk, "2026-06-27T00:00:00Z");
        // Chunk lines 3,5 with start_line 100 -> file lines 102,104.
        assert_eq!(f.line_numbers, vec![102, 104]);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.state, TriageState::Pending);
        // Fingerprint uses the mapped first line (102), not the raw 3.
        assert_eq!(
            f.fingerprint,
            fingerprint::fingerprint("src/Foo.cs", "SQLi", 102)
        );
    }
}
