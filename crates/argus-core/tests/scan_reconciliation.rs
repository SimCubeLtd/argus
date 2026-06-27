//! End-to-end scan orchestration tests against in-memory fakes — the core value
//! of Argus: triage state survives rescans, dismissed findings stay suppressed,
//! and context packs reach the model. No network, no LadybugDB.

use argus_core::context::{ContextProvider, StubContextProvider};
use argus_core::llm::{LlmClient, MockLlmClient};
use argus_core::report::{ReportMeta, render_markdown};
use argus_core::scan::model::TriageState;
use argus_core::scan::{ScanMode, ScanParams, run_scan};
use argus_core::store::{FindingStore, MemoryFindingStore};
use std::path::Path;
use std::sync::Arc;

fn params() -> ScanParams {
    ScanParams {
        max_tokens_per_chunk: 8000,
        context_budget: 8000,
        concurrency: 2,
    }
}

/// A pass-2 finding payload (pass 1 reply is irrelevant — any array works).
fn finding_json(vuln: &str, line: u32) -> String {
    format!(
        r#"[{{"vulnerability_type":"{vuln}","description":"d","severity":"High","line_numbers":[{line}],"reachability":"http request body reaches the sink","impact":"i","recommendation":"r","fix_example":""}}]"#
    )
}

/// A provider that yields a fixed candidate list and a fixed context pack.
struct FakeProvider {
    files: Vec<String>,
    pack: String,
}
impl ContextProvider for FakeProvider {
    fn refresh(&self, _changed_only: bool) -> anyhow::Result<()> {
        Ok(())
    }
    fn candidate_files(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.files.clone())
    }
    fn changed_files_since(&self, _sha: Option<&str>) -> anyhow::Result<Option<Vec<String>>> {
        Ok(None) // always full scan
    }
    fn head_sha(&self) -> Option<String> {
        Some("deadbeef".into())
    }
    fn context_pack(&self, _file: &str, _budget: usize) -> anyhow::Result<String> {
        Ok(self.pack.clone())
    }
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

#[tokio::test]
async fn new_finding_is_pending_and_appears_in_report() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "src/Login.cs", "var q = \"SELECT \" + input;");

    let provider: Arc<dyn ContextProvider> = Arc::new(FakeProvider {
        files: vec!["src/Login.cs".into()],
        pack: "CALLER: AuthBase.cs".into(),
    });
    // pass1 reply, pass2 reply.
    let llm: Arc<dyn LlmClient> = Arc::new(MockLlmClient::new(vec![
        "[]".into(),
        finding_json("SQL Injection", 1),
    ]));
    let mut store = MemoryFindingStore::new();

    let outcome = run_scan(
        dir.path(),
        provider,
        llm,
        &mut store,
        &params(),
        "2026-06-27T00:00:00Z",
    )
    .await
    .unwrap();

    assert_eq!(outcome.mode, ScanMode::Full);
    assert_eq!(outcome.new_findings, 1);
    assert!(outcome.context_available);

    let all = store.all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, TriageState::Pending);

    let md = render_markdown(
        "2026-06-27",
        &all,
        &ReportMeta {
            scan_mode: outcome.mode.label().into(),
            commit: outcome.head_sha.clone(),
            context_available: outcome.context_available,
        },
    );
    assert!(md.contains("SQL Injection"));
}

#[tokio::test]
async fn dismissed_finding_stays_suppressed_after_redetection() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "src/Login.cs", "var q = \"SELECT \" + input;");

    let mk_provider = || -> Arc<dyn ContextProvider> {
        Arc::new(FakeProvider {
            files: vec!["src/Login.cs".into()],
            pack: String::new(),
        })
    };
    let mut store = MemoryFindingStore::new();

    // First scan detects the issue.
    run_scan(
        dir.path(),
        mk_provider(),
        Arc::new(MockLlmClient::new(vec![
            "[]".into(),
            finding_json("SQL Injection", 1),
        ])),
        &mut store,
        &params(),
        "2026-06-27T00:00:00Z",
    )
    .await
    .unwrap();

    // Human dismisses it.
    let fp = store.all().unwrap()[0].fingerprint.clone();
    store.set_state(&fp, TriageState::Dismissed).unwrap();

    // Second scan re-detects the SAME issue.
    run_scan(
        dir.path(),
        mk_provider(),
        Arc::new(MockLlmClient::new(vec![
            "[]".into(),
            finding_json("SQL Injection", 1),
        ])),
        &mut store,
        &params(),
        "2026-06-28T00:00:00Z",
    )
    .await
    .unwrap();

    // Still exactly one finding, still dismissed — and absent from the report.
    let all = store.all().unwrap();
    assert_eq!(all.len(), 1, "re-detection must not create a duplicate");
    assert_eq!(
        all[0].state,
        TriageState::Dismissed,
        "dismissal must survive"
    );

    let reportable: Vec<_> = all
        .into_iter()
        .filter(|f| f.state != TriageState::Dismissed)
        .collect();
    let md = render_markdown(
        "2026-06-28",
        &reportable,
        &ReportMeta {
            scan_mode: "full".into(),
            commit: None,
            context_available: false,
        },
    );
    assert!(
        md.contains("No pending or confirmed findings"),
        "dismissed finding leaked into report:\n{md}"
    );
}

#[tokio::test]
async fn confirmed_state_is_preserved_across_rescan() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "src/Login.cs", "code");

    let mk_provider = || -> Arc<dyn ContextProvider> {
        Arc::new(FakeProvider {
            files: vec!["src/Login.cs".into()],
            pack: String::new(),
        })
    };
    let mut store = MemoryFindingStore::new();

    run_scan(
        dir.path(),
        mk_provider(),
        Arc::new(MockLlmClient::new(vec![
            "[]".into(),
            finding_json("XSS", 1),
        ])),
        &mut store,
        &params(),
        "2026-06-27T00:00:00Z",
    )
    .await
    .unwrap();

    let fp = store.all().unwrap()[0].fingerprint.clone();
    store.set_state(&fp, TriageState::Confirmed).unwrap();

    run_scan(
        dir.path(),
        mk_provider(),
        Arc::new(MockLlmClient::new(vec![
            "[]".into(),
            finding_json("XSS", 1),
        ])),
        &mut store,
        &params(),
        "2026-06-28T00:00:00Z",
    )
    .await
    .unwrap();

    assert_eq!(
        store.get(&fp).unwrap().unwrap().state,
        TriageState::Confirmed
    );
}

#[tokio::test]
async fn context_pack_reaches_the_model_prompt() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "src/Login.cs", "code");

    let provider: Arc<dyn ContextProvider> = Arc::new(FakeProvider {
        files: vec!["src/Login.cs".into()],
        pack: "UNIQUE_CONTEXT_MARKER_42".into(),
    });
    let mock = Arc::new(MockLlmClient::new(vec!["[]".into(), "[]".into()]));
    let llm: Arc<dyn LlmClient> = mock.clone();
    let mut store = MemoryFindingStore::new();

    run_scan(
        dir.path(),
        provider,
        llm,
        &mut store,
        &params(),
        "2026-06-27T00:00:00Z",
    )
    .await
    .unwrap();

    let prompts = mock.seen_user_prompts();
    assert!(
        prompts
            .iter()
            .any(|p| p.contains("UNIQUE_CONTEXT_MARKER_42")),
        "context pack was not injected into any prompt"
    );
}

#[tokio::test]
async fn malformed_json_yields_no_findings_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "src/Login.cs", "code");

    let provider: Arc<dyn ContextProvider> = Arc::new(StubContextProvider::new(
        dir.path(),
        vec![".cs".into()],
        vec![],
    ));
    // pass1, pass2 (garbage), retry (garbage) — scan must still succeed.
    let llm: Arc<dyn LlmClient> = Arc::new(MockLlmClient::new(vec![
        "not json".into(),
        "still not json".into(),
        "definitely not json".into(),
    ]));
    let mut store = MemoryFindingStore::new();

    let outcome = run_scan(
        dir.path(),
        provider,
        llm,
        &mut store,
        &params(),
        "2026-06-27T00:00:00Z",
    )
    .await
    .unwrap();

    assert_eq!(outcome.new_findings, 0);
    assert!(store.all().unwrap().is_empty());
}
