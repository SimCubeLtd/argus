//! End-to-end CLI tests. The SGLang endpoint is mocked with `wiremock`; the
//! Synapse graph builds against a real temp repo. These exercise the full
//! binary: init -> scan -> dismiss -> report -> status.

use assert_cmd::Command;
use std::path::Path;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build an OpenAI-style chat response wrapping `content`.
fn chat_response(content: &str) -> serde_json::Value {
    serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": content } }]
    })
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn argus(root: &Path, base_url: &str) -> Command {
    let mut cmd = Command::cargo_bin("argus").unwrap();
    cmd.current_dir(root)
        .env("ARGUS_BASE_URL", base_url)
        .env("RUST_LOG", "error");
    cmd
}

/// init -> scan (one finding) -> report contains it -> dismiss -> report drops
/// it -> status counts reflect the dismissal.
#[tokio::test]
async fn full_triage_lifecycle() {
    let server = MockServer::start().await;
    // Every chat call returns the same finding; pass 1's reply is also a valid
    // (if semantically wrong) array, which is fine — pass 2's reply is what
    // produces findings.
    let finding = r#"[{"vulnerability_type":"SQL Injection","description":"concatenated user input into a Marten query","severity":"High","line_numbers":[1],"impact":"data exfiltration","recommendation":"parameterize","fix_example":"session.Query(...)"}]"#;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_response(finding)))
        .mount(&server)
        .await;
    let base_url = format!("{}/v1", server.uri());

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/Login.cs",
        "var q = \"SELECT * FROM u WHERE n=\" + name;",
    );

    // init
    argus(root, &base_url).arg("init").assert().success();
    assert!(root.join(".triage-state/argus.toml").is_file());

    // scan -> prints report path; report exists and contains the finding.
    let out = argus(root, &base_url).arg("scan").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let report_path = stdout.trim();
    let report = std::fs::read_to_string(report_path).unwrap();
    assert!(report.contains("SQL Injection"), "report:\n{report}");
    assert!(report.contains("## High"));

    // Pull the fingerprint out of the findings store.
    let findings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".triage-state/findings.json")).unwrap(),
    )
    .unwrap();
    let fp = findings[0]["fingerprint"].as_str().unwrap().to_string();

    // status before dismiss: 1 pending.
    let out = argus(root, &base_url)
        .args(["status", "--json"])
        .assert()
        .success();
    let s: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(s["pending"], 1);
    assert_eq!(s["dismissed"], 0);

    // dismiss
    argus(root, &base_url)
        .args(["dismiss", &fp])
        .assert()
        .success();

    // report (no rescan) now excludes the dismissed finding.
    let out = argus(root, &base_url).arg("report").assert().success();
    let report_path = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let report = std::fs::read_to_string(report_path.trim()).unwrap();
    assert!(
        report.contains("No pending or confirmed findings"),
        "dismissed finding leaked:\n{report}"
    );

    // status after dismiss: 0 pending, 1 dismissed.
    let out = argus(root, &base_url)
        .args(["status", "--json"])
        .assert()
        .success();
    let s: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(s["pending"], 0);
    assert_eq!(s["dismissed"], 1);
}

#[tokio::test]
async fn confirm_keeps_finding_in_report() {
    let server = MockServer::start().await;
    let finding = r#"[{"vulnerability_type":"XSS","description":"unescaped {@html}","severity":"Medium","line_numbers":[1],"impact":"script injection","recommendation":"escape","fix_example":""}]"#;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_response(finding)))
        .mount(&server)
        .await;
    let base_url = format!("{}/v1", server.uri());

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "web/App.svelte", "{@html userInput}");

    argus(root, &base_url).arg("init").assert().success();
    argus(root, &base_url).arg("scan").assert().success();

    let findings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".triage-state/findings.json")).unwrap(),
    )
    .unwrap();
    let fp = findings[0]["fingerprint"].as_str().unwrap().to_string();

    argus(root, &base_url)
        .args(["confirm", &fp])
        .assert()
        .success();

    let out = argus(root, &base_url).arg("report").assert().success();
    let report_path = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let report = std::fs::read_to_string(report_path.trim()).unwrap();
    assert!(report.contains("XSS"));
    assert!(report.contains("confirmed"));
}

#[test]
fn scan_without_init_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    argus(dir.path(), "http://localhost:1/v1")
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicates::str::contains("argus init"));
}

#[test]
fn dismiss_unknown_fingerprint_fails() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    argus(root, "http://localhost:1/v1")
        .arg("init")
        .assert()
        .success();
    argus(root, "http://localhost:1/v1")
        .args(["dismiss", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("nonexistent"));
}
