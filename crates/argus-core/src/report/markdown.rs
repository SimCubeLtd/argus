//! Markdown rendering of the daily triage report.
//!
//! Concise on purpose: the report is pasted into an external LLM (Claude) for
//! validation, so it leads with a summary, groups findings by severity
//! (Critical -> Info), and prints each finding's fingerprint so a reviewer can
//! `argus dismiss <fp>` / `argus confirm <fp>`. The per-finding fields mirror
//! the Python pseudo-scanner's output shape.

use crate::scan::model::{Finding, Severity, TriageState};

/// Header facts for the report.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    /// "full" or "incremental".
    pub scan_mode: String,
    /// HEAD commit the scan covered, if known.
    pub commit: Option<String>,
    /// Whether cross-file context (Synapse graph) was available.
    pub context_available: bool,
}

/// `triage-YYYY-MM-DD.md`.
pub fn report_filename(date: &str) -> String {
    format!("triage-{date}.md")
}

/// Render the full report. `findings` must already exclude dismissed items.
pub fn render_markdown(date: &str, findings: &[Finding], meta: &ReportMeta) -> String {
    let mut out = String::new();

    out.push_str(&format!("# Security Triage Report — {date}\n\n"));

    // Summary header.
    let pending = findings
        .iter()
        .filter(|f| f.state == TriageState::Pending)
        .count();
    let confirmed = findings
        .iter()
        .filter(|f| f.state == TriageState::Confirmed)
        .count();
    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Scan mode: {}\n", meta.scan_mode));
    out.push_str(&format!(
        "- Cross-file context: {}\n",
        if meta.context_available {
            "available (Synapse graph)"
        } else {
            "none (file-only scan)"
        }
    ));
    if let Some(c) = &meta.commit {
        out.push_str(&format!("- Commit: {c}\n"));
    }
    out.push_str(&format!("- Pending: {pending}\n"));
    out.push_str(&format!("- Confirmed: {confirmed}\n"));
    out.push_str(&format!("- Reportable total: {}\n\n", findings.len()));

    if findings.is_empty() {
        out.push_str("No pending or confirmed findings. ✅\n");
        return out;
    }

    out.push_str(
        "> Paste this report to an LLM for validation. To triage: \
         `argus confirm <fingerprint>` or `argus dismiss <fingerprint>`.\n\n",
    );

    // Group by severity, most severe first.
    for sev in Severity::ordered() {
        let mut group: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        // Stable, useful order within a severity: by file then first line.
        group.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.first_line().cmp(&b.first_line()))
        });

        out.push_str(&format!("## {} ({})\n\n", sev.label(), group.len()));
        for f in group {
            render_finding(&mut out, f);
        }
    }

    out
}

fn render_finding(out: &mut String, f: &Finding) {
    out.push_str(&format!("### {} — `{}`\n\n", f.vulnerability_type, f.file));
    out.push_str(&format!("- **Lines**: {}\n", fmt_lines(&f.line_numbers)));
    if f.state == TriageState::Confirmed {
        out.push_str("- **State**: confirmed\n");
    }
    if !f.description.is_empty() {
        out.push_str(&format!("- **Description**: {}\n", f.description));
    }
    if !f.impact.is_empty() {
        out.push_str(&format!("- **Impact**: {}\n", f.impact));
    }
    if !f.recommendation.is_empty() {
        out.push_str(&format!("- **Recommendation**: {}\n", f.recommendation));
    }
    out.push_str(&format!("- **Fingerprint**: `{}`\n", f.fingerprint));
    if !f.fix_example.trim().is_empty() {
        out.push_str("\n**Fix example**:\n\n```\n");
        out.push_str(f.fix_example.trim_end());
        out.push_str("\n```\n");
    }
    out.push('\n');
}

fn fmt_lines(lines: &[u32]) -> String {
    if lines.is_empty() {
        return "n/a".to_string();
    }
    lines
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fp: &str, sev: Severity, state: TriageState, file: &str, line: u32) -> Finding {
        Finding {
            fingerprint: fp.into(),
            file: file.into(),
            vulnerability_type: "SQLi".into(),
            description: "desc".into(),
            severity: sev,
            line_numbers: vec![line],
            impact: "impact".into(),
            recommendation: "rec".into(),
            fix_example: String::new(),
            state,
            first_seen: "2026-06-27T00:00:00Z".into(),
            last_seen: "2026-06-27T00:00:00Z".into(),
        }
    }

    fn meta() -> ReportMeta {
        ReportMeta {
            scan_mode: "full".into(),
            commit: Some("abc123".into()),
            context_available: true,
        }
    }

    #[test]
    fn groups_by_severity_in_order() {
        let findings = vec![
            finding("low1", Severity::Low, TriageState::Pending, "b.cs", 1),
            finding("crit1", Severity::Critical, TriageState::Pending, "a.cs", 1),
            finding("hi1", Severity::High, TriageState::Pending, "a.cs", 1),
        ];
        let md = render_markdown("2026-06-27", &findings, &meta());
        let crit = md.find("## Critical").unwrap();
        let high = md.find("## High").unwrap();
        let low = md.find("## Low").unwrap();
        assert!(crit < high && high < low, "severity order wrong:\n{md}");
    }

    #[test]
    fn includes_fingerprint_for_triage() {
        let findings = vec![finding(
            "FPHASH",
            Severity::High,
            TriageState::Pending,
            "a.cs",
            7,
        )];
        let md = render_markdown("2026-06-27", &findings, &meta());
        assert!(md.contains("`FPHASH`"));
        assert!(md.contains("Lines**: 7"));
    }

    #[test]
    fn empty_findings_render_clean_message() {
        let md = render_markdown("2026-06-27", &[], &meta());
        assert!(md.contains("No pending or confirmed findings"));
        assert!(!md.contains("## Critical"));
    }

    #[test]
    fn header_reflects_context_and_mode() {
        let md = render_markdown("2026-06-27", &[], &meta());
        assert!(md.contains("Scan mode: full"));
        assert!(md.contains("available (Synapse graph)"));
        assert!(md.contains("Commit: abc123"));
    }
}
