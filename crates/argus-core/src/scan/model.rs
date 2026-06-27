//! Finding data model and triage state.
//!
//! [`RawFinding`] is the shape the LLM returns (mirroring the fields the Python
//! pseudo-scanner used, so the report format is recognisable). [`Finding`] is
//! the stored, fingerprinted form with triage state attached.

use serde::{Deserialize, Serialize};

/// Severity bucket, ordered most-severe-first so reports group naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Parse a model-supplied severity string; unknown values fall back to
    /// `Info` so a stray label never drops a finding entirely.
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Title-case label for report headings.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    /// All severities, most severe first — the report grouping order.
    pub fn ordered() -> [Severity; 5] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

/// Triage state of a finding across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TriageState {
    /// Newly detected, awaiting human/AI review.
    #[default]
    Pending,
    /// A real issue, confirmed by review. Stays in the report.
    Confirmed,
    /// A false positive / accepted risk. Suppressed from reports forever, even
    /// if re-detected on later runs.
    Dismissed,
}

impl TriageState {
    pub fn label(&self) -> &'static str {
        match self {
            TriageState::Pending => "pending",
            TriageState::Confirmed => "confirmed",
            TriageState::Dismissed => "dismissed",
        }
    }
}

/// A vulnerability as returned by the model for a single chunk. Field names and
/// shape intentionally match the Python pseudo-scanner's JSON so the prompt and
/// report stay recognisable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawFinding {
    #[serde(default, alias = "vuln_type")]
    pub vulnerability_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity: String,
    /// Lines reported by the model, relative to the chunk it saw. Mapped back to
    /// true file lines during merge.
    #[serde(default)]
    pub line_numbers: Vec<u32>,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub fix_example: String,
}

/// A fingerprinted, stored finding with its triage state and lifecycle stamps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identity: `sha256(file + vuln_type + first_line)`.
    pub fingerprint: String,
    pub file: String,
    pub vulnerability_type: String,
    pub description: String,
    pub severity: Severity,
    pub line_numbers: Vec<u32>,
    pub impact: String,
    pub recommendation: String,
    #[serde(default)]
    pub fix_example: String,
    #[serde(default)]
    pub state: TriageState,
    /// RFC3339 timestamp of first detection.
    pub first_seen: String,
    /// RFC3339 timestamp of most recent detection.
    pub last_seen: String,
}

impl Finding {
    /// The first reported line (used in the fingerprint and report ordering),
    /// or 0 when the model gave no line.
    pub fn first_line(&self) -> u32 {
        self.line_numbers.first().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_most_severe_first() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn severity_parse_is_case_insensitive_and_falls_back() {
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse(" high "), Severity::High);
        assert_eq!(Severity::parse("nonsense"), Severity::Info);
    }

    #[test]
    fn raw_finding_accepts_vuln_type_alias() {
        // The pseudo-scanner used `vulnerability_type`; tolerate `vuln_type` too.
        let j = r#"{"vuln_type":"SQLi","severity":"High","line_numbers":[3]}"#;
        let rf: RawFinding = serde_json::from_str(j).unwrap();
        assert_eq!(rf.vulnerability_type, "SQLi");
    }
}
