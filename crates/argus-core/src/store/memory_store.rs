//! In-memory [`FindingStore`] for tests. No filesystem, no I/O.

use super::store::{FindingStore, LastRun};
use crate::errors::ArgusError;
use crate::scan::model::{Finding, TriageState};
use anyhow::Result;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct MemoryFindingStore {
    findings: BTreeMap<String, Finding>,
    last_run: Option<LastRun>,
}

impl MemoryFindingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The upsert reconciliation rule, shared by every backend: a re-detected
/// fingerprint keeps its triage state and `first_seen`, but takes the new
/// detection's mutable detail (`last_seen`, lines, text). New fingerprints are
/// inserted verbatim.
pub(super) fn merge_upsert(existing: &mut BTreeMap<String, Finding>, incoming: Vec<Finding>) {
    for mut f in incoming {
        if let Some(prev) = existing.get(&f.fingerprint) {
            f.state = prev.state;
            f.first_seen = prev.first_seen.clone();
        }
        existing.insert(f.fingerprint.clone(), f);
    }
}

impl FindingStore for MemoryFindingStore {
    fn all(&self) -> Result<Vec<Finding>> {
        Ok(self.findings.values().cloned().collect())
    }

    fn get(&self, fingerprint: &str) -> Result<Option<Finding>> {
        Ok(self.findings.get(fingerprint).cloned())
    }

    fn upsert(&mut self, findings: Vec<Finding>) -> Result<()> {
        merge_upsert(&mut self.findings, findings);
        Ok(())
    }

    fn set_state(&mut self, fingerprint: &str, state: TriageState) -> Result<()> {
        let f = self
            .findings
            .get_mut(fingerprint)
            .ok_or_else(|| ArgusError::UnknownFingerprint(fingerprint.to_string()))?;
        f.state = state;
        Ok(())
    }

    fn last_run(&self) -> Result<Option<LastRun>> {
        Ok(self.last_run.clone())
    }

    fn set_last_run(&mut self, last_run: LastRun) -> Result<()> {
        self.last_run = Some(last_run);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::Severity;

    fn finding(fp: &str, state: TriageState) -> Finding {
        Finding {
            fingerprint: fp.to_string(),
            file: "src/Foo.cs".into(),
            vulnerability_type: "SQLi".into(),
            description: "d".into(),
            severity: Severity::High,
            line_numbers: vec![3],
            reachability: "http body -> query".into(),
            impact: "i".into(),
            recommendation: "r".into(),
            fix_example: String::new(),
            state,
            first_seen: "2026-01-01T00:00:00Z".into(),
            last_seen: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn upsert_preserves_state_and_first_seen() {
        let mut s = MemoryFindingStore::new();
        s.upsert(vec![finding("fp1", TriageState::Pending)])
            .unwrap();
        s.set_state("fp1", TriageState::Dismissed).unwrap();

        // Re-detect the same fingerprint with a newer timestamp.
        let mut again = finding("fp1", TriageState::Pending);
        again.last_seen = "2026-02-02T00:00:00Z".into();
        again.first_seen = "2026-02-02T00:00:00Z".into();
        s.upsert(vec![again]).unwrap();

        let got = s.get("fp1").unwrap().unwrap();
        assert_eq!(
            got.state,
            TriageState::Dismissed,
            "state must survive rescan"
        );
        assert_eq!(
            got.first_seen, "2026-01-01T00:00:00Z",
            "first_seen preserved"
        );
        assert_eq!(got.last_seen, "2026-02-02T00:00:00Z", "last_seen refreshed");
    }

    #[test]
    fn set_state_unknown_fingerprint_errors() {
        let mut s = MemoryFindingStore::new();
        let err = s.set_state("nope", TriageState::Confirmed).unwrap_err();
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn counts_bucket_by_state() {
        let mut s = MemoryFindingStore::new();
        s.upsert(vec![
            finding("a", TriageState::Pending),
            finding("b", TriageState::Confirmed),
            finding("c", TriageState::Dismissed),
            finding("d", TriageState::Pending),
        ])
        .unwrap();
        let c = s.counts().unwrap();
        assert_eq!(c.pending, 2);
        assert_eq!(c.confirmed, 1);
        assert_eq!(c.dismissed, 1);
        assert_eq!(c.total(), 4);
    }
}
