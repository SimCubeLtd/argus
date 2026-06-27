//! The [`FindingStore`] contract.

use crate::scan::model::{Finding, TriageState};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The stored last-run marker: which commit the previous scan covered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastRun {
    /// Full HEAD SHA at the previous run, or `None` if it ran with no git HEAD.
    pub sha: Option<String>,
    /// RFC3339 timestamp of the previous run.
    pub ran_at: String,
}

/// Triage-state counts for `argus status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Counts {
    pub pending: usize,
    pub confirmed: usize,
    pub dismissed: usize,
}

impl Counts {
    pub fn total(&self) -> usize {
        self.pending + self.confirmed + self.dismissed
    }
}

/// Persistence + query interface over triage findings and the last-run marker.
///
/// Implementations key findings by their stable fingerprint; an upsert of a
/// fingerprint that already exists must *preserve the existing triage state*
/// (that is the whole point of dismiss/confirm surviving a rescan) while
/// refreshing the mutable detail (`last_seen`, description, lines, ...).
pub trait FindingStore {
    /// Every stored finding, in a deterministic order (by fingerprint).
    fn all(&self) -> Result<Vec<Finding>>;

    /// Look up one finding by fingerprint.
    fn get(&self, fingerprint: &str) -> Result<Option<Finding>>;

    /// Insert new findings and refresh re-detected ones. For an existing
    /// fingerprint: keep its `state` and `first_seen`, update the rest. New
    /// fingerprints are inserted as-is (the caller stamps them `Pending`).
    fn upsert(&mut self, findings: Vec<Finding>) -> Result<()>;

    /// Set the triage state of one finding. Errors if the fingerprint is unknown.
    fn set_state(&mut self, fingerprint: &str, state: TriageState) -> Result<()>;

    /// Triage-state counts across all findings.
    fn counts(&self) -> Result<Counts> {
        let mut c = Counts::default();
        for f in self.all()? {
            match f.state {
                TriageState::Pending => c.pending += 1,
                TriageState::Confirmed => c.confirmed += 1,
                TriageState::Dismissed => c.dismissed += 1,
            }
        }
        Ok(c)
    }

    /// The previous run's marker, if any.
    fn last_run(&self) -> Result<Option<LastRun>>;

    /// Record this run's marker.
    fn set_last_run(&mut self, last_run: LastRun) -> Result<()>;
}
