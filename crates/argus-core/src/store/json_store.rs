//! JSON-file [`FindingStore`]: `.triage-state/findings.json` +
//! `.triage-state/last_run.json`.
//!
//! Findings are held in memory and flushed to disk atomically (write to a temp
//! file in the same directory, then rename) so an interrupted run can't leave a
//! half-written, unparseable findings file. The whole map is small (hundreds to
//! low-thousands of findings), so rewrite-on-change is fine.

use super::memory_store::merge_upsert;
use super::store::{Counts, FindingStore, LastRun};
use crate::config::triage_dir;
use crate::errors::ArgusError;
use crate::scan::model::{Finding, TriageState};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FINDINGS_FILE: &str = "findings.json";
const LAST_RUN_FILE: &str = "last_run.json";

pub struct JsonFindingStore {
    dir: PathBuf,
    findings: BTreeMap<String, Finding>,
    last_run: Option<LastRun>,
}

impl JsonFindingStore {
    /// Open (or start empty) the store rooted at a repo. Reads any existing
    /// `findings.json` / `last_run.json`; a missing file is an empty store.
    pub fn open(root: &Path) -> Result<Self> {
        let dir = triage_dir(root);
        let findings = read_json::<Vec<Finding>>(&dir.join(FINDINGS_FILE))?
            .unwrap_or_default()
            .into_iter()
            .map(|f| (f.fingerprint.clone(), f))
            .collect();
        let last_run = read_json::<LastRun>(&dir.join(LAST_RUN_FILE))?;
        Ok(Self {
            dir,
            findings,
            last_run,
        })
    }

    fn flush_findings(&self) -> Result<()> {
        let list: Vec<&Finding> = self.findings.values().collect();
        write_json_atomic(&self.dir, FINDINGS_FILE, &list)
    }

    fn flush_last_run(&self) -> Result<()> {
        if let Some(lr) = &self.last_run {
            write_json_atomic(&self.dir, LAST_RUN_FILE, lr)?;
        }
        Ok(())
    }
}

impl FindingStore for JsonFindingStore {
    fn all(&self) -> Result<Vec<Finding>> {
        Ok(self.findings.values().cloned().collect())
    }

    fn get(&self, fingerprint: &str) -> Result<Option<Finding>> {
        Ok(self.findings.get(fingerprint).cloned())
    }

    fn upsert(&mut self, findings: Vec<Finding>) -> Result<()> {
        merge_upsert(&mut self.findings, findings);
        self.flush_findings()
    }

    fn set_state(&mut self, fingerprint: &str, state: TriageState) -> Result<()> {
        let f = self
            .findings
            .get_mut(fingerprint)
            .ok_or_else(|| ArgusError::UnknownFingerprint(fingerprint.to_string()))?;
        f.state = state;
        self.flush_findings()
    }

    fn last_run(&self) -> Result<Option<LastRun>> {
        Ok(self.last_run.clone())
    }

    fn set_last_run(&mut self, last_run: LastRun) -> Result<()> {
        self.last_run = Some(last_run);
        self.flush_last_run()
    }

    fn counts(&self) -> Result<Counts> {
        let mut c = Counts::default();
        for f in self.findings.values() {
            match f.state {
                TriageState::Pending => c.pending += 1,
                TriageState::Confirmed => c.confirmed += 1,
                TriageState::Dismissed => c.dismissed += 1,
            }
        }
        Ok(c)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let v = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write `value` as pretty JSON to `<dir>/<name>` atomically: serialize to a
/// temp file in the same directory, then rename over the target.
fn write_json_atomic<T: serde::Serialize>(dir: &Path, name: &str, value: &T) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp"));
    let text = serde_json::to_string_pretty(value).context("serializing findings state")?;
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("renaming into {}", target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::Severity;

    fn finding(fp: &str) -> Finding {
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
            state: TriageState::Pending,
            first_seen: "2026-01-01T00:00:00Z".into(),
            last_seen: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = JsonFindingStore::open(dir.path()).unwrap();
            s.upsert(vec![finding("fp1")]).unwrap();
            s.set_state("fp1", TriageState::Confirmed).unwrap();
            s.set_last_run(LastRun {
                sha: Some("abc123".into()),
                ran_at: "2026-01-01T00:00:00Z".into(),
            })
            .unwrap();
        }
        // Re-open: the prior decision and marker survive.
        let s2 = JsonFindingStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.get("fp1").unwrap().unwrap().state,
            TriageState::Confirmed
        );
        assert_eq!(s2.last_run().unwrap().unwrap().sha.unwrap(), "abc123");
    }

    #[test]
    fn missing_files_open_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = JsonFindingStore::open(dir.path()).unwrap();
        assert!(s.all().unwrap().is_empty());
        assert!(s.last_run().unwrap().is_none());
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = JsonFindingStore::open(dir.path()).unwrap();
        s.upsert(vec![finding("fp1")]).unwrap();
        let tdir = triage_dir(dir.path());
        assert!(tdir.join(FINDINGS_FILE).is_file());
        assert!(!tdir.join(format!(".{FINDINGS_FILE}.tmp")).exists());
    }
}
