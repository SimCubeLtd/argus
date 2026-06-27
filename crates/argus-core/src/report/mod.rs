//! Daily report generation.

mod markdown;

pub use markdown::{ReportMeta, render_markdown, report_filename};

use crate::config::triage_dir;
use crate::scan::model::{Finding, TriageState};
use crate::store::FindingStore;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Build today's report from current store state and write it to
/// `<output_dir>/triage-YYYY-MM-DD.md`. Returns the path written.
///
/// Only pending + confirmed findings are included — dismissed ones never appear.
/// `date` is `YYYY-MM-DD` (injected for determinism); `meta` carries the header
/// facts (scan mode, commit, context availability).
pub fn write_report(
    root: &Path,
    output_dir: &str,
    date: &str,
    store: &dyn FindingStore,
    meta: &ReportMeta,
) -> Result<PathBuf> {
    let reportable: Vec<Finding> = store
        .all()?
        .into_iter()
        .filter(|f| f.state != TriageState::Dismissed)
        .collect();

    let body = render_markdown(date, &reportable, meta);

    let dir = resolve_dir(root, output_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(report_filename(date));
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Resolve a possibly-relative `output_dir` against the repo root, defaulting
/// under `.triage-state/` if it's relative.
fn resolve_dir(root: &Path, output_dir: &str) -> PathBuf {
    let p = Path::new(output_dir);
    if p.is_absolute() {
        p.to_path_buf()
    } else if output_dir.starts_with(".triage-state") {
        root.join(output_dir)
    } else {
        triage_dir(root).join(output_dir)
    }
}
