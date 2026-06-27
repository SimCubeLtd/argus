//! The real, Synapse-backed [`ContextProvider`] (compiled only with the
//! `synapse` feature).
//!
//! Wraps a `synapse::repo::Repo`, a default `synapse::config::SynapseConfig`, and
//! a LadybugDB graph store. `refresh` indexes the repo; `context_pack` runs
//! Synapse's pack selector (`PackMode::Path`) to gather the file plus its
//! callers/base-types/siblings as Markdown. File discovery and git facts come
//! straight from Synapse so behaviour matches the indexer.

use super::is_triage_candidate;
use super::provider::ContextProvider;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use synapse::config::SynapseConfig;
use synapse::graph::ladybug_store::LadybugGraphStore;
use synapse::pack::{self, PackFormat, PackMode, PackRequest};
use synapse::repo::Repo;

pub struct SynapseContextProvider {
    repo: Repo,
    config: SynapseConfig,
    store: LadybugGraphStore,
    root: PathBuf,
    include_extensions: Vec<String>,
    exclude_dirs: Vec<String>,
}

impl SynapseContextProvider {
    /// Discover the repo at `root` and open the LadybugDB graph under
    /// `.synapse/graph/synapse.lbug`. Uses Synapse's default config, whose
    /// include globs already cover .cs/.ts/.svelte/.json/.yaml.
    pub fn open(
        root: &Path,
        include_extensions: Vec<String>,
        exclude_dirs: Vec<String>,
    ) -> Result<Self> {
        let repo = Repo::discover(root).context("discovering repo root")?;
        let config = SynapseConfig::default();
        let graph_path = repo.root.join(&config.graph.path).join("synapse.lbug");
        let store = LadybugGraphStore::open(&graph_path)
            .with_context(|| format!("opening graph at {}", graph_path.display()))?;
        let root = repo.root.clone();
        Ok(Self {
            repo,
            config,
            store,
            root,
            include_extensions,
            exclude_dirs,
        })
    }

    fn is_candidate(&self, rel: &str) -> bool {
        is_triage_candidate(rel, &self.include_extensions, &self.exclude_dirs)
    }
}

impl ContextProvider for SynapseContextProvider {
    fn refresh(&self, changed_only: bool) -> Result<()> {
        let now = synapse_now();
        synapse::indexer::index_repo(
            &self.repo,
            &self.config,
            &self.store,
            /* force */ false,
            changed_only,
            &now,
            None,
        )
        .context("indexing repository graph")?;
        Ok(())
    }

    fn candidate_files(&self) -> Result<Vec<String>> {
        let all = self
            .repo
            .candidate_files(&self.config)
            .context("enumerating candidate files")?;
        Ok(all
            .into_iter()
            .filter(|rel| self.is_candidate(rel))
            .collect())
    }

    fn changed_files_since(&self, sha: Option<&str>) -> Result<Option<Vec<String>>> {
        let Some(sha) = sha else { return Ok(None) };
        let Some(diff) = git_diff_names(&self.root, sha) else {
            return Ok(None);
        };
        Ok(Some(
            diff.into_iter()
                .filter(|rel| self.is_candidate(rel))
                .collect(),
        ))
    }

    fn head_sha(&self) -> Option<String> {
        synapse::git::full_commit(&self.root)
    }

    fn context_pack(&self, file: &str, budget: usize) -> Result<String> {
        let request = PackRequest {
            mode: PackMode::Path(file.to_string()),
            budget,
            depth: 1,
            include_tests: false,
            include_config: false,
            include_diff: false,
            dry_run: false,
            explain: false,
            format: PackFormat::Markdown,
        };
        let info = synapse::git::info(&self.root);
        let result = pack::build_pack(&self.repo, &self.config, &self.store, &info, &request)
            .with_context(|| format!("building context pack for {file}"))?;
        Ok(result.rendered)
    }
}

/// RFC3339-ish timestamp for the indexer's `last_indexed_at` stamps.
fn synapse_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// `git -C <root> diff --name-only <sha> HEAD`, forward-slashed, or `None` when
/// not a repo / the SHA is unknown.
fn git_diff_names(root: &Path, sha: &str) -> Option<Vec<String>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--name-only", sha, "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.replace('\\', "/"))
            .collect(),
    )
}
