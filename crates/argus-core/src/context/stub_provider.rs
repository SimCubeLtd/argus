//! A graph-free [`ContextProvider`]: walks the tree with the `ignore` crate and
//! returns empty context packs.
//!
//! Two roles: (1) the unit-test double for `argus-core` (no LadybugDB build),
//! and (2) the runtime fallback when the Synapse graph can't be initialised —
//! Argus degrades to file-only scanning rather than blocking the daily run.

use super::is_triage_candidate;
use super::provider::ContextProvider;
use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct StubContextProvider {
    root: PathBuf,
    include_extensions: Vec<String>,
    exclude_dirs: Vec<String>,
}

impl StubContextProvider {
    pub fn new(root: &Path, include_extensions: Vec<String>, exclude_dirs: Vec<String>) -> Self {
        Self {
            root: root.to_path_buf(),
            include_extensions,
            exclude_dirs,
        }
    }

    fn walk(&self) -> Vec<String> {
        let mut out = Vec::new();
        let walker = WalkBuilder::new(&self.root)
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .parents(true)
            .build();
        for entry in walker.flatten() {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(&self.root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            if is_triage_candidate(&rel, &self.include_extensions, &self.exclude_dirs) {
                out.push(rel);
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Run `git -C <root> <args>`, trimmed stdout on success, else `None`.
    fn git(&self, args: &[&str]) -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

impl ContextProvider for StubContextProvider {
    fn refresh(&self, _changed_only: bool) -> Result<()> {
        Ok(())
    }

    fn candidate_files(&self) -> Result<Vec<String>> {
        Ok(self.walk())
    }

    fn changed_files_since(&self, sha: Option<&str>) -> Result<Option<Vec<String>>> {
        // Without a stored SHA we can't produce an incremental set => full scan.
        let Some(sha) = sha else { return Ok(None) };
        // An unknown/unreachable SHA (rebased away, shallow clone) => full scan.
        let Some(diff) = self.git(&["diff", "--name-only", sha, "HEAD"]) else {
            return Ok(None);
        };
        let changed = diff
            .lines()
            .map(|l| l.replace('\\', "/"))
            .filter(|rel| is_triage_candidate(rel, &self.include_extensions, &self.exclude_dirs))
            .collect();
        Ok(Some(changed))
    }

    fn head_sha(&self) -> Option<String> {
        self.git(&["rev-parse", "HEAD"]).filter(|s| !s.is_empty())
    }

    fn context_pack(&self, _file: &str, _budget: usize) -> Result<String> {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn provider(root: &Path) -> StubContextProvider {
        StubContextProvider::new(
            root,
            [".cs", ".ts"].iter().map(|s| s.to_string()).collect(),
            ["bin", "node_modules", "migrations"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    }

    #[test]
    fn walk_selects_only_triage_candidates() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/Foo.cs", "x");
        write(dir.path(), "web/app.ts", "x");
        write(dir.path(), "README.md", "x"); // wrong ext
        write(dir.path(), "src/bin/Gen.cs", "x"); // excluded dir
        write(dir.path(), "db/migrations/0001.cs", "x"); // excluded dir

        let files = provider(dir.path()).candidate_files().unwrap();
        assert_eq!(
            files,
            vec!["src/Foo.cs".to_string(), "web/app.ts".to_string()]
        );
    }

    #[test]
    fn context_pack_is_always_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(provider(dir.path()).context_pack("x.cs", 8000).unwrap(), "");
    }

    #[test]
    fn changed_since_none_means_full_scan() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            provider(dir.path())
                .changed_files_since(None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn head_sha_is_none_outside_a_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        assert!(provider(dir.path()).head_sha().is_none());
    }
}
