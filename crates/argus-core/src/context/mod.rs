//! The context-engine seam.
//!
//! Argus enriches each scanned file with cross-file context (callers, base
//! types, project siblings) so the model can judge real exploitability. That
//! context comes from Synapse's code graph, but the scanner only ever talks to
//! the [`ContextProvider`] trait — so tests run against [`StubContextProvider`]
//! with no LadybugDB/C++ build, and the real [`SynapseContextProvider`] (behind
//! the `synapse` feature) is wired only by the binary.

mod provider;
mod stub_provider;
#[cfg(feature = "synapse")]
mod synapse_provider;

pub use provider::ContextProvider;
pub use stub_provider::StubContextProvider;
#[cfg(feature = "synapse")]
pub use synapse_provider::SynapseContextProvider;

/// True if `rel` (a forward-slash, repo-relative path) should be triaged: its
/// extension is in `include_extensions` and no path component is an
/// `exclude_dirs` name. Shared by every provider so file selection is identical
/// whether or not the Synapse graph is available.
pub fn is_triage_candidate(
    rel: &str,
    include_extensions: &[String],
    exclude_dirs: &[String],
) -> bool {
    if rel
        .split('/')
        .any(|seg| exclude_dirs.iter().any(|d| d == seg))
    {
        return false;
    }
    include_extensions
        .iter()
        .any(|ext| rel.ends_with(ext.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exts() -> Vec<String> {
        [".cs", ".ts"].iter().map(|s| s.to_string()).collect()
    }
    fn excludes() -> Vec<String> {
        ["bin", "node_modules", "migrations"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn includes_matching_extension() {
        assert!(is_triage_candidate("src/Foo.cs", &exts(), &excludes()));
        assert!(is_triage_candidate("web/app.ts", &exts(), &excludes()));
    }

    #[test]
    fn rejects_wrong_extension() {
        assert!(!is_triage_candidate("README.md", &exts(), &excludes()));
    }

    #[test]
    fn prunes_excluded_dirs_anywhere_in_path() {
        assert!(!is_triage_candidate("src/bin/Gen.cs", &exts(), &excludes()));
        assert!(!is_triage_candidate(
            "db/migrations/0001.cs",
            &exts(),
            &excludes()
        ));
        assert!(!is_triage_candidate(
            "node_modules/pkg/index.ts",
            &exts(),
            &excludes()
        ));
    }

    #[test]
    fn dir_name_must_be_a_full_segment() {
        // "binary" contains "bin" but isn't the excluded dir.
        assert!(is_triage_candidate(
            "src/binary/Foo.cs",
            &exts(),
            &excludes()
        ));
    }
}
