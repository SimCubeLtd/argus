//! Stable finding fingerprints.
//!
//! A finding's identity is `sha256(file + vuln_type + first_line)`. This is what
//! makes triage durable: the same issue re-detected on a later run hashes to the
//! same value, so a prior `dismissed`/`confirmed` decision is reapplied instead
//! of resurfacing as new. The inputs are joined with a NUL separator so
//! `("ab","c")` and `("a","bc")` can't collide.

use sha2::{Digest, Sha256};

/// Compute the stable fingerprint for a finding.
pub fn fingerprint(file: &str, vuln_type: &str, first_line: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file.as_bytes());
    hasher.update([0u8]);
    hasher.update(vuln_type.as_bytes());
    hasher.update([0u8]);
    hasher.update(first_line.to_string().as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic() {
        let a = fingerprint("src/Foo.cs", "SQL Injection", 42);
        let b = fingerprint("src/Foo.cs", "SQL Injection", 42);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn differs_on_each_input() {
        let base = fingerprint("src/Foo.cs", "SQLi", 10);
        assert_ne!(base, fingerprint("src/Bar.cs", "SQLi", 10));
        assert_ne!(base, fingerprint("src/Foo.cs", "XSS", 10));
        assert_ne!(base, fingerprint("src/Foo.cs", "SQLi", 11));
    }

    #[test]
    fn separator_prevents_field_boundary_collisions() {
        // Without the NUL separator these would both hash "abc...".
        assert_ne!(fingerprint("ab", "c", 1), fingerprint("a", "bc", 1));
    }
}
