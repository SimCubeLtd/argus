//! Two-pass, stack-aware, context-injected security prompts.
//!
//! Pass 1 (*discover*) asks the model to surface candidate security-relevant
//! patterns, explicitly using the Synapse **context pack** (callers, base types,
//! project siblings) to judge whether inputs are validated upstream and whether
//! auth is actually enforced. Pass 2 (*evaluate*) re-examines each candidate
//! with the same context and emits final findings in the pseudo-scanner's field
//! shape. Both passes ask for JSON only; [`extract_json_array`] tolerates fenced
//! output and the orchestrator retries once on a parse failure.

/// System prompt shared by both passes — primes a general, language-agnostic
/// security reviewer. Concrete framework examples are illustrative cues, not a
/// fixed stack, so the same prompt works across C#, Rust, Python, Go, and
/// JS/TS/Svelte codebases. The model is told to infer the actual language and
/// frameworks from the code and context it is given.
pub const SYSTEM_PROMPT: &str = "\
You are a senior application-security engineer reviewing source code. Infer the \
language and frameworks from the code and context you are given; do not assume \
any particular stack.

Reason about REAL exploitability, not surface pattern matches. The classes of \
issue to weigh (examples, not an exhaustive or stack-specific list):
- Injection: untrusted input concatenated/interpolated into SQL, NoSQL, ORM/\
query-builder calls, shell commands, templates, or any interpreter.
- Authentication & authorization: endpoints/handlers missing auth checks, broken \
object-level authorization (IDOR), privilege escalation, unvalidated input DTOs.
- Web frontend: XSS via raw-HTML sinks (e.g. `{@html}`, `dangerouslySetInnerHTML`, \
`innerHTML`), CSRF gaps, secrets shipped to the client, server data leaking to \
the browser.
- Secrets & crypto: hardcoded credentials/keys/tokens, weak or misused crypto, \
insecure randomness.
- Other high-impact bugs: SSRF, path traversal, insecure deserialization, unsafe \
file handling, race conditions on security-relevant state.

You are given the TARGET CODE plus a CONTEXT PACK (its callers, base types, and \
sibling files from a code graph). USE THE CONTEXT: if input is validated by a \
caller or a base type/handler already enforces auth, do not flag it. Prefer \
precision over recall — a daily triage feed must not drown reviewers in false \
positives.

Always respond with JSON only. No prose, no markdown fences.";

/// Build the pass-1 user message: discover candidate patterns.
pub fn discover_prompt(file: &str, code: &str, context_pack: &str) -> String {
    format!(
        "## TARGET FILE: {file}\n\n\
         ```\n{code}\n```\n\n\
         {context_section}\
         ## TASK (pass 1 of 2 — DISCOVER)\n\
         List security-relevant CANDIDATE patterns in the target file. For each, \
         give the pattern and the 1-based line number(s) IN THE TARGET FILE above. \
         Use the context pack to avoid flagging inputs already validated upstream \
         or endpoints whose auth is enforced by a base class.\n\n\
         Respond with a JSON array of objects:\n\
         [{{\"pattern\": \"...\", \"line_numbers\": [12], \"why_relevant\": \"...\"}}]\n\
         Return [] if nothing is security-relevant.",
        file = file,
        code = code,
        context_section = context_block(context_pack),
    )
}

/// Build the pass-2 user message: evaluate the candidates into final findings.
pub fn evaluate_prompt(
    file: &str,
    code: &str,
    context_pack: &str,
    candidates_json: &str,
) -> String {
    format!(
        "## TARGET FILE: {file}\n\n\
         ```\n{code}\n```\n\n\
         {context_section}\
         ## CANDIDATE PATTERNS (from pass 1)\n\
         {candidates}\n\n\
         ## TASK (pass 2 of 2 — EVALUATE)\n\
         Evaluate each candidate against the code and context. DROP false \
         positives the context rules out (validated upstream, auth enforced, not \
         reachable with attacker input). For each REAL issue, emit a finding.\n\n\
         Respond with a JSON array of objects with EXACTLY these fields:\n\
         [{{\
         \"vulnerability_type\": \"...\", \
         \"description\": \"...\", \
         \"severity\": \"Critical|High|Medium|Low|Info\", \
         \"line_numbers\": [12], \
         \"impact\": \"...\", \
         \"recommendation\": \"...\", \
         \"fix_example\": \"...\"\
         }}]\n\
         `line_numbers` are 1-based lines in the TARGET FILE above. Return [] if \
         there are no real issues.",
        file = file,
        code = code,
        context_section = context_block(context_pack),
        candidates = candidates_json,
    )
}

/// Render the context pack as a delimited section, or a clear "no context"
/// marker so the model knows it is reasoning file-only.
fn context_block(context_pack: &str) -> String {
    let trimmed = context_pack.trim();
    if trimmed.is_empty() {
        "## CONTEXT PACK\n(no cross-file context available — reason from the \
         target file alone)\n\n"
            .to_string()
    } else {
        format!("## CONTEXT PACK (callers / base types / siblings)\n{trimmed}\n\n")
    }
}

/// Extract a JSON array from a model response, tolerating ```` ```json ```` /
/// ```` ``` ```` fences and leading/trailing prose. Returns the substring from
/// the first `[` to its matching `]`, or `None` if no array is present.
pub fn extract_json_array(raw: &str) -> Option<String> {
    let s = strip_fences(raw);
    let start = s.find('[')?;
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(s[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip a single surrounding Markdown code fence if present.
fn strip_fences(raw: &str) -> &str {
    let t = raw.trim();
    if let Some(rest) = t.strip_prefix("```") {
        // Drop an optional language tag on the opening fence line.
        let rest = rest.split_once('\n').map(|(_, r)| r).unwrap_or(rest);
        rest.trim_end().strip_suffix("```").unwrap_or(rest).trim()
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_prompt_embeds_code_and_context() {
        let p = discover_prompt("src/Login.cs", "var x = 1;", "CALLER: Auth.cs");
        assert!(p.contains("src/Login.cs"));
        assert!(p.contains("var x = 1;"));
        assert!(p.contains("CALLER: Auth.cs"));
        assert!(p.contains("DISCOVER"));
    }

    #[test]
    fn evaluate_prompt_embeds_candidates_and_field_shape() {
        let p = evaluate_prompt("a.cs", "code", "ctx", "[{\"pattern\":\"x\"}]");
        assert!(p.contains("vulnerability_type"));
        assert!(p.contains("fix_example"));
        assert!(p.contains("[{\"pattern\":\"x\"}]"));
    }

    #[test]
    fn empty_context_renders_no_context_marker() {
        let p = discover_prompt("a.cs", "code", "   ");
        assert!(p.contains("no cross-file context available"));
    }

    #[test]
    fn extracts_plain_array() {
        let got = extract_json_array("[{\"a\":1}]").unwrap();
        assert_eq!(got, "[{\"a\":1}]");
    }

    #[test]
    fn extracts_from_json_fence_with_prose() {
        let raw = "Here you go:\n```json\n[{\"a\": 1}]\n```\nthanks";
        assert_eq!(extract_json_array(raw).unwrap(), "[{\"a\": 1}]");
    }

    #[test]
    fn ignores_brackets_inside_strings() {
        let raw = r#"[{"desc": "array like [1,2]"}]"#;
        assert_eq!(extract_json_array(raw).unwrap(), raw);
    }

    #[test]
    fn returns_none_when_no_array() {
        assert!(extract_json_array("I could not find anything").is_none());
    }
}
