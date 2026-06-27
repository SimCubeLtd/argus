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
caller or a base type/handler already enforces auth, do not flag it.

THE REACHABILITY TEST (apply to EVERY candidate before reporting it). A finding \
is REAL only if you can name a concrete path by which an UNTRUSTED, \
ATTACKER-CONTROLLED value reaches the dangerous sink. Untrusted = data crossing \
a trust boundary at runtime: an HTTP request/body/header/query, a webhook, an \
uploaded file, a message off a queue, or third-party API output. The following \
are NOT untrusted and MUST NOT be flagged on their own:
- A CLI flag, argument, env var, or local config file value. The operator \
running the tool is trusted; configuring their own tool is not an attack.
- A constant, hard-coded literal, or value the program itself produces.
- A file path the program is explicitly designed to read/write as its job \
(a scanner reading source files, a report writer emitting its output file).
- The mere USE of a powerful API (spawning a subprocess with fixed/derived \
args, `reqwest`/HTTP to a configured endpoint, reading a file, deserializing \
trusted local state). Capability is not vulnerability.

Concretely, do NOT report: 'SSRF' because a URL/base-url is configurable; \
'path traversal' because the program reads a path it was given; 'command \
injection' when subprocess args are fixed or derived from trusted local data; \
'XSS' when the output is not served as HTML to a browser (e.g. a Markdown \
report, a log line, a terminal); 'prompt injection' as a finding about the \
tool's own intended design.

DEFAULT TO NOT-A-FINDING. If you cannot trace attacker-controlled input to the \
sink, drop it. Prefer precision over recall HARD — a daily triage feed that \
cries wolf gets ignored. It is far better to miss a borderline issue than to \
emit a false positive.

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
         Apply THE REACHABILITY TEST from your instructions to each candidate. \
         For a candidate to survive, you must be able to state a concrete path by \
         which ATTACKER-CONTROLLED input (HTTP request, upload, queue message, \
         third-party response — NOT a CLI flag, env var, config value, constant, \
         or a file the program is designed to handle) reaches the sink. If you \
         cannot, DROP it. When in doubt, DROP it.\n\n\
         For each surviving REAL issue, emit a finding. The `reachability` field \
         must name the untrusted source and trace it to the sink in one sentence; \
         if you find yourself writing \"if an attacker could control...\" about a \
         CLI/config/constant value, that is NOT a finding — drop it.\n\n\
         Respond with a JSON array of objects with EXACTLY these fields:\n\
         [{{\
         \"vulnerability_type\": \"...\", \
         \"description\": \"...\", \
         \"severity\": \"Critical|High|Medium|Low|Info\", \
         \"line_numbers\": [12], \
         \"reachability\": \"untrusted source X reaches sink Y via ...\", \
         \"impact\": \"...\", \
         \"recommendation\": \"...\", \
         \"fix_example\": \"...\"\
         }}]\n\
         `line_numbers` are 1-based lines in the TARGET FILE above. Return [] if \
         there are no real issues — an empty array is the EXPECTED result for \
         most files.",
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
    fn prompts_enforce_the_reachability_gate() {
        // The precision fix: the model must trace attacker-controlled input to a
        // sink and default to not-a-finding. Guard the key phrasing so a future
        // edit can't silently loosen it back into the over-flagging behaviour.
        assert!(SYSTEM_PROMPT.contains("REACHABILITY TEST"));
        assert!(SYSTEM_PROMPT.contains("DEFAULT TO NOT-A-FINDING"));
        // The exact false-positive classes seen on real scans are named as
        // must-not-flag examples.
        assert!(SYSTEM_PROMPT.contains("CLI flag"));
        assert!(SYSTEM_PROMPT.contains("Capability is not vulnerability"));

        let p = evaluate_prompt("a.cs", "code", "ctx", "[]");
        assert!(p.contains("REACHABILITY TEST"));
        assert!(p.contains("reachability"));
        assert!(p.contains("When in doubt, DROP it"));
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
