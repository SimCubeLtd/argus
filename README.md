# Argus

**Local, daily, LLM-driven security triage for any codebase.**

Argus scans a codebase with a self-hosted **SGLang** inference endpoint
(OpenAI-compatible API), enriches each file with cross-file context from a
[Synapse](https://github.com/SimCubeLtd/synapse) code graph, and produces a
concise daily Markdown report for human or AI review. It tracks findings across
runs with stable fingerprints and a triage workflow (pending → confirmed /
dismissed), so a once-reviewed false positive never resurfaces.

## The name

In Greek myth, **Argus Panoptes** (Ἄργος Πανόπτης — "all-seeing") was a giant
with a hundred eyes set all over his body. Because only a few ever slept at
once while the rest kept watch, he was the perfect, unsleeping guardian: Hera
set him to watch over the heifer-nymph Io so that nothing escaped his notice. He
was eventually lulled to sleep and slain by Hermes — and Hera, to honour him,
scattered his hundred eyes across the tail of the peacock, where they remain.

The tool earns the name. Like its namesake it keeps **many eyes on the code at
once** — every changed file watched in parallel, each seen not in isolation but
together with the callers and types around it — and it runs **every day without
tiring**. The hundred eyes are the point: a single eye on one file misses the
vulnerability that only shows when you can see who calls it and what it trusts.

```text
repo  ──►  Synapse graph (callers, base types, siblings)
      ──►  per-file context pack + the file's code
      ──►  two-pass LLM review (discover → evaluate)
      ──►  fingerprinted findings + triage state
      ──►  .triage-state/reports/triage-YYYY-MM-DD.md
```

## Why context matters

A handler or a database query read **in isolation** can't tell you whether its
input is validated upstream, who calls it, or whether an auth check is actually
enforced on every path. Argus feeds the model the file *plus* its callers, base
types, and project siblings — pulled from Synapse's
`REFERENCES` / `INHERITS` / `IMPLEMENTS` / `CONTAINS_FILE` graph edges — so it
can judge **real exploitability** instead of pattern-matching in the dark. This
sharply cuts the false positives that drown a daily triage feed.

Synapse extracts symbols and relationships across **C#, Rust, Python, Go,
JavaScript, TypeScript, and Svelte**, so the context engine works on most
real-world repositories — Argus is not tied to any one stack.

## Install / build

Requires a recent Rust toolchain **and a C++ toolchain** — Argus embeds
Synapse, whose graph engine (LadybugDB) statically compiles on first build.

```bash
cargo build --release          # binary at target/release/argus
```

> The fast unit-test suite needs neither the network nor the C++ engine:
> `cargo test -p argus-core` mocks the LLM and the context provider. The full
> suite (`cargo test --workspace`) builds Synapse and mocks SGLang with
> `wiremock`.

## Setup

```bash
argus init                     # writes .triage-state/argus.toml
```

Point it at your SGLang server — edit `[endpoint]` in the config, or set
`ARGUS_BASE_URL`:

```bash
export ARGUS_BASE_URL=http://ippex-inference:8000/v1
export ARGUS_MODEL=your-served-model-name
```

SGLang requires no auth, so the API key defaults to a dummy value. **Never**
commit a real key.

## Daily workflow

```bash
argus scan                                   # 1. scan → today's report path on stdout
#   paste .triage-state/reports/triage-YYYY-MM-DD.md into Claude for validation
argus confirm <fingerprint>                  # 2. real issue → kept in reports
argus dismiss <fingerprint>                  # 2. false positive → suppressed forever
argus status                                 # 3. pending / confirmed / dismissed counts
```

- **First run** scans every candidate file. **Later runs** scan only files git
  reports changed since the last run's commit (stored in
  `.triage-state/last_run.json`). Not a git repo / no commits yet → full scan.
- A **dismissed** finding stays out of every future report, even if re-detected.
- `argus report` regenerates today's report from current state **without**
  rescanning — handy after a batch of confirms/dismisses.

## Commands

| Command | Purpose |
|---|---|
| `argus init [--force]` | Write a default `.triage-state/argus.toml`. |
| `argus scan` | Refresh the graph, scan (full or incremental), persist findings, write today's report. Prints the report path. |
| `argus dismiss <fingerprint>` | Mark a finding dismissed (suppressed from reports forever). |
| `argus confirm <fingerprint>` | Mark a finding confirmed (kept in reports). |
| `argus report` | Regenerate today's report from current state — no rescan. |
| `argus status [--json]` | Show pending / confirmed / dismissed / total counts. |

Global flags (override config): `--base-url`, `--model`, `--concurrency`,
`--max-tokens`, `--root`.

## Configuration

`.triage-state/argus.toml`:

```toml
[endpoint]
base_url = "http://ippex-inference:8000/v1"
model = "default"
api_key = "sglang"          # dummy — SGLang needs no auth
timeout_secs = 300
concurrency = 4             # max in-flight LLM requests

[scan]
include_extensions = [".cs", ".svelte", ".ts", ".js", ".json", ".yaml", ".yml"]
exclude_dirs = ["bin", "obj", ".git", "node_modules", "migrations"]
max_tokens_per_chunk = 8000 # files over this (chars/4 estimate) are chunked
context_budget = 8000       # token budget for each file's context pack

[report]
output_dir = ".triage-state/reports"
```

### Override precedence

For each setting: **CLI flag > environment variable > config file > default.**

| Setting | CLI flag | Env var |
|---|---|---|
| Base URL | `--base-url` | `ARGUS_BASE_URL` |
| Model | `--model` | `ARGUS_MODEL` |
| API key | — | `ARGUS_API_KEY` |
| Concurrency | `--concurrency` | `ARGUS_CONCURRENCY` |
| Chunk token cap | `--max-tokens` | `ARGUS_MAX_TOKENS` |

Set `RUST_LOG=info` (or `debug`) for verbose diagnostics on stderr.

## How a scan works

1. **Refresh** the Synapse graph (incremental on later runs).
2. **Select** files: changed-since-last-run, or all on a first/clean run,
   narrowed to the configured extensions and exclude-dirs.
3. For each file (bounded by `concurrency`): pull a **context pack**, chunk the
   file if it exceeds the token cap, and run a **two-pass** prompt per chunk —
   *discover* candidate patterns, then *evaluate* them into findings, dropping
   false positives the context rules out. Malformed JSON is retried once.
4. **Fingerprint** each finding as `sha256(file + vuln_type + first_line)` and
   reconcile against `.triage-state/findings.json`: new → pending, re-detected →
   prior triage state preserved.
5. **Report** only pending + confirmed findings, grouped by severity.

## State & git

Everything under `.triage-state/` (config, findings, last-run marker, reports)
and the `.synapse/` graph workspace are **local-only** and git-ignored.

## Layout

```text
crates/
  argus-core/   library: config, chunk, fingerprint, scan orchestration,
                LLM client (trait + SGLang), context provider (trait + Synapse),
                JSON/memory finding stores, report renderer
  argus-cli/    binary `argus`: clap, settings resolution, command wiring
```

The context engine (`ContextProvider`), LLM endpoint (`LlmClient`), and
persistence (`FindingStore`) are each traits with a real implementation and a
test double — so the core scanning pipeline is fully testable without a network,
a terminal, or the C++ graph build.

## License

[0BSD](LICENSE) — the same license as
[Synapse](https://github.com/SimCubeLtd/synapse). Copyright © 2026 SimCube Ltd.
