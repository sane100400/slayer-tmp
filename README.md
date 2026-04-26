# SLAyer

> **Security scanner for vibe-coded web services**
> CMUX x AIM Hackathon 2026 - Developer Tooling track

SLAyer detects seven recurring security vulnerability patterns in **web-service code
(Python, JavaScript, and TypeScript)** generated with vibe-coding tools such as Claude,
GPT, or Cursor. It can then patch detected issues through an already-installed AI CLI
and open the deployment gate.

```bash
# Development install
pip install -e ".[dev]"

slayer start .    # Scan -> print violations
slayer patch .    # Scan -> auto-patch -> Deployment Approved
```

**No API keys required.** If Claude Code, Codex CLI, or Gemini CLI is already installed,
SLAyer can use it for patching immediately. `slayer start` works without AI; only
`slayer patch` requires one supported AI CLI.

---

## Why SLAyer?

Existing tools such as Bandit and Semgrep use general security rules. SLAyer focuses on
**data-backed vulnerability patterns that repeatedly appear in AI-generated code**.

| | SLAyer | Bandit | Semgrep |
|---|---|---|---|
| Target | Patterns specific to AI-generated code | General Python | General, rule authoring required |
| Languages | Python, JS, TS | Python | Many |
| Patching | Automatic patching through an AI CLI | None | None |
| Setup | Zero; run immediately | Configuration required | Rule files required |

| Cause | Pattern |
|------|------|
| "Just make it work" prompts | Hard-coded credentials, external calls, `shell=True` |
| Outdated tutorial training data | f-string SQL, `Math.random()` token generation |
| Shipping development examples | `DEBUG=True`, `debug: true` |
| "Make the error go away" prompts | `except: pass`, empty `catch {}` |

---

## Why these seven rules?

We collected and analyzed GitHub repositories that include `CLAUDE.md`, then selected the
final seven rules with a **frequency x impact scoring matrix**.

```
Final score = weighted_impact_score * 0.6 + log10(frequency) / log10(max) * 5 * 0.4
```

Impact is evaluated across five axes: exploitability (25%), damage severity (25%),
time-to-exploit (20%), detection confidence (15%), and AI amplification factor (15%).

| Rule | Final score | Severity |
|----|-----------|----------|
| NO_HARDCODED_SECRETS | 5.00 | critical |
| NO_EXEC | 3.98 | critical |
| SQL_PARAM_BINDING | 3.91 | high |
| NO_DEBUG_MODE | 3.87 | high |
| NO_NETWORK | 2.63 | critical |
| NO_WEAK_RANDOM | 2.91 | high |
| NO_BARE_EXCEPT | 3.00 | medium |

See the full methodology in [`spec.md` section 0.55](./spec.md).

---

## Supported languages

Python (`.py`), JavaScript (`.js`, `.jsx`), and TypeScript (`.ts`, `.tsx`).

## Supported OSes and AI CLIs

- **OS:** Windows, macOS, Linux
- **Python:** 3.11 or later
- **AI CLI patching:** Claude Code, Codex CLI, or Gemini CLI installed on the local `PATH`

```bash
slayer model auto      # Auto-detect in claude -> codex -> gemini order
slayer model claude    # Pin Claude Code and save to .slayer.yml
slayer model codex     # Pin Codex CLI
slayer model gemini    # Pin Gemini CLI
```

---

## Usage

### `slayer start` - scan

```bash
slayer start .                   # Scan the current directory
slayer start demo_vuln.py        # Scan one file
slayer start . --format json     # JSON output for CI/CD integration
```

Example output:

```text
  CRITICAL  NO_HARDCODED_SECRETS  demo_vuln.py:3
            API_KEY = "sk-prod-abc123..."
            -> Use os.environ.get('API_KEY') - keep secrets out of the code.

  HIGH      SQL_PARAM_BINDING     demo_vuln.py:7
            cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
            -> Use cursor.execute('SELECT ... WHERE name=?', (name,))

  4 violations - Deployment BLOCKED

  Run slayer patch demo_vuln.py to fix automatically.
```

### `slayer patch` - automatic patching

```bash
slayer patch demo_vuln.py        # Scan -> patch -> rescan
slayer patch . --format json     # JSON result output
```

`.slayer.yml` must contain an `ai:` setting. Run `slayer model claude` first if you want
to pin Claude Code.

Example output:

```text
  Patching via claude...

  demo_vuln.py patched

  Patch explanations:
  - NO_HARDCODED_SECRETS  demo_vuln.py:3  - Moved the secret out of the code
    Replaced hard-coded keys or passwords with environment variable lookups.

  Deployment Approved
```

### `slayer model` - configure the AI CLI

```bash
slayer model              # Show detection status and current setting
slayer model claude       # Save claude as the selected CLI in .slayer.yml
slayer model codex        # Save codex as the selected CLI
slayer model auto         # Reset to auto-detection
```

---

## Exit codes

| Code | Meaning |
|------|------|
| `0` | No violations; deployment approved |
| `1` | Violations found; deployment blocked |
| `2` | Runtime error |

---

## CI/CD integration

```bash
# Check deployability from JSON output
slayer patch . --format json | jq -e '.deployable'
```

```yaml
# pre-commit
repos:
  - repo: local
    hooks:
      - id: slayer
        name: SLAyer Security Check
        entry: slayer start
        language: python
        types_or: [python, javascript, ts]
```

---

## Installation

```bash
# Development install
pip install -e ".[dev]"
```

Dependencies: `pydantic`, `typer`, and `rich`. SLAyer uses no AI SDK and requires no API
keys.

---

## Benchmarks

**slayer-bench-v0** - 28 manually curated cases (22 true positives + 6 false-positive-free):

| Rule | Case count |
|----|----------|
| NO_WEAK_RANDOM | 5 |
| NO_NETWORK | 4 |
| NO_HARDCODED_SECRETS | 3 |
| SQL_PARAM_BINDING | 3 |
| NO_DEBUG_MODE | 3 |
| NO_EXEC | 2 |
| NO_BARE_EXCEPT | 2 |

**ai-bench-v1** - Four real web-service files generated by Claude Haiku, with 15 detected
violations. This independently verifies that the patterns SLAyer targets appear in
vibe-coded output.

Case sources: SecretBench, CredData, OWASP Benchmark, SecurityEval, PatchEval, CVEfixes,
SARD/Juliet, and NVD CVE.

---

## Limitations

- **Indirect SSRF is not detected:** SLAyer detects direct patterns such as
  `requests.get(url)` when `url` is externally supplied. It does not currently track values
  through intermediate assignments such as `url = user_input; requests.get(url)`.
- **Dynamic code is not detected:** Dynamically assembled strings passed into `eval()` or
  `exec()` are outside the current detection scope.
- **Security context classification is limited:** `NO_WEAK_RANDOM` detects `random` usage
  near tokens, sessions, and OTPs, but it cannot perfectly recognize every security context.
- **Patch scope is limited:** AI patching fixes only detected violations. Undetected
  vulnerabilities remain unchanged.

---

## Architecture

```text
slayer/
|-- cli.py              # slayer start / patch / model
|-- analyzers/
|   |-- py_analyzer.py  # Python AST detection; no AI required
|   `-- js_analyzer.py  # JS/TS regex detection; no AI required
|-- ai_runner.py        # AI CLI detection (claude -> codex -> gemini) and delegation
|-- patcher/
|   `-- llm_patcher.py  # SLAyer-scoped automatic patching
`-- models.py           # Pydantic data models
```

Detection is deterministic and does not use AI. The AI CLI is used only for patching.

---

## Related files

- [`spec.md`](./spec.md) - Detailed development specification
- [`demo_vuln.py`](./demo_vuln.py) - Python vulnerable-pattern demo
- [`demo_vuln.js`](./demo_vuln.js) - JS vulnerable-pattern demo
- [`dataset/slayer-bench-v0/`](./dataset/slayer-bench-v0/) - Vulnerable, fixed, and false-positive-free benchmark cases
- [`dataset/ai-bench-v1/`](./dataset/ai-bench-v1/) - AI-generated code benchmark
- [`presentation.html`](./presentation.html) - Presentation material

---

*CMUX x AIM Hackathon 2026 - Developer Tooling track*
