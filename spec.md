# SLAyer - Development Specification v7

> Track: Developer Tooling | CMUX x AIM | 2026-04-26

---

## 0. One-sentence summary

**SLAyer is a CLI tool that detects seven security vulnerability patterns in
vibe-coded web-service code (Python, JS, and TS), patches them through an already
installed AI CLI (Claude Code, Codex CLI, or Gemini CLI), and opens the deployment gate.**

```bash
pip install slayer-sec   # Install
slayer start .           # Scan -> print violations
slayer patch .           # Auto-patch violations -> Deployment Approved
slayer model             # Check AI CLI status or set the preferred model
```

**Supported languages:** Python (`.py`), JavaScript (`.js`, `.jsx`), and TypeScript (`.ts`, `.tsx`)
**Target user:** a vibe coder who already has Claude Code, Codex CLI, or Gemini CLI installed.

**Meaning of "zero SLAyer configuration":**

- SLAyer itself has no API key, config file, or login requirement.
- The user is expected to have already installed and authenticated the AI CLI, such as Claude Code.
- If no AI CLI is available, AST scanning still works; only patching is unavailable and SLAyer shows setup guidance.

---

## 0.5 Dataset strategy

### GitHub-collected vibe-coding repositories as the basis for the seven rules

Repositories containing `CLAUDE.md` or `AGENTS.md` provide direct evidence that the project was
built with an AI CLI workflow.

| Item | Details |
|------|------|
| Collection method | GitHub Code Search API (`filename:CLAUDE.md`) |
| Scale | Direct collection of vibe-coding repositories |
| Analysis tool | `tools/extract_vulns.py` |
| Result | `dataset/analysis.json` (336 vulnerable files, 485 findings) |

**Observed vulnerability frequency** based on `dataset/analysis.json`, aggregated across three sources:

| SLAyer rule | `extract_vulns` rule name | Observed count | Note |
|-----------|------------------|---------------|------|
| SQL_PARAM_BINDING | SQL_INJECTION | **1,564** | Includes 1,524 real-repository findings |
| NO_HARDCODED_SECRETS | HARDCODED_SECRETS | **1,552** | Hard-coded API keys |
| NO_EXEC | COMMAND_INJECTION | **913** | `shell=True` |
| NO_DEBUG_MODE | DEBUG_MODE_ON | 168 | `debug=True` in deployment paths |
| NO_WEAK_RANDOM | WEAK_HASH | 133 | Weak security primitives mapped to the current weak-randomness rule |
| NO_NETWORK | SSRF | 125 | User-input URL targets |
| NO_BARE_EXCEPT | Not detected by that extractor | - | Outside `extract_vulns.py` scope; SLAyer detects this independently with AST/regex logic |

Total: 4,927 findings across 2,473 vulnerable files from the `dataset`, `drepos`, and `repos` sources.
This frequency data is the basis for selecting the seven rules.

---

## 0.55 Seven-rule selection methodology: frequency x impact matrix

### Five impact axes, each scored from 1 to 5

| Axis | Description | Weight |
|----|------|--------|
| **A. Real-world exploitability** | Based on the inverse of CVSS attack complexity | 25% |
| **B. Damage severity** | Maximum impact such as data exposure, RCE, or financial loss | 25% |
| **C. Time-to-exploit** | Time until first automated bot attack | 20% |
| **D. AST/regex detection confidence** | Whether deterministic detection is possible with low FP/FN risk | 15% |
| **E. AI-code amplification factor** | How much more often or severely it appears in AI-generated code than in human-written code | 15% |

### Final selection formula

```text
Final score = weighted_impact_score(A through E) * 0.6 + normalized_frequency * 0.4

normalized_frequency = log10(count) / log10(max_count) * 5   # converted to a 1-5 scale
```

### Candidate-to-final selection result

Frequency normalization uses `log10(1564) = 3.194` as the maximum, based on SQL_INJECTION with 1,564 findings.

| Rule | Weighted impact | Observed count | Frequency score (1-5) | Final score | Selected |
|----|-----------|---------|-------------|---------|------|
| NO_HARDCODED_SECRETS | 5.00 | 1,552 | 4.99 | **5.00** | yes |
| NO_EXEC | 4.70 | 913 | 4.63 | **4.67** | yes |
| SQL_PARAM_BINDING | 4.20 | 1,564 | 5.00 | **4.52** | yes |
| NO_NETWORK | 3.70 | 125 | 3.28 | **3.53** | yes |
| NO_DEBUG_MODE | 3.55 | 168 | 3.48 | **3.52** | yes |
| NO_WEAK_RANDOM | 3.55 | 133 | 3.32 | **3.46** | yes |
| NO_BARE_EXCEPT | 3.00 | Independent SLAyer detection | 3.00 | **3.00** | yes |
| INSECURE_DESERIALIZATION | 4.20 | 31 | 2.33 | 3.45 | no; AST detection not implemented yet, v2 candidate |
| CORS_WILDCARD | 2.95 | 167 | 3.48 | 3.16 | no; high false-positive risk |
| INSECURE_COOKIE | 2.60 | 186 | 3.55 | 2.98 | no; JS-only and outside current scope |

### Benchmark datasets

| Component | Path |
|------|------|
| Vulnerable cases | `dataset/slayer-bench-v0/vulnerable/` |
| Fixed cases | `dataset/slayer-bench-v0/fixed/` |
| False-positive-free cases | `dataset/slayer-bench-v0/false_positive/` |
| AI-generated code cases | `dataset/ai-bench-v0/` |

---

## 0.6 Vibe coding vulnerability taxonomy

### Why vibe-coded applications become vulnerable

| Root cause | Description |
|----------|------|
| "Just make it work" prompts | Feature implementation is prioritized without security context |
| Outdated tutorial data | Training data contains old patterns such as f-string SQL and MD5 hashing |
| Shipping development examples | `DEBUG=True` and hard-coded credentials are not replaced before deployment |
| Requests to remove errors | `except: pass` appears as a result of prompts like "make the error go away" |

### Seven-rule vibe coding ruleset

GitHub analysis of 1,000 vibe-coding repositories showed these high-frequency patterns.

| ID | Rule type | Severity | Observed frequency |
|----|-----------|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | critical | 33.9% of repositories |
| V-02 | NO_NETWORK | critical | 61.3% of repositories |
| V-03 | NO_EXEC | critical | 48.3% of repositories |
| V-04 | SQL_PARAM_BINDING | high | 56.7% of repositories |
| V-05 | NO_DEBUG_MODE | high | 10.2% of repositories |
| V-06 | NO_WEAK_RANDOM | high | 8.7% of repositories |
| V-07 | NO_BARE_EXCEPT | medium | 42.1% of repositories |

### Patch strategy by language, replacing code with working implementations

| Rule | Python patch | JS/TS patch |
|------|------------|-----------|
| NO_HARDCODED_SECRETS | `os.environ.get("VAR", "")` | `process.env.VAR ?? ""` |
| NO_NETWORK | `raise NotImplementedError("External calls are blocked")` | `throw new Error("External calls are blocked")` |
| NO_EXEC | `shell=False` with list arguments | `execFile("cmd", [arg], cb)` |
| SQL_PARAM_BINDING | `cursor.execute("... WHERE x=?", (val,))` | `query("... WHERE x=$1", [val])` |
| NO_DEBUG_MODE | `os.environ.get("DEBUG", "false") == "true"` | `process.env.NODE_ENV !== "production"` |
| NO_WEAK_RANDOM | `secrets.token_hex(32)` | `crypto.randomUUID()` |
| NO_BARE_EXCEPT | `except Exception as e: logger.warning(e)` | `catch(e){ console.error(e) }` |

---

## 1. Architecture

SLAyer is a single Python package with plain-text CLI output. AI calls are delegated to a
**local AI CLI process** instead of using a direct API, so there is no `anthropic` SDK dependency.

```text
slayer/
|-- slayer/
|   |-- cli.py              # entry point: slayer start / patch / model
|   |-- models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
|   |-- ai_runner.py        # AI CLI detection (claude -> codex -> gemini) and prompt delegation
|   |-- scanner.py          # file collection and analyzer dispatch
|   |-- reporter.py         # text/json output rendering
|   |-- rules.py            # DEFAULT_RULES_BY_ID
|   |-- analyzers/
|   |   |-- py_analyzer.py   # Python AST analysis; no AI required
|   |   `-- js_analyzer.py   # JS/TS regex analysis; no AI required
|   `-- patcher/
|       `-- llm_patcher.py   # automatic patching through AI CLI delegation and language detection
|-- pyproject.toml
|-- demo_vuln.py             # Python demo
|-- demo_vuln.js             # JS demo
`-- spec.md
```

---

## 2. AI CLI detection and delegation (`ai_runner.py`)

**SLAyer does not call AI APIs directly.** It sends prompts to a locally installed AI CLI and reads stdout.

### Detection priority

| AI CLI | Detection command | Execution command |
|--------|----------|----------|
| `claude` | `claude --version` | `claude -p "{prompt}"` |
| `codex` | `codex --version` | `codex exec "{prompt}"` |
| `gemini` | `gemini --version` | `gemini "{prompt}"` |

**Successful detection condition:** the check command exits with code 0.
**Priority:** saved value in `.slayer.yml` first, then auto-detection in the order above.

### Error handling

| Situation | Behavior |
|------|------|
| No AI CLI is installed | `AICliNotFoundError` -> show installation guidance; AST scanning still works |
| CLI exit code is not 0 | Show stderr content as the error message and keep the original file |
| stdout is not valid code | Restore the original file and show "Patch failed" |
| 60-second timeout | Restore the original file |

**Message when no AI CLI is found:**

```text
No AI CLI was detected.

Install one of the following:
  - Claude Code   https://claude.ai/code
  - Codex CLI     npm install -g @openai/codex
  - Gemini CLI    npm install -g @google/gemini-cli

AST-based scanning works without AI; only patching requires an AI CLI.
```

---

## 3. CLI interface

SLAyer exposes three commands.

### 3-1. `slayer start`

```bash
slayer start <path>
```

- Recursively collect `.py`, `.js`, `.jsx`, `.ts`, and `.tsx` files -> run AST/regex scans -> print violations as plain text.
- If `path` is omitted, use the current directory (`.`).

### 3-2. `slayer patch`

```bash
slayer patch <path>
```

- Scan -> when violations are found, patch through the AI CLI -> rescan.
- After patching, print `Deployment Approved` or the remaining violation list.

### 3-3. `slayer model`

```bash
slayer model                # Show detected AI CLI status and current setting
slayer model claude         # Save claude in .slayer.yml
slayer model codex          # Save codex in .slayer.yml
slayer model gemini         # Save gemini in .slayer.yml
slayer model auto           # Reset to auto-detection, the default
```

**Exit codes for both `start` and `patch`:**

- `0` - no violations; Deployment Approved.
- `1` - violations exist; Deployment BLOCKED.
- `2` - runtime error.

**Common option:**

```text
--format [text|json]   Output format, default: text
```

---

## 4. Output format

### Text format, default

```text
SLAyer  Scanning demo_vuln.py

NO_HARDCODED_SECRETS  demo_vuln.py:5   API_KEY = "sk-prod-..."
NO_NETWORK            demo_vuln.py:9   requests.get(...)
SQL_PARAM_BINDING     demo_vuln.py:13  f"SELECT * FROM ..."
NO_EXEC               demo_vuln.py:17  subprocess.run(..., shell=True)

Deployment BLOCKED
```

### JSON format (`--format json`)

```json
{
  "violations": [
    {
      "rule_id": "rule_1",
      "rule_name": "No external network calls",
      "file": "/abs/path/demo_vuln.py",
      "line": 9,
      "col": 0,
      "code_snippet": "    return requests.get(...)",
      "explanation": "This code sends data to an external server."
    }
  ],
  "pass_count": 0,
  "fail_count": 4,
  "deployable": false
}
```

---

## 5. Data models (`models.py`)

```python
RuleType = Literal["NO_NETWORK", "NO_EXEC", "NO_HARDCODED_SECRETS",
                   "SQL_PARAM_BINDING", "NO_DEBUG_MODE",
                   "NO_WEAK_RANDOM", "NO_BARE_EXCEPT", "CUSTOM"]
Severity = Literal["critical", "high", "medium"]

class SLARule(BaseModel):
    id: str
    name: str
    description: str
    raw_nl: str
    rule_type: RuleType
    severity: Severity

class Violation(BaseModel):
    rule_id: str
    rule_name: str
    file: str
    line: int
    col: int
    code_snippet: str
    explanation: str    # English

class ScanResult(BaseModel):
    rules: List[SLARule]
    violations: List[Violation]
    pass_count: int
    fail_count: int
    deployable: bool

class PatchResult(BaseModel):
    patched_files: List[str]
    diffs: Dict[str, str]       # filepath -> unified diff
    patch_explanations: List[PatchExplanation]
    remaining_violations: List[Violation]
    deployable: bool
    ai_used: str                # "claude" / "codex" / "gemini"
```

---

## 6. Analyzers (`analyzers/`)

The analyzers operate deterministically without AI.

### `py_analyzer.py` - Python AST-based analyzer

- **NO_NETWORK:** network library imports and method calls such as `requests`, `httpx`, and `urllib`.
- **NO_EXEC:** `subprocess.run(shell=True)`, `os.system()`, and similar patterns.
- **NO_HARDCODED_SECRETS:** assignments to password, api_key, secret, or token variables, plus `sk-` and `ghp_` patterns.
- **SQL_PARAM_BINDING:** f-strings containing SQL keywords such as SELECT, INSERT, UPDATE, DELETE, or DROP.
- **NO_DEBUG_MODE:** `DEBUG=True` and `app.run(debug=True)`.
- **NO_WEAK_RANDOM:** `random.choice()` and related weak randomness in security contexts.
- **NO_BARE_EXCEPT:** `except: pass` and `except Exception: pass`.

### `js_analyzer.py` - JS/TS regex-based analyzer

- **NO_NETWORK:** `fetch(`, `axios.get/post`, and similar calls.
- **NO_EXEC:** `child_process.exec`, `execSync`, and `spawnSync`.
- **NO_HARDCODED_SECRETS:** const/let/var secret assignments, plus `ghp_` and `sk-` patterns.
- **SQL_PARAM_BINDING:** template literals containing SQL keywords.
- **NO_DEBUG_MODE:** `debug: true` and `DEBUG = true`.
- **NO_WEAK_RANDOM:** `Math.random()` in token, session, or OTP contexts.
- **NO_BARE_EXCEPT:** empty `catch(e) {}` blocks.

---

## 7. LLM patcher (`patcher/llm_patcher.py`)

SLAyer sends the file contents and the detected violation list to the AI CLI, then receives the corrected full code.

**Core principle:** the AI may fix only the violations detected by SLAyer. It must not change unrelated code.

### Syntax validation by language

| Language | Validation | On failure |
|------|------|---------|
| Python | `ast.parse()` | Restore the original file |
| JS/TS | `node --check` | Restore the original file |

### Rollback conditions

1. AI CLI exit code is not 0.
2. Python `ast.parse()` fails.
3. JS/TS changed lines exceed 20% of the original file.
4. The AI CLI times out after 60 seconds.

---

## 8. Acceptance criteria

### AC-01 - `start`: scan output

```text
Given: slayer start demo_vuln.py
Then:  print violations in the format "RULE_TYPE  file:line  snippet"
       violations > 0 -> exit 1, violations = 0 -> exit 0
```

### AC-02 - `start`: directory with no target files

```text
Given: a directory with no target files
Then:  print "No files found", exit 0
```

### AC-03 - `start`: JSON output

```text
Given: slayer start demo_vuln.py --format json
Then:  output parseable JSON containing violations[], pass_count, fail_count, and deployable
```

### AC-04 - `patch`: automatic patching

```text
Given: slayer patch demo_vuln.py in an environment with an AI CLI installed
Then:  print "Patching via {ai_name}..."
       after rescan, if violations=0 -> print "Deployment Approved" and exit 0
       if violations remain -> print the remaining list and exit 1
```

### AC-05 - `patch`: JSON output

```text
Given: slayer patch demo_vuln.py --format json
Then:  output JSON containing patched_files, diffs, remaining_violations, deployable, and ai_used
```

### AC-06 - environment without an AI CLI

```text
Given: claude, codex, and gemini are all missing
When:  slayer start runs -> AST scanning works normally
When:  slayer patch runs -> print "No AI CLI was detected" with install guidance, exit 2
```

### AC-07 - SyntaxError file handling

```text
Given: the scan includes a file with SyntaxError
Then:  print a syntax-error warning, skip that file, and keep scanning the remaining files
```

### AC-08 - benchmark pass

```text
Given: dataset/slayer-bench-v0/
Then:  every vulnerable/ case is BLOCKED
       every fixed/ case is Approved
       every false_positive/ case is Approved
```

---

## 9. Demo scenario

```bash
# Install
pip install slayer-sec

# Scan
slayer start demo_vuln.py
# NO_HARDCODED_SECRETS  demo_vuln.py:5   API_KEY = "sk-prod-..."
# NO_NETWORK            demo_vuln.py:9   requests.get(...)
# SQL_PARAM_BINDING     demo_vuln.py:13  f"SELECT * FROM ..."
# NO_EXEC               demo_vuln.py:17  subprocess.run(..., shell=True)
# Deployment BLOCKED

# Automatic patching
slayer patch demo_vuln.py
# Patching via claude...
# Deployment Approved

# CI integration
slayer patch ./src --format json | jq '.deployable'
# -> true
```

---

## 10. Distribution

```bash
pip install -e ".[dev]"     # Development install
python -m build             # Build
pip install slayer-sec      # User install
```

**Dependencies:** `pydantic`, `typer`, and `rich`. SLAyer uses no AI SDK.
