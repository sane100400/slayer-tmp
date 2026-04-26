# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**SLAyer** - CMUX x AIM Hackathon | Developer Tooling track | 2026-04-26

SLAyer is a CLI tool that detects **seven security vulnerability patterns** in
**vibe-coded web-service code (Python, JS, and TS)**, patches them through an already
installed **AI CLI (Claude Code, Codex CLI, or Gemini CLI)**, and opens the deployment gate.

Install with one command: `pip install slayer-sec`. No API-key setup. No TUI - only a
plain CLI.

**Specification:** `spec.md` (detailed requirements)

---

## Architecture

SLAyer is a single Python package with plain-text CLI output. AI calls are delegated to a
**local AI CLI process** instead of a direct API; there is no `anthropic` SDK dependency.

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

**Core flow:**

1. `slayer start <path>` -> AST/regex scan -> print violation list as plain text.
2. `slayer patch <path>` -> scan -> AI CLI patch -> rescan -> Deployment Approved.
3. `slayer model [name]` -> inspect AI CLI status or save the preferred AI to `.slayer.yml`.

---

## Key constraints

- Analysis targets: web-service code with `.py`, `.js`, `.jsx`, `.ts`, or `.tsx` extensions.
- The seven detection rules must work **without AI**: Python uses AST detection, JS/TS uses regex detection.
- Automatic patching is the only feature that requires an AI CLI.
- AI CLI detection order: `claude` -> `codex` -> `gemini` (use the first installed CLI).
- AI selection: `slayer model claude/codex/gemini` saves the choice in `.slayer.yml`; `patch` uses it automatically.
- Do not add API-key management code; use the existing authentication from the AI CLI.
- Do not add a TUI or a `textual` dependency.
- Exit codes: `0` = all pass, `1` = violations found, `2` = error.

---

## Commands

### Development run

```bash
cd slayer
pip install -e ".[dev]"

# Scan
slayer start demo_vuln.py

# JSON output
slayer start demo_vuln.py --format json

# Configure the AI CLI
slayer model claude

# Automatic patching
slayer patch demo_vuln.py
```

### Build and distribution

```bash
pip install build
python -m build
pip install dist/slayer_sec-*.whl
```

### Tests

```bash
pytest tests/ -v

# Demo: detect seven violations
slayer start demo_vuln.py

# Demo: automatic patching
slayer patch demo_vuln.py
# -> Patching via claude... -> Deployment Approved
```

---

## Data models

`slayer/models.py`:

```text
SLARule     { id, name, description, raw_nl, rule_type, severity }
Violation   { rule_id, rule_name, file, line, col, code_snippet, explanation }
ScanResult  { rules[], violations[], pass_count, fail_count, deployable, scanned_files[], syntax_errors[] }
PatchResult { patched_files[], diffs{}, patch_explanations[], remaining_violations[], deployable, ai_used }
```

`rule_type`: `NO_NETWORK | NO_EXEC | NO_HARDCODED_SECRETS | SQL_PARAM_BINDING | NO_DEBUG_MODE | NO_WEAK_RANDOM | NO_BARE_EXCEPT | CUSTOM`

---

## Vibe coding ruleset (seven classes)

`slayer/analyzers/py_analyzer.py` and `js_analyzer.py` provide deterministic detection without AI:

| V# | Rule | Detection target | Severity |
|----|-----|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | API keys, passwords, and token literals | critical |
| V-02 | NO_NETWORK | Network imports or network calls with unsafe targets | critical |
| V-03 | NO_EXEC | Shell execution functions and `shell=True` patterns | critical |
| V-04 | SQL_PARAM_BINDING | f-strings or template literals with SQL keywords | high |
| V-05 | NO_DEBUG_MODE | `DEBUG=True` or `debug: true` | high |
| V-06 | NO_WEAK_RANDOM | `random.choice()` or `Math.random()` in security contexts | high |
| V-07 | NO_BARE_EXCEPT | `except: pass` or empty `catch {}` blocks | medium |

Patch strategy (AI CLI, language detected automatically):

- NO_EXEC: Python -> `shell=False` with list arguments; JS -> `execFile("cmd", [arg])`.
- NO_DEBUG_MODE: Python -> `os.environ.get("DEBUG", "false")`; JS -> `process.env.NODE_ENV`.
- NO_WEAK_RANDOM: Python -> `secrets.token_hex()`; JS -> `crypto.randomUUID()`.
- NO_BARE_EXCEPT: Python -> `except Exception as e: logger.warning(e)`; JS -> `catch(e){ console.error(e) }`.
