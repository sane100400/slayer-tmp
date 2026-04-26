# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**SLAyer** — CMUX x AIM 해커톤 | Developer Tooling 트랙 | 2026-04-26

바이브코딩으로 생성된 **웹서비스 코드(Python · JS · TS)** 에서 **7종 보안 취약 패턴**을 탐지하고, 이미 설치된 **AI CLI(Claude Code / Codex / Gemini)** 로 자동 패치 후 배포 게이트를 여는 CLI 도구.

`pip install slayer-sec` 한 줄로 설치. API 키 설정 없음. TUI 없음 — 순수 CLI.

**Specification**: `spec.md` (상세 명세)

---

## Architecture

단일 Python 패키지. plain 텍스트 CLI 출력.
AI 호출은 직접 API 대신 **로컬 AI CLI 프로세스에 위임** — `anthropic` SDK 의존성 없음.

```
slayer/
├── slayer/
│   ├── cli.py              # entry point — slayer start / patch / model
│   ├── models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
│   ├── ai_runner.py        # AI CLI 감지 (claude→codex→gemini) + 프롬프트 위임
│   ├── scanner.py          # 파일 수집 + 분석기 디스패치
│   ├── reporter.py         # text/json 출력 렌더링
│   ├── rules.py            # DEFAULT_RULES_BY_ID
│   ├── analyzers/
│   │   ├── py_analyzer.py   # Python AST 분석 (AI 불필요)
│   │   └── js_analyzer.py   # JS/TS regex 분석 (AI 불필요)
│   └── patcher/
│       └── llm_patcher.py   # 자동 패치 (AI CLI 위임, 언어 자동 감지)
├── pyproject.toml
├── demo_vuln.py             # Python 데모
├── demo_vuln.js             # JS 데모
└── spec.md
```

**핵심 흐름**:
1. `slayer start <path>` → AST/regex 스캔 → 위반 목록 plain 텍스트 출력
2. `slayer patch <path>` → 스캔 → AI CLI 패치 → 재스캔 → Deployment Approved
3. `slayer model [name]` → AI CLI 상태 확인 / .slayer.yml에 선호 AI 저장

---

## Key Constraints

- 분석 대상: 웹서비스 코드 — `.py` · `.js` · `.jsx` · `.ts` · `.tsx`
- **탐지 7종은 AI 없이 동작**: Python=AST 기반, JS/TS=regex 기반
- **AI CLI 필요 작업**: 자동 패치만
- **AI CLI 감지 순서**: `claude` → `codex` → `gemini` (설치된 첫 번째 사용)
- **AI 선택**: `slayer model claude/codex/gemini` → `.slayer.yml`에 저장, patch 시 자동 적용
- API 키 관리 코드 없음 — AI CLI의 기존 인증 사용
- TUI 없음 — textual 의존성 없음
- Exit codes: `0` = all pass, `1` = violations found, `2` = error

---

## Commands

### 개발 실행

```bash
cd slayer
pip install -e ".[dev]"

# 스캔
slayer start demo_vuln.py

# JSON 출력
slayer start demo_vuln.py --format json

# AI CLI 설정
slayer model claude

# 자동 패치
slayer patch demo_vuln.py
```

### 빌드 / 배포

```bash
pip install build
python -m build
pip install dist/slayer_sec-*.whl
```

### 테스트

```bash
pytest tests/ -v

# 데모: 7개 위반 탐지
slayer start demo_vuln.py

# 데모: 자동 패치
slayer patch demo_vuln.py
# → Patching via claude... → 🚀 Deployment Approved
```

---

## Data Models

`slayer/models.py`:

```
SLARule     { id, name, description, raw_nl, rule_type, severity }
Violation   { rule_id, rule_name, file, line, col, code_snippet, explanation }
ScanResult  { rules[], violations[], pass_count, fail_count, deployable, scanned_files[], syntax_errors[] }
PatchResult { patched_files[], diffs{}, remaining_violations[], deployable, ai_used }
```

`rule_type`: `NO_NETWORK | NO_EXEC | NO_HARDCODED_SECRETS | SQL_PARAM_BINDING | NO_DEBUG_MODE | NO_WEAK_RANDOM | NO_BARE_EXCEPT | CUSTOM`

---

## Vibe Coding Ruleset (7종)

`slayer/analyzers/py_analyzer.py` + `js_analyzer.py` — AI 없이 결정적 탐지:

| V# | 룰 | 탐지 대상 | Severity |
|----|-----|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | API 키·패스워드·토큰 리터럴 | critical |
| V-02 | NO_NETWORK | 네트워크 라이브러리 임포트 + 메서드 호출 | critical |
| V-03 | NO_EXEC | 쉘 실행 함수 + `shell=True` 패턴 | critical |
| V-04 | SQL_PARAM_BINDING | f-string/템플릿 리터럴 + SQL 키워드 | high |
| V-05 | NO_DEBUG_MODE | `DEBUG=True` / `debug:true` | high |
| V-06 | NO_WEAK_RANDOM | `random.choice()` / `Math.random()` in security context | high |
| V-07 | NO_BARE_EXCEPT | `except: pass` / 빈 `catch {}` | medium |

패치 전략 (AI CLI, 언어 자동 감지):
- NO_EXEC: Python → `shell=False` + 리스트, JS → `execFile("cmd", [arg])`
- NO_DEBUG_MODE: Python → `os.environ.get("DEBUG","false")`, JS → `process.env.NODE_ENV`
- NO_WEAK_RANDOM: Python → `secrets.token_hex()`, JS → `crypto.randomUUID()`
- NO_BARE_EXCEPT: Python → `except Exception as e: logger.warning(e)`, JS → `catch(e){console.error(e)}`
