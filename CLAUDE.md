# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**SLAyer** — CMUX x AIM 해커톤 | Developer Tooling 트랙 | 2026-04-26

바이브코딩으로 생성된 Python 코드에서 **7종 보안 취약 패턴**을 AST 기반으로 탐지하고, 이미 설치된 **AI CLI(Claude Code / Codex / Gemini)** 로 자동 패치 후 배포 게이트를 여는 TUI 도구.

`pip install slayer-sec` 한 줄로 설치. API 키 설정 없음.

**Specification**: `spec.md` (상세 명세)

---

## Architecture

단일 Python 패키지. **Textual** TUI + stdout 비-TTY 시 자동 CI 모드.
AI 호출은 직접 API 대신 **로컬 AI CLI 프로세스에 위임** — `anthropic` SDK 의존성 없음.

```
slayer/
├── slayer/
│   ├── cli.py              # entry point — slayer start / patch
│   ├── tui/
│   │   ├── app.py          # Textual App — SLayerTUI
│   │   ├── screens/
│   │   │   └── scan_screen.py
│   │   └── widgets/
│   │       ├── file_panel.py       # 왼쪽: 파일 트리
│   │       ├── violation_panel.py  # 오른쪽 상단: 위반 목록
│   │       └── code_viewer.py      # 오른쪽 하단: 코드 뷰어
│   ├── models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
│   ├── ai_runner.py        # AI CLI 감지 (claude→codex→gemini) + 프롬프트 위임
│   ├── config.py           # .slayer.yml 로딩
│   ├── analyzers/
│   │   ├── ast_analyzer.py  # 결정적 AST 분석 (AI 불필요)
│   │   └── llm_analyzer.py  # CUSTOM 룰 시맨틱 분석 (AI CLI 위임)
│   └── patcher/
│       └── llm_patcher.py   # 자동 패치 (AI CLI 위임)
├── pyproject.toml
├── demo_vuln.py
└── spec.md
```

**핵심 흐름**:
1. `slayer start <path>` → AST 스캔 → TUI 실행 (터미널) / plain 텍스트 (파이프/CI)
2. TUI 안에서: 파일 선택 → 위반 목록 → 코드 위치 → `f` 키로 Fix All → 자동 재스캔
3. `slayer patch <path>` → non-interactive 스캔+패치+재스캔 → Deployment Approved

---

## TUI Layout

```
┌─ Files ──────────┬─ Violations ───────────────────────────┐
│ ▶ demo_vuln.py  4│ ✗ NO_NETWORK      demo_vuln.py:9        │
│   utils.py      0│ ✗ NO_HARDCODED    demo_vuln.py:5        │
│                  │ ✗ SQL_PARAM       demo_vuln.py:13       │
│                  │ ✗ NO_EXEC         demo_vuln.py:17       │
├──────────────────┴────────────────────────────────────────┤
│  7 │                                                       │
│  8 │  def get_user(user_id):                               │
│  9 │►     return requests.get(f"https://...")              │
│ 10 │                                                       │
├───────────────────────────────────────────────────────────┤
│  [F] Fix All   [R] Rescan   [Q] Quit   [↑↓] Navigate      │
└───────────────────────────────────────────────────────────┘
```

- `f` → "Patching via {ai_name}..." 스피너 → 파일 직접 수정 → 자동 재스캔 → violations 0이면 "🚀 Deployment Approved"
- `r` → 재스캔, `q` → 종료, `Tab` → 패널 포커스 전환

---

## Key Constraints

- 분석 대상: Python (`.py`) 파일만 (v1 scope)
- **AST 7종은 AI 없이 동작**: NO_NETWORK, NO_EXEC, NO_HARDCODED_SECRETS, SQL_PARAM_BINDING, NO_DEBUG_MODE, NO_INSECURE_HASH, NO_BARE_EXCEPT
- **AI CLI 필요 작업**: CUSTOM 룰 분석, 자동 패치
- **AI CLI 감지 순서**: `claude` → `codex` → `gemini` (설치된 첫 번째 사용)
- API 키 관리 코드 없음 — AI CLI의 기존 인증 사용
- Exit codes: `0` = all pass, `1` = violations found, `2` = error

---

## Commands

### 개발 실행

```bash
cd slayer
pip install -e ".[dev]"

# TUI 모드 (터미널에서 직접)
slayer start demo_vuln.py

# CI 모드 (자동 감지: stdout이 TTY 아닐 때)
slayer start ./src | cat

# JSON 출력
slayer start ./src --format json

# 자동 패치 (non-interactive)
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
# → TUI, 위반 목록 표시

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
ScanResult  { rules[], violations[], pass_count, fail_count, deployable }
PatchResult { patched_files[], diffs{}, remaining_violations[], deployable, ai_used }
```

`rule_type`: `NO_NETWORK | NO_EXEC | NO_HARDCODED_SECRETS | SQL_PARAM_BINDING | NO_DEBUG_MODE | NO_INSECURE_HASH | NO_BARE_EXCEPT | CUSTOM`

---

## Vibe Coding Ruleset (7종)

`slayer/analyzers/ast_analyzer.py` — AI 없이 결정적 탐지:

| V# | 룰 | 탐지 대상 | Severity |
|----|-----|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | 정규식 6종: API 키·패스워드·토큰 리터럴 | critical |
| V-02 | NO_NETWORK | 네트워크 라이브러리 임포트 + 메서드 호출 | critical |
| V-03 | NO_EXEC | 쉘 실행 함수 + `shell=True` 패턴 | critical |
| V-04 | SQL_PARAM_BINDING | f-string/%-format/.format() + SQL 키워드 | high |
| V-05 | NO_DEBUG_MODE | `DEBUG=True` / `app.run(debug=True)` | high |
| V-06 | NO_INSECURE_HASH | `hashlib.md5/sha1` + 패스워드 컨텍스트 | high |
| V-07 | NO_BARE_EXCEPT | `except: pass` / `except Exception: pass` | medium |

패치 전략 — 실제 동작하는 코드로 교체:
- NO_EXEC `shell=True` → `shell=False` + 인수 리스트
- NO_DEBUG_MODE → `os.environ.get("DEBUG", "false").lower() == "true"`
- NO_INSECURE_HASH → `hashlib.pbkdf2_hmac("sha256", ...)`
- NO_BARE_EXCEPT → `except Exception as e: logger.warning(...)`
