# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**SLAyer** — CMUX x AIM 해커톤 | Developer Tooling 트랙 | 2026-04-26

Claude/GPT/Cursor로 생성된 Python 코드에서 **반복적으로 나타나는 바이브코딩 취약 패턴 7종**을 데이터 기반으로 탐지하고, Claude API로 실제 동작하는 안전한 코드로 자동 패치 후 배포 게이트를 여는 **TUI 도구**.

`pip install slayer-sec` 한 줄로 설치. 인터랙티브 TUI 또는 CI/CD 파이프라인 논인터랙티브 모드 모두 지원.

**Specification**: `spec.md` (상세 명세)

---

## Architecture

단일 Python 패키지. **Textual** 기반 TUI + `--ci` 플래그로 non-interactive 출력 전환.

```
slayer/
├── slayer/
│   ├── cli.py              # entry point — slayer scan / init 커맨드
│   ├── tui/
│   │   ├── app.py          # Textual App — SLayerTUI
│   │   ├── screens/
│   │   │   └── scan_screen.py   # 메인 스캔 화면
│   │   └── widgets/
│   │       ├── file_panel.py    # 왼쪽: 파일 트리
│   │       ├── violation_panel.py  # 오른쪽 상단: 위반 목록
│   │       └── code_viewer.py   # 오른쪽 하단: 코드 뷰어
│   ├── models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
│   ├── config.py           # .slayer.yml 로딩 / ANTHROPIC_API_KEY 관리
│   ├── analyzers/
│   │   ├── ast_analyzer.py  # 결정적 AST 분석 (Claude 불필요)
│   │   └── llm_analyzer.py  # CUSTOM 룰 시맨틱 분석 (Claude)
│   └── patcher/
│       └── llm_patcher.py   # 자동 패치 (claude-sonnet-4-6)
├── pyproject.toml
├── demo_vuln.py
└── spec.md
```

**핵심 흐름**:
1. `slayer scan <path> --rules "..."` → TUI 실행 (터미널 감지 시) / `--ci` 플래그 시 plain 출력
2. TUI 안에서: 파일 선택 → 위반 목록 → 코드 위치 → `f` 키로 Fix → 재스캔
3. `slayer init` → `.slayer.yml` 생성

---

## TUI Layout

```
┌─ Files ──────────┬─ Violations ───────────────────────────┐
│ ▶ demo_vuln.py  3│ ✗ NO_NETWORK      demo_vuln.py:9        │
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

**패널 동작**:
- **Files panel** (왼쪽): 스캔 대상 `.py` 목록 + 파일별 위반 수 배지. Enter로 선택.
- **Violations panel** (오른쪽 상단): 선택된 파일의 위반 목록. 화살표로 선택 시 코드 뷰어 이동.
- **Code viewer** (오른쪽 하단): 선택된 위반의 코드 컨텍스트 ±3줄, 위반 라인 하이라이트.
- **Keybindings bar**: `f`=Fix All, `r`=Rescan, `q`=Quit, `j/k` or `↑/↓`=navigate, `tab`=패널 포커스 전환.

**Fix 플로우**: `f` 누르면 → "Patching via claude-sonnet-4-6..." 스피너 → 파일 직접 수정 → 자동 재스캔 → violations 0이면 "🚀 Deployment Approved" 배너 표시.

---

## Key Constraints

- 분석 대상: Python (`.py`) 파일만 (v1 scope)
- AST 룰 5종은 Claude 없이 동작: `NO_NETWORK`, `NO_EXEC`, `NO_HARDCODED_SECRETS`, `SQL_PARAM_BINDING`, `NO_EVAL`
- Claude 필요 작업: SLA 파싱, CUSTOM 룰 분석, 자동 패치
- `ANTHROPIC_API_KEY`는 OS 환경변수 또는 `.slayer.yml` — 코드에 절대 하드코딩 금지
- TUI 모드: 터미널에서 직접 실행 시 기본값
- CI 모드 (`--ci` 또는 stdout이 TTY가 아닐 때): plain 텍스트 / JSON 출력, exit code 0/1/2
- Exit codes: `0` = all pass, `1` = violations found, `2` = error

---

## Commands

### 개발 실행

```bash
cd slayer
pip install -e ".[dev]"

# TUI 모드 (기본)
slayer scan demo_vuln.py --rules "외부 네트워크 호출 없음\nshell 실행 없음"

# CI 모드 (non-interactive)
slayer scan ./src --rules-file .slayer.yml --ci

# JSON 출력
slayer scan ./src --format json --ci

# 설정 초기화
slayer init
```

### 빌드 / 배포

```bash
pip install build
python -m build

pip install dist/slayer_sec-*.whl
pipx install slayer-sec
```

### 테스트

```bash
pytest tests/ -v

# 데모 시나리오
slayer scan demo_vuln.py --rules "외부 네트워크 호출 없음\nshell 실행 없음\n하드코딩 credential 없음\nSQL 파라미터 바인딩"
# → TUI 열림, 4 violations 표시

# CI 데모
slayer scan demo_vuln.py --rules "..." --ci
# → plain 텍스트, exit 1
```

---

## Data Models

`slayer/models.py`:

```
SLARule     { id, name, description, raw_nl, rule_type, severity }
Violation   { rule_id, file, line, col, code_snippet, explanation }
ScanResult  { rules[], violations[], pass_count, fail_count, deployable }
PatchResult { patched_files[], diff, remaining_violations, deployable }
```

`rule_type` 값: `NO_NETWORK | NO_EXEC | NO_HARDCODED_SECRETS | SQL_PARAM_BINDING | NO_EVAL | CUSTOM`

---

## Vibe Coding Ruleset (7종)

`slayer/analyzers/ast_analyzer.py` — Claude 없이 결정적 탐지:

| V# | 룰 | 탐지 대상 | Severity |
|----|-----|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | 정규식 6종 라인 스캔 (API 키·패스워드·토큰 리터럴) | critical |
| V-02 | NO_NETWORK | 네트워크 라이브러리 8종 임포트 + 메서드 호출 | critical |
| V-03 | NO_EXEC | 쉘 실행 함수 8종 + `shell=True` 패턴 | critical |
| V-04 | SQL_PARAM_BINDING | f-string/%-format/.format() + SQL 키워드 조합 | high |
| V-05 | NO_DEBUG_MODE | `DEBUG=True` / `debug=True` / `app.run(debug=True)` | high |
| V-06 | NO_INSECURE_HASH | `hashlib.md5/sha1` + 패스워드 컨텍스트 | high |
| V-07 | NO_BARE_EXCEPT | `except: pass` / `except Exception: pass` | medium |

**패치 전략**: 단순 `raise NotImplementedError` 대신 실제 동작하는 안전한 코드로 교체.
- NO_EXEC `shell=True` → `shell=False` + 인수 리스트 변환
- NO_DEBUG_MODE → `os.environ.get("DEBUG", "false").lower() == "true"`
- NO_INSECURE_HASH → `hashlib.pbkdf2_hmac("sha256", ...)`
- NO_BARE_EXCEPT → `except Exception as e: logger.warning(...)`

---

## Acceptance Criteria

`spec.md` AC-01~AC-12 참조. TUI 컨텍스트 기준:

- AC-01: `slayer scan <path>` → `.py` 파일 자동 수집 후 TUI 실행
- AC-02: `.py` 없으면 warning + exit 0
- AC-03: SLA 파싱 5초 이내 (TUI 스피너 표시)
- AC-04: `--rules` 미입력 시 `.slayer.yml` fallback, 없으면 기본 4개 룰
- AC-05: 스캔 결과 3초 이내 TUI 렌더링 (1000줄 이하)
- AC-06: 룰별 위반 + file:line + 한국어 explanation + 코드 컨텍스트 뷰어
- AC-07: violations 있으면 exit 1 (`--ci` 모드)
- AC-08: `f` 키 → 패치 → 자동 재스캔 → TUI 업데이트
- AC-09: 패치 후 전체 통과 → "Deployment Approved" 배너 → exit 0
- AC-10: `--format json --ci` → JSON stdout (CI/CD 통합)
- AC-11: `ANTHROPIC_API_KEY` 없으면 TUI에 인라인 에러 + 설정 방법 안내
- AC-12: SyntaxError 파일 → warning badge 표시 후 나머지 계속

데모 입력 파일: `demo_vuln.py` (requests 호출, subprocess shell=True, 하드코딩 credential, f-string SQL 포함)
