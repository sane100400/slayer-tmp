# SLAyer

> **바이브코딩 웹서비스 전문 보안 스캐너**  
> CMUX × AIM 해커톤 2026 · Developer Tooling 트랙

바이브코딩(Claude / GPT / Cursor)으로 생성된 **웹서비스 코드(Python · JS · TS)** 에서  
7가지 보안 취약 패턴을 탐지하고, 이미 설치된 AI CLI로 자동 패치 후 배포 게이트를 여는 도구.

```bash
pip install slayer-sec

slayer start .    # 스캔 → 위반 목록 출력
slayer patch .    # 스캔 → 자동 패치 → 🚀 Deployment Approved
```

**API 키 없음. 설정 없음.** Claude Code / Codex / Gemini가 이미 설치되어 있으면 바로 패치.

---

## Why SLAyer?

bandit, semgrep 같은 기존 도구는 일반 보안 규칙을 쓴다.  
SLAyer는 **AI 생성 코드의 반복 취약 패턴**을 데이터 기반으로 탐지한다.

| 원인 | 패턴 |
|------|------|
| "일단 동작하게" 프롬프트 | 하드코딩 크레덴셜, 외부 호출, `shell=True` |
| 오래된 튜토리얼 학습 데이터 | f-string SQL, `Math.random()` 토큰 생성 |
| 개발 예제 그대로 배포 | `DEBUG=True`, `debug: true` |
| "에러 없애줘" 프롬프트 | `except: pass`, 빈 `catch {}` |

---

## 지원 언어

Python (`.py`) · JavaScript (`.js`, `.jsx`) · TypeScript (`.ts`, `.tsx`)

---

## 사용법

### slayer start — 스캔

```bash
slayer start .                   # 현재 디렉토리 전체 스캔
slayer start demo_vuln.py        # 특정 파일 스캔
slayer start . --format json     # JSON 출력 (CI/CD 통합)
```

출력 예시:
```
  ✗  NO_HARDCODED_SECRETS  demo_vuln.py:5   API_KEY = "sk-prod-..."
  ✗  NO_NETWORK            demo_vuln.py:9   requests.get(f"https://...")
  ✗  SQL_PARAM_BINDING     demo_vuln.py:13  f"SELECT * FROM users WHERE name='{query}'"
  ✗  NO_EXEC               demo_vuln.py:17  subprocess.run(..., shell=True)

  4 violations · 🔒 Deployment BLOCKED
```

### slayer patch — 자동 패치

```bash
slayer patch demo_vuln.py        # 스캔 → 패치 → 재스캔
slayer patch . --format json     # JSON 결과 출력
```

출력 예시:
```
  Patching via claude...

  ✓  demo_vuln.py patched (4 violations fixed)

  🚀 Deployment Approved
```

---

## slayer model — AI CLI 설정

```bash
slayer model              # 감지 상태 + 현재 설정 확인
slayer model claude       # claude 사용으로 .slayer.yml에 저장
slayer model codex        # codex 사용으로 저장
slayer model auto         # 자동 감지로 초기화
```

출력 예시:
```
  AI CLI Status
  ─────────────────────────────────
  ✓  claude
  ✓  codex
  ✗  gemini

  Saved preference : claude  (from .slayer.yml)
  Active AI CLI    : claude
```

설정된 AI는 `slayer patch`에서 자동으로 사용된다.

AI CLI가 없으면 `slayer start` 스캔은 정상 동작하고, `slayer patch` 실행 시 설치 안내를 출력한다.

---

## Exit Codes

| 코드 | 의미 |
|------|------|
| `0` | 위반 없음 — Deployment Approved |
| `1` | 위반 존재 — Deployment BLOCKED |
| `2` | 실행 오류 |

---

## CI/CD 통합

```bash
# 파이프 시 자동으로 plain 텍스트 출력 (TTY 감지)
slayer start . | cat

# JSON으로 deployable 체크
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

## 설치

```bash
# 개발 설치
pip install -e ".[dev]"

# PyPI
pip install slayer-sec
```

의존성: `pydantic` · `typer` · `rich` — AI SDK 없음, API 키 불필요.

---

## 아키텍처

```
slayer/
├── cli.py              # slayer start / patch
├── analyzers/
│   ├── py_analyzer.py  # Python AST 기반 탐지 (AI 불필요)
│   └── js_analyzer.py  # JS/TS regex 기반 탐지 (AI 불필요)
├── ai_runner.py        # AI CLI 감지 (claude→codex→gemini) + 위임
├── patcher/
│   └── llm_patcher.py  # SLAyer-scoped 자동 패치
└── models.py           # Pydantic 데이터 모델
```

탐지는 AI 없이 결정적으로 동작. AI CLI는 패치에만 사용.

---

## 관련 파일

- [`spec.md`](./spec.md) — 상세 개발 명세서
- [`demo_vuln.py`](./demo_vuln.py) — Python 취약 패턴 데모
- [`demo_vuln.js`](./demo_vuln.js) — JS 취약 패턴 데모

---

*CMUX × AIM 해커톤 2026 · Developer Tooling 트랙*
