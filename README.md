# SL/yer

> **바이브코딩 취약 패턴 전문 보안 집행관**  
> CMUX × AIM 해커톤 2026 · Developer Tooling 트랙

Claude/GPT/Cursor로 생성된 Python 코드에서 **반복적으로 나타나는 바이브코딩 취약 패턴 7종**을 데이터 기반으로 탐지하고, Claude API로 실제 동작하는 안전한 코드로 자동 패치 후 배포 게이트를 여는 인터랙티브 TUI 도구.

```bash
pip install slayer-sec
slayer scan ./src --rules "외부 네트워크 호출 없음"
# → Textual TUI 실행 — 파일 / 위반 / 코드 3패널
# f 키 → 자동 패치 → 🚀 Deployment Approved
```

---

## Why SLAyer?

bandit, semgrep 같은 기존 도구는 **일반 보안 규칙**을 쓴다.  
SLAyer는 다르다. **AI 생성 코드의 반복 취약 패턴을 연구해서 만든 룰셋**을 사용한다.

| 원인 | 패턴 |
|------|------|
| "일단 동작하게" 프롬프트 | 하드코딩 크레덴셜, 외부 호출, `shell=True` |
| 오래된 튜토리얼 학습 데이터 | `hashlib.md5()` 패스워드 해싱, f-string SQL |
| 개발 예제 그대로 배포 | `DEBUG=True` |
| "에러 없애줘" 프롬프트 | `except: pass` |

---

## Vibe Coding Ruleset (7종)

| V# | Rule | 탐지 | Severity | 패치 전략 |
|----|------|------|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | API 키·패스워드 리터럴 | critical | `os.environ.get()` |
| V-02 | NO_NETWORK | 네트워크 라이브러리 + 메서드 호출 | critical | `raise NotImplementedError` |
| V-03 | NO_EXEC | 쉘 실행 함수 + `shell=True` | critical | `shell=False` + 인수 리스트 |
| V-04 | SQL_PARAM_BINDING | f-string/포맷 + SQL 키워드 | high | 파라미터 바인딩 `(?, val)` |
| V-05 | NO_DEBUG_MODE | `DEBUG=True`, `app.run(debug=True)` | high | `os.environ.get("DEBUG","false")` |
| V-06 | NO_INSECURE_HASH | `hashlib.md5/sha1` + 패스워드 컨텍스트 | high | `pbkdf2_hmac("sha256", ...)` |
| V-07 | NO_BARE_EXCEPT | `except: pass` | medium | `except Exception as e: logger.warning(e)` |

V-01~V-04는 Claude 없이 AST 기반으로 결정적 탐지. V-05~V-07도 AST로 탐지.

---

## 설치

```bash
# 개발 설치
cd slayer
pip install -e ".[dev]"

# PyPI (출시 후)
pip install slayer-sec
pipx install slayer-sec
```

---

## 사용법

### TUI 모드 (기본)

```bash
slayer scan demo_vuln.py --rules "외부 네트워크 호출 없음\n하드코딩 credential 없음"
```

```
┌─ Files ──────────┬─ Violations ───────────────────────────┐
│ ▶ demo_vuln.py  7│ ✗ NO_HARDCODED    demo_vuln.py:7        │
│                  │ ✗ NO_DEBUG_MODE   demo_vuln.py:11       │
│                  │ ✗ NO_NETWORK      demo_vuln.py:14       │
│                  │ ✗ SQL_PARAM       demo_vuln.py:20       │
│                  │ ✗ NO_EXEC         demo_vuln.py:26       │
│                  │ ✗ NO_INSECURE_HASH demo_vuln.py:31      │
│                  │ ✗ NO_BARE_EXCEPT  demo_vuln.py:37       │
├──────────────────┴────────────────────────────────────────┤
│ 14 │►     return requests.get(f"https://...")              │
├───────────────────────────────────────────────────────────┤
│  [F] Fix All   [R] Rescan   [Q] Quit   [↑↓] Navigate      │
└───────────────────────────────────────────────────────────┘
```

키바인딩: `f` Fix All · `r` Rescan · `q` Quit · `↑↓`/`j/k` 탐색 · `Tab` 패널 전환

### CI 모드

```bash
# plain 텍스트
slayer scan ./src --rules-file .slayer.yml --ci

# JSON (파이프라인 통합)
slayer scan ./src --format json --ci | jq '.deployable'

# JUnit (CI 리포트)
slayer scan ./src --format junit --ci
```

### 설정 초기화

```bash
slayer init
# .slayer.yml 생성
```

---

## CLI 옵션

```
slayer scan <path> [OPTIONS]

  --rules TEXT              자연어 SLA 규칙
  --rules-file PATH         .slayer.yml 경로
  --ci                      TUI 없이 plain 출력
  --format [text|json|junit]
  --no-color
  --api-key TEXT            ANTHROPIC_API_KEY

Exit codes: 0=pass  1=violations  2=error
```

---

## 아키텍처

```
slayer/
├── slayer/
│   ├── cli.py
│   ├── tui/
│   │   ├── app.py                  # Textual App
│   │   ├── screens/scan_screen.py
│   │   └── widgets/
│   │       ├── file_panel.py       # ListView
│   │       ├── violation_panel.py  # DataTable
│   │       └── code_viewer.py      # TextArea (read-only)
│   ├── models.py                   # SLARule, Violation, ScanResult, PatchResult
│   ├── config.py
│   ├── analyzers/
│   │   ├── sla_parser.py           # 자연어 → SLARule[] (Claude API)
│   │   ├── ast_analyzer.py         # Vibe Ruleset 7종 결정적 탐지
│   │   └── llm_analyzer.py         # CUSTOM 룰 시맨틱 분석
│   └── patcher/
│       └── llm_patcher.py          # 기능 보존 자동 패치
├── pyproject.toml
└── demo_vuln.py                    # 바이브코딩 패턴 7종 데모 파일
```

의존성: `textual>=0.47` · `anthropic>=0.23` · `pydantic>=2.0` · `typer>=0.9` · `rich>=13.0`

---

## pre-commit 통합

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: slayer
        name: SLAyer Vibe Security Check
        entry: slayer scan
        args: [--rules-file, .slayer.yml, --ci]
        language: python
        types: [python]
```

---

## 관련 파일

- [`spec.md`](./spec.md) — 상세 개발 명세서 (TUI Edition v4)
- [`branding.html`](./branding.html) — 브랜딩 / 발표 자료
- [`demo_vuln.py`](./demo_vuln.py) — 바이브코딩 패턴 7종 데모 파일

---

*CMUX × AIM 해커톤 2026 · Developer Tooling 트랙*
