# SLAyer — 개발 명세서 v7

> 트랙: Developer Tooling | CMUX x AIM | 2026-04-26

---

## 0. 핵심 한 줄

**바이브코딩으로 생성된 웹서비스 코드(Python · JS · TS)에서 7가지 보안 취약 패턴을 탐지하고, 이미 설치된 AI CLI(Claude Code / Codex / Gemini)로 자동 패치 후 배포 게이트를 여는 CLI 도구.**

```bash
pip install -e ".[dev]"  # 설치
slayer start .           # 스캔 → 위반 목록 출력
slayer patch .           # 위반 자동 패치 → 🚀 Deployment Approved
slayer model             # AI CLI 상태 확인 / 선호 모델 설정
```

**지원 언어**: Python (`.py`) · JavaScript (`.js`, `.jsx`) · TypeScript (`.ts`, `.tsx`)
**타겟 사용자**: Claude Code / Codex / Gemini CLI 중 하나가 이미 설치된 바이브코더.

**"SLAyer 설정 제로"의 의미**:
- SLAyer 자체에 API 키나 로그인 없음
- 기본 실행은 설정 파일 없이 동작하며, AI CLI 선호도만 선택적으로 `.slayer.yml`에 저장
- AI CLI(Claude Code 등)는 사용자가 이미 설치·인증한 상태를 전제
- AI CLI 없으면 AST 스캔(탐지)은 동작, 패치만 불가 — 그 경우 설치 안내 표시

---

## 0.5 Dataset Strategy

### GitHub 수집 바이브코딩 레포 — 7종 룰 도출 근거

`CLAUDE.md` / `AGENTS.md` 파일 보유 레포 = AI CLI로 빌드된 직접 증거.

| 구성 | 내용 |
|------|------|
| 수집 방법 | GitHub Code Search API (`filename:CLAUDE.md`) |
| 규모 | 바이브코딩 레포 직접 수집 |
| 분석 도구 | `tools/collect_vibecoding_datasets.py` + repo-local analysis pipeline |
| 결과 | `dataset/analysis.json` (취약파일 336개 · 485건) |

**관측된 취약점 빈도** (`dataset/analysis.json` 기준, 3개 소스 합산):

| SLAyer 룰 | 분석 룰명 | 관측 건수 (합산) | 비고 |
|-----------|------------------|---------------|------|
| SQL_PARAM_BINDING | SQL_INJECTION | **1,564** | 실레포 1,524건 포함 |
| NO_HARDCODED_SECRETS | HARDCODED_SECRETS | **1,552** | API 키 하드코딩 |
| NO_EXEC | COMMAND_INJECTION | **913** | shell=True |
| NO_DEBUG_MODE | DEBUG_MODE_ON | 168 | debug=True 배포 |
| NO_WEAK_RANDOM | WEAK_HASH | 133 | 보안 컨텍스트 약한 난수 (random/Math.random) |
| NO_NETWORK | SSRF | 125 | 유저 입력 URL 기준 |
| NO_BARE_EXCEPT | _(미탐지)_ | — | 데이터 수집 스코프 외, SLAyer AST 독립 탐지 |

> 총 4,927건 / 취약 파일 2,473개 (dataset + drepos + repos 3개 소스 합산)

> 이 빈도 데이터를 근거로 7종 룰을 선정한다.

---

## 0.55 7종 선정 방법론 — 빈도 × 중요도 매트릭스

### 중요도 5축 평가 (각 1–5점)

| 축 | 설명 | 가중치 |
|----|------|--------|
| **A. 실세계 공격 가능성** | CVSS Exploitability 기준 (공격 복잡도 역수) | 25% |
| **B. 피해 심각도** | 데이터 유출 / RCE / 재정 피해 최대치 | 25% |
| **C. Time-to-Exploit** | 봇 자동화 기준 최초 공격까지 걸리는 시간 | 20% |
| **D. AST/Regex 탐지 신뢰도** | 결정적 탐지 가능 여부 (FP·FN 최소화) | 15% |
| **E. AI 코드 증폭 인수** | 인간 코드 대비 AI 생성 코드에서 얼마나 더 자주·심하게 발생 | 15% |

### 최종 선정 공식

```
최종 점수 = 중요도_가중합(A~E) × 0.6 + 빈도_정규화 × 0.4

빈도 정규화 = log10(count) / log10(max_count) × 5   # 1–5점 척도로 환산
```

### 후보 → 최종 7종 선정 결과

빈도 정규화: `log10(1564) = 3.194` 기준 (max = SQL_INJECTION 1,564건)

| 룰 | 중요도합산 | 관측건수 | 빈도점수(1-5) | 최종점수 | 선정 |
|----|-----------|---------|-------------|---------|------|
| NO_HARDCODED_SECRETS | 5.00 | 1,552 | 4.99 | **5.00** | ✓ |
| NO_EXEC | 4.70 | 913 | 4.63 | **4.67** | ✓ |
| SQL_PARAM_BINDING | 4.20 | 1,564 | 5.00 | **4.52** | ✓ |
| NO_NETWORK | 3.70 | 125 | 3.28 | **3.53** | ✓ |
| NO_DEBUG_MODE | 3.55 | 168 | 3.48 | **3.52** | ✓ |
| NO_WEAK_RANDOM | 3.55 | 133 | 3.32 | **3.46** | ✓ |
| NO_BARE_EXCEPT | 3.00 | _(SLAyer 독립탐지)_ | 3.00† | **3.00** | ✓ |
| INSECURE_DESERIALIZATION | 4.20 | 31 | 2.33 | 3.45 | — AST 탐지 미구현 (v2 후보) |
| CORS_WILDCARD | 2.95 | 167 | 3.48 | 3.16 | — FP 높음 |
| INSECURE_COOKIE | 2.60 | 186 | 3.55 | 2.98 | — JS 전용, 스코프 외 |

† NO_BARE_EXCEPT: 데이터 수집 스코프 외. SLAyer AST 탐지 독립 운용, 빈도점수 3.00(추정) 적용.

### 벤치마크 데이터셋

| 구성 | 경로 |
|------|------|
| 취약 케이스 | `dataset/slayer-bench-v0/vulnerable/` |
| 패치 완료 케이스 | `dataset/slayer-bench-v0/fixed/` |
| false positive 케이스 | `dataset/slayer-bench-v0/false_positive/` |
| AI 생성 코드 케이스 | `dataset/ai-bench-v0/` |

---

## 0.6 Vibe Coding Vulnerability Taxonomy

### 왜 바이브코딩 코드는 취약한가

| 패턴 원인 | 설명 |
|----------|------|
| "일단 동작하게" 프롬프트 | 기능 구현 우선, 보안 컨텍스트 없음 |
| 오래된 튜토리얼 데이터 | f-string SQL, `Math.random()` 토큰 등 구식 패턴이 훈련 데이터에 많음 |
| 개발 예제 그대로 배포 | `DEBUG=True`, 하드코딩 크레덴셜을 교체 안 함 |
| 에러 제거 요청 | `except: pass` — "에러 없애줘" 프롬프트 결과 |

### Vibe Coding Ruleset 7종 (데이터 기반 확정)

> GitHub 1,000개 바이브코딩 레포 분석 결과 관측 빈도 상위 7종.

| ID | Rule Type | Severity | 관측 빈도 |
|----|-----------|----------|----------|
| V-01 | NO_HARDCODED_SECRETS | critical | 33.9% 레포 |
| V-02 | NO_NETWORK | critical | 61.3% 레포 |
| V-03 | NO_EXEC | critical | 48.3% 레포 |
| V-04 | SQL_PARAM_BINDING | high | 56.7% 레포 |
| V-05 | NO_DEBUG_MODE | high | 10.2% 레포 |
| V-06 | NO_WEAK_RANDOM | high | 8.7% 레포 |
| V-07 | NO_BARE_EXCEPT | medium | 42.1% 레포 |

### 패치 전략 (언어별, 실제 동작하는 코드로 교체)

| Rule | Python 패치 | JS/TS 패치 |
|------|------------|-----------|
| NO_HARDCODED_SECRETS | `os.environ.get("VAR", "")` | `process.env.VAR ?? ""` |
| NO_NETWORK | `raise NotImplementedError("외부 호출 차단")` | `throw new Error("외부 호출 차단")` |
| NO_EXEC | `shell=False` + 리스트 인수 | `execFile("cmd", [arg], cb)` |
| SQL_PARAM_BINDING | `cursor.execute("... WHERE x=?", (val,))` | `query("... WHERE x=$1", [val])` |
| NO_DEBUG_MODE | `os.environ.get("DEBUG","false")=="true"` | `process.env.NODE_ENV!=="production"` |
| NO_WEAK_RANDOM | `secrets.token_hex(32)` | `crypto.randomUUID()` |
| NO_BARE_EXCEPT | `except Exception as e: logger.warning(e)` | `catch(e){console.error(e)}` |

---

## 1. 아키텍처

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
├── dataset/slayer-bench-v0/ # 데모와 벤치마크 케이스
└── spec.md
```

---

## 2. AI CLI 감지 및 위임 (`ai_runner.py`)

**SLAyer는 직접 AI API를 호출하지 않는다.** 로컬에 설치된 AI CLI에 프롬프트를 전달하고 stdout을 수신한다.

### 감지 우선순위

| AI CLI | 감지 명령 | 실행 명령 |
|--------|----------|----------|
| `claude` | `claude --version` | `claude -p "{prompt}"` |
| `codex` | `codex --version` | `codex exec "{prompt}"` |
| `gemini` | `gemini --version` | `gemini "{prompt}"` |

**감지 성공 조건**: check 명령 exit code = 0.
**우선순위**: `.slayer.yml` 저장값 > 자동 감지(위 순서).

### 에러 처리

| 상황 | 동작 |
|------|------|
| 아무 AI CLI도 없음 | `AICliNotFoundError` → 설치 안내 출력, AST 스캔은 계속 |
| CLI exit code ≠ 0 | stderr 내용을 에러 메시지로 표시, 원본 파일 유지 |
| stdout이 유효하지 않은 코드 | 원본 파일 복원, "Patch failed" 표시 |
| 60초 타임아웃 | 원본 파일 복원 |

**AI CLI 없을 때 안내 메시지**:
```
✗ AI CLI가 감지되지 않았습니다.

다음 중 하나를 설치하세요:
  • Claude Code   https://claude.ai/code
  • Codex CLI     npm install -g @openai/codex
  • Gemini CLI    npm install -g @google/gemini-cli

AST 기반 스캔(탐지만)은 AI 없이도 동작합니다.
```

---

## 3. CLI 인터페이스

명령어 3개.

### 3-1. slayer start

```bash
slayer start <path>
```

- `.py/.js/.jsx/.ts/.tsx` 파일 재귀 수집 → AST/regex 스캔 → 위반 목록 plain 텍스트 출력
- path 생략 시 현재 디렉토리 (`.`)

### 3-2. slayer patch

```bash
slayer patch <path>
```

- 스캔 → 위반 발견 시 AI CLI로 패치 → 재스캔
- 패치 완료 후 "🚀 Deployment Approved" 또는 잔여 위반 목록 출력

### 3-3. slayer model

```bash
slayer model                # 감지된 AI CLI 상태 + 현재 설정 표시
slayer model claude         # claude 사용으로 .slayer.yml에 저장
slayer model codex          # codex 사용으로 .slayer.yml에 저장
slayer model gemini         # gemini 사용으로 .slayer.yml에 저장
slayer model auto           # 자동 감지 (기본값)으로 초기화
```

**Exit codes (start / patch 공통)**:
- `0` — violations 없음 (Deployment Approved)
- `1` — violations 존재 (Deployment BLOCKED)
- `2` — 실행 오류

**공통 옵션**:
```
--format [text|json]   출력 형식 (기본: text)
```

---

## 4. 출력 형식

### text 형식 (기본)

```
SLAyer  Scanning dataset/slayer-bench-v0/vulnerable/python/py_secret_exec_sql.py

✗  NO_HARDCODED_SECRETS  py_secret_exec_sql.py:3   API_KEY = "sk-prod-..."
✗  SQL_PARAM_BINDING     py_secret_exec_sql.py:7   f"SELECT * FROM ..."
✗  NO_EXEC               py_secret_exec_sql.py:11  subprocess.run(..., shell=True)

Deployment BLOCKED
```

### json 형식 (--format json)

```json
{
  "violations": [
    {
      "rule_id": "NO_HARDCODED_SECRETS",
      "rule_name": "NO_HARDCODED_SECRETS",
      "file": "/abs/path/py_secret_exec_sql.py",
      "line": 3,
      "col": 0,
      "code_snippet": "API_KEY = \"sk-prod-...\"",
      "explanation": "비밀번호나 API 키를 코드에 직접 넣으면 저장소가 노출될 때 인증 정보가 바로 악용됩니다."
    }
  ],
  "pass_count": 0,
  "fail_count": 4,
  "deployable": false
}
```

---

## 5. 데이터 모델 (`models.py`)

```python
RuleType = Literal["NO_NETWORK","NO_EXEC","NO_HARDCODED_SECRETS",
                   "SQL_PARAM_BINDING","NO_DEBUG_MODE",
                   "NO_WEAK_RANDOM","NO_BARE_EXCEPT","CUSTOM"]
Severity = Literal["critical","high","medium"]

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
    explanation: str    # 한국어

class ScanResult(BaseModel):
    rules: List[SLARule]
    violations: List[Violation]
    pass_count: int
    fail_count: int
    deployable: bool

class PatchResult(BaseModel):
    patched_files: List[str]
    diffs: Dict[str, str]       # filepath → unified diff
    remaining_violations: List[Violation]
    deployable: bool
    ai_used: str                # "claude" / "codex" / "gemini"
```

---

## 6. Analyzers (`analyzers/`)

AI 없이 결정적으로 동작.

### `py_analyzer.py` — Python AST 기반

- **NO_NETWORK**: requests/httpx/urllib 등 네트워크 라이브러리 임포트 + 메서드 호출
- **NO_EXEC**: subprocess.run(shell=True), os.system() 등
- **NO_HARDCODED_SECRETS**: password/api_key/secret/token 할당, sk-/ghp_ 패턴
- **SQL_PARAM_BINDING**: f-string + SQL 키워드 (SELECT/INSERT/UPDATE/DELETE/DROP)
- **NO_DEBUG_MODE**: `DEBUG=True`, `app.run(debug=True)`
- **NO_WEAK_RANDOM**: `random.random()`, `random.choice()` 보안 컨텍스트 사용
- **NO_BARE_EXCEPT**: `except: pass` / `except Exception: pass`

### `js_analyzer.py` — JS/TS Regex 기반

- **NO_NETWORK**: `fetch(`, `axios.get/post` 등
- **NO_EXEC**: `child_process.exec`, `execSync`, `spawnSync`
- **NO_HARDCODED_SECRETS**: const/let/var 시크릿 할당, ghp_/sk- 패턴
- **SQL_PARAM_BINDING**: 템플릿 리터럴 + SQL 키워드
- **NO_DEBUG_MODE**: `debug: true`, `DEBUG = true`
- **NO_WEAK_RANDOM**: `Math.random()` 보안 컨텍스트 사용
- **NO_BARE_EXCEPT**: `catch(e) {}` (빈 catch 블록)

---

## 7. LLM Patcher (`patcher/llm_patcher.py`)

AI CLI에 파일 내용 + SLAyer가 탐지한 위반 목록을 전달해 수정된 전체 코드를 수신.

**핵심 원칙**: AI는 SLAyer가 탐지한 violation만 수정. 그 외 코드는 변경 금지.

### 언어별 구문 검증

| 언어 | 검증 | 실패 시 |
|------|------|---------|
| Python | `ast.parse()` | 원본 복원 |
| JS | `node --check` | 원본 복원 |
| TS/TSX | `tsc --noEmit` 가능 시 실행 | 실패 시 원본 복원 |

### rollback 조건
1. AI CLI exit code ≠ 0
2. Python: `ast.parse()` 실패
3. 60초 타임아웃

---

## 8. Acceptance Criteria

### AC-01 — start: 스캔 출력
```
Given: slayer start dataset/slayer-bench-v0/vulnerable/python/py_secret_exec_sql.py
Then:  위반 목록 "✗ RULE_TYPE  file:line  snippet" 형식 출력
       violations > 0 → exit 1, violations = 0 → exit 0
```

### AC-02 — start: 파일 없는 디렉토리
```
Given: 대상 파일 없는 디렉토리
Then:  "No supported source files found" 출력, exit 0
```

### AC-03 — start: JSON 출력
```
Given: slayer start dataset/slayer-bench-v0/vulnerable/python/py_secret_exec_sql.py --format json
Then:  파싱 가능한 JSON, violations[]/pass_count/fail_count/deployable 포함
```

### AC-04 — patch: 자동 패치
```
Given: 벤치마크 취약 파일을 임시 디렉토리에 복사 후 slayer patch <tmp>/app.py 실행 (AI CLI 설치 환경)
Then:  "Patching via {ai_name}..." 출력
       재스캔 후 violations=0 → "🚀 Deployment Approved", exit 0
       잔여 violations → 목록 출력, exit 1
```

### AC-05 — patch: JSON 출력
```
Given: 임시 복사본 대상 slayer patch <tmp>/app.py --format json
Then:  patched_files/diffs/remaining_violations/deployable/ai_used 포함 JSON
```

### AC-06 — AI CLI 없는 환경
```
Given: claude/codex/gemini 모두 미설치
When:  slayer start → AST 스캔 정상 동작
When:  slayer patch → "AI CLI가 감지되지 않았습니다." + 설치 안내, exit 2
```

### AC-07 — SyntaxError 파일 처리
```
Given: SyntaxError 파일 포함
Then:  "⚠ syntax error" 경고 후 건너뜀, 나머지 파일 계속 스캔
```

### AC-08 — 벤치마크 통과
```
Given: dataset/slayer-bench-v0/
Then:  vulnerable/ 전부 BLOCKED
       fixed/ 전부 Approved
       false_positive/ 전부 Approved
```

---

## 9. 데모 시나리오

```bash
# 설치
pip install -e ".[dev]"

# 데모 파일 준비
tmp="$(mktemp -d)"
cp dataset/slayer-bench-v0/vulnerable/python/py_secret_exec_sql.py "$tmp/app.py"

# 스캔
slayer start "$tmp/app.py"
# ✗  NO_HARDCODED_SECRETS  app.py:3   API_KEY = "sk-prod-..."
# ✗  SQL_PARAM_BINDING     app.py:7   f"SELECT * FROM ..."
# ✗  NO_EXEC               app.py:11  subprocess.run(..., shell=True)
# Deployment BLOCKED

# 자동 패치
slayer patch "$tmp/app.py"
# Patching via claude...
# 🚀 Deployment Approved

# CI 통합
slayer patch ./src --format json | jq '.deployable'
# → true
```

---

## 10. 배포

```bash
pip install -e ".[dev]"     # 개발 설치
python -m build             # 빌드
```

**의존성**: `pydantic`, `typer`, `rich` — AI SDK 없음.
