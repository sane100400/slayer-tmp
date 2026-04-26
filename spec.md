# SLAyer — 개발 명세서 v6 (Web-Specialized Edition)

> 트랙: Developer Tooling | CMUX x AIM | 2026-04-26

---

## 0. 핵심 한 줄

**바이브코딩으로 생성된 웹서비스 코드(Python · JS · TS)에서 7가지 보안 취약 패턴을 탐지하고, 이미 설치된 AI CLI(Claude Code / Codex / Gemini)로 자동 패치 후 배포 게이트를 여는 TUI 도구.**

```bash
pip install slayer-sec   # 설치
slayer start .           # 스캔 TUI 실행
slayer patch .           # 위반 자동 패치 → 🚀 Deployment Approved
```

**지원 언어**: Python (`.py`) · JavaScript (`.js`, `.jsx`) · TypeScript (`.ts`, `.tsx`)
**타겟 사용자**: Claude Code / Codex / Gemini CLI 중 하나가 이미 설치된 바이브코더.

**"SLAyer 설정 제로"의 의미**:
- SLAyer 자체에 API 키, config 파일, 로그인 없음
- AI CLI(Claude Code 등)는 사용자가 이미 설치·인증한 상태를 전제
- AI CLI 없으면 AST 스캔(탐지)은 동작, 패치만 불가 — 그 경우 설치 안내 표시

---

## 0.5 Dataset Strategy

두 종류의 데이터셋을 목적에 따라 분리하여 사용한다.

### HuggingFace 데이터셋 — 7종 CWE 도출 근거

| 데이터셋 | 샘플 수 | 용도 |
|---------|--------|------|
| `code-search-net/code_search_net` (Python) | 30,000+ 함수 | 일반 Python 코드 베이스라인 |
| `HuggingFaceH4/CodeAlpaca_20K` | 20,000 샘플 | AI 생성 코드 패턴 |

AST 기반 패턴 분석으로 각 CWE 후보의 **관측 빈도**를 계산하고, 그 빈도가 높은 상위 7종을 SLAyer 룰셋으로 확정한다. 데이터에서 관측되지 않은 CWE는 포함하지 않는다.

분석 스크립트: `tools/analyze_hf_dataset.py`
결과 리포트: `tools/hf_pattern_report.json`, `tools/codealp_pattern_report.json`

### GitHub 수집 바이브코딩 파일 — 성능 평가 벤치마크

`CLAUDE.md` 파일 보유 레포 = Claude Code로 빌드된 직접 증거.

| 구성 | 내용 |
|------|------|
| 수집 방법 | GitHub Code Search API (`filename:CLAUDE.md + flask/fastapi/django`) |
| 저장 위치 | `dataset/` (gitignore, 배포 미포함) |
| 용도 | SLAyer 7종 룰의 **탐지 정확도(recall) 측정** |
| 목표 | 210개 이상 실제 바이브코딩 Python 파일 |

수집 스크립트: `tools/collect_dataset.py`
벤치마크 실행: `tools/benchmark.py` (추후 구현)

> **원칙**: 7종 CWE는 HF 데이터에서 통계적으로 도출. GitHub 파일은 구현 후 SLAyer가 얼마나 잘 잡는지 검증하는 데 사용.

---

## 0.6 Vibe Coding Vulnerability Taxonomy

AI 코드 생성 도구로 작성된 Python 코드에서 **반복적으로 등장하는 보안 취약 패턴** 7종.

### 왜 바이브코딩 코드는 취약한가

| 패턴 원인 | 설명 |
|----------|------|
| "일단 동작하게" 프롬프트 | 기능 구현 우선, 보안 컨텍스트 없음 |
| 오래된 튜토리얼 데이터 | f-string SQL, MD5 해싱 등 구식 패턴이 훈련 데이터에 많음 |
| 개발 예제 그대로 배포 | `DEBUG=True`, 하드코딩 크레덴셜을 교체 안 함 |
| 에러 제거 요청 | `except: pass` — "에러 없애줘" 프롬프트 결과 |

### Vibe Coding Ruleset — 데이터셋 분석 후 확정

> **미확정**: 7종 룰은 GitHub + HuggingFace Spaces 수집 데이터셋(Python/JS/TS)에서 관측된 빈도를 기반으로 확정한다.
> 데이터 없이 선정하지 않는다.

수집 완료 후 `tools/analyze_hf_dataset.py --local dataset/` 실행 결과로 채울 것:

| ID | Rule Type | Python 탐지 패턴 | JS/TS 탐지 패턴 | Severity | 관측 빈도 |
|----|-----------|----------------|----------------|----------|----------|
| V-01 | TBD | — | — | — | — |
| V-02 | TBD | — | — | — | — |
| V-03 | TBD | — | — | — | — |
| V-04 | TBD | — | — | — | — |
| V-05 | TBD | — | — | — | — |
| V-06 | TBD | — | — | — | — |
| V-07 | TBD | — | — | — | — |

### 패치 전략 (언어별, 실제 동작하는 코드로 교체)

룰 확정 후 채울 것. AI CLI는 파일 확장자로 언어를 자동 판별하여 패치 프롬프트에 명시한다.

| Rule | Python 패치 | JS/TS 패치 |
|------|------------|-----------|
| (확정 후 추가) | | |

---

## 1. 아키텍처

단일 Python 패키지. **Textual** TUI + CI 논인터랙티브 모드.
AI 호출은 직접 API 대신 **설치된 AI CLI에 위임** (인증 불필요).

```
slayer/
├── slayer/
│   ├── cli.py              # entry point (slayer start / patch)
│   ├── tui/
│   │   ├── app.py          # Textual App — SLayerTUI
│   │   ├── screens/
│   │   │   └── scan_screen.py
│   │   └── widgets/
│   │       ├── file_panel.py       # 왼쪽: 파일 트리
│   │       ├── violation_panel.py  # 오른쪽 상단: 위반 목록
│   │       └── code_viewer.py      # 오른쪽 하단: 코드 뷰어
│   ├── models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
│   ├── ai_runner.py        # AI CLI 감지 및 프롬프트 위임
│   ├── config.py           # .slayer.yml 로딩
│   ├── analyzers/
│   │   ├── base_analyzer.py # 공통 인터페이스
│   │   ├── py_analyzer.py   # Python AST 분석 (AI 불필요)
│   │   ├── js_analyzer.py   # JS/TS regex 분석 (AI 불필요)
│   │   └── llm_analyzer.py  # CUSTOM 룰 시맨틱 분석 (AI CLI 위임)
│   └── patcher/
│       └── llm_patcher.py   # 자동 패치 (AI CLI 위임, 언어 자동 감지)
├── pyproject.toml           # entry_point: slayer = slayer.cli:app
├── demo_vuln.py             # Python 데모
├── demo_vuln.js             # JS 데모
└── spec.md
```

---

## 2. AI CLI 감지 및 위임 (`ai_runner.py`)

**SLAyer는 직접 AI API를 호출하지 않는다.** 대신 로컬에 설치된 AI CLI에 프롬프트를 전달하고 stdout을 수신한다.

### 감지 우선순위

```python
AI_CANDIDATES = [
    {
        "name": "claude",
        "check": ["claude", "--version"],   # exit 0 + stdout 포함이면 사용 가능
        "run": lambda prompt: ["claude", "-p", prompt],
    },
    {
        "name": "codex",
        "check": ["codex", "--version"],    # exit 0이면 사용 가능
        "run": lambda prompt: ["codex", "exec", prompt],
    },
    {
        "name": "gemini",
        "check": ["gemini", "--version"],   # exit 0이면 사용 가능
        "run": lambda prompt: ["gemini", prompt],
    },
]
```

**감지 성공 조건**: `check` 명령 실행 시 exit code = 0. stdout/stderr 내용 무관.
**감지 실패 조건**: `check` 명령이 FileNotFoundError (미설치) 또는 exit code ≠ 0.

### `ai_runner.py` 인터페이스

```python
def detect_ai_cli() -> dict | None:
    """설치된 AI CLI 중 첫 번째 사용 가능한 것을 반환. 없으면 None."""

def run_ai(prompt: str, timeout: int = 60) -> str:
    """감지된 AI CLI에 프롬프트를 전달하고 stdout 반환. 실패 시 AICliError."""
```

### 실행 명령 포맷

| AI CLI | 감지 명령 | 실행 명령 | 응답 |
|--------|----------|----------|------|
| `claude` | `claude --version` | `claude -p "{prompt}"` | stdout 전체 = 수정된 코드 |
| `codex` | `codex --version` | `codex exec "{prompt}"` | stdout 전체 = 수정된 코드 |
| `gemini` | `gemini --version` | `gemini "{prompt}"` | stdout 전체 = 수정된 코드 |

**응답 파싱 규칙**:
1. stdout 전체를 raw 문자열로 수신
2. 코드 블록(` ```python ... ``` ` 또는 ` ``` ... ``` `)이 있으면 블록 내부만 추출
3. 코드 블록 없으면 stdout 전체를 코드로 사용
4. 결과가 `ast.parse()` 통과하면 파일에 기록, 실패하면 원본 복원

### 에러 처리

| 상황 | 동작 |
|------|------|
| 아무 AI CLI도 없음 | `AICliNotFoundError` → TUI 안내 메시지 표시, AST 스캔은 계속 |
| CLI exit code ≠ 0 | stderr 내용을 에러 메시지로 표시, 원본 파일 유지 |
| stdout이 유효한 Python이 아님 | `ast.parse` 실패 → 원본 파일 복원, "Patch failed" 표시 |
| 60초 타임아웃 | `AICliTimeoutError` → 원본 파일 복원 |

**TUI 안내 메시지 (AI CLI 없을 때)**:
```
✗ AI CLI가 감지되지 않았습니다.

다음 중 하나를 설치하세요:
  • Claude Code   https://claude.ai/code
  • Codex CLI     npm install -g @openai/codex
  • Gemini CLI    npm install -g @google/gemini-cli

AST 기반 스캔(탐지만)은 AI 없이도 동작합니다.
```

> **핵심**: AST 스캔(V-01~V-07 탐지)은 AI 없이 동작. AI CLI는 CUSTOM 룰 분석과 자동 패치에만 필요.

---

## 3. CLI 인터페이스

명령어 3개.

### 3-1. slayer start

```bash
slayer start <path>
```

- `.py/.js/.jsx/.ts/.tsx` 파일 재귀 수집 → AST/regex 스캔 → 위반 목록 plain 텍스트 출력
- path 생략 시 현재 디렉토리 (`.`)

**Exit codes (두 명령 공통):**
- `0` — 스캔 완료, violations 없음 (Deployment Approved)
- `1` — 스캔 완료, violations 존재 (Deployment BLOCKED)
- `2` — 실행 오류 (파일 읽기 실패, AI CLI 실행 실패 등)

### 3-2. slayer patch

```bash
slayer patch <path>
```

- `.py/.js/.jsx/.ts/.tsx` 파일 스캔 → 위반 발견 즉시 AI CLI로 패치 → 재스캔
- non-interactive (터미널에서 바로 실행)
- 패치 완료 후 "🚀 Deployment Approved" 또는 잔여 위반 목록 출력

### 3-3. slayer model

```bash
slayer model                # 감지된 AI CLI 상태 + 현재 설정 표시
slayer model claude         # claude 사용으로 .slayer.yml에 저장
slayer model codex          # codex 사용으로 .slayer.yml에 저장
slayer model gemini         # gemini 사용으로 .slayer.yml에 저장
slayer model auto           # 자동 감지 (기본값)으로 초기화
```

- 설정 저장 위치: `.slayer.yml` (`ai: claude` 형식)
- `slayer patch`는 `--ai` 플래그 > `.slayer.yml` 설정 > 자동 감지 순으로 우선순위 적용
- AI CLI가 하나도 없으면 설치 안내 출력

**출력 예시 (`slayer model`)**:
```
  AI CLI Status
  ─────────────────────────────────
  ✓  claude
  ✓  codex
  ✗  gemini

  Saved preference : auto  (first available)
  Active AI CLI    : claude
```

**공통 옵션 (start / patch)**:
```
--format [text|json]   출력 형식 (기본: text)
```

**기본 룰 (자동 적용, 설정 불필요, .py/.js/.ts/.jsx/.tsx 모두 적용)**:
1. NO_NETWORK — 외부 네트워크 호출
2. NO_EXEC — shell 명령어 실행
3. NO_HARDCODED_SECRETS — 하드코딩 API 키·패스워드
4. SQL_PARAM_BINDING — SQL 직접 삽입 (f-string / 템플릿 리터럴)
5. NO_DEBUG_MODE — DEBUG=True / debug:true
6. NO_WEAK_RANDOM — 보안 컨텍스트에서 random/Math.random() 사용
7. NO_BARE_EXCEPT — except: pass / 빈 catch 블록

---

## 4. 출력 형식

### text 형식 (기본)

```
$ slayer start demo_vuln.py | cat

  SLAyer  Scanning demo_vuln.py

  ✗  NO_NETWORK        line 9    requests.get(...)
  ✗  NO_HARDCODED      line 5    API_KEY = "sk-prod-..."
  ✗  SQL_PARAM_BINDING line 13   f"SELECT * FROM users WHERE name='{query}'"
  ✗  NO_EXEC           line 17   subprocess.run(..., shell=True)

  Result  4 violations · 🔒 Deployment BLOCKED
```

### json 형식 (--format json)

```json
{
  "rules": [...],
  "violations": [
    {
      "rule_id": "rule_1",
      "rule_name": "외부 네트워크 호출 없음",
      "file": "/abs/path/demo_vuln.py",
      "line": 9,
      "col": 0,
      "code_snippet": "    return requests.get(...)",
      "explanation": "외부 서버로 데이터를 보내는 코드예요."
    }
  ],
  "pass_count": 0,
  "fail_count": 4,
  "deployable": false
}
```

---

## 6. 데이터 모델 (`models.py`)

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
    file: str           # 절대 경로
    line: int
    col: int            # 항상 0
    code_snippet: str
    explanation: str    # "~을 하면 ~이 됩니다" 형식 한국어

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
    ai_used: str                # 사용된 AI CLI 이름 ("claude" / "codex" / "gemini")
```

---

## 7. Analyzers (`analyzers/`)

AI 없이 결정적으로 동작. 언어별 분리.

### `py_analyzer.py` — Python AST 기반

```python
# NO_NETWORK
NETWORK_IMPORTS = {"requests","urllib","urllib3","httpx","aiohttp","socket","websocket","boto3"}
NETWORK_METHODS = {"get","post","put","delete","patch","request","urlopen","socket"}

# NO_EXEC
EXEC_MODULE_CALLS = {
    "subprocess.run","subprocess.Popen","subprocess.call",
    "subprocess.check_output","os.system","os.popen","os.execvp","os.execve"
}

# NO_HARDCODED_SECRETS — 정규식 6종 라인 스캔
# (1) password/passwd/pwd = "..."
# (2) api_key/apikey = "..." (8자 이상)
# (3) secret/token = "..." (8자 이상)
# (4) sk- 로 시작하는 20자 이상
# (5) AWS: aws_access_key_id = "..."
# (6) GitHub PAT: ghp_ 로 시작하는 36자

# SQL_PARAM_BINDING
# f-string + r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b'

# NO_DEBUG_MODE
DEBUG_PATTERNS = [
    r'(?i)^DEBUG\s*=\s*True',
    r'app\.run\(.*debug\s*=\s*True',
]

# NO_WEAK_RANDOM: random.random/randint/choice + 보안 컨텍스트 함수명
# NO_BARE_EXCEPT: ast.ExceptHandler.type is None
```

### `js_analyzer.py` — JS/TS Regex 기반

```python
# 대상 확장자: .js .jsx .ts .tsx

# NO_HARDCODED_SECRETS — Python과 동일 정규식 + JS 문법
SECRET_RE_JS = [
    re.compile(r'(?i)(?:const|let|var)\s+\w*(password|api_?key|secret|token)\w*\s*=\s*["\'][^"\']{8,}["\']'),
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
]

# NO_NETWORK: fetch( / axios.get( / axios.post( 등
NETWORK_RE_JS = re.compile(r'\b(fetch|axios\.(get|post|put|delete|patch)|http\.(get|post))\s*\(')

# NO_EXEC: child_process.exec / execSync / spawnSync 문자열 인수
EXEC_RE_JS = re.compile(r'\b(exec|execSync|spawnSync)\s*\(\s*[`"\']')

# SQL_PARAM_BINDING: 템플릿 리터럴 + SQL 키워드
SQL_RE_JS = re.compile(r'`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{')

# NO_DEBUG_MODE
DEBUG_RE_JS = re.compile(r'(?i)(debug\s*:\s*true|NODE_ENV\s*!==?\s*["\']production["\'])')

# NO_WEAK_RANDOM: Math.random() + 보안 컨텍스트
WEAK_RANDOM_RE_JS = re.compile(r'Math\.random\s*\(\s*\)')

# NO_BARE_EXCEPT: catch\s*(\w*)?\s*\{\s*\}  (빈 catch 블록)
BARE_CATCH_RE_JS = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
```

---

## 8. SLA 파서 (`analyzers/sla_parser.py`)

자연어 룰 → SLARule[] 변환. AI CLI에 위임.

```python
PARSE_PROMPT = """
다음 자연어 보안 조건을 JSON 배열로만 변환하세요 (마크다운 없이).

각 항목:
{
  "id": "rule_N",
  "name": "...",
  "description": "'~을 하면 ~이 됩니다' 형식 한국어",
  "raw_nl": "원본 입력",
  "rule_type": "NO_NETWORK|NO_EXEC|NO_HARDCODED_SECRETS|SQL_PARAM_BINDING|NO_DEBUG_MODE|NO_WEAK_RANDOM|NO_BARE_EXCEPT|CUSTOM",
  "severity": "critical|high|medium"
}

입력 규칙:
{rules}
"""
```

빈 rules → 기본 4개 룰 자동 적용 (AC-04).

---

## 9. LLM Patcher (`patcher/llm_patcher.py`)

AI CLI에 파일 내용 + **SLAyer가 탐지한 위반 목록**을 전달해 수정된 전체 코드를 수신.

### 핵심 원칙: SLAyer-scoped patch

> **AI는 SLAyer가 탐지한 violation만 수정한다. 그 외 코드는 한 글자도 바꾸지 않는다.**

AI CLI에 위반 목록(`violations_json`)을 명시적으로 전달하고, 프롬프트에 "위반 목록에 없는 코드는 변경 금지"를 강제한다. 이 범위 제한이 없으면 AI가 스타일 변경, 리팩토링, 로직 변경 등 의도하지 않은 수정을 할 수 있다.

```python
PATCH_PROMPT = """
다음 {language} 코드에서 아래 위반 목록에 해당하는 보안 취약점만 수정하세요.
수정된 전체 코드만 반환하세요 (설명, 마크다운 없이).

**중요**: 위반 목록에 없는 코드는 절대 변경하지 마세요.
변수명, 로직, 주석, 포맷 등 보안 위반과 무관한 부분은 원본 그대로 유지하세요.

위반 목록 (이것만 수정):
{violations_json}

각 위반의 file, line, rule_id를 기준으로 해당 위치만 수정하세요.

수정 지침 (rule_id별, Python / JS·TS):
- NO_HARDCODED_SECRETS:
    Python: `os.environ.get("VAR_NAME", "")` (import os 추가)
    JS/TS:  `process.env.VAR_NAME ?? ""`
- NO_NETWORK:
    Python: `raise NotImplementedError("외부 호출이 차단됨")`
    JS/TS:  `throw new Error("외부 호출이 차단됨")`
- NO_EXEC:
    Python: `shell=True` → `shell=False`, 명령어 문자열 → `["cmd", "arg"]` 리스트
    JS/TS:  `exec("cmd arg")` → `execFile("cmd", ["arg"], callback)`
- SQL_PARAM_BINDING:
    Python sqlite3/psycopg2: `cursor.execute("SELECT ... WHERE x = ?", (val,))`
    Python SQLAlchemy:       `text("SELECT ... WHERE x = :x").bindparams(x=val)`
    JS/TS (pg):              `client.query("SELECT ... WHERE x = $1", [val])`
    JS/TS (mysql2):          `connection.execute("SELECT ... WHERE x = ?", [val])`
- NO_DEBUG_MODE:
    Python: `os.environ.get("DEBUG", "false").lower() == "true"`
    JS/TS:  `process.env.NODE_ENV !== "production"` 또는 `process.env.DEBUG === "true"`
- NO_WEAK_RANDOM:
    Python: `secrets.token_hex(32)` 또는 `secrets.choice(alphabet)`
    JS/TS:  `crypto.randomUUID()` 또는 `crypto.getRandomValues(new Uint8Array(32))`
- NO_BARE_EXCEPT:
    Python: `except Exception as e: logger.warning("Unexpected error: %s", e)`
    JS/TS:  `catch (e) {{ console.error("Unexpected error:", e); }}`

원본 코드:
{code}
"""
```

### 입력/출력

| 항목 | 내용 |
|------|------|
| 입력 | `code` (파일 전체), `violations_json` (SLAyer 탐지 결과만), `language` (py/js/ts) |
| 출력 | 수정된 전체 코드 (코드블록 있으면 추출, 없으면 stdout 전체) |
| 검증 | 언어별 구문 검사 후 실패 시 원본 자동 복원 |
| 범위 보장 | 패치 후 diff 생성 → 수정 라인이 violation line ±5 범위 외이면 "Unexpected change detected" 경고 |

### 언어별 구문 검증

| 언어 | 검증 수단 | 실패 시 |
|------|---------|---------|
| Python (`.py`) | `ast.parse(patched_code)` | 원본 복원 + "Patch failed: syntax error" |
| JS/TS (`.js/.jsx/.ts/.tsx`) | `node --check <tempfile>` (Node.js 내장 구문 검사, npm 패키지 불필요) | 원본 복원 + "Patch failed: syntax error" |

> `node --check`는 Node.js 내장 플래그로 파일을 실행하지 않고 구문만 파싱한다.  
> node가 설치되어 있지 않은 환경(fallback): diff 변경 라인 수 > 원본 × 0.2 초과 시 거부.  
> 두 경우 모두 실패 시 동일한 rollback 절차 적용.

### 원본 복원 (rollback) 전략

패치 시작 전 `original = path.read_text()`로 원본을 메모리에 보관.  
아래 조건 중 하나라도 해당하면 즉시 `path.write_text(original)` 복원:
1. AI CLI exit code ≠ 0
2. Python: `ast.parse()` 실패
3. JS/TS: diff 변경 라인 수 > 원본 라인 수 × 0.2
4. 타임아웃 (60초)

복원 후 `PatchResult.deployable = False`, `remaining_violations` = 원래 위반 목록 반환.

패치 후 AST Analyzer 재실행으로 remaining_violations 확인.

---

## 10. Acceptance Criteria

### AC-01 — start: 스캔 출력
```
Given: `slayer start demo_vuln.py`
When:  명령어 완료
Then:  위반 목록이 "✗ RULE_TYPE  file:line  snippet" 형식으로 stdout 출력됨
       violations > 0이면 exit code 1, violations = 0이면 exit code 0
```

### AC-02 — start: 스캔 대상 없는 디렉토리
```
Given: 웹서비스 파일(.py/.js/.ts)이 없는 빈 디렉토리로 `slayer start ./empty/`
When:  명령어 완료
Then:  "No files found" 메시지 출력, exit code 0
```

### AC-03 — start: 스캔 속도
```
Given: 1000줄 이하 파일
When:  `slayer start` 실행
Then:  결과 출력까지 3초 이내
```

### AC-04 — start: 위반 정보 완전성
```
Given: demo_vuln.py (NO_NETWORK, NO_EXEC, NO_HARDCODED_SECRETS, SQL_PARAM_BINDING 포함)
When:  `slayer start demo_vuln.py`
Then:  각 위반에 rule_type + file명 + 라인 번호 + code_snippet 출력
       explanation은 한국어 ("~을 하면 ~이 됩니다" 형식)
```

### AC-05 — start: 기본 룰 자동 적용
```
Given: `slayer start .` (rules 옵션 없음, .slayer.yml 없음)
When:  스캔 실행
Then:  7종 Vibe Coding 룰이 자동 적용되어 스캔됨
       demo_vuln.py에서 4개 이상의 위반이 탐지됨
```

### AC-06 — start: JSON 출력
```
Given: `slayer start demo_vuln.py --format json`
When:  명령어 완료
Then:  stdout이 파싱 가능한 JSON
       violations[], pass_count, fail_count, deployable 필드 포함
```

### AC-07 — patch: 자동 패치
```
Given: `slayer patch demo_vuln.py` (AI CLI 설치된 환경)
When:  명령어 완료
Then:  "Patching via {ai_name}..." 출력 (ai_name = 감지된 CLI)
       파일이 수정됨
       재스캔 후 violations = 0이면 "🚀 Deployment Approved", exit 0
       잔여 violations 있으면 목록 출력, exit 1
```

### AC-08 — patch: JSON 출력
```
Given: `slayer patch demo_vuln.py --format json`
When:  명령어 완료
Then:  stdout이 파싱 가능한 JSON, 스키마:
       {
         "patched_files": ["<절대경로>"],
         "diffs": { "<절대경로>": "<unified diff>" },
         "remaining_violations": [...],
         "deployable": true | false,
         "ai_used": "claude" | "codex" | "gemini"
       }
```

### AC-09 — AI CLI 없는 환경
```
Given: claude/codex/gemini 모두 미설치 환경
When:  `slayer start .` 실행
Then:  AST 스캔은 정상 동작하여 violations 출력
When:  `slayer patch .` 실행
Then:  "AI CLI가 감지되지 않았습니다." + 설치 안내 출력, exit 2
```

### AC-10 — SyntaxError 파일 처리
```
Given: SyntaxError가 있는 broken.py가 스캔 대상에 포함
When:  `slayer start .`
Then:  broken.py에 "⚠ syntax error" 경고 출력 후 건너뜀
       나머지 정상 파일은 계속 스캔됨
```

### AC-11 — demo_vuln.py 전체 시나리오
```
Given: demo_vuln.py (requests, subprocess shell=True, 하드코딩 credential, f-string SQL)
When:  `slayer patch demo_vuln.py` (claude 설치 환경)
Then:  4개 이상 위반 탐지 후 패치
       패치 후 ast.parse() 통과
       "🚀 Deployment Approved", exit 0
```

---

## 11. 개발 순서

| 단계 | 작업 | 예상 |
|------|------|------|
| P0-1 | pyproject.toml + 의존성 (pydantic, typer, rich) | 10분 |
| P0-2 | models.py (Pydantic) | 10분 |
| P0-3 | py_analyzer.py + js_analyzer.py (7개 룰) | 40분 |
| P0-4 | cli.py `slayer start` plain 출력 | 20분 |
| **P0** | **파일 수집 → 스캔 → 위반 출력** | **~1.5h** |
| P1-1 | ai_runner.py (AI CLI 감지 + 위임) | 20분 |
| P1-2 | llm_patcher.py + `slayer patch` | 30분 |
| P1-3 | `--format json` 출력 | 15분 |
| **P1** | **전체 플로우 동작** | **~2.5h** |
| P2-1 | Deployment Approved 출력 + PyPI 빌드 | 20분 |

---

## 12. 데모 시나리오 (3분)

```bash
# 1. 설치 (Claude Code 이미 설치된 바이브코더)
pip install slayer-sec

# 2. 스캔 — 위반 목록 확인
slayer start demo_vuln.py
# ✗  NO_HARDCODED_SECRETS  demo_vuln.py:5   API_KEY = "sk-prod-..."
# ✗  NO_NETWORK            demo_vuln.py:9   requests.get(...)
# ✗  SQL_PARAM_BINDING     demo_vuln.py:13  f"SELECT * FROM ..."
# ✗  NO_EXEC               demo_vuln.py:17  subprocess.run(..., shell=True)
# 4 violations · 🔒 Deployment BLOCKED

# 3. 자동 패치
slayer patch demo_vuln.py
# Patching via claude...
# ✓  demo_vuln.py patched (4 violations fixed)
# 🚀 Deployment Approved

# 4. CI 통합
slayer patch ./src --format json | jq '.deployable'
# → true
```

**demo_vuln.py**:
```python
import requests
import subprocess
import sqlite3

API_KEY = "sk-prod-abc123secretkey9999"
DB_PASSWORD = "supersecret123"

def get_user(user_id):
    return requests.get(f"https://api.example.com/user/{user_id}").json()

def search(query):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

def analyze(filename):
    subprocess.run(f"analyze {filename}", shell=True, capture_output=True)
```

---

## 13. 배포

```bash
# 개발 설치
pip install -e ".[dev]"

# PyPI 배포
python -m build
twine upload dist/*

# 사용자 설치
pip install slayer-sec
```

---

## 14. 의존성

```toml
[project]
dependencies = [
    "textual>=0.47.0",
    "pydantic>=2.0",
    "typer>=0.9.0",
    "rich>=13.0",
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio"]
```

**서드파티 의존성**: textual, pydantic, typer, rich만. AI SDK 없음.
**표준 라이브러리 사용** (별도 설치 불필요): `ast`, `re`, `os`, `json`, `pathlib`, `shutil`
- AI CLI 실행: `os` 내 child process 실행 기능 사용
- AST 분석: `ast`
- 정규식 스캔: `re`
- JSON 출력: `json`
