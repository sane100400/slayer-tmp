# SLAyer — 개발 명세서 v5 (AI CLI Edition)

> 트랙: Developer Tooling | CMUX x AIM | 2026-04-26

---

## 0. 핵심 한 줄

**바이브코딩으로 생성된 Python 코드에서 7가지 보안 취약 패턴을 탐지하고, 이미 설치된 AI CLI(Claude Code / Codex / Gemini)로 자동 패치 후 배포 게이트를 여는 TUI 도구.**

```bash
pip install slayer-sec   # 설치
slayer start .           # 스캔 TUI 실행
slayer patch .           # 위반 자동 패치 → 🚀 Deployment Approved
```

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

### Vibe Coding Ruleset (7종)

| ID | Rule Type | 탐지 패턴 | Severity | 바이브 원인 |
|----|-----------|----------|----------|------------|
| V-01 | NO_HARDCODED_SECRETS | API 키·패스워드 리터럴 할당 | critical | "일단 예시로" 생성 |
| V-02 | NO_NETWORK | 네트워크 라이브러리 임포트 + 메서드 호출 | critical | 기능 구현 집중 |
| V-03 | NO_EXEC | 쉘 실행 함수 + `shell=True` | critical | "편하게 동작하게" 프롬프트 |
| V-04 | SQL_PARAM_BINDING | f-string/포맷 + SQL 키워드 | high | 오래된 튜토리얼 패턴 |
| V-05 | NO_DEBUG_MODE | `DEBUG=True`, `debug=True`, `app.run(debug=True)` | high | 개발 예제 그대로 배포 |
| V-06 | NO_WEAK_RANDOM | `random.random/randint/choice` in security context | high | 보안 컨텍스트에 비암호학적 난수 사용 |
| V-07 | NO_BARE_EXCEPT | `except:` 또는 `except Exception: pass` | medium | "에러 없애줘" 프롬프트 |

### 패치 전략 (실제 동작하는 코드로 교체)

| Rule | 기존 패턴 | 패치 결과 |
|------|---------|----------|
| NO_HARDCODED_SECRETS | `API_KEY = "sk-..."` | `os.environ.get("API_KEY", "")` |
| NO_NETWORK | `requests.get(...)` | `raise NotImplementedError("외부 호출 차단")` |
| NO_EXEC | `subprocess.run(cmd, shell=True)` | `subprocess.run(["cmd", arg], shell=False)` |
| SQL_PARAM_BINDING | `f"SELECT ... '{x}'"` | `cursor.execute("SELECT ... ?", (x,))` |
| NO_DEBUG_MODE | `DEBUG = True` | `os.environ.get("DEBUG","false").lower()=="true"` |
| NO_WEAK_RANDOM | `random.choice(token)` | `secrets.token_hex(32)` or `secrets.choice(...)` |
| NO_BARE_EXCEPT | `except: pass` | `except Exception as e: logger.warning(e)` |

---

## 1. 아키텍처

단일 Python 패키지. **Textual** TUI + CI 논인터랙티브 모드.
AI 호출은 직접 API 대신 **설치된 AI CLI에 위임** (인증 불필요).

```
slayer/
├── slayer/
│   ├── cli.py              # entry point (slayer scan / init)
│   ├── tui/
│   │   ├── app.py          # Textual App — SLayerTUI
│   │   ├── screens/
│   │   │   └── scan_screen.py
│   │   └── widgets/
│   │       ├── file_panel.py       # 왼쪽: 파일 트리
│   │       ├── violation_panel.py  # 오른쪽 상단: 위반 목록
│   │       └── code_viewer.py      # 오른쪽 하단: 코드 뷰어
│   ├── models.py           # Pydantic: SLARule, Violation, ScanResult, PatchResult
│   ├── ai_runner.py        # AI CLI 감지 및 프롬프트 위임 (핵심 신규)
│   ├── config.py           # .slayer.yml 로딩
│   ├── analyzers/
│   │   ├── ast_analyzer.py  # 결정적 AST 분석 (AI 불필요)
│   │   └── llm_analyzer.py  # CUSTOM 룰 시맨틱 분석 (AI CLI 위임)
│   └── patcher/
│       └── llm_patcher.py   # 자동 패치 (AI CLI 위임)
├── pyproject.toml           # entry_point: slayer = slayer.cli:app
├── demo_vuln.py
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

명령어 2개만.

### 3-1. slayer start

```bash
slayer start <path>
```

- `.py` 파일 재귀 수집 → AST 스캔 → TUI 실행
- stdout이 TTY가 아니면 자동으로 plain 텍스트 출력 (CI 모드)
- path 생략 시 현재 디렉토리 (`.`)

**Exit codes (두 명령 공통):**
- `0` — 스캔 완료, violations 없음 (Deployment Approved)
- `1` — 스캔 완료, violations 존재 (Deployment BLOCKED)
- `2` — 실행 오류 (파일 읽기 실패, AI CLI 실행 실패 등)

### 3-2. slayer patch

```bash
slayer patch <path>
```

- 해당 경로 `.py` 파일 스캔 → 위반 발견 즉시 AI CLI로 패치 → 재스캔
- TUI 없이 터미널에서 바로 실행 (non-interactive)
- 패치 완료 후 "🚀 Deployment Approved" 또는 잔여 위반 목록 출력

**공통 옵션 (두 명령 모두)**:
```
--format [text|json]   출력 형식 (기본: text)
```

**기본 룰 (자동 적용, 설정 불필요)**:
1. NO_NETWORK — 외부 네트워크 호출
2. NO_EXEC — shell 명령어 실행
3. NO_HARDCODED_SECRETS — 하드코딩 API 키·패스워드
4. SQL_PARAM_BINDING — SQL 직접 삽입
5. NO_DEBUG_MODE — DEBUG=True
6. NO_WEAK_RANDOM — 보안 컨텍스트에서 random 모듈 사용
7. NO_BARE_EXCEPT — except: pass

---

## 4. TUI 레이아웃 (Textual)

```
┌─ Files ──────────┬─ Violations ───────────────────────────┐  ← 상단 60%
│ ▶ demo_vuln.py  4│ ✗ NO_NETWORK      demo_vuln.py:9        │
│   utils.py      0│ ✗ NO_HARDCODED    demo_vuln.py:5        │
│                  │ ✗ SQL_PARAM       demo_vuln.py:13       │
│                  │ ✗ NO_EXEC         demo_vuln.py:17       │
├──────────────────┴────────────────────────────────────────┤
│  7 │                                                       │  ← 하단 40%
│  8 │  def get_user(user_id):                               │
│  9 │►     return requests.get(f"https://...")              │
│ 10 │                                                       │
├───────────────────────────────────────────────────────────┤
│  [F] Fix All   [R] Rescan   [Q] Quit   [↑↓] Navigate      │
└───────────────────────────────────────────────────────────┘
```

**레이아웃 비율**: 좌(Files) 30% / 우(Violations+Code) 70%. 우측 상단(Violations) 60% / 우측 하단(Code) 40%.

### 패널 상세

**Files panel** (왼쪽 30%)
- `.py` 파일 목록 + 파일별 위반 수 배지 (빨간 숫자 / 통과 시 초록 체크)
- `Enter` 또는 `↑↓`로 선택

**Violations panel** (오른쪽 상단 60%)
- 선택된 파일의 위반 목록 (rule_type + file:line + 한줄 explanation)
- `↑↓`로 선택 → Code viewer 해당 위치로 스크롤
- 통과 시 "✓ All rules passed" 표시

**Code viewer** (오른쪽 하단 40%)
- 선택된 위반의 코드 컨텍스트 (±3줄), 위반 라인 `►` 강조

**Keybindings bar** (하단 1줄)

| 키 | 동작 |
|----|------|
| `f` | Fix All — 자동 패치 (AI CLI 위임) |
| `r` | Rescan |
| `q` | Quit |
| `↑` / `k` | 위 항목 |
| `↓` / `j` | 아래 항목 |
| `Tab` | 패널 포커스 전환 |

### TUI 초기 상태

1. `.py` 파일 목록이 Files panel에 표시
2. 첫 번째 파일 자동 선택
3. AST 스캔 백그라운드 자동 시작 (`app.call_later(run_scan)`)
4. 스캔 중: "Scanning..." 스피너
5. 스캔 완료: 첫 번째 파일 위반 목록 로드

### Fix 플로우 (TUI)

1. `f` 키 입력
2. "Patching via `{ai_name}`..." 스피너 (감지된 AI CLI 이름 표시)
3. `ai_runner.run_ai(patch_prompt)` — 블로킹 방지: `app.call_in_thread()`
4. 파일 직접 수정
5. 자동 재스캔
6. violations = 0 → "🚀 Deployment Approved" 배너
7. `q` 종료 → exit 0

### 에러 표시 (TUI)

| 상황 | 표시 |
|------|------|
| AI CLI 없음 | 빨간 박스 + 설치 안내 (AST 스캔은 계속 동작) |
| CLI 타임아웃 | "Patch timeout — try again (f)" + 원본 복원 |
| CLI 응답 파싱 실패 | "Patch failed. Original file preserved." |

---

## 5. CI 모드 출력 (--ci)

### text 형식 (기본)

```
$ slayer scan demo_vuln.py --ci

  SLAyer  Scanning demo_vuln.py

  ✗  NO_NETWORK        line 9    requests.get(...)
  ✗  NO_HARDCODED      line 5    API_KEY = "sk-prod-..."
  ✗  SQL_PARAM_BINDING line 13   f"SELECT * WHERE name='{query}'"
  ✗  NO_EXEC           line 17   subprocess.run(shell=True)

  Result  4 violations · 🔒 Deployment BLOCKED
```

### json 형식 (--format json --ci)

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

## 7. AST Analyzer (`analyzers/ast_analyzer.py`)

AI 없이 결정적으로 동작. 7개 Vibe Coding 특화 규칙.

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
# (4) sk- 로 시작하는 20자 이상 알파뉴메릭
# (5) AWS: aws_access_key_id = "A...Z0-9" (16자 이상)
# (6) GitHub PAT: ghp_ 로 시작하는 36자

# SQL_PARAM_BINDING
# f-string/%-format/.format() + SQL_KEYWORDS r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b'

# NO_DEBUG_MODE
DEBUG_PATTERNS = [
    r'(?i)^DEBUG\s*=\s*True',
    r'(?i)debug\s*=\s*True',
    r'app\.run\(.*debug\s*=\s*True',
    r'app\.config\[.DEBUG.\]\s*=\s*True',
]

# NO_WEAK_RANDOM
# random.random / random.randint / random.choice / random.shuffle
# + 같은 함수 내 token/secret/password/key/auth 변수명 또는 함수명

# NO_BARE_EXCEPT
# ast.ExceptHandler.type is None
# 또는 ExceptHandler.type = Exception + body[0] = Pass
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

AI CLI에 파일 내용 + 위반 목록을 전달해 수정된 전체 코드를 수신.

```python
PATCH_PROMPT = """
다음 Python 코드의 보안 위반을 수정하세요.
수정된 전체 코드만 반환하세요 (설명, 마크다운 없이).

위반 목록:
{violations_json}

수정 지침:
- NO_HARDCODED_SECRETS: os.environ.get("VAR_NAME", "")로 교체 (import os 추가)
- NO_NETWORK: raise NotImplementedError("외부 호출이 차단됨")
- NO_EXEC: shell=True → shell=False + 인수 리스트 변환
- SQL_PARAM_BINDING: 파라미터 바인딩으로 교체
- NO_DEBUG_MODE: os.environ.get("DEBUG","false").lower()=="true"로 교체
- NO_WEAK_RANDOM: secrets.token_hex(32) 또는 secrets.choice(...)
- NO_BARE_EXCEPT: except Exception as e: logger.warning(e)
- 위반 없는 코드는 한 글자도 변경하지 말 것

코드:
{code}
"""
```

패치 후 AST Analyzer 재실행으로 remaining_violations 확인.

---

## 10. Acceptance Criteria

### AC-01 — start: TUI 자동 실행
```
Given: 터미널에서 `slayer start demo_vuln.py` 실행 (stdout=TTY)
When:  명령어 완료
Then:  Textual TUI가 열리고 Files panel에 demo_vuln.py가 표시된다
       Violations panel에 1개 이상의 위반이 표시된다
```

### AC-02 — start: CI 자동 감지
```
Given: `slayer start demo_vuln.py | cat` (stdout≠TTY)
When:  명령어 완료
Then:  TUI 없이 plain text 출력
       위반 목록이 "✗ RULE_TYPE  file:line  snippet" 형식으로 출력된다
       violations > 0이면 exit code 1, violations = 0이면 exit code 0
```

### AC-03 — start: .py 없는 디렉토리
```
Given: .py 파일이 없는 빈 디렉토리 경로로 `slayer start ./empty/`
When:  명령어 완료
Then:  "No Python files found" 메시지 출력
       exit code 0
```

### AC-04 — start: AST 스캔 속도
```
Given: 1000줄 이하 .py 파일
When:  `slayer start` 실행
Then:  TUI 첫 렌더링까지 3초 이내
       스캔 중 "Scanning..." 스피너 표시
```

### AC-05 — start: 위반 정보 완전성
```
Given: demo_vuln.py (NO_NETWORK, NO_EXEC, NO_HARDCODED_SECRETS, SQL_PARAM_BINDING 포함)
When:  TUI에서 위반 항목 선택
Then:  Violations panel: rule_type + file명 + 라인 번호 표시
       Code viewer: 위반 라인 ±3줄, 해당 라인 "►" 강조
       explanation은 한국어 ("~을 하면 ~이 됩니다" 형식)
```

### AC-06 — start: 기본 룰 자동 적용
```
Given: `slayer start .` (rules 옵션 없음, .slayer.yml 없음)
When:  스캔 실행
Then:  7종 Vibe Coding 룰이 자동 적용되어 스캔된다
       demo_vuln.py에서 4개 이상의 위반이 탐지된다
```

### AC-07 — start: TUI Fix 플로우
```
Given: TUI 실행 중, violations > 0
When:  `f` 키 입력
Then:  "Patching via {ai_name}..." 스피너 표시 (ai_name = 감지된 CLI 이름)
       파일이 직접 수정됨 (원본과 diff 발생)
       자동 재스캔 실행
       violations = 0이면 "🚀 Deployment Approved" 배너 표시
```

### AC-08 — patch: non-interactive 패치
```
Given: `slayer patch demo_vuln.py` (AI CLI 설치된 환경)
When:  명령어 완료
Then:  터미널에 패치 진행 상황 출력 ("Patching via {ai_name}...")
       파일이 수정됨
       재스캔 후 violations = 0이면 "🚀 Deployment Approved" 출력, exit 0
       잔여 violations 있으면 목록 출력, exit 1
```

### AC-09 — patch: JSON 출력
```
Given: `slayer patch demo_vuln.py --format json`
When:  명령어 완료
Then:  stdout이 파싱 가능한 JSON, 스키마:
       {
         "patched_files": ["<절대경로>"],
         "diffs": { "<절대경로>": "<unified diff 문자열>" },
         "remaining_violations": [
           {
             "rule_id": "rule_N",
             "rule_name": "...",
             "file": "<절대경로>",
             "line": <int>,
             "col": 0,
             "code_snippet": "...",
             "explanation": "..."
           }
         ],
         "deployable": true | false,
         "ai_used": "claude" | "codex" | "gemini"
       }
       `| jq '.deployable'` → true (violations 없으면)
```

### AC-10 — AI CLI 없는 환경
```
Given: claude/codex/gemini 모두 미설치 환경에서 `slayer start .`
When:  TUI 실행
Then:  AST 스캔은 정상 동작하여 violations 표시
       `f` 키 입력 시 빨간 에러 박스:
         "AI CLI가 감지되지 않았습니다.
          다음 중 하나를 설치하세요:
          • Claude Code  https://claude.ai/code
          • Codex CLI    npm install -g @openai/codex
          • Gemini CLI   npm install -g @google/gemini-cli"
```

### AC-11 — SyntaxError 파일 처리
```
Given: SyntaxError가 있는 broken.py가 스캔 대상에 포함
When:  `slayer start .`
Then:  broken.py에 "⚠ syntax error" 배지 표시
       나머지 정상 .py 파일은 계속 스캔됨
       exit code는 나머지 파일 결과에 따름
```

### AC-12 — demo_vuln.py 전체 시나리오
```
Given: demo_vuln.py (requests, subprocess shell=True, 하드코딩 credential, f-string SQL)
When:  `slayer patch demo_vuln.py` (claude 설치 환경)
Then:  다음 4개 이상 위반 탐지됨:
         NO_NETWORK (line 9), NO_HARDCODED_SECRETS (line 5),
         SQL_PARAM_BINDING (line 13), NO_EXEC (line 17)
       패치 후 모든 위반 제거됨
       수정된 코드가 Python 문법 오류 없이 파싱 가능 (`ast.parse` 통과)
       exit code 0
```

---

## 11. 개발 순서

| 단계 | 작업 | 예상 |
|------|------|------|
| P0-1 | pyproject.toml + 의존성 (textual, pydantic, typer, rich) | 10분 |
| P0-2 | models.py (Pydantic) | 10분 |
| P0-3 | ast_analyzer.py (7개 룰) | 40분 |
| P0-4 | cli.py + TUI 기본 3패널 레이아웃 | 30분 |
| **P0** | **파일 선택 → AST 스캔 → TUI 표시** | **~1.5h** |
| P1-1 | ai_runner.py (AI CLI 감지 + 위임) | 20분 |
| P1-2 | sla_parser.py (AI CLI로 자연어 룰 파싱) | 20분 |
| P1-3 | llm_patcher.py + `f` 키 Fix 플로우 | 30분 |
| P1-4 | `--ci` + `--format json` 출력 | 15분 |
| P1-5 | config.py + `slayer init` | 15분 |
| **P1** | **전체 플로우 동작** | **~3.5h** |
| P2-1 | Deployment Approved 배너 애니메이션 | 20분 |
| P2-2 | PyPI 패키지 빌드 + README | 20분 |

---

## 12. 데모 시나리오 (3분)

```bash
# 1. 설치 (Claude Code 이미 설치된 바이브코더)
pip install slayer-sec

# 2. TUI 스캔
slayer start demo_vuln.py
# → TUI 자동 실행, 7개 위반 표시
# → 파일 패널 / 위반 패널 / 코드 뷰어 네비게이션

# 3. 자동 패치 (non-interactive)
slayer patch demo_vuln.py
# → "Patching via claude..." 진행 표시
# → 재스캔 → 🚀 Deployment Approved

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
