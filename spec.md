# SLAyer — 개발 명세서 v4 (TUI Edition)

> 트랙: Developer Tooling | CMUX x AIM | 2026-04-26

---

## 0. 핵심 한 줄

**Claude/GPT/Cursor로 생성된 Python 코드에서 반복적으로 나타나는 7가지 보안 취약 패턴을 데이터 기반으로 탐지하고, Claude API로 실제 동작하는 안전한 코드로 자동 패치 후 배포 게이트를 여는 인터랙티브 TUI 도구.**

```bash
pip install slayer-sec
slayer scan ./src --rules "외부 네트워크 호출 없음"
# → Textual TUI 실행 — 파일 / 위반 / 코드 3패널 인터랙티브 탐색
# f 키 → 자동 패치 → 🚀 Deployment Approved
```

---

## 0.5 Vibe Coding Vulnerability Taxonomy

AI 코드 생성 도구(Claude/GPT/Cursor)로 작성된 Python 코드에서 **반복적으로 등장하는 보안 취약 패턴** 7종. bandit/semgrep 등 기존 도구는 일반 보안 규칙을 적용하지만, SLAyer는 **바이브코딩 출력에 특화된 룰셋**을 사용한다.

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
| V-06 | NO_INSECURE_HASH | `hashlib.md5/sha1` + 패스워드 컨텍스트 | high | 구식 튜토리얼 |
| V-07 | NO_BARE_EXCEPT | `except:` 또는 `except Exception: pass` | medium | "에러 없애줘" 프롬프트 |

### 패치 전략 (실제 동작하는 코드로 교체)

| Rule | 기존 (단순 차단) | 새 전략 (기능 보존) |
|------|----------------|-------------------|
| NO_HARDCODED_SECRETS | NotImplementedError | `os.environ.get("VAR_NAME", "")` |
| NO_NETWORK | NotImplementedError | `raise NotImplementedError` (외부 호출은 차단이 맞음) |
| NO_EXEC | NotImplementedError | `subprocess.run([cmd, arg], shell=False)` 인수 리스트 변환 |
| SQL_PARAM_BINDING | NotImplementedError | `cursor.execute("... ?", (val,))` 파라미터 바인딩 |
| NO_DEBUG_MODE | NotImplementedError | `os.environ.get("DEBUG", "false").lower() == "true"` |
| NO_INSECURE_HASH | NotImplementedError | `hashlib.pbkdf2_hmac("sha256", ...)` 또는 `bcrypt` |
| NO_BARE_EXCEPT | NotImplementedError | `except Exception as e: logger.warning(e)` |

---

## 1. 아키텍처

단일 Python 패키지. **Textual** TUI + CI 논인터랙티브 모드.

```
slayer/
├── slayer/
│   ├── cli.py              # entry point (slayer scan / init)
│   ├── tui/
│   │   ├── app.py          # Textual App — SLayerTUI
│   │   ├── screens/
│   │   │   └── scan_screen.py
│   │   └── widgets/
│   │       ├── file_panel.py       # Textual ListView
│   │       ├── violation_panel.py  # Textual DataTable
│   │       └── code_viewer.py      # Textual TextArea (read-only)
│   ├── models.py           # Pydantic 모델: SLARule, Violation, ScanResult, PatchResult
│   ├── config.py           # .slayer.yml 로딩 및 API 키 우선순위 관리
│   ├── analyzers/
│   │   ├── sla_parser.py    # Claude API → SLARule[] 파싱
│   │   ├── ast_analyzer.py  # 결정적 정적 분석 (Claude 불필요)
│   │   └── llm_analyzer.py  # CUSTOM 룰 시맨틱 분석 (Claude)
│   └── patcher/
│       └── llm_patcher.py   # claude-sonnet-4-6
├── pyproject.toml           # entry_point: slayer = slayer.cli:app
├── demo_vuln.py
└── spec.md
```

---

## 2. CLI 인터페이스

### 2-1. slayer scan

```bash
slayer scan <path> [OPTIONS]

Arguments:
  path  파일 또는 디렉토리 경로 (재귀적으로 .py 수집)

Options:
  --rules TEXT        자연어 SLA 규칙 (줄바꿈 구분 또는 반복)
  --rules-file PATH   .slayer.yml 경로 (기본: 현재 디렉토리)
  --ci                TUI 없이 plain 텍스트 출력 (파이프 / CI 환경)
  --format [text|json|junit]  --ci 모드 출력 형식 (기본: text)
  --no-color          색상 없는 출력
  --api-key TEXT      ANTHROPIC_API_KEY (환경변수 우선)
```

**실행 모드 결정**:
- stdout이 TTY이고 `--ci` 없으면 → TUI 모드
- `--ci` 또는 파이프 환경 → non-interactive plain/JSON 출력
- `--no-color`: CI 모드 plain 텍스트 출력에서만 적용 (TUI는 Textual이 색상 처리하므로 무시)

**다중 파일 스캔 동작**:
- 디렉토리 지정 시 재귀적으로 `.py` 파일 수집 (glob `**/*.py`, `exclude` 패턴 제외)
- 파일별 ScanResult 생성. TUI의 Files panel에 파일당 위반 수 배지 표시.
- ScanResult.violations는 전체 파일 violations 합산. ScanResult.pass_count/fail_count는 룰 기준 (파일 기준 아님).

**Exit codes:**
- `0` — 모든 룰 통과 (Deployment Approved)
- `1` — 위반 존재 (Deployment BLOCKED)
- `2` — 오류 (API key 없음, 파일 읽기 실패 등)

### 2-2. slayer init

```bash
slayer init
# .slayer.yml 생성
```

생성되는 `.slayer.yml`:
```yaml
rules:
  - "외부 네트워크 호출 없음"
  - "shell 명령어 실행 없음"
  - "하드코딩된 비밀번호/API 키 없음"
  - "SQL 쿼리에 사용자 입력 직접 삽입 없음"

exclude:
  - "tests/"
  - "venv/"
  - "__pycache__/"

# api_key: "..."  # 환경변수 ANTHROPIC_API_KEY 우선, 없을 때만 사용
```

**기본 4개 룰** (AC-04 — `--rules` 미입력 + `.slayer.yml` 없을 때 자동 적용):
1. `"외부 네트워크 호출 없음"` → NO_NETWORK (critical)
2. `"shell 명령어 실행 없음"` → NO_EXEC (critical)
3. `"하드코딩된 비밀번호/API 키 없음"` → NO_HARDCODED_SECRETS (critical)
4. `"SQL 쿼리에 사용자 입력 직접 삽입 없음"` → SQL_PARAM_BINDING (high)

**API 키 로딩 우선순위** (`config.py`):
1. `--api-key` CLI 플래그
2. `ANTHROPIC_API_KEY` OS 환경변수
3. `.slayer.yml` → `api_key` 필드
4. 없으면 → AC-11 에러 처리

---

## 3. TUI 레이아웃 (Textual)

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
│ 10 │      # 외부 서버로 데이터를 보내는 코드예요.            │
│ 11 │                                                       │
├───────────────────────────────────────────────────────────┤
│  [F] Fix All   [R] Rescan   [Q] Quit   [↑↓] Navigate      │  ← 1줄
└───────────────────────────────────────────────────────────┘
```

**레이아웃 비율**: 좌(Files) 30% / 우(Violations+Code) 70%. 우측 상단(Violations) 60% / 우측 하단(Code viewer) 40%. 하단 keybindings bar 1줄 고정.

### 패널 상세

**Files panel** (왼쪽 30%)
- 스캔 대상 `.py` 파일 목록
- 파일명 옆 위반 수 배지 (빨간 숫자 / 통과 시 초록 체크)
- `Enter` 또는 `↑↓`로 선택 → Violations panel 업데이트

**Violations panel** (오른쪽 상단 60%)
- 선택된 파일의 위반 목록 (rule_type + file:line + 한줄 explanation)
- `↑↓`로 선택 → Code viewer 해당 위치로 스크롤
- 통과 시 "✓ All rules passed" 표시

**Code viewer** (오른쪽 하단 40%, 줄 번호 포함)
- 선택된 위반의 코드 컨텍스트 (±3줄)
- 위반 라인 강조 표시 (`►` 마커 + 빨간 배경)
- 파일 전체 스크롤 가능

**Keybindings bar** (하단 1줄)
| 키 | 동작 |
|----|------|
| `f` | Fix All — 모든 위반 자동 패치 (Claude) |
| `r` | Rescan — 재스캔 |
| `q` | Quit |
| `↑` / `k` | 위 항목 선택 |
| `↓` / `j` | 아래 항목 선택 |
| `Tab` | 패널 포커스 전환 |

### TUI 초기 상태

TUI 실행 직후:
1. 스캔 대상 `.py` 파일 목록이 Files panel에 표시됨
2. 첫 번째 파일이 자동 선택됨
3. SLA 파싱 + AST 스캔이 백그라운드에서 자동 시작 (`app.call_later(run_scan)`)
4. 스캔 중: Violations panel에 "Scanning..." 스피너 표시
5. 스캔 완료: 첫 번째 파일의 위반 목록 자동 로드

### Fix 플로우 (TUI)

1. `f` 키 입력
2. Violations panel에 "Patching via claude-sonnet-4-6..." 스피너 오버레이
3. Claude API 호출은 `asyncio.get_event_loop().run_in_executor()` 또는 `app.call_in_thread()`로 실행 (TUI 이벤트 루프 블로킹 방지)
4. 파일 직접 수정 완료
5. 자동 재스캔 (스피너)
6. violations = 0 → 전체 화면에 "🚀 Deployment Approved" 배너
7. `q` 로 종료 시 exit 0

### API 에러 처리 (TUI)

| 에러 상황 | TUI 표시 |
|----------|---------|
| API 키 없음 | Violations panel에 빨간 에러 박스 + 설정 방법 3줄 안내 |
| API 타임아웃 (>30초) | "Patch timeout — try again (f)" 메시지 + 원본 파일 복원 |
| API 응답 파싱 실패 | "Patch failed — invalid response. Original file preserved." |
| 네트워크 끊김 | "Connection error — check internet and retry (r)" |

모든 에러 케이스에서 원본 파일은 패치 전에 임시 백업 후, 실패 시 자동 복원.

---

## 4. CI 모드 출력 (--ci)

### text 형식 (기본)

```
$ slayer scan demo_vuln.py --rules "..." --ci

 SLAyer  Parsing 4 rules...

  Rule                    Type                    Severity
  외부 네트워크 호출 없음   NO_NETWORK              critical
  shell 실행 없음          NO_EXEC                 critical
  하드코딩 credential 없음  NO_HARDCODED_SECRETS    critical
  SQL 파라미터 바인딩       SQL_PARAM_BINDING        high

 Scanning demo_vuln.py

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
      "explanation": "외부 서버로 데이터를 보내는 코드예요..."
    }
  ],
  "pass_count": 0,
  "fail_count": 4,
  "deployable": false
}
```

---

## 5. 데이터 모델

```python
# slayer/models.py

RuleType = Literal["NO_NETWORK","NO_EXEC","NO_HARDCODED_SECRETS",
                   "SQL_PARAM_BINDING","NO_EVAL","CUSTOM"]
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
    rule_name: str     # SLARule.name 역참조 (JSON 출력 편의)
    file: str          # 절대 경로
    line: int
    col: int           # 항상 0 (라인 단위 탐지)
    code_snippet: str
    explanation: str   # "~을 하면 ~이 됩니다" 형식 한국어

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
```

---

## 6. SLA 파싱 (Claude API)

**엔드포인트**: `slayer/analyzers/sla_parser.py`

```python
PARSE_SYSTEM = """
자연어 보안 조건을 JSON 배열로 변환한다.
출력: JSON 배열만 (마크다운, 코드블록 없음).

각 항목:
{
  "id": "rule_N",
  "name": "...",
  "description": "보안 용어 없이 '~을 하면 ~이 됩니다' 형식 한국어",
  "raw_nl": "원본 입력",
  "rule_type": "NO_NETWORK|NO_EXEC|NO_HARDCODED_SECRETS|SQL_PARAM_BINDING|NO_EVAL|CUSTOM",
  "severity": "critical|high|medium"
}

매핑:
- 네트워크/http → NO_NETWORK (critical)
- shell/subprocess → NO_EXEC (critical)
- password/secret/token/key → NO_HARDCODED_SECRETS (critical)
- SQL/injection → SQL_PARAM_BINDING (high)
- eval/동적실행 → NO_EVAL (high)
- 그 외 → CUSTOM (medium)
"""
```

빈 rules 입력 시 기본 4개 룰 자동 적용 (AC-04).

---

## 7. AST Analyzer

Claude 없이 결정적으로 동작. **7개 Vibe Coding 특화 규칙** (기존 5 + 신규 2).

```python
# NO_NETWORK — ast.Import / ast.ImportFrom 탐지 후 해당 라이브러리 .Call 탐지
NETWORK_IMPORTS = {
    "requests", "urllib", "urllib3", "httpx",
    "aiohttp", "socket", "websocket", "boto3"
}
NETWORK_METHODS = {
    "get", "post", "put", "delete", "patch",
    "request", "urlopen", "socket"
}

# NO_EXEC — ast.Call 노드에서 함수명 매칭
EXEC_MODULE_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "os.system", "os.popen",
    "os.execvp", "os.execve"
}
EXEC_BUILTINS = {"eval", "exec", "compile"}

# NO_HARDCODED_SECRETS — 정규식 6종으로 라인 단위 스캔
# (1) 패스워드류 변수 할당: password/passwd/pwd = "..."
# (2) API 키 변수 할당: api_key/apikey = "..." (8자 이상)
# (3) 시크릿/토큰 변수 할당: secret/token = "..." (8자 이상)
# (4) OpenAI 스타일 키: sk- 로 시작하는 20자 이상 알파뉴메릭
# (5) AWS Access Key: aws_access_key_id = "A...Z0-9" (16자 이상)
# (6) GitHub PAT: ghp_ 로 시작하는 36자 알파뉴메릭

# SQL_PARAM_BINDING — ast 두 단계 탐지
# 1단계: ast.JoinedStr (f-string) 또는 % BinOp 또는 .format() Call 내부에 SQL 키워드 포함
# 2단계: SQL_KEYWORDS = r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b' 정규식으로 확인

# NO_EVAL — ast.Call.func가 Name.id ∈ {"eval", "exec", "compile"} 인 노드
```

```python
# NO_DEBUG_MODE — 신규 추가 (Vibe Coding 패턴 V-05)
DEBUG_PATTERNS = [
    r'(?i)^DEBUG\s*=\s*True',               # DEBUG = True
    r'(?i)debug\s*=\s*True',                 # debug=True (kwarg)
    r'app\.run\(.*debug\s*=\s*True',         # Flask app.run(debug=True)
    r'app\.config\[.DEBUG.\]\s*=\s*True',    # Flask config
]

# NO_INSECURE_HASH — 신규 추가 (Vibe Coding 패턴 V-06)
# ast.Call에서 hashlib.md5 / hashlib.sha1 + 패스워드 변수명 컨텍스트
INSECURE_HASH_FUNCS = {"md5", "sha1", "sha"}
# 같은 함수 내에 password/passwd/pwd 변수명이 있으면 위반

# NO_BARE_EXCEPT — 신규 추가 (Vibe Coding 패턴 V-07)
# ast.ExceptHandler.type is None (bare except:)
# 또는 ast.ExceptHandler.type = Exception + body[0] = Pass
```

**탐지 정확도 기준**: demo_vuln.py 기준 **7개 위반** 모두 탐지 (0 false negative). 임포트만 있고 실제 호출 없는 경우는 위반으로 처리하지 않음 (NO_EXEC, NO_EVAL 제외 — 실제 함수 호출 탐지).

---

## 8. LLM Analyzer (CUSTOM 룰 fallback)

```python
ANALYZE_SYSTEM = """
Python 코드를 주어진 보안 룰에 따라 검사하세요.
위반 발견 시 JSON 배열 반환, 없으면 [] 반환.
출력: JSON만.

각 위반:
{"line": <int>, "col": 0, "code_snippet": "<줄>", "explanation": "<한국어>"}
"""
# model: claude-sonnet-4-6, max_tokens: 2048
```

---

## 9. LLM Patcher

```python
PATCH_SYSTEM = """
Python 코드의 보안 위반을 최소한으로 수정하세요.
수정된 전체 코드만 반환 (설명, 마크다운 없이).

수정 지침 (rule_type별, 기능 보존 우선):
- NO_HARDCODED_SECRETS: os.environ.get("ORIGINAL_VAR_NAME", "")로 교체 (import os 추가)
- NO_NETWORK: raise NotImplementedError("외부 호출이 SLA에 의해 차단됨") — 외부 호출은 차단이 맞음
- NO_EXEC: shell=True인 경우 shell=False + 인수 리스트로 변환
  예) subprocess.run(f"cmd {arg}", shell=True) → subprocess.run(["cmd", arg], shell=False)
  shell 파라미터 없이 문자열 전달하는 경우만 NotImplementedError
- SQL_PARAM_BINDING: 파라미터 바인딩으로 교체
  예) cursor.execute(f"SELECT ... '{x}'") → cursor.execute("SELECT ... ?", (x,))
- NO_DEBUG_MODE: 환경변수 참조로 교체
  예) DEBUG = True → DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
      app.run(debug=True) → app.run(debug=os.environ.get("DEBUG","false")=="true")
- NO_INSECURE_HASH: 안전한 해시로 교체
  예) hashlib.md5(pwd.encode()) → hashlib.pbkdf2_hmac("sha256", pwd.encode(), os.urandom(16), 100000)
- NO_BARE_EXCEPT: 로깅으로 교체
  예) except: pass → except Exception as e: logger.warning("Suppressed error: %s", e)
  (import logging + logger 정의 없으면 추가)
- NO_EVAL: ast.literal_eval 또는 raise NotImplementedError

안전성 원칙:
- 위반하지 않는 코드는 한 글자도 변경하지 않는다
- 함수 시그니처, 반환 타입, 클래스 구조를 유지한다
- 위반 라인만 최소 범위로 수정한다
"""
# model: claude-sonnet-4-6, max_tokens: 8192
```

**패치 안전성 검증**: 패치 완료 후 AST Analyzer를 재실행하여 remaining_violations가 [] 인지 확인. 재스캔 후 새로운 위반이 발생한 경우 PatchResult.remaining_violations에 포함.

---

## 10. Acceptance Criteria

| ID | 조건 | 검증 |
|----|------|------|
| AC-01 | `slayer scan <path>` → `.py` 자동 수집 후 TUI 실행 | 직접 실행 |
| AC-02 | `.py` 없으면 (빈 디렉토리 포함) warning 출력 + exit 0 | 빈 디렉토리 |
| AC-03 | SLA 파싱 5초 이내 (TUI 스피너) | 타이머 |
| AC-04 | `--rules` 미입력 시 `.slayer.yml` fallback, 없으면 기본 4개 룰 | 빈 입력 |
| AC-05 | 스캔 결과 3초 이내 TUI 렌더링 (1000줄 이하). 초과 시 "Large file — scanning..." progress bar 표시 | 타이머 |
| AC-06 | 룰별 위반 + file:line + 한국어 explanation + 코드 컨텍스트 | TUI 탐색 |
| AC-07 | violations 있으면 exit 1 (`--ci` 모드) | `echo $?` |
| AC-08 | `f` 키 → 패치 완료 후 자동 재스캔 → TUI 업데이트 | TUI 조작 |
| AC-09 | 패치 후 전체 통과 → "Deployment Approved" 배너 → exit 0 | 재스캔 결과 |
| AC-10 | `--format json --ci` → 파싱 가능한 JSON stdout | `jq` 파이핑 |
| AC-11 | `ANTHROPIC_API_KEY` 없으면 TUI 인라인 에러 + 설정 방법 | 키 없이 실행 |
| AC-12 | SyntaxError 파일 → warning badge 후 나머지 계속 | 깨진 .py 포함 |

---

## 11. 개발 순서

| 단계 | 작업 | 예상 |
|------|------|------|
| P0-1 | pyproject.toml + 의존성 (textual, anthropic, pydantic) | 10분 |
| P0-2 | models.py (Pydantic) | 10분 |
| P0-3 | ast_analyzer.py (5개 룰) | 40분 |
| P0-4 | cli.py `scan` 커맨드 + TUI 기본 뼈대 (3패널 레이아웃) | 30분 |
| **P0** | **파일 선택 → AST 스캔 → TUI 표시** | **~1.5h** |
| P1-1 | sla_parser.py (Claude API) | 20분 |
| P1-2 | llm_analyzer.py (CUSTOM 룰) | 20분 |
| P1-3 | llm_patcher.py + `f` 키 Fix 플로우 | 30분 |
| P1-4 | `--ci` + `--format json` 출력 | 15분 |
| P1-5 | config.py + `slayer init` | 15분 |
| **P1** | **전체 플로우 동작** | **~3.5h** |
| P2-1 | Deployment Approved 배너 애니메이션 | 20분 |
| P2-2 | `--format junit` (CI 통합) | 20분 |
| P2-3 | PyPI 패키지 빌드 | 20분 |

---

## 12. 데모 시나리오 (3분)

```bash
# 1. 설치
pip install slayer-sec

# 2. TUI 스캔 — 4개 위반 발견
slayer scan demo_vuln.py --rules "외부 네트워크 호출 없음\nshell 실행 없음\n하드코딩 credential 없음\nSQL 파라미터 바인딩"
# → TUI 실행, 파일 패널 / 위반 패널 / 코드 뷰어 시연
# → 위반 코드 라인 네비게이션

# 3. 자동 패치 (f 키)
# → "Patching via claude-sonnet-4-6..." 스피너
# → 재스캔 → 🚀 Deployment Approved

# 4. CI 통합 예시
slayer scan ./src --format json --ci | jq '.deployable'
# → true
```

**demo_vuln.py 내용:**
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
# 또는
pipx install slayer-sec

# pre-commit 통합
# .pre-commit-config.yaml:
# - repo: local
#   hooks:
#     - id: slayer
#       name: SLAyer Security Check
#       entry: slayer scan
#       args: [--rules-file, .slayer.yml, --ci]
#       language: python
#       types: [python]
```

---

## 14. JUnit 출력 형식 (--format junit --ci)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="SLAyer" tests="{rule_count}" failures="{fail_count}" errors="0">
  <testcase name="{rule_name}" classname="slayer.{rule_type}">
    <!-- 위반 없을 때: 빈 testcase -->
  </testcase>
  <testcase name="{rule_name}" classname="slayer.{rule_type}">
    <failure message="{explanation}" type="{rule_type}">
      {file}:{line} — {code_snippet}
    </failure>
  </testcase>
</testsuite>
```

---

## 15. 의존성

```toml
[project]
dependencies = [
    "textual>=0.47.0",
    "anthropic>=0.23.0",
    "pydantic>=2.0",
    "typer>=0.9.0",
    "rich>=13.0",      # CI 모드 출력용
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio"]
```
