# SLAyer

> **바이브코딩 웹서비스 전문 보안 스캐너**  
> CMUX × AIM 해커톤 2026 · Developer Tooling 트랙

바이브코딩(Claude / GPT / Cursor)으로 생성된 **웹서비스 코드(Python · JS · TS)** 에서  
7가지 보안 취약 패턴을 탐지하고, 이미 설치된 AI CLI로 자동 패치 후 배포 게이트를 여는 도구.

```bash
# 개발 설치
pip install -e ".[dev]"

slayer start .    # 스캔 → 위반 목록 출력
slayer patch .    # 스캔 → 자동 패치 → 🚀 Deployment Approved
```

**API 키 없음.** Claude Code / Codex / Gemini가 이미 설치되어 있으면 바로 패치.  
`slayer start`는 AI 없이도 동작. `slayer patch`만 AI CLI 하나가 필요.

---

## Why SLAyer?

bandit, semgrep 같은 기존 도구는 일반 보안 규칙을 쓴다.  
SLAyer는 **AI 생성 코드의 반복 취약 패턴**을 데이터 기반으로 탐지한다.

| | SLAyer | Bandit | Semgrep |
|---|---|---|---|
| 대상 | AI 생성 코드 특화 패턴 | Python 범용 | 범용 (규칙 작성 필요) |
| 언어 | Python · JS · TS | Python | 다수 |
| 패치 | AI CLI로 자동 패치 | 없음 | 없음 |
| 설정 | 0 — 바로 실행 | 설정 필요 | 규칙 파일 필요 |

| 원인 | 패턴 |
|------|------|
| "일단 동작하게" 프롬프트 | 하드코딩 크레덴셜, 외부 호출, `shell=True` |
| 오래된 튜토리얼 학습 데이터 | f-string SQL, `Math.random()` 토큰 생성 |
| 개발 예제 그대로 배포 | `DEBUG=True`, `debug: true` |
| "에러 없애줘" 프롬프트 | `except: pass`, 빈 `catch {}` |

---

## 왜 이 7가지인가?

`CLAUDE.md` 보유 GitHub 레포를 직접 수집·분석해 빈도를 측정하고,  
**빈도 × 중요도 합산 매트릭스**로 최종 7종을 선별했다.

```
최종 점수 = 중요도_가중합 × 0.6 + log10(빈도) / log10(max) × 5 × 0.4
```

중요도는 5축으로 평가: 공격 가능성(25%) · 피해 심각도(25%) · Time-to-Exploit(20%) · 탐지 신뢰도(15%) · AI 증폭 인수(15%).

| 룰 | 최종 점수 | Severity |
|----|-----------|----------|
| NO_HARDCODED_SECRETS | 5.00 | critical |
| NO_EXEC | 3.98 | critical |
| SQL_PARAM_BINDING | 3.91 | high |
| NO_DEBUG_MODE | 3.87 | high |
| NO_NETWORK | 2.63 | critical |
| NO_WEAK_RANDOM | 2.91 | high |
| NO_BARE_EXCEPT | 3.00 | medium |

> 상세 방법론: [`spec.md § 0.55`](./spec.md)

---

## 지원 언어

Python (`.py`) · JavaScript (`.js`, `.jsx`) · TypeScript (`.ts`, `.tsx`)

## 지원 OS 및 AI CLI

- **OS:** Windows, macOS, Linux
- **Python:** 3.11 이상
- **AI CLI 패치:** 로컬 PATH에 설치된 Claude Code, Codex CLI, Gemini CLI

```bash
slayer model auto      # claude → codex → gemini 순서로 자동 감지
slayer model claude    # Claude Code 고정 후 .slayer.yml에 저장
slayer model codex     # Codex CLI 고정
slayer model gemini    # Gemini CLI 고정
```

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
  ● CRITICAL  NO_HARDCODED_SECRETS  demo_vuln.py:3
              API_KEY = "sk-prod-abc123..."
              → Use os.environ.get('API_KEY') — keep secrets out of the code.

  ▲ HIGH      SQL_PARAM_BINDING     demo_vuln.py:7
              cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
              → Use cursor.execute('SELECT ... WHERE name=?', (name,))

  4 violations · 🔒 Deployment BLOCKED

  Run slayer patch demo_vuln.py to fix automatically.
```

### slayer patch — 자동 패치

```bash
slayer patch demo_vuln.py        # 스캔 → 패치 → 재스캔
slayer patch . --format json     # JSON 결과 출력
```

`.slayer.yml`에 `ai:` 설정이 필요합니다. `slayer model claude`로 먼저 설정하세요.

출력 예시:
```
  Patching via claude...

  ✓  demo_vuln.py patched

  Patch explanations:
  • NO_HARDCODED_SECRETS  demo_vuln.py:3  — 비밀값을 코드 밖으로 옮겼어요
    하드코딩된 키나 비밀번호 대신 환경 변수 조회를 사용하도록 바꿔...

  🚀 Deployment Approved
```

### slayer model — AI CLI 설정

```bash
slayer model              # 감지 상태 + 현재 설정 확인
slayer model claude       # claude 사용으로 .slayer.yml에 저장
slayer model codex        # codex 사용으로 저장
slayer model auto         # 자동 감지로 초기화
```

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
```

의존성: `pydantic` · `typer` · `rich` — AI SDK 없음, API 키 불필요.

---

## 벤치마크

### slayer-bench-v0 — 수작업 큐레이션

32 케이스 (22 취약 + 6 FP-free + 4 blind_spot) 전수 실행 결과:

**In-scope 탐지 (직접 패턴):**

| 지표 | 값 |
|------|-----|
| TP (정탐) | 22 |
| FP (오탐) | 0 |
| TN (정상 정확 처리) | 6 |
| FN (미탐) | 0 |
| **Precision** | **1.000** |
| **Recall** | **1.000** |
| **F1** | **1.000** |

**Blind spot 케이스 (알려진 한계 — 탐지하지 않음):**

| 케이스 | 룰 | 이유 |
|--------|-----|------|
| 변수 경유 SSRF | NO_NETWORK | URL을 부분 조합 후 호출 — 직접 사용자 입력 아님 |
| 함수 리턴 시크릿 | NO_HARDCODED_SECRETS | `return "sk-..."` 형태 — 직접 대입 패턴만 탐지 |
| split() 셸 인젝션 | NO_EXEC | `shell=False` + `cmd.split()` — 셸 체크 통과하나 여전히 취약 |
| 배열 조인 SQL | SQL_PARAM_BINDING | `parts.join(' ')` 조합 — template literal/concat 패턴 아님 |

룰별 케이스 수:

| 룰 | 케이스 |
|----|--------|
| NO_WEAK_RANDOM | 5 |
| NO_NETWORK | 4 |
| NO_HARDCODED_SECRETS | 3 |
| SQL_PARAM_BINDING | 3 |
| NO_DEBUG_MODE | 3 |
| NO_EXEC | 2 |
| NO_BARE_EXCEPT | 2 |

### ai-bench-v1 — AI 생성 코드 독립 검증

Claude Haiku(`claude-haiku-4-5`)가 생성한 실제 웹서비스 코드 4개 파일을 SLAyer로 스캔:

| 파일 | 언어 | 라인 수 | 탐지된 위반 |
|------|------|---------|------------|
| user-auth-service-py.py | Python | 125 | 10 |
| data-pipeline-py.py | Python | 240 | 1 |
| rest-api-js.js | JavaScript | 211 | 4 |
| webhook-handler-ts.ts | TypeScript | 475 | 0 |

총 15개 위반 탐지. 룰별: SQL_PARAM_BINDING(5) · NO_BARE_EXCEPT(3) · NO_DEBUG_MODE(3) · NO_WEAK_RANDOM(2) · NO_HARDCODED_SECRETS(1) · NO_EXEC(1)

바이브코딩 결과물에서 SLAyer가 탐지 대상으로 삼는 패턴이 실제로 나타남을 학습 데이터와 독립된 방법으로 검증.

> slayer-bench-v0 케이스 출처: SecretBench · CredData · OWASP Benchmark · SecurityEval · PatchEval · CVEfixes · SARD/Juliet · NVD CVE

---

## 한계

- **간접 SSRF 미탐지**: `requests.get(url)` 형태에서 `url`이 외부에서 주입되는 경우만 탐지. 변수를 거쳐 우회하는 패턴(`url = user_input; requests.get(url)`)은 현재 탐지하지 않음.
- **동적 코드 미탐지**: `eval()`, `exec()`에 문자열을 동적으로 조립하는 패턴은 탐지 범위 외.
- **암호화 컨텍스트 구분**: `NO_WEAK_RANDOM`은 보안 컨텍스트(토큰·세션·OTP) 근처의 `random` 사용을 탐지하나, 모든 보안 컨텍스트를 완벽히 인식하지 않음.
- **패치 범위**: AI 패치는 탐지된 위반만 수정. 탐지되지 않은 취약점은 그대로 남음.

---

## 아키텍처

```
slayer/
├── cli.py              # slayer start / patch / model
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
- [`dataset/slayer-bench-v0/`](./dataset/slayer-bench-v0/) — 취약/패치/FP-free 벤치마크
- [`dataset/ai-bench-v1/`](./dataset/ai-bench-v1/) — AI 생성 코드 벤치마크
- [`presentation.html`](./presentation.html) — 발표 자료

---

*CMUX × AIM 해커톤 2026 · Developer Tooling 트랙*
