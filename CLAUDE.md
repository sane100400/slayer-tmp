# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**SLAyer** — CMUX x AIM 해커톤 | Developer Tooling 트랙 | 2026-04-26

바이브코딩으로 만든 Python 웹 서비스 코드를 파일 경로로 지정하면, 7가지 웹 취약점을 자동 탐지하고 Claude API로 한 번에 패치하는 네이티브 GUI 바이너리.

---

## 개발 실행

두 개의 터미널이 필요하다.

```bash
# 터미널 1 — Python 백엔드
cd backend
pip install -r requirements.txt
python3 -m uvicorn main:app --port 18765 --reload

# 터미널 2 — Tauri 앱 (Linux에서 PKG_CONFIG_PATH 필요)
source ~/.cargo/env
export PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH"
npm run tauri dev
```

프론트엔드 타입 검사만 할 때:
```bash
npm run build   # tsc + vite build
```

백엔드 AST 분석기 단독 테스트:
```bash
cd backend
python3 -c "
from analyzers import ast_analyzer
from models import SLARule
rule = SLARule(id='r1', name='test', description='', raw_nl='', rule_type='SQL_INJECTION', severity='critical')
vs = ast_analyzer.analyze(open('../demo_vuln.py').read(), rule, 'demo_vuln.py')
print(len(vs), 'violations')
"
```

백엔드 API 직접 호출:
```bash
curl http://localhost:18765/api/health

curl -X POST http://localhost:18765/api/scan \
  -H "Content-Type: application/json" \
  -d '{"files":["/abs/path/demo_vuln.py"],"rules":[{"id":"r1","name":"SQLi","description":"test","raw_nl":"","rule_type":"SQL_INJECTION","severity":"critical"}]}'
```

---

## 아키텍처

```
React (TypeScript) WebView
    ↕  tauri::invoke  (pick_path, list_py_files, read_file)
Rust Core  src-tauri/src/lib.rs
    ↕  HTTP 127.0.0.1:18765
Python FastAPI  backend/
    ├── analyzers/ast_analyzer.py   (결정적 AST 분석, Claude 불필요)
    ├── analyzers/llm_analyzer.py   (CUSTOM 룰 fallback)
    └── patcher/llm_patcher.py      (claude-sonnet-4-6)
```

**핵심 흐름:**
1. `pick_path` Tauri 커맨드 → OS 다이얼로그 또는 텍스트박스 경로 입력 → `list_py_files` → `.py` 절대 경로 목록
2. `POST /api/scan` — 파일 목록 + PRESET_RULES(7개) → AST 분석 → `ScanResult`
3. `POST /api/patch` — 위반 목록 → Claude 패치 → 파일 직접 덮어쓰기 → 자동 재스캔

**UX 흐름 (3단계):** 파일 선택 → 스캔 → 딸깍 패치

규칙은 `src/App.tsx`의 `PRESET_RULES` 상수에 하드코딩되어 있다. 사용자는 규칙을 볼 필요 없다.

---

## 탐지 룰 (7종)

| rule_type | 탐지 방법 | 위험도 |
|-----------|----------|--------|
| `SQL_INJECTION` | f-string/% 포맷 SQL | critical |
| `HARDCODED_SECRETS` | 정규식 (password/api_key/token/sk-…) | critical |
| `COMMAND_INJECTION` | subprocess.*/os.system/eval/exec 호출 | critical |
| `DEBUG_MODE_ON` | `debug=True` kwarg, `DEBUG = True` 할당 | high |
| `INSECURE_COOKIE` | `set_cookie()` without httponly/secure | high |
| `WEAK_HASH` | `hashlib.md5/sha1`, `hashlib.new("md5")` | high |
| `OPEN_REDIRECT` | `redirect(request.args.get(…))` | medium |

AST 분석은 Claude 없이 동작한다. `CUSTOM` 룰만 `llm_analyzer.py`로 fallback.

---

## API 키 전달 방식

프론트엔드 `localStorage["ANTHROPIC_API_KEY"]` → 모든 fetch에 `X-API-Key` 헤더 → FastAPI `get_client(api_key)` → `anthropic.Anthropic(api_key=key)`.

OS 환경변수 `ANTHROPIC_API_KEY`도 fallback으로 동작한다.

---

## 데이터 모델

`src/types/index.ts`와 `backend/models.py`가 동일한 스키마를 공유한다.

```
SLARule     { id, name, description, raw_nl, rule_type, severity }
Violation   { rule_id, file(절대경로), line, col, code_snippet, explanation }
ScanResult  { rules[], violations[], pass_count, fail_count, deployable }
PatchResult { original_code, patched_code, diff, remaining_violations, deployable }
```

`rule_type` 추가 시 반드시 두 파일 모두 업데이트해야 한다.

---

## Linux 빌드 환경 주의사항

- WSL2에서 실행 시 `PKG_CONFIG_PATH` 설정 필수 (위 명령 참조)
- `src-tauri/.cargo/config.toml`에 `-L /usr/lib/x86_64-linux-gnu` 링커 경로 고정되어 있음
- Tauri v2 dialog 플러그인: `blocking_pick_file_or_folder()` 없음 → `blocking_pick_folder()` + 텍스트 입력 fallback 사용 중 (`FileSelector.tsx`)

---

## 데모 파일

`demo_vuln.py` — Flask 웹 앱에 7가지 취약점 전부 포함. 스캔 시 12건 위반 탐지 확인됨.
