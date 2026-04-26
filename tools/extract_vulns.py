"""
dataset/ 폴더의 Python/JS/TS/JSX/TSX/HTML 파일에서
최대한 넓게 취약점을 탐지한 뒤, 빈도 기준 상위 7종을 출력.

사용법:
  python tools/extract_vulns.py
  python tools/extract_vulns.py --dataset dataset/ --output dataset/vulns.jsonl --workers 8
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ── 지원 확장자 ──────────────────────────────────────────────
SUPPORTED_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".html"}

# ═══════════════════════════════════════════════════════════
# 웹서비스 파일 필터
# ═══════════════════════════════════════════════════════════

WEB_FRAMEWORK_PY = re.compile(
    r"^\s*(import|from)\s+"
    r"(flask|django|fastapi|aiohttp|tornado|starlette|bottle|falcon|"
    r"sanic|quart|pyramid|cherrypy|uvicorn|connexion|responder|"
    r"werkzeug|jinja2|sqlalchemy|databases|tortoise|peewee|"
    r"requests|httpx|pydantic|jwt|authlib)",
    re.IGNORECASE | re.MULTILINE,
)

WEB_FRAMEWORK_JS = re.compile(
    r"(require\s*\(\s*['\"]"
    r"(express|fastify|koa|hapi|nestjs|next|nuxt|remix|sveltekit|"
    r"hono|elysia|prisma|sequelize|typeorm|mongoose|"
    r"axios|node-fetch|mysql|pg|sqlite|mongodb|redis|jsonwebtoken|passport)['\"]"
    r"|from\s+['\"]"
    r"(express|fastify|koa|next|nuxt|hono|elysia|"
    r"prisma|sequelize|typeorm|mongoose|axios|node-fetch|"
    r"mysql2|pg|sqlite3|mongodb|ioredis|jsonwebtoken|passport)['\"])",
    re.IGNORECASE,
)

WEB_PATH_HINTS = re.compile(
    r"(route|view|api|handler|controller|endpoint|blueprint|middleware|"
    r"serializer|schema|app|server|auth|login|user|model|database|db|"
    r"admin|dashboard|session|cookie|jwt|token)",
    re.IGNORECASE,
)

EXCLUDE_PATH = re.compile(
    r"(test_|_test\b|\.test\.|\.spec\.|__test|/tests/|conftest|"
    r"migration|alembic|\.github|setup\.py|manage\.py|celery|wsgi|asgi|"
    r"_pb2\.py|proto|fixture|factory|seed|mock|node_modules|dist/|build/)",
    re.IGNORECASE,
)


def is_web_file(filepath: str, content: str, ext: str) -> bool:
    fname = filepath.replace("\\", "/")
    if EXCLUDE_PATH.search(fname):
        return False
    head = "\n".join(content.splitlines()[:80])
    if ext == ".py":
        return bool(WEB_FRAMEWORK_PY.search(head)) or (
            bool(WEB_PATH_HINTS.search(fname)) and ("def " in content or "class " in content)
        )
    if ext in {".js", ".ts", ".jsx", ".tsx"}:
        return bool(WEB_FRAMEWORK_JS.search(head)) or bool(WEB_PATH_HINTS.search(fname))
    if ext == ".html":
        return bool(re.search(r"<script|{%|{{|\$\{", content, re.IGNORECASE))
    return False


# ═══════════════════════════════════════════════════════════
# 공통 상수
# ═══════════════════════════════════════════════════════════

SQL_KW = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC)\b')

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',       "비밀번호"),
    (r'(?i)(api_key|apikey|api[-_]key)\s*[=:]\s*["\'][^"\']{8,}["\']', "API 키"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\'][^"\']{8,}["\']',     "시크릿 키"),
    (r'(?i)(token)\s*[=:]\s*["\'][^"\']{8,}["\']',                      "토큰"),
    (r'sk-[A-Za-z0-9]{20,}',                                             "OpenAI 키"),
    (r'(?i)aws_access_key_id\s*[=:]\s*["\'][A-Z0-9]{16,}["\']',         "AWS 키"),
    (r'ghp_[A-Za-z0-9]{36}',                                             "GitHub 토큰"),
    (r'(?i)(db_pass|database_password|db_password)\s*[=:]\s*["\'][^"\']{4,}["\']', "DB 패스워드"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',                  "개인 키"),
    (r'(?i)(jwt_secret|jwt[-_]key)\s*[=:]\s*["\'][^"\']{8,}["\']',      "JWT 시크릿"),
]

WEAK_HASH_NAMES = {"md5", "sha1", "sha"}
REDIRECT_SRCS = {"request.args", "request.form", "request.values", "request.GET", "request.POST",
                 "request.referrer", "request.url", "req.query", "req.params", "req.body"}


def _snip(lines: list[str], lineno: int, ctx: int = 2) -> str:
    s = max(0, lineno - 1 - ctx)
    e = min(len(lines), lineno + ctx)
    return "\n".join(lines[s:e])


def _v(rule: str, fp: str, lines: list[str], ln: int, col: int, msg: str) -> dict:
    return {"rule_type": rule, "file": fp, "line": ln, "col": col,
            "code_snippet": _snip(lines, ln), "explanation": msg}


# ═══════════════════════════════════════════════════════════
# Python AST 분석 — 넓은 커버리지
# ═══════════════════════════════════════════════════════════

def analyze_py(fp: str, src: str) -> list[dict]:
    lines = src.splitlines()
    try:
        tree = ast.parse(src, filename=fp)
    except SyntaxError:
        return []

    viols: list[dict] = []

    # ── 변수 추적: user-input 유래 변수명 수집 (단순 heuristic) ──
    user_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # var = request.args.get(...) / request.form[...] 등
            val_src = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
            if any(s in val_src for s in ("request.args", "request.form", "request.values",
                                           "request.GET", "request.POST", "request.json",
                                           "request.data", "request.files")):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        user_vars.add(t.id)

    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if not ln:
            continue
        line_src = lines[ln - 1] if ln <= len(lines) else ""

        # ── SQL_INJECTION ─────────────────────────────────
        if isinstance(node, ast.JoinedStr) and SQL_KW.search(line_src):
            viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                "f-string SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            val = ""
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
                val = str(node.left.value)
            elif isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant):
                val = str(node.left.value)
            if val and SQL_KW.search(val):
                viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                    "문자열 연결 SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."))

        elif isinstance(node, ast.Call):
            fn = node.func
            fn_attr = fn.attr if isinstance(fn, ast.Attribute) else ""
            fn_name = fn_attr or (fn.id if isinstance(fn, ast.Name) else "")
            obj_name = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""

            # SQL .format()
            if (fn_attr == "format" and isinstance(fn.value, ast.Constant)
                    and isinstance(fn.value.value, str) and SQL_KW.search(fn.value.value)):
                viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                    ".format() SQL — 사용자 입력이 쿼리에 삽입될 수 있어요."))

            # DEBUG_MODE_ON
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    viols.append(_v("DEBUG_MODE_ON", fp, lines, ln, node.col_offset,
                        "debug=True — 에러 시 서버 내부 코드·경로·환경변수가 노출돼요."))

            # INSECURE_COOKIE
            if fn_name == "set_cookie":
                kws = {kw.arg for kw in node.keywords}
                missing = [f for f in ["httponly", "secure"] if f not in kws]
                if missing:
                    viols.append(_v("INSECURE_COOKIE", fp, lines, ln, node.col_offset,
                        f"쿠키에 {', '.join(missing)} 없음 — JS로 쿠키가 탈취될 수 있어요."))

            # WEAK_HASH
            hash_name = ""
            if fn_attr in WEAK_HASH_NAMES:
                hash_name = fn_attr
            elif fn_name in WEAK_HASH_NAMES:
                hash_name = fn_name
            if fn_attr == "new" and node.args and isinstance(node.args[0], ast.Constant):
                if str(node.args[0].value).lower() in WEAK_HASH_NAMES:
                    hash_name = str(node.args[0].value)
            if hash_name:
                viols.append(_v("WEAK_HASH", fp, lines, ln, node.col_offset,
                    f"{hash_name.upper()} — 1초 내 해독 가능, DB 유출 시 비밀번호 전원 노출됩니다."))

            # COMMAND_INJECTION
            EXEC_ATTRS = {
                "subprocess": {"run", "Popen", "call", "check_output", "check_call"},
                "os": {"system", "popen", "execvp", "execve", "popen2"},
            }
            if fn_name in {"eval", "exec", "compile"} and isinstance(fn, ast.Name):
                viols.append(_v("COMMAND_INJECTION", fp, lines, ln, node.col_offset,
                    f"{fn_name}() — 코드가 동적 실행되어 서버가 원격 조종당할 수 있어요."))
            elif obj_name in EXEC_ATTRS and fn_attr in EXEC_ATTRS[obj_name]:
                viols.append(_v("COMMAND_INJECTION", fp, lines, ln, node.col_offset,
                    f"{obj_name}.{fn_attr}() — 서버 명령어가 원격 실행될 수 있어요."))

            # OPEN_REDIRECT — redirect() + user-controlled arg
            if fn_name == "redirect":
                arg_src = line_src
                # 같은 줄에 request 소스 있거나, 알려진 user_vars 사용
                if any(s in arg_src for s in REDIRECT_SRCS):
                    viols.append(_v("OPEN_REDIRECT", fp, lines, ln, node.col_offset,
                        "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."))
                elif node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in user_vars:
                    viols.append(_v("OPEN_REDIRECT", fp, lines, ln, node.col_offset,
                        "redirect(user_input) — 사용자 입력이 redirect 목적지로 사용돼요."))

            # PATH_TRAVERSAL — open/send_file/send_from_directory + user input
            if fn_name in {"open", "send_file", "send_from_directory", "FileResponse"}:
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in user_vars:
                    viols.append(_v("PATH_TRAVERSAL", fp, lines, ln, node.col_offset,
                        "open(user_input) — 공격자가 서버의 임의 파일을 읽을 수 있어요."))
                elif node.args and isinstance(node.args[0], ast.JoinedStr):
                    viols.append(_v("PATH_TRAVERSAL", fp, lines, ln, node.col_offset,
                        "f-string 파일 경로 — 경로 조작으로 서버 파일이 노출될 수 있어요."))

            # INSECURE_DESERIALIZATION
            if fn_attr in {"loads", "load"} and obj_name in {"pickle", "marshal", "shelve"}:
                viols.append(_v("INSECURE_DESERIALIZATION", fp, lines, ln, node.col_offset,
                    f"{obj_name}.{fn_attr}() — 악성 데이터로 서버 코드가 실행될 수 있어요."))
            if fn_attr == "load" and obj_name == "yaml":
                # yaml.load without Loader=yaml.SafeLoader
                has_safe = any(
                    (kw.arg == "Loader" and isinstance(kw.value, ast.Attribute)
                     and "Safe" in getattr(kw.value, "attr", ""))
                    for kw in node.keywords
                )
                if not has_safe:
                    viols.append(_v("INSECURE_DESERIALIZATION", fp, lines, ln, node.col_offset,
                        "yaml.load() without SafeLoader — 임의 코드가 실행될 수 있어요."))

            # SSRF — requests/httpx + user input
            if (obj_name in {"requests", "httpx", "urllib"}
                    and fn_attr in {"get", "post", "put", "delete", "request", "urlopen"}):
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in user_vars:
                    viols.append(_v("SSRF", fp, lines, ln, node.col_offset,
                        "외부 URL을 사용자 입력으로 — 내부 네트워크를 공격자가 스캔할 수 있어요."))
                elif node.args and isinstance(node.args[0], ast.JoinedStr):
                    viols.append(_v("SSRF", fp, lines, ln, node.col_offset,
                        "f-string URL 요청 — 내부 서버로의 SSRF 공격이 가능할 수 있어요."))

            # CORS_WILDCARD
            if fn_name in {"CORS", "CORSMiddleware"}:
                for kw in node.keywords:
                    if kw.arg in {"origins", "allow_origins"}:
                        val_repr = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                        if '"*"' in val_repr or "'*'" in val_repr:
                            viols.append(_v("CORS_WILDCARD", fp, lines, ln, node.col_offset,
                                "CORS allow_origins='*' — 모든 도메인이 API를 호출할 수 있어요."))

        # DEBUG_MODE_ON: DEBUG = True (module-level)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in {"DEBUG", "TESTING"}:
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        viols.append(_v("DEBUG_MODE_ON", fp, lines, ln, t.col_offset,
                            f"{t.id}=True — 에러 시 서버 내부 정보가 노출돼요."))

    # ── 라인 스캔 ─────────────────────────────────────────
    for ln, line in enumerate(lines, 1):
        # HARDCODED_SECRETS
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, line):
                viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                    f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
                break

        # MASS_ASSIGNMENT: model(**request.form) / Model(**request.json)
        if re.search(r'\*\*(request\.(form|json|values|data|args))', line):
            viols.append(_v("MASS_ASSIGNMENT", fp, lines, ln, 0,
                "**request.form — 사용자가 임의 필드를 덮어써서 권한 상승이 가능해요."))

        # XSS: Markup(user_input) / | safe in templates
        if re.search(r'Markup\s*\(', line) or re.search(r'\|\s*safe\b', line):
            if any(uv in line for uv in ("request.", "form.", "args.")):
                viols.append(_v("XSS", fp, lines, ln, 0,
                    "Markup(user_input) — 사용자 입력이 HTML로 렌더링되어 XSS 공격이 가능해요."))

    return viols


# ═══════════════════════════════════════════════════════════
# JS/TS/JSX/TSX Regex 분석
# ═══════════════════════════════════════════════════════════

JS_LINE_RULES: list[tuple[str, re.Pattern, str]] = [
    ("SQL_INJECTION",
     re.compile(r'`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)[^`]*\$\{', re.I),
     "템플릿 리터럴 SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."),

    ("SQL_INJECTION",
     re.compile(r'["\'][^"\']*\+\s*\w+.*?(SELECT|INSERT|UPDATE|DELETE)\b', re.I),
     "문자열 연결 SQL — 사용자 입력이 쿼리에 직접 삽입돼요."),

    ("COMMAND_INJECTION",
     re.compile(r'\b(eval\s*\(|new\s+Function\s*\(|execSync\s*\(|spawnSync\s*\(|child_process\.exec)', re.I),
     "eval/exec/spawn — 사용자 입력이 서버 명령어로 실행될 수 있어요."),

    ("DEBUG_MODE_ON",
     re.compile(r'\bdebug\s*[=:]\s*true\b', re.I),
     "debug:true — 에러 시 서버 내부 정보가 노출돼요."),

    ("WEAK_HASH",
     re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", re.I),
     "MD5/SHA1 — 1초 내 해독 가능, DB 유출 시 비밀번호 전원 노출됩니다."),

    ("INSECURE_COOKIE",
     re.compile(r'res\.cookie\s*\([^)]*\)', re.I),
     "res.cookie — httpOnly/secure 옵션 누락 여부를 확인하세요."),

    ("OPEN_REDIRECT",
     re.compile(r'res\.redirect\s*\(\s*req\.(query|params|body|headers)', re.I),
     "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."),

    ("PATH_TRAVERSAL",
     re.compile(r'(fs\.readFile|fs\.readFileSync|fs\.createReadStream|path\.join)\s*\(\s*req\.(params|query|body)', re.I),
     "파일 경로에 사용자 입력 — 서버의 임의 파일이 노출될 수 있어요."),

    ("XSS",
     re.compile(r'(\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)', re.I),
     "innerHTML/dangerouslySetInnerHTML — 사용자 입력이 HTML로 렌더링되어 XSS 공격이 가능해요."),

    ("INSECURE_JWT",
     re.compile(r'jwt\.verify\s*\([^,)]+,[^,)]+,\s*\{[^}]*algorithms\s*:\s*\[[^\]]*none', re.I),
     "JWT algorithm=none — 서명 검증 없이 토큰 위조가 가능해요."),

    ("MASS_ASSIGNMENT",
     re.compile(r'Object\.assign\s*\(\s*\w+\s*,\s*req\.(body|query|params)', re.I),
     "Object.assign(model, req.body) — 사용자가 임의 필드를 덮어쓸 수 있어요."),

    ("CORS_WILDCARD",
     re.compile(r"(origin\s*[:=]\s*['\"]?\*['\"]?|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*)", re.I),
     "CORS * — 모든 도메인이 API를 호출할 수 있어요."),

    ("SSRF",
     re.compile(r'(fetch|axios\.get|axios\.post|http\.get|https\.get)\s*\(\s*(req\.(query|params|body)|`[^`]*\$\{req\.)', re.I),
     "외부 URL을 사용자 입력으로 — 내부 네트워크 SSRF 공격이 가능해요."),

    ("PROTOTYPE_POLLUTION",
     re.compile(r'\[[\'"__proto__[\'"]|\[[\'"constructor[\'"]|\[[\'"prototype[\'"]', re.I),
     "__proto__/constructor 키 접근 — 프로토타입 오염으로 서버 동작이 변경될 수 있어요."),
]


def analyze_js(fp: str, src: str) -> list[dict]:
    lines = src.splitlines()
    viols: list[dict] = []
    for ln, line in enumerate(lines, 1):
        # HARDCODED_SECRETS
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, line):
                viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                    f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
                break
        # JS 룰
        for rule_type, pat, msg in JS_LINE_RULES:
            m = pat.search(line)
            if m:
                viols.append(_v(rule_type, fp, lines, ln, m.start(), msg))
    return viols


# ═══════════════════════════════════════════════════════════
# HTML 분석
# ═══════════════════════════════════════════════════════════

def analyze_html(fp: str, src: str) -> list[dict]:
    lines = src.splitlines()
    viols: list[dict] = []
    for ln, line in enumerate(lines, 1):
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, line):
                viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                    f"{label} HTML에 하드코딩 — 소스 보기로 누구나 볼 수 있어요."))
                break
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', src, re.DOTALL | re.IGNORECASE):
        base_ln = src[:m.start(1)].count("\n") + 1
        for rel, line in enumerate(m.group(1).splitlines()):
            abs_ln = min(base_ln + rel, len(lines))
            for rule_type, pat, msg in JS_LINE_RULES:
                hit = pat.search(line)
                if hit:
                    viols.append(_v(rule_type, fp, lines, abs_ln, hit.start(), msg))
    return viols


# ═══════════════════════════════════════════════════════════
# 파일별 디스패처
# ═══════════════════════════════════════════════════════════

def process_file(args: tuple[str, str, str]) -> dict | None:
    fp, content, ext = args
    if not is_web_file(fp, content, ext):
        return None
    if ext == ".py":
        viols = analyze_py(fp, content)
    elif ext in {".js", ".ts", ".jsx", ".tsx"}:
        viols = analyze_js(fp, content)
    elif ext == ".html":
        viols = analyze_html(fp, content)
    else:
        return None
    if not viols:
        return None
    return {"file": fp, "ext": ext, "violations": viols}


# ═══════════════════════════════════════════════════════════
# Progress bar
# ═══════════════════════════════════════════════════════════

def _bar(done: int, total: int, width: int = 30) -> str:
    frac = done / total if total else 0
    filled = int(frac * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {frac*100:.1f}%"


def _eta(elapsed: float, done: int, total: int) -> str:
    if done == 0:
        return "ETA: --"
    rate = done / elapsed
    remaining = (total - done) / rate
    if remaining < 60:
        return f"ETA: {remaining:.0f}s"
    return f"ETA: {remaining/60:.1f}m"


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

def load_files(dataset_dir: Path) -> list[tuple[str, str, str]]:
    items = []
    for p in sorted(dataset_dir.iterdir()):
        if p.suffix.lower() not in SUPPORTED_EXT:
            continue
        try:
            items.append((str(p), p.read_text(encoding="utf-8", errors="ignore"), p.suffix.lower()))
        except Exception:
            pass
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description="취약점 추출기 (py/js/ts/jsx/tsx/html)")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent.parent / "dataset")
    parser.add_argument("--output",  type=Path, default=Path(__file__).parent.parent / "dataset" / "vulns.jsonl")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--top",     type=int, default=7, help="상위 N개 룰 출력 (기본 7)")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"  SLAyer 취약점 추출기")
    print(f"{'='*60}")
    print(f"  dataset : {args.dataset}")
    print(f"  output  : {args.output}")
    print(f"  workers : {args.workers}")

    files = load_files(args.dataset)
    by_ext: dict[str, int] = {}
    for _, _, ext in files:
        by_ext[ext] = by_ext.get(ext, 0) + 1
    print(f"\n  파일 수 : {len(files):,}개  →  " + "  ".join(f"{e}:{n}" for e, n in sorted(by_ext.items())))
    print(f"{'='*60}\n")

    total = len(files)
    done = 0
    web_count = 0
    vuln_count = 0
    file_with_vulns = 0
    start = time.time()
    type_counter: Counter = Counter()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as out_f:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_file, item): item[0] for item in files}
            for future in as_completed(futures):
                done += 1
                try:
                    result = future.result()
                except Exception:
                    result = None

                if result is not None:
                    web_count += 1
                    if result["violations"]:
                        file_with_vulns += 1
                        vuln_count += len(result["violations"])
                        for v in result["violations"]:
                            type_counter[v["rule_type"]] += 1
                        out_f.write(json.dumps(result, ensure_ascii=False) + "\n")

                # 진행 바 (인플레이스 업데이트)
                elapsed = time.time() - start
                bar = _bar(done, total)
                eta = _eta(elapsed, done, total)
                status = (f"\r  {bar}  {done:>5}/{total}  "
                          f"웹:{web_count}  취약:{vuln_count}  {eta}    ")
                sys.stdout.write(status)
                sys.stdout.flush()

    elapsed = time.time() - start
    print(f"\n\n{'='*60}")
    print(f"  ✅  분석 완료  ({elapsed:.1f}초)")
    print(f"{'='*60}")
    print(f"  웹서비스 파일  : {web_count:,}개")
    print(f"  취약점 파일    : {file_with_vulns:,}개")
    print(f"  총 취약점      : {vuln_count:,}건")
    print(f"\n  ─── 빈도 TOP {args.top} ──────────────────────────────")
    for rank, (rule, cnt) in enumerate(type_counter.most_common(args.top), 1):
        bar = "▓" * min(30, int(cnt / max(type_counter.values()) * 30))
        print(f"  {rank}위  {rule:<30} {cnt:>5}건  {bar}")
    print(f"\n  저장 : {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
