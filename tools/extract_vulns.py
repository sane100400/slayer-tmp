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
import csv
import json
import os
import re
import signal
import sys
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

# ── 지원 확장자 ──────────────────────────────────────────────
SUPPORTED_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".html"}
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "__tests__",
    "env",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "coverage",
    "doc",
    "docs",
    "documentation",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "test",
    "tests",
    "third_party",
    "venv",
}

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
    r"((^|[/_.-])tests?([/_.-]|$)|(^|[/_.-])spec([/_.-]|$)|"
    r"\.test\.|\.spec\.|__test|conftest|"
    r"migration|alembic|\.github|setup\.py|manage\.py|celery|wsgi|asgi|"
    r"_pb2\.py|proto|fixture|factory|seed|mock|benchmark|"
    r"node_modules|site-packages|/venv/|/env/|dist/|build/|coverage|"
    r"playwright-report|static/assets/|/assets/index-[A-Za-z0-9_-]+\.js|"
    r"[_/]assets[_/]index-[A-Za-z0-9_-]+\.js|\.min\.(js|css))",
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
SQL_STMT = re.compile(
    r"(?is)\b("
    r"SELECT\b.+\bFROM\b|"
    r"INSERT\s+INTO\b|"
    r"UPDATE\s+[\w.`\"[\]]+\s+SET\b|"
    r"DELETE\s+FROM\b|"
    r"DROP\s+(TABLE|DATABASE)\b|"
    r"ALTER\s+TABLE\b|"
    r"UNION\s+SELECT\b|"
    r"EXEC(UTE)?\s+"
    r")"
)

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
PLACEHOLDER_SECRET_VALUE = re.compile(
    r"""["']\s*([^"']*(\.\.\.|not-needed|none|null|dummy|example|sample|test|"""
    r"""changeme|change-me|your[-_\w]*|abc123|placeholder)[^"']*|\*{4,}|<[^>]+>)\s*["']""",
    re.IGNORECASE,
)

WEAK_HASH_NAMES = {"md5", "sha1", "sha"}
REDIRECT_SRCS = {"request.args", "request.form", "request.values", "request.GET", "request.POST",
                 "request.referrer", "request.url", "req.query", "req.params", "req.body"}
PY_USER_SOURCE_MARKERS = (
    "request.args", "request.form", "request.values", "request.GET", "request.POST",
    "request.json", "request.data", "request.files", "request.cookies", "request.headers",
)
JS_USER_SOURCE_RE = re.compile(
    r"\b(req|request)\.(query|params|body|headers|cookies)\b|"
    r"\b(searchParams|URLSearchParams|location\.(search|hash)|document\.cookie)\b",
    re.I,
)
JS_ESCAPE_RE = re.compile(r"\b(esc|escapeHtml|sanitize|DOMPurify\.sanitize|textContent)\b", re.I)
SECURITY_CONTEXT_RE = re.compile(r"(password|passwd|pwd|secret|token|jwt|session|auth|credential|api[_-]?key)", re.I)


class FileAnalysisTimeout(Exception):
    pass


def _snip(lines: list[str], lineno: int, ctx: int = 2) -> str:
    s = max(0, lineno - 1 - ctx)
    e = min(len(lines), lineno + ctx)
    return "\n".join(lines[s:e])


def _v(rule: str, fp: str, lines: list[str], ln: int, col: int, msg: str) -> dict:
    return {"rule_type": rule, "file": fp, "line": ln, "col": col,
            "code_snippet": _snip(lines, ln), "explanation": msg}


def _expr_src(node: ast.AST) -> str:
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


def _contains_py_user_input(expr_src: str, user_vars: set[str]) -> bool:
    return any(s in expr_src for s in PY_USER_SOURCE_MARKERS) or any(
        re.search(rf"\b{re.escape(name)}\b", expr_src) for name in user_vars
    )


def _is_dynamic_py_node(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _is_sql_sink(fn_name: str) -> bool:
    return fn_name.lower() in {
        "execute", "executemany", "executescript", "raw", "extra", "query",
        "post_query", "run_query", "read_sql", "text", "fetch", "fetchall", "fetchone",
    }


def _is_safe_yaml_loader(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg != "Loader":
            continue
        loader_src = _expr_src(kw.value)
        if "SafeLoader" in loader_src or loader_src.endswith("safe_load"):
            return True
    return False


def _is_security_hash_context(line: str, fp: str) -> bool:
    haystack = f"{fp} {line}"
    return bool(SECURITY_CONTEXT_RE.search(haystack))


def _is_dynamic_js(line: str) -> bool:
    return "${" in line or JS_USER_SOURCE_RE.search(line) is not None


def _secret_label_for_line(line: str) -> str | None:
    if line.lstrip().startswith("#"):
        return None
    for pat, label in SECRET_PATTERNS:
        if re.search(pat, line):
            if PLACEHOLDER_SECRET_VALUE.search(line):
                return None
            return label
    return None


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
    sql_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # var = request.args.get(...) / request.form[...] 등
            val_src = _expr_src(node.value)
            if any(s in val_src for s in PY_USER_SOURCE_MARKERS):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        user_vars.add(t.id)
            if (
                SQL_STMT.search(val_src)
                and _is_dynamic_py_node(node.value)
                and _contains_py_user_input(val_src, user_vars)
            ):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        sql_vars.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            val_src = _expr_src(node.value) if node.value is not None else ""
            if any(s in val_src for s in PY_USER_SOURCE_MARKERS):
                user_vars.add(node.target.id)
            if (
                node.value is not None
                and SQL_STMT.search(val_src)
                and _is_dynamic_py_node(node.value)
                and _contains_py_user_input(val_src, user_vars)
            ):
                sql_vars.add(node.target.id)

    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if not ln:
            continue
        line_src = lines[ln - 1] if ln <= len(lines) else ""

        if isinstance(node, ast.Call):
            fn = node.func
            fn_attr = fn.attr if isinstance(fn, ast.Attribute) else ""
            fn_name = fn_attr or (fn.id if isinstance(fn, ast.Name) else "")
            obj_name = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""

            # SQL_INJECTION: SQL sink + SQL-shaped dynamic expression.
            if _is_sql_sink(fn_name) and node.args:
                query_arg = node.args[0]
                query_src = _expr_src(query_arg)
                if isinstance(query_arg, ast.Name) and query_arg.id in sql_vars:
                    viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                        "사용자 입력으로 조립된 SQL 변수가 실행되어 DB 데이터가 노출 또는 변조될 수 있어요."))
                elif (
                    SQL_STMT.search(query_src)
                    and _is_dynamic_py_node(query_arg)
                    and _contains_py_user_input(query_src, user_vars)
                ):
                    viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                        "동적 SQL에 사용자 입력이 포함되어 DB 데이터가 노출 또는 변조될 수 있어요."))
                elif (
                    isinstance(query_arg, ast.Call)
                    and isinstance(query_arg.func, ast.Attribute)
                    and query_arg.func.attr == "format"
                    and SQL_STMT.search(query_src)
                    and _contains_py_user_input(query_src, user_vars)
                ):
                    viols.append(_v("SQL_INJECTION", fp, lines, ln, node.col_offset,
                        ".format() SQL — 포맷 인자가 쿼리에 직접 삽입될 수 있어요."))

            # DEBUG_MODE_ON
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    viols.append(_v("DEBUG_MODE_ON", fp, lines, ln, node.col_offset,
                        "debug=True — 에러 시 서버 내부 코드·경로·환경변수가 노출돼요."))

            # INSECURE_COOKIE
            if fn_name == "set_cookie":
                kws = {kw.arg for kw in node.keywords}
                missing = []
                for flag in ["httponly", "secure"]:
                    value = next((kw.value for kw in node.keywords if kw.arg == flag), None)
                    if value is None:
                        missing.append(flag)
                    elif isinstance(value, ast.Constant) and value.value is False:
                        missing.append(flag)
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
            if hash_name and _is_security_hash_context(line_src, fp):
                viols.append(_v("WEAK_HASH", fp, lines, ln, node.col_offset,
                    f"{hash_name.upper()} — 인증/시크릿 맥락에서 쓰이면 충돌·크래킹 위험이 커요."))

            # COMMAND_INJECTION
            OS_EXEC_ATTRS = {"system", "popen", "execvp", "execve", "popen2"}
            SUBPROCESS_ATTRS = {"run", "Popen", "call", "check_output", "check_call"}
            call_src = _expr_src(node)
            if fn_name in {"eval", "exec"} and isinstance(fn, ast.Name) and _contains_py_user_input(call_src, user_vars):
                viols.append(_v("COMMAND_INJECTION", fp, lines, ln, node.col_offset,
                    f"{fn_name}() — 코드가 동적 실행되어 서버가 원격 조종당할 수 있어요."))
            elif obj_name == "os" and fn_attr in OS_EXEC_ATTRS and _contains_py_user_input(call_src, user_vars):
                viols.append(_v("COMMAND_INJECTION", fp, lines, ln, node.col_offset,
                    f"os.{fn_attr}() — 서버 명령어가 원격 실행될 수 있어요."))
            elif obj_name == "subprocess" and fn_attr in SUBPROCESS_ATTRS:
                # shell=True 있을 때만 — shell=False는 안전
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if has_shell_true and _contains_py_user_input(call_src, user_vars):
                    viols.append(_v("COMMAND_INJECTION", fp, lines, ln, node.col_offset,
                        f"subprocess.{fn_attr}(shell=True) — shell=True는 인수가 그대로 쉘에 전달돼요."))

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

            # PATH_TRAVERSAL — open/send_file/send_from_directory + user input only
            if fn_name in {"open", "send_file", "send_from_directory", "FileResponse"}:
                if fn_name == "open" and not isinstance(fn, ast.Name):
                    continue
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in user_vars:
                    viols.append(_v("PATH_TRAVERSAL", fp, lines, ln, node.col_offset,
                        "open(user_input) — 공격자가 서버의 임의 파일을 읽을 수 있어요."))
                elif node.args and isinstance(node.args[0], ast.JoinedStr):
                    # f-string 파일 경로 중 user-input 유래 변수 포함된 것만
                    fstr_src = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
                    if any(uv in fstr_src for uv in user_vars) or any(
                        s in fstr_src for s in ("request.", "req.")
                    ):
                        viols.append(_v("PATH_TRAVERSAL", fp, lines, ln, node.col_offset,
                            "f-string 파일 경로(사용자 입력) — 경로 조작으로 서버 파일이 노출될 수 있어요."))

            # INSECURE_DESERIALIZATION
            if fn_attr in {"loads", "load"} and obj_name in {"pickle", "marshal", "shelve"}:
                call_src = _expr_src(node)
                if not _contains_py_user_input(call_src, user_vars) and "request" not in fp.lower():
                    continue
                viols.append(_v("INSECURE_DESERIALIZATION", fp, lines, ln, node.col_offset,
                    f"{obj_name}.{fn_attr}() — 악성 데이터로 서버 코드가 실행될 수 있어요."))
            if fn_attr == "load" and obj_name == "yaml":
                # yaml.load without Loader=yaml.SafeLoader
                if not _is_safe_yaml_loader(node):
                    viols.append(_v("INSECURE_DESERIALIZATION", fp, lines, ln, node.col_offset,
                        "yaml.load() without SafeLoader — 임의 코드가 실행될 수 있어요."))

            # SSRF — requests/httpx + user input (user_vars 유래이거나 request.* 포함)
            if (obj_name in {"requests", "httpx", "urllib"}
                    and fn_attr in {"get", "post", "put", "delete", "request", "urlopen"}):
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in user_vars:
                    viols.append(_v("SSRF", fp, lines, ln, node.col_offset,
                        "외부 URL을 사용자 입력으로 — 내부 네트워크를 공격자가 스캔할 수 있어요."))
                elif node.args and isinstance(node.args[0], ast.JoinedStr):
                    fstr_src = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
                    if any(uv in fstr_src for uv in user_vars) or any(
                        s in fstr_src for s in ("request.", "req.")
                    ):
                        viols.append(_v("SSRF", fp, lines, ln, node.col_offset,
                            "f-string URL(사용자 입력) — 내부 서버로의 SSRF 공격이 가능해요."))

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
        label = _secret_label_for_line(line)
        if label is not None:
            viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))

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
     re.compile(r'res\.cookie\s*\([^)]*\)(?!.*(?:httpOnly|secure)\s*:\s*true)', re.I),
     "res.cookie — httpOnly/secure 옵션 없음: JS로 쿠키가 탈취될 수 있어요."),

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
     re.compile(r"(Access-Control-Allow-Origin['\"]?\s*[:=,]\s*['\"]?\*['\"]?|cors\s*\([^)]*origin\s*:\s*['\"]?\*['\"]?|\ballow_origins\s*=\s*\[['\"]?\*['\"]?\])", re.I),
     "CORS * — 모든 도메인이 API를 호출할 수 있어요."),

    ("SSRF",
     re.compile(r'(fetch|axios\.get|axios\.post|http\.get|https\.get)\s*\(\s*(req\.(query|params|body)|`[^`]*\$\{req\.)', re.I),
     "외부 URL을 사용자 입력으로 — 내부 네트워크 SSRF 공격이 가능해요."),

]


def _scan_js_line(fp: str, lines: list[str], ln: int, line: str) -> list[dict]:
    viols: list[dict] = []

    if SQL_STMT.search(line) and _is_dynamic_js(line):
        if re.search(r"\b(query|execute|raw|sql)\b", line, re.I):
            col = max(0, SQL_KW.search(line).start() if SQL_KW.search(line) else 0)
            viols.append(_v("SQL_INJECTION", fp, lines, ln, col,
                "동적 SQL에 사용자 입력이 포함되어 DB 데이터가 노출 또는 변조될 수 있어요."))

    if re.search(r"\b(eval\s*\(|new\s+Function\s*\()", line, re.I):
        if JS_USER_SOURCE_RE.search(line):
            viols.append(_v("COMMAND_INJECTION", fp, lines, ln, line.find("("),
                "사용자 입력이 동적 코드 실행으로 전달될 수 있어요."))

    if re.search(r"\b(execSync|spawnSync|child_process\.exec|exec)\s*\(", line, re.I):
        if _is_dynamic_js(line):
            viols.append(_v("COMMAND_INJECTION", fp, lines, ln, line.find("("),
                "사용자 입력이 서버 명령어로 실행될 수 있어요."))

    if re.search(r"\bdebug\s*[=:]\s*true\b", line, re.I):
        viols.append(_v("DEBUG_MODE_ON", fp, lines, ln, 0,
            "debug:true — 에러 시 서버 내부 정보가 노출돼요."))

    if re.search(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", line, re.I):
        if _is_security_hash_context(line, fp):
            viols.append(_v("WEAK_HASH", fp, lines, ln, 0,
                "MD5/SHA1 — 인증/시크릿 맥락에서 쓰이면 충돌·크래킹 위험이 커요."))

    if re.search(r"res\.cookie\s*\(", line, re.I):
        context = "\n".join(lines[ln - 1:min(len(lines), ln + 4)])
        has_httponly = re.search(r"httpOnly\s*:\s*true", context)
        has_secure = re.search(r"secure\s*:\s*true", context)
        if not (has_httponly and has_secure):
            viols.append(_v("INSECURE_COOKIE", fp, lines, ln, 0,
                "res.cookie — httpOnly/secure 옵션이 모두 확인되지 않아요."))

    if re.search(r"res\.redirect\s*\(\s*req\.(query|params|body|headers)", line, re.I):
        viols.append(_v("OPEN_REDIRECT", fp, lines, ln, 0,
            "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."))

    if re.search(r"(fs\.readFile|fs\.readFileSync|fs\.createReadStream|path\.join)\s*\(\s*req\.(params|query|body)", line, re.I):
        viols.append(_v("PATH_TRAVERSAL", fp, lines, ln, 0,
            "파일 경로에 사용자 입력 — 서버의 임의 파일이 노출될 수 있어요."))

    if re.search(r"(\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)", line, re.I):
        if JS_USER_SOURCE_RE.search(line) and not JS_ESCAPE_RE.search(line):
            viols.append(_v("XSS", fp, lines, ln, 0,
                "사용자 입력이 HTML로 렌더링되어 XSS 공격이 가능해요."))

    if re.search(r"jwt\.verify\s*\([^,)]+,[^,)]+,\s*\{[^}]*algorithms\s*:\s*\[[^\]]*none", line, re.I):
        viols.append(_v("INSECURE_JWT", fp, lines, ln, 0,
            "JWT algorithm=none — 서명 검증 없이 토큰 위조가 가능해요."))

    if re.search(r"Object\.assign\s*\(\s*\w+\s*,\s*req\.(body|query|params)", line, re.I):
        viols.append(_v("MASS_ASSIGNMENT", fp, lines, ln, 0,
            "Object.assign(model, req.body) — 사용자가 임의 필드를 덮어쓸 수 있어요."))

    if re.search(r"(Access-Control-Allow-Origin['\"]?\s*[:=,]\s*['\"]?\*['\"]?|cors\s*\([^)]*origin\s*:\s*['\"]?\*['\"]?)", line, re.I):
        viols.append(_v("CORS_WILDCARD", fp, lines, ln, 0,
            "CORS * — 모든 도메인이 API를 호출할 수 있어요."))

    if re.search(r"(fetch|axios\.get|axios\.post|http\.get|https\.get)\s*\(", line, re.I):
        if JS_USER_SOURCE_RE.search(line) and "nextUrl.origin" not in line:
            viols.append(_v("SSRF", fp, lines, ln, 0,
                "외부 URL을 사용자 입력으로 — 내부 네트워크 SSRF 공격이 가능해요."))

    return viols


def analyze_js(fp: str, src: str) -> list[dict]:
    lines = src.splitlines()
    viols: list[dict] = []
    for ln, line in enumerate(lines, 1):
        # HARDCODED_SECRETS
        label = _secret_label_for_line(line)
        if label is not None:
            viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
        viols.extend(_scan_js_line(fp, lines, ln, line))
    return viols


# ═══════════════════════════════════════════════════════════
# HTML 분석
# ═══════════════════════════════════════════════════════════

def analyze_html(fp: str, src: str) -> list[dict]:
    lines = src.splitlines()
    viols: list[dict] = []
    for ln, line in enumerate(lines, 1):
        label = _secret_label_for_line(line)
        if label is not None:
            viols.append(_v("HARDCODED_SECRETS", fp, lines, ln, 0,
                f"{label} HTML에 하드코딩 — 소스 보기로 누구나 볼 수 있어요."))
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', src, re.DOTALL | re.IGNORECASE):
        base_ln = src[:m.start(1)].count("\n") + 1
        for rel, line in enumerate(m.group(1).splitlines()):
            abs_ln = min(base_ln + rel, len(lines))
            viols.extend(_scan_js_line(fp, lines, abs_ln, line))
    return viols


# ═══════════════════════════════════════════════════════════
# 파일별 디스패처
# ═══════════════════════════════════════════════════════════

def _timeout_handler(_signum, _frame) -> None:
    raise FileAnalysisTimeout()


def process_file(args: tuple[str, str] | tuple[str, str, int]) -> dict | None:
    fp, ext = args[:2]
    timeout_seconds = args[2] if len(args) > 2 else 0
    old_handler = None
    if timeout_seconds > 0:
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout_seconds)
    try:
        try:
            content = Path(fp).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

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
    except FileAnalysisTimeout:
        return None
    finally:
        if timeout_seconds > 0:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


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

def load_files(dataset_dir: Path, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []

    if dataset_dir.is_file():
        ext = dataset_dir.suffix.lower()
        if ext not in SUPPORTED_EXT:
            return []
        try:
            if max_file_bytes > 0 and dataset_dir.stat().st_size > max_file_bytes:
                return []
        except OSError:
            return []
        return [(str(dataset_dir), ext)]

    for root, dirs, files in os.walk(dataset_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIR_NAMES)
        for name in sorted(files):
            p = Path(root) / name
            ext = p.suffix.lower()
            if ext not in SUPPORTED_EXT:
                continue
            try:
                if max_file_bytes > 0 and p.stat().st_size > max_file_bytes:
                    continue
            except OSError:
                continue
            items.append((str(p), ext))
    return items


def write_analysis(
    json_path: Path,
    csv_path: Path,
    *,
    dataset: Path,
    output: Path,
    total_files: int,
    by_ext: dict[str, int],
    files_with_vulns: int,
    vuln_count: int,
    type_counter: Counter,
    elapsed: float,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "dataset": str(dataset),
        "output": str(output),
        "target_files": total_files,
        "files_with_vulnerabilities": files_with_vulns,
        "vulnerabilities": vuln_count,
        "by_extension": dict(sorted(by_ext.items())),
        "by_rule": dict(type_counter.most_common()),
        "elapsed_seconds": round(elapsed, 3),
    }
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["rule_type", "count"])
        writer.writeheader()
        for rule, count in type_counter.most_common():
            writer.writerow({"rule_type": rule, "count": count})


def main() -> None:
    parser = argparse.ArgumentParser(description="취약점 추출기 (py/js/ts/jsx/tsx/html)")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent.parent / "dataset")
    parser.add_argument("--output",  type=Path, default=Path(__file__).parent.parent / "dataset" / "vulns.jsonl")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--top",     type=int, default=7, help="상위 N개 룰 출력 (기본 7)")
    parser.add_argument("--analysis-json", type=Path, default=None)
    parser.add_argument("--analysis-csv", type=Path, default=None)
    parser.add_argument(
        "--max-pending",
        type=int,
        default=0,
        help="동시에 큐에 올릴 최대 파일 수 (기본: workers*4)",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=2.0,
        help="분석할 단일 파일 최대 크기 MB (기본 2.0, 0 이하면 제한 없음)",
    )
    parser.add_argument(
        "--file-timeout",
        type=int,
        default=10,
        help="단일 파일 분석 제한 시간 초 (기본 10, 0 이하면 제한 없음)",
    )
    args = parser.parse_args()
    max_file_bytes = 0 if args.max_file_mb <= 0 else int(args.max_file_mb * 1024 * 1024)
    max_pending = args.max_pending if args.max_pending > 0 else max(args.workers * 4, 1)
    analysis_json = args.analysis_json or args.output.with_name(f"{args.output.stem}_analysis.json")
    analysis_csv = args.analysis_csv or args.output.with_name(f"{args.output.stem}_analysis.csv")

    print(f"{'='*60}")
    print(f"  SLAyer 취약점 추출기")
    print(f"{'='*60}")
    print(f"  dataset : {args.dataset}")
    print(f"  output  : {args.output}")
    print(f"  analysis: {analysis_json}, {analysis_csv}")
    print(f"  workers : {args.workers}")
    print(f"  pending : {max_pending}")
    print(f"  max file: {'unlimited' if max_file_bytes <= 0 else f'{args.max_file_mb:g} MB'}")
    print(f"  timeout : {'unlimited' if args.file_timeout <= 0 else f'{args.file_timeout}s/file'}")

    files = load_files(args.dataset, max_file_bytes=max_file_bytes)
    by_ext: dict[str, int] = {}
    for _, ext in files:
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
            file_iter = iter(files)
            pending: dict = {}

            def submit_next() -> bool:
                try:
                    item = next(file_iter)
                except StopIteration:
                    return False
                task = (item[0], item[1], args.file_timeout)
                pending[executor.submit(process_file, task)] = item[0]
                return True

            for _ in range(min(max_pending, total)):
                submit_next()

            while pending:
                completed_futures, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed_futures:
                    pending.pop(future, None)
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

                    submit_next()

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
    if type_counter:
        max_count = max(type_counter.values())
        for rank, (rule, cnt) in enumerate(type_counter.most_common(args.top), 1):
            bar = "▓" * min(30, int(cnt / max_count * 30))
            print(f"  {rank}위  {rule:<30} {cnt:>5}건  {bar}")
    else:
        print("  탐지된 취약점 없음")
    print(f"\n  저장 : {args.output}")
    write_analysis(
        analysis_json,
        analysis_csv,
        dataset=args.dataset,
        output=args.output,
        total_files=total,
        by_ext=by_ext,
        files_with_vulns=file_with_vulns,
        vuln_count=vuln_count,
        type_counter=type_counter,
        elapsed=elapsed,
    )
    print(f"  분석 : {analysis_json}, {analysis_csv}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
