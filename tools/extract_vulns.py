"""
dataset/ 폴더의 Python/JS/TS/JSX/TSX/HTML 파일 중 웹서비스 관련 파일만 필터링하여
7대 취약점 분석 후 JSONL로 저장.

  Python/HTML : AST(Python) + regex(HTML)
  JS/TS/JSX/TSX: regex 기반 탐지

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
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ── 지원 확장자 ──────────────────────────────────────────────
SUPPORTED_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".html"}

# ── 웹서비스 파일 필터 ────────────────────────────────────────

WEB_FRAMEWORK_PY = re.compile(
    r"^\s*(import|from)\s+"
    r"(flask|django|fastapi|aiohttp|tornado|starlette|bottle|falcon|"
    r"sanic|quart|pyramid|cherrypy|uvicorn|connexion|responder|"
    r"werkzeug|jinja2|sqlalchemy|databases|tortoise|peewee|"
    r"requests|httpx|pydantic)",
    re.IGNORECASE | re.MULTILINE,
)

WEB_FRAMEWORK_JS = re.compile(
    r"(require\s*\(\s*['\"]"
    r"(express|fastify|koa|hapi|nest|next|nuxt|remix|sveltekit|"
    r"@hono|hono|elysia|@nestjs|prisma|sequelize|typeorm|mongoose|"
    r"axios|node-fetch|mysql|pg|sqlite|mongodb|redis)['\"]"
    r"|from\s+['\"]"
    r"(express|fastify|koa|hapi|next|nuxt|remix|@hono|hono|elysia|"
    r"@nestjs|prisma|sequelize|typeorm|mongoose|axios|node-fetch|"
    r"mysql2|pg|sqlite3|mongodb|ioredis)['\"])",
    re.IGNORECASE,
)

WEB_PATH_HINTS = re.compile(
    r"(route|view|api|handler|controller|endpoint|blueprint|middleware|"
    r"serializer|schema|app|server|auth|login|user|model|database|db|"
    r"admin|dashboard)",
    re.IGNORECASE,
)

EXCLUDE_PATH = re.compile(
    r"(test_|_test\b|__test|/tests/|conftest|migration|alembic|"
    r"\.github|setup\.py|manage\.py|celery|wsgi|asgi|"
    r"_pb2\.py|proto|fixture|factory|seed|mock|spec\.|\.spec\.|"
    r"\.test\.|_test\.|node_modules)",
    re.IGNORECASE,
)


def is_web_file(filepath: str, content: str, ext: str) -> bool:
    fname = filepath.replace("\\", "/")
    if EXCLUDE_PATH.search(fname):
        return False

    head = "\n".join(content.splitlines()[:80])

    if ext == ".py":
        if WEB_FRAMEWORK_PY.search(head):
            return True
        if WEB_PATH_HINTS.search(fname) and ("def " in content or "class " in content):
            return True
        return False

    if ext in {".js", ".ts", ".jsx", ".tsx"}:
        if WEB_FRAMEWORK_JS.search(head):
            return True
        if WEB_PATH_HINTS.search(fname):
            return True
        return False

    if ext == ".html":
        # HTML은 <script> 태그 안에 코드가 있거나 서버사이드 템플릿이면 포함
        return bool(re.search(r"<script|{%|{{|\$\{", content, re.IGNORECASE))

    return False


# ── 공통 상수 ────────────────────────────────────────────────

SQL_KEYWORDS = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b')
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',      "비밀번호"),
    (r'(?i)(api_key|apikey|api[-_]key)\s*[=:]\s*["\'][^"\']{8,}["\']', "API 키"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\'][^"\']{8,}["\']',    "시크릿 키"),
    (r'(?i)(token)\s*[=:]\s*["\'][^"\']{8,}["\']',                     "토큰"),
    (r'sk-[A-Za-z0-9]{20,}',                                            "OpenAI API 키"),
    (r'(?i)aws_access_key_id\s*[=:]\s*["\'][A-Z0-9]{16,}["\']',        "AWS 액세스 키"),
    (r'ghp_[A-Za-z0-9]{36}',                                            "GitHub 토큰"),
]
REDIRECT_SOURCES = {
    "request.args.get", "request.form.get", "request.values.get",
    "request.GET.get", "request.POST.get",
}


def _snippet(lines: list[str], lineno: int, ctx: int = 2) -> str:
    start = max(0, lineno - 1 - ctx)
    end = min(len(lines), lineno + ctx)
    return "\n".join(lines[start:end])


def _v(rule_type: str, filepath: str, lines: list[str], lineno: int, col: int, msg: str) -> dict:
    return {
        "rule_type": rule_type,
        "file": filepath,
        "line": lineno,
        "col": col,
        "code_snippet": _snippet(lines, lineno),
        "explanation": msg,
    }


# ── Python AST 분석 ──────────────────────────────────────────

WEAK_HASH_NAMES = {"md5", "sha1", "sha"}


def analyze_py(filepath: str, content: str) -> list[dict]:
    lines = content.splitlines()
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return []

    violations: list[dict] = []

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", None)
        if not lineno:
            continue
        src = lines[lineno - 1] if lineno <= len(lines) else ""

        # SQL_INJECTION
        if isinstance(node, ast.JoinedStr) and SQL_KEYWORDS.search(src):
            violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                "f-string SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if SQL_KEYWORDS.search(node.left.value):
                    violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                        "%-포맷 SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."))
        elif isinstance(node, ast.Call):
            fn = node.func

            # SQL .format()
            if (isinstance(fn, ast.Attribute) and fn.attr == "format"
                    and isinstance(fn.value, ast.Constant)
                    and isinstance(fn.value.value, str)
                    and SQL_KEYWORDS.search(fn.value.value)):
                violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                    ".format() SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."))

            # DEBUG_MODE_ON: app.run(debug=True)
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    violations.append(_v("DEBUG_MODE_ON", filepath, lines, lineno, node.col_offset,
                        "debug=True — 에러 시 서버 내부 코드·경로·환경변수가 노출돼요."))

            # INSECURE_COOKIE
            fn_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if fn_name == "set_cookie":
                kw_names = {kw.arg for kw in node.keywords}
                missing = [f for f in ["httponly", "secure"] if f not in kw_names]
                if missing:
                    violations.append(_v("INSECURE_COOKIE", filepath, lines, lineno, node.col_offset,
                        f"쿠키에 {', '.join(missing)} 없음 — JS로 쿠키가 탈취될 수 있어요."))

            # WEAK_HASH
            hash_name = ""
            if isinstance(fn, ast.Attribute) and fn.attr in WEAK_HASH_NAMES:
                hash_name = fn.attr
            elif isinstance(fn, ast.Name) and fn.id in WEAK_HASH_NAMES:
                hash_name = fn.id
            if (isinstance(fn, ast.Attribute) and fn.attr == "new"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and str(node.args[0].value).lower() in WEAK_HASH_NAMES):
                hash_name = str(node.args[0].value)
            if hash_name:
                violations.append(_v("WEAK_HASH", filepath, lines, lineno, node.col_offset,
                    f"{hash_name.upper()} — 1초 내 해독 가능, DB 유출 시 비밀번호 전원 노출됩니다."))

            # COMMAND_INJECTION
            EXEC_ATTRS = {
                "subprocess": {"run", "Popen", "call", "check_output", "check_call"},
                "os": {"system", "popen", "execvp", "execve"},
            }
            if isinstance(fn, ast.Name) and fn.id in {"eval", "exec"}:
                violations.append(_v("COMMAND_INJECTION", filepath, lines, lineno, node.col_offset,
                    f"{fn.id}() — 사용자 입력이 코드로 실행되어 서버가 원격 조종당할 수 있어요."))
            elif isinstance(fn, ast.Attribute):
                obj = fn.value.id if isinstance(fn.value, ast.Name) else ""
                if obj in EXEC_ATTRS and fn.attr in EXEC_ATTRS[obj]:
                    violations.append(_v("COMMAND_INJECTION", filepath, lines, lineno, node.col_offset,
                        f"{obj}.{fn.attr}() — 서버 명령어가 원격 실행될 수 있어요."))

            # OPEN_REDIRECT
            if fn_name == "redirect" and node.args:
                if any(rs in src for rs in REDIRECT_SOURCES):
                    violations.append(_v("OPEN_REDIRECT", filepath, lines, lineno, node.col_offset,
                        "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."))

        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        violations.append(_v("DEBUG_MODE_ON", filepath, lines, lineno, t.col_offset,
                            "DEBUG=True — 에러 시 서버 내부 정보가 노출돼요."))

    # HARDCODED_SECRETS (라인 스캔)
    for lineno, line in enumerate(lines, 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                violations.append(_v("HARDCODED_SECRETS", filepath, lines, lineno, 0,
                    f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
                break

    return violations


# ── JS/TS/JSX/TSX Regex 분석 ─────────────────────────────────

# JS 취약점 패턴 (lineno 포함 방식: 라인별 순회)
JS_RULES: list[tuple[str, re.Pattern, str]] = [
    # SQL_INJECTION: 템플릿 리터럴 + SQL 키워드
    ("SQL_INJECTION",
     re.compile(r'`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)[^`]*\$\{', re.IGNORECASE),
     "템플릿 리터럴 SQL — 사용자 입력이 쿼리에 삽입되어 DB 전체가 탈취될 수 있어요."),

    # COMMAND_INJECTION: exec/eval/spawn/execSync
    ("COMMAND_INJECTION",
     re.compile(r'\b(eval\s*\(|exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(|child_process\.exec)', re.IGNORECASE),
     "eval/exec/spawn — 사용자 입력이 서버 명령어로 실행될 수 있어요."),

    # DEBUG_MODE_ON
    ("DEBUG_MODE_ON",
     re.compile(r'\b(debug\s*[:=]\s*true|DEBUG\s*=\s*true|app\.set\s*\(\s*[\'"]env[\'"]\s*,\s*[\'"]development[\'"]\s*\))', re.IGNORECASE),
     "debug=true — 에러 시 서버 내부 정보가 노출돼요."),

    # WEAK_HASH: crypto.createHash('md5'|'sha1')
    ("WEAK_HASH",
     re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", re.IGNORECASE),
     "MD5/SHA1 — 1초 내 해독 가능, DB 유출 시 비밀번호 전원 노출됩니다."),

    # INSECURE_COOKIE: res.cookie() without httpOnly/secure
    ("INSECURE_COOKIE",
     re.compile(r'res\.cookie\s*\((?![^)]*httpOnly)(?![^)]*secure)', re.IGNORECASE),
     "쿠키에 httpOnly/secure 없음 — JS로 쿠키가 탈취될 수 있어요."),

    # OPEN_REDIRECT: res.redirect(req.query/params/body)
    ("OPEN_REDIRECT",
     re.compile(r'res\.redirect\s*\(\s*req\.(query|params|body)', re.IGNORECASE),
     "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."),
]


def analyze_js(filepath: str, content: str) -> list[dict]:
    lines = content.splitlines()
    violations: list[dict] = []

    for lineno, line in enumerate(lines, 1):
        # HARDCODED_SECRETS
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                violations.append(_v("HARDCODED_SECRETS", filepath, lines, lineno, 0,
                    f"{label} 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
                break

        # 나머지 JS 룰
        for rule_type, pat, msg in JS_RULES:
            if pat.search(line):
                col = (pat.search(line).start() if pat.search(line) else 0)
                violations.append(_v(rule_type, filepath, lines, lineno, col, msg))

    return violations


# ── HTML 분석 ────────────────────────────────────────────────

def analyze_html(filepath: str, content: str) -> list[dict]:
    """<script> 블록 추출 후 JS 분석 + 인라인 시크릿 탐지."""
    lines = content.splitlines()
    violations: list[dict] = []

    # HARDCODED_SECRETS (전체 라인)
    for lineno, line in enumerate(lines, 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                violations.append(_v("HARDCODED_SECRETS", filepath, lines, lineno, 0,
                    f"{label} 하드코딩 — HTML 소스에 노출돼요."))
                break

    # <script> 블록 내 JS 분석
    script_blocks = re.finditer(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
    for m in script_blocks:
        block_start_line = content[:m.start(1)].count("\n") + 1
        block_lines = m.group(1).splitlines()
        for rel_lineno, line in enumerate(block_lines, 0):
            abs_lineno = block_start_line + rel_lineno
            for rule_type, pat, msg in JS_RULES:
                if pat.search(line):
                    col = pat.search(line).start()
                    violations.append(_v(rule_type, filepath, lines,
                                         min(abs_lineno, len(lines)), col, msg))

    return violations


# ── 파일별 디스패처 ──────────────────────────────────────────

def process_file(args: tuple[str, str, str]) -> dict | None:
    filepath, content, ext = args
    if not is_web_file(filepath, content, ext):
        return None

    if ext == ".py":
        violations = analyze_py(filepath, content)
    elif ext in {".js", ".ts", ".jsx", ".tsx"}:
        violations = analyze_js(filepath, content)
    elif ext == ".html":
        violations = analyze_html(filepath, content)
    else:
        return None

    if not violations:
        return None
    return {"file": filepath, "ext": ext, "violations": violations}


def load_files(dataset_dir: Path) -> list[tuple[str, str, str]]:
    items = []
    for p in sorted(dataset_dir.iterdir()):
        if p.suffix.lower() not in SUPPORTED_EXT:
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            items.append((str(p), content, p.suffix.lower()))
        except Exception:
            pass
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description="7대 취약점 추출기 (py/js/ts/jsx/tsx/html)")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent.parent / "dataset")
    parser.add_argument("--output",  type=Path, default=Path(__file__).parent.parent / "dataset" / "vulns.jsonl")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    print(f"📂  dataset : {args.dataset}")
    print(f"💾  output  : {args.output}")
    print(f"⚙️   workers : {args.workers}")

    files = load_files(args.dataset)
    by_ext: dict[str, int] = {}
    for _, _, ext in files:
        by_ext[ext] = by_ext.get(ext, 0) + 1
    print(f"\n🔍  총 {len(files)}개 파일: " + ", ".join(f"{e}={n}" for e, n in sorted(by_ext.items())))
    print("    필터링 + 분석 시작...")

    web_count = 0
    vuln_count = 0
    file_with_vulns = 0
    done = 0
    total = len(files)

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
                        out_f.write(json.dumps(result, ensure_ascii=False) + "\n")

                if done % 500 == 0 or done == total:
                    pct = done / total * 100
                    print(f"  [{done:>5}/{total}]  {pct:.1f}%  — 웹서비스 파일 {web_count}개, 취약점 {vuln_count}건", flush=True)

    # 룰별 집계
    from collections import Counter
    type_counter: Counter = Counter()
    with open(args.output, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            for v in d["violations"]:
                type_counter[v["rule_type"]] += 1

    print(f"\n✅  완료")
    print(f"   웹서비스 파일  : {web_count:,}개")
    print(f"   취약점 파일    : {file_with_vulns:,}개")
    print(f"   총 취약점      : {vuln_count:,}건")
    for rule, cnt in type_counter.most_common():
        print(f"     {rule:<25}: {cnt:,}건")
    print(f"\n   저장 경로      : {args.output}")


if __name__ == "__main__":
    main()
