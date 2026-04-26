"""
dataset/ 폴더의 Python 파일 중 웹서비스 관련 파일만 필터링하여
7대 취약점 AST 분석 후 JSONL로 저장.

사용법:
  cd slayer
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

# ── 웹 프레임워크 감지 패턴 ───────────────────────────────────
WEB_FRAMEWORK_IMPORTS = re.compile(
    r"^\s*(import|from)\s+"
    r"(flask|django|fastapi|aiohttp|tornado|starlette|bottle|falcon|"
    r"sanic|quart|pyramid|cherrypy|uvicorn|connexion|responder|"
    r"werkzeug|jinja2|sqlalchemy|databases|tortoise|peewee|"
    r"requests|httpx|aiofiles|pydantic)",
    re.IGNORECASE | re.MULTILINE,
)

# 파일명에 이 단어가 있으면 웹서비스 관련 가능성 높음 (프레임워크 없어도 포함)
WEB_PATH_HINTS = re.compile(
    r"(route|view|api|handler|controller|endpoint|blueprint|middleware|"
    r"serializer|schema|app|server|auth|login|user|model|database|db|"
    r"admin|dashboard)",
    re.IGNORECASE,
)

# 파일명에 이 단어가 있으면 제외
EXCLUDE_PATH_PATTERNS = re.compile(
    r"(test_|_test\b|__test|/tests/|conftest|migration|alembic|"
    r"\.github|setup\.py|manage\.py|celery|wsgi|asgi|"
    r"_pb2\.py|proto|fixture|factory|seed|mock)",
    re.IGNORECASE,
)


def is_web_service_file(filepath: str, content: str) -> bool:
    """웹서비스 관련 파일 여부 판별."""
    fname = filepath.replace("\\", "/")

    if EXCLUDE_PATH_PATTERNS.search(fname):
        return False

    # 상단 60줄만 검사
    head = "\n".join(content.splitlines()[:60])

    if WEB_FRAMEWORK_IMPORTS.search(head):
        return True

    # 프레임워크 import 없어도 경로 힌트 + 함수/클래스 존재하면 포함
    if WEB_PATH_HINTS.search(fname) and ("def " in content or "class " in content):
        return True

    return False


# ── 7대 취약점 룰 ────────────────────────────────────────────

SQL_KEYWORDS = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b')
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',      "비밀번호"),
    (r'(?i)(api_key|apikey|api[-_]key)\s*=\s*["\'][^"\']{8,}["\']', "API 키"),
    (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'][^"\']{8,}["\']',    "시크릿 키"),
    (r'(?i)(token)\s*=\s*["\'][^"\']{8,}["\']',                     "토큰"),
    (r'sk-[A-Za-z0-9]{20,}',                                         "OpenAI API 키"),
    (r'(?i)aws_access_key_id\s*=\s*["\'][A-Z0-9]{16,}["\']',        "AWS 액세스 키"),
    (r'ghp_[A-Za-z0-9]{36}',                                         "GitHub 토큰"),
]
WEAK_HASH_NAMES = {"md5", "sha1", "sha"}
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


def analyze_file(filepath: str, content: str) -> list[dict]:
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

        # ── SQL_INJECTION ─────────────────────────────────────
        if isinstance(node, ast.JoinedStr) and SQL_KEYWORDS.search(src):
            violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                "f-string SQL — 사용자 입력이 쿼리에 직접 삽입되어 DB 전체가 탈취될 수 있어요."))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if SQL_KEYWORDS.search(node.left.value):
                    violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                        "%-포맷 SQL — 사용자 입력이 쿼리에 직접 삽입되어 DB 전체가 탈취될 수 있어요."))
        elif isinstance(node, ast.Call):
            fn = node.func

            # SQL .format()
            if (isinstance(fn, ast.Attribute) and fn.attr == "format"
                    and isinstance(fn.value, ast.Constant)
                    and isinstance(fn.value.value, str)
                    and SQL_KEYWORDS.search(fn.value.value)):
                violations.append(_v("SQL_INJECTION", filepath, lines, lineno, node.col_offset,
                    ".format() SQL — 사용자 입력이 쿼리에 직접 삽입되어 DB 전체가 탈취될 수 있어요."))

            # DEBUG_MODE_ON: app.run(debug=True)
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    violations.append(_v("DEBUG_MODE_ON", filepath, lines, lineno, node.col_offset,
                        "debug=True — 에러 시 서버 내부 코드·경로·환경변수가 사용자에게 노출돼요."))

            # INSECURE_COOKIE: set_cookie without httponly/secure
            fn_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if fn_name == "set_cookie":
                kw_names = {kw.arg for kw in node.keywords}
                missing = []
                if "httponly" not in kw_names:
                    missing.append("httponly=True")
                if "secure" not in kw_names:
                    missing.append("secure=True")
                if missing:
                    violations.append(_v("INSECURE_COOKIE", filepath, lines, lineno, node.col_offset,
                        f"쿠키에 {', '.join(missing)} 없음 — 해커가 JS로 쿠키를 훔쳐갈 수 있어요."))

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
                    f"{hash_name.upper()} — 요즘 컴퓨터로 1초도 안 걸려 해독돼요. DB 유출 시 비밀번호 전원 노출됩니다."))

            # COMMAND_INJECTION
            EXEC_ATTRS = {
                "subprocess": {"run", "Popen", "call", "check_output", "check_call"},
                "os": {"system", "popen", "execvp", "execve"},
            }
            EXEC_BUILTINS = {"eval", "exec"}
            if isinstance(fn, ast.Name) and fn.id in EXEC_BUILTINS:
                violations.append(_v("COMMAND_INJECTION", filepath, lines, lineno, node.col_offset,
                    f"{fn.id}() — 사용자 입력이 코드로 실행되어 서버 전체를 원격 조종당할 수 있어요."))
            elif isinstance(fn, ast.Attribute):
                obj = fn.value.id if isinstance(fn.value, ast.Name) else ""
                if obj in EXEC_ATTRS and fn.attr in EXEC_ATTRS[obj]:
                    violations.append(_v("COMMAND_INJECTION", filepath, lines, lineno, node.col_offset,
                        f"{obj}.{fn.attr}() — 사용자 입력이 서버 명령어로 실행되어 원격 조종당할 수 있어요."))

            # OPEN_REDIRECT
            if fn_name == "redirect" and node.args:
                if any(rs in src for rs in REDIRECT_SOURCES):
                    violations.append(_v("OPEN_REDIRECT", filepath, lines, lineno, node.col_offset,
                        "redirect(user_input) — 공격자가 피싱 사이트로 사용자를 유도할 수 있어요."))

        # DEBUG_MODE_ON: DEBUG = True (module level assign)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        violations.append(_v("DEBUG_MODE_ON", filepath, lines, lineno, t.col_offset,
                            "DEBUG=True — 에러 시 서버 내부 코드·경로·환경변수가 사용자에게 노출돼요."))

    # HARDCODED_SECRETS (라인 스캔)
    for lineno, line in enumerate(lines, 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                violations.append(_v("HARDCODED_SECRETS", filepath, lines, lineno, 0,
                    f"{label}가 코드에 하드코딩 — GitHub 업로드 즉시 자동화 봇이 수 분 내로 악용해요."))
                break

    return violations


def process_file(args: tuple[str, str]) -> dict | None:
    """멀티프로세싱 워커."""
    filepath, content = args
    if not is_web_service_file(filepath, content):
        return None
    violations = analyze_file(filepath, content)
    if not violations:
        return None
    return {"file": filepath, "violations": violations}


def load_files(dataset_dir: Path) -> list[tuple[str, str]]:
    items = []
    for p in sorted(dataset_dir.glob("*.py")):
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            items.append((str(p), content))
        except Exception:
            pass
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description="7대 취약점 추출기")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent.parent / "dataset")
    parser.add_argument("--output",  type=Path, default=Path(__file__).parent.parent / "dataset" / "vulns.jsonl")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    print(f"📂  dataset: {args.dataset}")
    print(f"💾  output : {args.output}")
    print(f"⚙️   workers: {args.workers}")

    files = load_files(args.dataset)
    total = len(files)
    print(f"\n🔍  총 {total}개 .py 파일 로드 완료 — 필터링 + 분석 시작...")

    web_count = 0
    vuln_count = 0
    file_with_vulns = 0
    done = 0

    with open(args.output, "w", encoding="utf-8") as out_f:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_file, item): item[0] for item in files}
            for future in as_completed(futures):
                done += 1
                result = future.result()
                if result is None:
                    pass
                else:
                    web_count += 1
                    if result["violations"]:
                        file_with_vulns += 1
                        vuln_count += len(result["violations"])
                        out_f.write(json.dumps(result, ensure_ascii=False) + "\n")

                if done % 500 == 0 or done == total:
                    pct = done / total * 100
                    print(f"  [{done:>5}/{total}] {pct:.1f}%  — 웹서비스 파일 {web_count}개, 취약점 {vuln_count}건", flush=True)

    print(f"\n✅  완료")
    print(f"   웹서비스 파일  : {web_count:,}개")
    print(f"   취약점 파일    : {file_with_vulns:,}개")
    print(f"   총 취약점      : {vuln_count:,}건")
    print(f"   저장 경로      : {args.output}")


if __name__ == "__main__":
    main()
