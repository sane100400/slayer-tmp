import ast
import re
from typing import List

try:
    from backend.models import SLARule, Violation
except ImportError:
    from models import SLARule, Violation

# ── 사용자 친화 설명 ──────────────────────────────────────────────
FRIENDLY_MSG = {
    "NO_NETWORK":
        "사용자 입력이 외부 주소로 직접 요청될 수 있어요. "
        "내부망 조회나 민감정보 전송으로 이어질 수 있습니다.",
    "NO_EXEC":
        "사용자 입력이 서버 명령어에 그대로 들어가요. "
        "공격자가 입력창에 명령어를 입력하면 서버 전체를 원격으로 조종할 수 있어요.",
    "NO_HARDCODED_SECRETS":
        "비밀번호나 API 키가 코드에 직접 적혀 있어요. "
        "GitHub에 올리는 순간 누구나 볼 수 있고, 자동화 봇이 수 분 내로 악용해요.",
    "SQL_PARAM_BINDING":
        "누군가 로그인 폼이나 검색창에 특수문자를 입력해서 "
        "데이터베이스 안의 모든 회원정보를 훔쳐갈 수 있어요.",
    "NO_DEBUG_MODE":
        "디버그 모드가 켜진 채로 배포되면 에러가 날 때 "
        "서버 내부 코드·파일 경로·환경변수가 사용자 화면에 그대로 노출돼요.",
    "NO_INSECURE_HASH":
        "MD5나 SHA-1로 저장된 비밀번호는 요즘 컴퓨터로 1초도 안 걸려서 해독돼요. "
        "DB가 유출되면 모든 회원 비밀번호가 바로 노출됩니다.",
    "NO_BARE_EXCEPT":
        "예외를 조용히 삼키면 공격 징후와 장애 원인이 숨겨져 위험한 동작이 계속될 수 있어요.",
    "SQL_INJECTION":
        "누군가 로그인 폼이나 검색창에 특수문자를 입력해서 "
        "데이터베이스 안의 모든 회원정보를 훔쳐갈 수 있어요.",
    "HARDCODED_SECRETS":
        "비밀번호나 API 키가 코드에 직접 적혀 있어요. "
        "GitHub에 올리는 순간 누구나 볼 수 있고, 자동화 봇이 수 분 내로 악용해요.",
    "DEBUG_MODE_ON":
        "디버그 모드가 켜진 채로 배포되면 에러가 날 때 "
        "서버 내부 코드·파일 경로·환경변수가 사용자 화면에 그대로 노출돼요.",
    "INSECURE_COOKIE":
        "로그인 쿠키에 보안 옵션이 없어요. "
        "해커가 광고 배너 한 줄로 사용자의 로그인 상태를 통째로 훔쳐갈 수 있어요.",
    "WEAK_HASH":
        "MD5나 SHA-1로 저장된 비밀번호는 요즘 컴퓨터로 1초도 안 걸려서 해독돼요. "
        "DB가 유출되면 모든 회원 비밀번호가 바로 노출됩니다.",
    "COMMAND_INJECTION":
        "사용자 입력이 서버 명령어에 그대로 들어가요. "
        "공격자가 입력창에 명령어를 입력하면 서버 전체를 원격으로 조종할 수 있어요.",
    "OPEN_REDIRECT":
        "로그인 후 이동 URL을 사용자가 마음대로 바꿀 수 있어요. "
        "공격자가 피싱 사이트 주소를 심어서 사용자를 속일 수 있어요.",
}

SQL_KEYWORDS = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b')
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',     "비밀번호"),
    (r'(?i)(api_key|apikey|api[-_]key)\s*=\s*["\'][^"\']{8,}["\']', "API 키"),
    (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'][^"\']{8,}["\']',   "시크릿 키"),
    (r'(?i)(token)\s*=\s*["\'][^"\']{8,}["\']',                    "토큰"),
    (r'sk-[A-Za-z0-9]{20,}',                                        "OpenAI API 키"),
    (r'(?i)aws_access_key_id\s*=\s*["\'][A-Z0-9]{16,}["\']',       "AWS 액세스 키"),
    (r'ghp_[A-Za-z0-9]{36}',                                        "GitHub 토큰"),
]
WEAK_HASH_NAMES = {"md5", "sha1"}
REDIRECT_SOURCES = {"request.args.get", "request.form.get", "request.values.get", "request.GET.get", "request.POST.get"}
NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch", "httpx.request",
    "urllib.request.urlopen", "urllib3.request", "aiohttp.request",
}
SECURITY_CONTEXT_WORDS = ("token", "secret", "password", "passwd", "pwd", "session", "otp", "auth", "reset", "csrf", "credential")
PLACEHOLDER_WORDS = {"example", "dummy", "test", "changeme", "your_api_key", "xxxxx", "sample", "placeholder"}
RULE_TYPE_ALIASES = {
    "SQL_INJECTION": "SQL_PARAM_BINDING",
    "HARDCODED_SECRETS": "NO_HARDCODED_SECRETS",
    "DEBUG_MODE_ON": "NO_DEBUG_MODE",
    "WEAK_HASH": "NO_INSECURE_HASH",
    "COMMAND_INJECTION": "NO_EXEC",
}


def _snippet(lines: list[str], lineno: int, ctx: int = 2) -> str:
    start = max(0, lineno - 1 - ctx)
    end = min(len(lines), lineno + ctx)
    return "\n".join(lines[start:end])


def _violation(rule: SLARule, filepath: str, lines: list[str], node, msg: str) -> Violation:
    lineno = getattr(node, "lineno", 1)
    col = getattr(node, "col_offset", 0)
    return Violation(
        rule_id=rule.id, file=filepath,
        line=lineno, col=col,
        code_snippet=_snippet(lines, lineno),
        explanation=msg,
    )


def _canonical_rule_type(rule_type: str) -> str:
    return RULE_TYPE_ALIASES.get(rule_type, rule_type)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _mask_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in PLACEHOLDER_WORDS)


def _is_dynamic_network_target(node: ast.AST) -> bool:
    return not (isinstance(node, ast.Constant) and isinstance(node.value, str))


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_function_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name.lower()
        current = parents.get(current)
    return ""


def _assignment_targets(parent: ast.AST | None) -> list[str]:
    if isinstance(parent, ast.Assign):
        names: list[str] = []
        for target in parent.targets:
            if isinstance(target, ast.Name):
                names.append(target.id.lower())
        return names
    if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
        return [parent.target.id.lower()]
    return []


def _has_security_context(node: ast.AST, parents: dict[ast.AST, ast.AST], line: str) -> bool:
    haystacks = [line.lower(), _enclosing_function_name(node, parents)]
    current = parents.get(node)
    while current is not None:
        haystacks.extend(_assignment_targets(current))
        current = parents.get(current)
    return any(any(word in haystack for word in SECURITY_CONTEXT_WORDS) for haystack in haystacks)


def _body_is_empty_or_pass(body: list[ast.stmt]) -> bool:
    return not body or all(isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in body)


def _sql_call_has_binding_issue(node: ast.Call) -> bool:
    if not node.args:
        return False
    query = node.args[0]
    if isinstance(query, ast.JoinedStr):
        return True
    if isinstance(query, ast.BinOp) and isinstance(query.op, (ast.Mod, ast.Add)):
        left = query.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str) and SQL_KEYWORDS.search(left.value):
            return True
    if isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "format":
        base = query.func.value
        if isinstance(base, ast.Constant) and isinstance(base.value, str) and SQL_KEYWORDS.search(base.value):
            return True
    return False


def analyze(code: str, rule: SLARule, filepath: str) -> List[Violation]:
    lines = code.splitlines()
    try:
        tree = ast.parse(code, filename=filepath)
    except SyntaxError:
        return []

    violations: List[Violation] = []
    rule_type = _canonical_rule_type(rule.rule_type)
    msg = FRIENDLY_MSG.get(rule_type, FRIENDLY_MSG.get(rule.rule_type, rule.description))
    parents = _build_parent_map(tree)

    # ── SQL_INJECTION ──────────────────────────────────────────────
    if rule_type == "SQL_PARAM_BINDING":
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"execute", "executemany"}
                and _sql_call_has_binding_issue(node)
            ):
                violations.append(_violation(rule, filepath, lines, node, msg))

    # ── HARDCODED_SECRETS ──────────────────────────────────────────
    elif rule_type == "NO_HARDCODED_SECRETS":
        for lineno, line in enumerate(lines, 1):
            for pattern, label in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match and not _mask_placeholder(match.group(0)):
                    violations.append(Violation(
                        rule_id=rule.id, file=filepath,
                        line=lineno, col=0,
                        code_snippet=_snippet(lines, lineno),
                        explanation=f"{FRIENDLY_MSG['NO_HARDCODED_SECRETS']} ({label})",
                    ))
                    break

    # ── DEBUG_MODE_ON ──────────────────────────────────────────────
    elif rule_type == "NO_DEBUG_MODE":
        for node in ast.walk(tree):
            # app.run(debug=True)
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        violations.append(_violation(rule, filepath, lines, node, msg))
            # DEBUG = True (module level)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            violations.append(_violation(rule, filepath, lines, node, msg))

    # ── NO_NETWORK ─────────────────────────────────────────────────
    elif rule_type == "NO_NETWORK":
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                dotted = _dotted_name(node.func)
                if dotted in NETWORK_CALLS:
                    url_arg = node.args[1] if dotted.endswith(".request") and len(node.args) > 1 else (node.args[0] if node.args else None)
                    url_arg = next((kw.value for kw in node.keywords if kw.arg in {"url", "endpoint"}), url_arg)
                    if url_arg is not None and _is_dynamic_network_target(url_arg):
                        violations.append(_violation(rule, filepath, lines, node, msg))

    # ── INSECURE_COOKIE ────────────────────────────────────────────
    elif rule.rule_type == "INSECURE_COOKIE":
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                fn_name = ""
                if isinstance(fn, ast.Attribute):
                    fn_name = fn.attr
                elif isinstance(fn, ast.Name):
                    fn_name = fn.id
                if fn_name == "set_cookie":
                    kw_names = {kw.arg for kw in node.keywords}
                    missing = []
                    if "httponly" not in kw_names:
                        missing.append("httponly=True")
                    if "secure" not in kw_names:
                        missing.append("secure=True")
                    if missing:
                        extra = f" ({', '.join(missing)} 옵션이 없어요)"
                        violations.append(Violation(
                            rule_id=rule.id, file=filepath,
                            line=node.lineno, col=node.col_offset,
                            code_snippet=_snippet(lines, node.lineno),
                            explanation=msg + extra,
                        ))

    # ── WEAK_HASH ──────────────────────────────────────────────────
    elif rule_type == "NO_INSECURE_HASH":
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                hash_name = ""
                if isinstance(fn, ast.Attribute) and fn.attr in WEAK_HASH_NAMES:
                    hash_name = fn.attr
                elif isinstance(fn, ast.Name) and fn.id in WEAK_HASH_NAMES:
                    hash_name = fn.id
                # hashlib.new("md5") / hashlib.new("sha1")
                if (isinstance(fn, ast.Attribute) and fn.attr == "new"
                        and node.args and isinstance(node.args[0], ast.Constant)
                        and str(node.args[0].value).lower() in WEAK_HASH_NAMES):
                    hash_name = str(node.args[0].value)
                line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                if hash_name and _has_security_context(node, parents, line):
                    violations.append(_violation(rule, filepath, lines, node,
                                                  f"{FRIENDLY_MSG['NO_INSECURE_HASH']} ({hash_name.upper()} 사용 중)"))

    # ── COMMAND_INJECTION ──────────────────────────────────────────
    elif rule_type == "NO_EXEC":
        EXEC_ATTRS = {
            "subprocess": {"run", "Popen", "call", "check_output", "check_call"},
            "os": {"system", "popen", "execvp", "execve"},
        }
        EXEC_BUILTINS = {"eval", "exec"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in EXEC_BUILTINS:
                    violations.append(_violation(rule, filepath, lines, node, msg))
                elif isinstance(fn, ast.Attribute):
                    obj = fn.value.id if isinstance(fn.value, ast.Name) else ""
                    if obj in EXEC_ATTRS and fn.attr in EXEC_ATTRS[obj]:
                        has_shell_true = any(
                            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        if obj == "os" or has_shell_true:
                            violations.append(_violation(rule, filepath, lines, node, msg))

    # ── NO_BARE_EXCEPT ─────────────────────────────────────────────
    elif rule_type == "NO_BARE_EXCEPT":
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                broad_exception = node.type is None or (isinstance(node.type, ast.Name) and node.type.id == "Exception")
                if broad_exception and _body_is_empty_or_pass(node.body):
                    violations.append(_violation(rule, filepath, lines, node, msg))

    # ── OPEN_REDIRECT ──────────────────────────────────────────────
    elif rule.rule_type == "OPEN_REDIRECT":
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                fn_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
                if fn_name == "redirect" and node.args:
                    # redirect() 첫 번째 인수가 request.xxx.get(...) 이면 위험
                    arg = node.args[0]
                    src = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    if any(rs in src for rs in REDIRECT_SOURCES):
                        violations.append(_violation(rule, filepath, lines, node, msg))

    return violations
