from __future__ import annotations

import ast
import re
from pathlib import Path

from slayer.models import SLARule, SyntaxIssue, Violation
from slayer.rules import DEFAULT_RULES_BY_ID

SQL_KEYWORDS = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)\b')
SECRET_ASSIGN_RE = re.compile(
    r'(?ix)\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential|access[_-]?key)\b\s*=\s*(["\'])(?P<value>[^"\']{4,})\1'
)
PROVIDER_SECRET_PATTERNS = (
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'),
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}'),
)
PLACEHOLDER_WORDS = {"example", "dummy", "test", "changeme", "your_api_key", "xxxxx", "sample", "placeholder"}
NETWORK_CALLS = {
    'requests.get',
    'requests.post',
    'requests.put',
    'requests.delete',
    'requests.patch',
    'requests.request',
    'httpx.get',
    'httpx.post',
    'httpx.put',
    'httpx.delete',
    'httpx.patch',
    'httpx.request',
    'urllib.request.urlopen',
    'urllib3.request',
    'aiohttp.request',
    'socket.create_connection',
    'socket.socket.connect',
    'boto3.client',
}
EXEC_CALLS = {
    'subprocess.run',
    'subprocess.Popen',
    'subprocess.call',
    'subprocess.check_call',
    'subprocess.check_output',
    'os.system',
    'os.popen',
    'os.execv',
    'os.execve',
    'os.execvp',
}
SECURITY_CONTEXT_WORDS = ('token', 'secret', 'password', 'session', 'otp', 'auth', 'reset', 'csrf')
RANDOM_CALLS = {'random.random', 'random.randint', 'random.randrange', 'random.choice', 'random.choices'}


def _snippet(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ''


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f'{prefix}.{node.attr}' if prefix else node.attr
    return ''


def _mask_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in PLACEHOLDER_WORDS)


def _violation(rule: SLARule, path: Path, lineno: int, lines: list[str], explanation: str | None = None) -> Violation:
    return Violation(
        rule_id=rule.id,
        rule_name=rule.name,
        file=str(path.resolve()),
        line=lineno,
        code_snippet=_snippet(lines, lineno),
        explanation=explanation or rule.description,
    )


def _is_user_controlled_url(node: ast.AST) -> bool:
    """Flag only URLs that are plausibly user-controlled to avoid false positives on config variables."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # "http://" + var
        return True
    if isinstance(node, ast.Subscript):  # data["url"], request.args["url"]
        return True
    if isinstance(node, ast.Attribute):  # req.url, request.form.get("url")
        dotted = _dotted_name(node).lower()
        return any(w in dotted for w in ('request', 'req', 'query', 'form', 'body', 'args', 'params', 'data'))
    return False


def _body_is_empty_or_pass(body: list[ast.stmt]) -> bool:
    if not body:
        return True
    return all(isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in body)


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
    return ''


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
    return any(any(word in haystack for word in SECURITY_CONTEXT_WORDS) for haystack in haystacks if haystack)


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
    if isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == 'format':
        base = query.func.value
        if isinstance(base, ast.Constant) and isinstance(base.value, str) and SQL_KEYWORDS.search(base.value):
            return True
    return False


def analyze(path: Path, source: str) -> tuple[list[Violation], list[SyntaxIssue]]:
    lines = source.splitlines()
    rules = DEFAULT_RULES_BY_ID
    violations: list[Violation] = []
    syntax_issues: list[SyntaxIssue] = []

    for lineno, line in enumerate(lines, 1):
        match = SECRET_ASSIGN_RE.search(line)
        if match and not _mask_placeholder(match.group('value')):
            violations.append(_violation(rules['NO_HARDCODED_SECRETS'], path, lineno, lines))
            continue
        for pattern in PROVIDER_SECRET_PATTERNS:
            provider_match = pattern.search(line)
            if provider_match and not _mask_placeholder(provider_match.group(0)):
                violations.append(_violation(rules['NO_HARDCODED_SECRETS'], path, lineno, lines))
                break

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        syntax_issues.append(
            SyntaxIssue(
                file=str(path.resolve()),
                message=exc.msg,
                line=exc.lineno or 0,
                col=exc.offset or 0,
            )
        )
        return violations, syntax_issues

    parents = _build_parent_map(tree)
    for node in ast.walk(tree):
        lineno = getattr(node, 'lineno', 1)
        line = _snippet(lines, lineno)

        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted in NETWORK_CALLS:
                url_arg = node.args[1] if dotted.endswith('.request') and len(node.args) > 1 else (node.args[0] if node.args else None)
                url_arg = next((kw.value for kw in node.keywords if kw.arg in {'url', 'endpoint'}), url_arg)
                if url_arg is not None and _is_user_controlled_url(url_arg):
                    violations.append(_violation(rules['NO_NETWORK'], path, lineno, lines))

            if dotted in EXEC_CALLS:
                has_shell_true = any(kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                # os.system / os.popen always use a shell — always flag.
                # For subprocess.*, only flag when shell=True is explicit.
                if dotted.startswith('os.') or has_shell_true:
                    violations.append(_violation(rules['NO_EXEC'], path, lineno, lines))

            if isinstance(node.func, ast.Attribute) and node.func.attr in {'execute', 'executemany'} and _sql_call_has_binding_issue(node):
                violations.append(_violation(rules['SQL_PARAM_BINDING'], path, lineno, lines))

            if dotted in RANDOM_CALLS and _has_security_context(node, parents, line):
                violations.append(_violation(rules['NO_WEAK_RANDOM'], path, lineno, lines))

            if any(kw.arg == 'debug' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
                violations.append(_violation(rules['NO_DEBUG_MODE'], path, lineno, lines))

        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == 'DEBUG' and isinstance(node.value, ast.Constant) and node.value.value is True:
                    violations.append(_violation(rules['NO_DEBUG_MODE'], path, lineno, lines))
                    break

        if isinstance(node, ast.ExceptHandler):
            broad_exception = (
                node.type is None
                or (isinstance(node.type, ast.Name) and node.type.id == 'Exception' and _body_is_empty_or_pass(node.body))
            )
            if broad_exception:
                violations.append(_violation(rules['NO_BARE_EXCEPT'], path, lineno, lines))

    return violations, syntax_issues
