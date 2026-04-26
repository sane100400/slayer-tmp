from __future__ import annotations

import ast
import re
from pathlib import Path

from slayer.artifact_store import RuntimeArtifactBundle
from slayer.models import SLARule, SyntaxIssue, Violation
from slayer.redaction import mask_text
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
    'requests.get', 'requests.post', 'requests.put', 'requests.delete', 'requests.patch', 'requests.request',
    'httpx.get', 'httpx.post', 'httpx.put', 'httpx.delete', 'httpx.patch', 'httpx.request',
    'urllib.request.urlopen', 'urllib3.request', 'aiohttp.request', 'socket.create_connection', 'socket.socket.connect', 'boto3.client',
}
EXEC_CALLS = {
    'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output',
    'os.system', 'os.popen', 'os.execv', 'os.execve', 'os.execvp',
}
SECURITY_CONTEXT_WORDS = ('token', 'secret', 'password', 'session', 'otp', 'auth', 'reset', 'csrf')
RANDOM_CALLS = {'random.random', 'random.randint', 'random.randrange', 'random.choice', 'random.choices'}


def _snippet(lines: list[str], lineno: int) -> str:
    return lines[lineno - 1].rstrip() if 1 <= lineno <= len(lines) else ''


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
        code_snippet=mask_text(_snippet(lines, lineno)),
        explanation=explanation or rule.description,
    )


def _is_dynamic_network_target(node: ast.AST) -> bool:
    return not (isinstance(node, ast.Constant) and isinstance(node.value, str))


def _body_is_empty_or_pass(body: list[ast.stmt]) -> bool:
    return (not body) or all(isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in body)


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
        return [target.id.lower() for target in parent.targets if isinstance(target, ast.Name)]
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


def _dedupe(violations: list[Violation]) -> list[Violation]:
    seen: set[tuple[str, str, int]] = set()
    deduped: list[Violation] = []
    for violation in violations:
        key = (violation.rule_id, violation.file, violation.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(violation)
    return deduped


def _artifact_secret_patterns(bundle: RuntimeArtifactBundle | None) -> list[re.Pattern[str]]:
    if bundle is None:
        return []
    return [
        re.compile(artifact.regex)
        for artifact in bundle.secret_patterns
        if not artifact.languages or 'python' in artifact.languages or 'shared' in artifact.languages
    ]


def _artifact_scanner_patterns(bundle: RuntimeArtifactBundle | None) -> list[tuple[re.Pattern[str], SLARule]]:
    if bundle is None:
        return []
    overlays: list[tuple[re.Pattern[str], SLARule]] = []
    for artifact in bundle.scanner_patterns:
        if artifact.language != 'python':
            continue
        rule = DEFAULT_RULES_BY_ID.get(artifact.rule_id)
        if rule is not None:
            overlays.append((re.compile(artifact.regex), rule))
    return overlays


def analyze(path: Path, source: str, artifact_bundle: RuntimeArtifactBundle | None = None) -> tuple[list[Violation], list[SyntaxIssue]]:
    lines = source.splitlines()
    rules = DEFAULT_RULES_BY_ID
    violations: list[Violation] = []
    syntax_issues: list[SyntaxIssue] = []
    artifact_secret_patterns = _artifact_secret_patterns(artifact_bundle)
    artifact_scanner_patterns = _artifact_scanner_patterns(artifact_bundle)

    for lineno, line in enumerate(lines, 1):
        match = SECRET_ASSIGN_RE.search(line)
        if match and not _mask_placeholder(match.group('value')):
            violations.append(_violation(rules['NO_HARDCODED_SECRETS'], path, lineno, lines))
            continue
        provider_hit = False
        for pattern in PROVIDER_SECRET_PATTERNS:
            provider_match = pattern.search(line)
            if provider_match and not _mask_placeholder(provider_match.group(0)):
                violations.append(_violation(rules['NO_HARDCODED_SECRETS'], path, lineno, lines))
                provider_hit = True
                break
        if provider_hit:
            continue
        for pattern in artifact_secret_patterns:
            artifact_match = pattern.search(line)
            if artifact_match and not _mask_placeholder(artifact_match.group(0)):
                violations.append(_violation(rules['NO_HARDCODED_SECRETS'], path, lineno, lines))
                break

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        syntax_issues.append(SyntaxIssue(file=str(path.resolve()), message=exc.msg, line=exc.lineno or 0, col=exc.offset or 0))
        return _dedupe(violations), syntax_issues

    parents = _build_parent_map(tree)
    for node in ast.walk(tree):
        lineno = getattr(node, 'lineno', 1)
        line = _snippet(lines, lineno)
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted in NETWORK_CALLS:
                url_arg = node.args[1] if dotted.endswith('.request') and len(node.args) > 1 else (node.args[0] if node.args else None)
                url_arg = next((kw.value for kw in node.keywords if kw.arg in {'url', 'endpoint'}), url_arg)
                if url_arg is not None and _is_dynamic_network_target(url_arg):
                    violations.append(_violation(rules['NO_NETWORK'], path, lineno, lines))
            if dotted in EXEC_CALLS:
                has_shell_true = any(kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                first_arg = node.args[0] if node.args else None
                dangerous_string = isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)
                if dotted.startswith('os.') or has_shell_true or dangerous_string:
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
            broad_exception = node.type is None or (isinstance(node.type, ast.Name) and node.type.id == 'Exception' and _body_is_empty_or_pass(node.body))
            if broad_exception:
                violations.append(_violation(rules['NO_BARE_EXCEPT'], path, lineno, lines))

    for lineno, line in enumerate(lines, 1):
        for pattern, rule in artifact_scanner_patterns:
            if pattern.search(line):
                violations.append(_violation(rule, path, lineno, lines))

    return _dedupe(violations), syntax_issues
