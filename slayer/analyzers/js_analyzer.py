from __future__ import annotations

import re
from pathlib import Path

from slayer.models import Violation
from slayer.rules import DEFAULT_RULES_BY_ID

SECRET_ASSIGN_RE = re.compile(
    r'(?ix)(?:const|let|var)?\s*[A-Za-z_$][\w$]*(?:password|passwd|pwd|api_?key|secret|token|credential)[\w$]*\s*=\s*(["\'])(?P<value>[^"\']{4,})\1'
)
PROVIDER_PATTERNS = (
    re.compile(r'sk-[A-Za-z0-9-]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'),
)
PLACEHOLDER_WORDS = {"example", "dummy", "test", "changeme", "your_api_key", "xxxxx", "sample", "placeholder"}
NETWORK_RE = re.compile(r'\b(fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|request)|https\.(?:get|request))\s*\(')
EXEC_DIRECT_RE = re.compile(
    r'(?:child_process|cp)\.(?:exec|execSync|spawnSync)\s*\('
    r'|require\([\"\']child_process[\"\']\)\.(?:exec|execSync|spawnSync)\s*\('
)
EXEC_IMPORT_RE = re.compile(r'(?:const|let|var)\s*\{(?P<names>[^}]+)\}\s*=\s*require\([\"\']child_process[\"\']\)')
EXEC_IMPORT_ESM_RE = re.compile(r'import\s*\{(?P<names>[^}]+)\}\s*from\s*[\"\']child_process[\"\']')
EXEC_NAMES = {'exec', 'execSync', 'spawnSync'}
SQL_TEMPLATE_RE = re.compile(r'`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{', re.IGNORECASE)
SQL_CONCAT_RE = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*(?:\+|concat\()')
DEBUG_RE = re.compile(r'(?i)\bdebug\s*:\s*true\b|\bdebug\s*=\s*true\b')
INSECURE_HASH_RE = re.compile(r'createHash\(\s*[\"\'](?:md5|sha1)[\"\']\s*\)', re.IGNORECASE)
EMPTY_CATCH_RE = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}', re.MULTILINE)
SECURITY_CONTEXT_WORDS = ("token", "secret", "password", "passwd", "pwd", "session", "otp", "auth", "reset", "csrf", "credential")
SQL_CONTEXT_WORDS = ("sql", "query", "db.", "database", "execute")


def _snippet(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ""


def _mask_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in PLACEHOLDER_WORDS)


def _violation(rule_id: str, path: Path, lineno: int, lines: list[str]) -> Violation:
    rule = DEFAULT_RULES_BY_ID[rule_id]
    return Violation(
        rule_id=rule.id,
        rule_name=rule.name,
        file=str(path.resolve()),
        line=lineno,
        code_snippet=_snippet(lines, lineno),
        explanation=rule.description,
    )


def _first_argument(line: str, match: re.Match[str]) -> str:
    rest = line[match.end():]
    if ')' in rest:
        rest = rest.split(')', 1)[0]
    return rest.split(',', 1)[0].strip()


def _is_safe_literal(expr: str) -> bool:
    if not expr:
        return False
    expr = expr.strip()
    if '${' in expr:
        return False
    if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
        return True
    return False


def _line_number(source: str, index: int) -> int:
    return source.count('\n', 0, index) + 1


def _has_security_context(line: str) -> bool:
    lowered = line.lower()
    return any(word in lowered for word in SECURITY_CONTEXT_WORDS)


def _has_sql_context(line: str) -> bool:
    lowered = line.lower()
    return any(word in lowered for word in SQL_CONTEXT_WORDS)


def _imported_child_process_exec_names(source: str) -> set[str]:
    names: set[str] = set()
    for pattern in (EXEC_IMPORT_RE, EXEC_IMPORT_ESM_RE):
        for match in pattern.finditer(source):
            for raw_name in match.group('names').split(','):
                alias_separator = ' as ' if ' as ' in raw_name else ':'
                parts = [part.strip() for part in raw_name.strip().split(alias_separator, 1)]
                name = parts[0]
                local_name = parts[-1]
                if name in EXEC_NAMES:
                    names.add(local_name)
    return names


def _has_exec_violation(line: str, imported_exec_names: set[str]) -> bool:
    if EXEC_DIRECT_RE.search(line):
        return True
    return any(re.search(rf'(?<![\w$.]){re.escape(name)}\s*\(', line) for name in imported_exec_names)


def analyze(path: Path, source: str) -> list[Violation]:
    lines = source.splitlines()
    violations: list[Violation] = []
    imported_exec_names = _imported_child_process_exec_names(source)

    for lineno, line in enumerate(lines, 1):
        match = SECRET_ASSIGN_RE.search(line)
        if match and not _mask_placeholder(match.group('value')):
            violations.append(_violation('NO_HARDCODED_SECRETS', path, lineno, lines))
            continue
        for pattern in PROVIDER_PATTERNS:
            provider_match = pattern.search(line)
            if provider_match and not _mask_placeholder(provider_match.group(0)):
                violations.append(_violation('NO_HARDCODED_SECRETS', path, lineno, lines))
                break

        network_match = NETWORK_RE.search(line)
        if network_match:
            first_arg = _first_argument(line, network_match)
            lowered = first_arg.lower()
            if not _is_safe_literal(first_arg) or any(token in lowered for token in ('req.', 'request.', 'params.', 'query.', 'body.', '${')):
                violations.append(_violation('NO_NETWORK', path, lineno, lines))

        if _has_exec_violation(line, imported_exec_names):
            violations.append(_violation('NO_EXEC', path, lineno, lines))

        if (SQL_TEMPLATE_RE.search(line) or SQL_CONCAT_RE.search(line)) and _has_sql_context(line):
            violations.append(_violation('SQL_PARAM_BINDING', path, lineno, lines))

        if DEBUG_RE.search(line):
            violations.append(_violation('NO_DEBUG_MODE', path, lineno, lines))

        if INSECURE_HASH_RE.search(line) and _has_security_context(line):
            violations.append(_violation('NO_INSECURE_HASH', path, lineno, lines))

    for match in EMPTY_CATCH_RE.finditer(source):
        lineno = _line_number(source, match.start())
        violations.append(_violation('NO_BARE_EXCEPT', path, lineno, lines))

    return violations
