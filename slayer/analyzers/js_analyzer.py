from __future__ import annotations

import re
from pathlib import Path

from slayer.artifact_store import RuntimeArtifactBundle
from slayer.models import Violation
from slayer.redaction import mask_text
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
EXEC_RE = re.compile(r'\b(?:child_process\.)?(?:exec|execSync|spawnSync)\s*\(')
SQL_TEMPLATE_RE = re.compile(r'`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{', re.IGNORECASE)
SQL_CONCAT_RE = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*(?:\+|concat\()')
DEBUG_RE = re.compile(r'(?i)\bdebug\s*:\s*true\b|\bDEBUG\s*=\s*true\b|NODE_ENV\s*!==?\s*["\']production["\']')
WEAK_RANDOM_RE = re.compile(r'Math\.random\s*\(')
EMPTY_CATCH_RE = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}', re.MULTILINE)
SECURITY_CONTEXT_WORDS = ("token", "secret", "password", "session", "otp", "auth", "reset", "csrf")


def _snippet(lines: list[str], lineno: int) -> str:
    return lines[lineno - 1].rstrip() if 1 <= lineno <= len(lines) else ""


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
        code_snippet=mask_text(_snippet(lines, lineno)),
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
    return (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'"))


def _line_number(source: str, index: int) -> int:
    return source.count('\n', 0, index) + 1


def _artifact_secret_patterns(bundle: RuntimeArtifactBundle | None) -> list[re.Pattern[str]]:
    if bundle is None:
        return []
    return [
        re.compile(artifact.regex)
        for artifact in bundle.secret_patterns
        if not artifact.languages or 'javascript' in artifact.languages or 'typescript' in artifact.languages or 'shared' in artifact.languages
    ]


def _artifact_scanner_patterns(bundle: RuntimeArtifactBundle | None, language: str) -> list[tuple[re.Pattern[str], str]]:
    if bundle is None:
        return []
    overlays: list[tuple[re.Pattern[str], str]] = []
    for artifact in bundle.scanner_patterns:
        if artifact.language not in {language, 'javascript'}:
            continue
        if artifact.rule_id in DEFAULT_RULES_BY_ID:
            overlays.append((re.compile(artifact.regex), artifact.rule_id))
    return overlays


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


def analyze(path: Path, source: str, artifact_bundle: RuntimeArtifactBundle | None = None) -> list[Violation]:
    lines = source.splitlines()
    language = 'typescript' if path.suffix.lower() in {'.ts', '.tsx'} else 'javascript'
    artifact_secret_patterns = _artifact_secret_patterns(artifact_bundle)
    artifact_scanner_patterns = _artifact_scanner_patterns(artifact_bundle, language)
    violations: list[Violation] = []

    for lineno, line in enumerate(lines, 1):
        match = SECRET_ASSIGN_RE.search(line)
        if match and not _mask_placeholder(match.group('value')):
            violations.append(_violation('NO_HARDCODED_SECRETS', path, lineno, lines))
            continue
        provider_hit = False
        for pattern in PROVIDER_PATTERNS:
            provider_match = pattern.search(line)
            if provider_match and not _mask_placeholder(provider_match.group(0)):
                violations.append(_violation('NO_HARDCODED_SECRETS', path, lineno, lines))
                provider_hit = True
                break
        if provider_hit:
            continue
        for pattern in artifact_secret_patterns:
            artifact_match = pattern.search(line)
            if artifact_match and not _mask_placeholder(artifact_match.group(0)):
                violations.append(_violation('NO_HARDCODED_SECRETS', path, lineno, lines))
                break

        network_match = NETWORK_RE.search(line)
        if network_match:
            first_arg = _first_argument(line, network_match)
            lowered = first_arg.lower()
            if not _is_safe_literal(first_arg) or any(token in lowered for token in ('req.', 'request.', 'params.', 'query.', 'body.', '${')):
                violations.append(_violation('NO_NETWORK', path, lineno, lines))

        if EXEC_RE.search(line):
            violations.append(_violation('NO_EXEC', path, lineno, lines))
        if SQL_TEMPLATE_RE.search(line) or SQL_CONCAT_RE.search(line):
            violations.append(_violation('SQL_PARAM_BINDING', path, lineno, lines))
        if DEBUG_RE.search(line):
            violations.append(_violation('NO_DEBUG_MODE', path, lineno, lines))
        if WEAK_RANDOM_RE.search(line) and any(word in line.lower() for word in SECURITY_CONTEXT_WORDS):
            violations.append(_violation('NO_WEAK_RANDOM', path, lineno, lines))
        for pattern, rule_id in artifact_scanner_patterns:
            if pattern.search(line):
                violations.append(_violation(rule_id, path, lineno, lines))

    for match in EMPTY_CATCH_RE.finditer(source):
        lineno = _line_number(source, match.start())
        violations.append(_violation('NO_BARE_EXCEPT', path, lineno, lines))
    return _dedupe(violations)
