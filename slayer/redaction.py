from __future__ import annotations

import re
from collections.abc import Iterable

from slayer.models import Violation

# Broad runtime masking patterns. These intentionally cover the provider-specific
# classes used by the scanner plus common assignment-style secret literals so
# reports, prompts, and diffs do not leak discovered values.
PROVIDER_SECRET_RE = re.compile(
    r'(?x)('
    r'sk-[A-Za-z0-9-]{12,}'
    r'|ghp_[A-Za-z0-9]{20,}'
    r'|github_pat_[A-Za-z0-9_]{20,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|ASIA[0-9A-Z]{16}'
    r'|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}'
    r')'
)
SECRET_ASSIGN_RE = re.compile(
    r'(?ix)'
    r'(\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential|access[_-]?key)\b\s*[:=]\s*["\'])'
    r'([^"\']{4,})'
    r'(["\'])'
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----.*?-----END (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----',
    re.DOTALL,
)


def mask_secret_value(value: str) -> str:
    """Return a non-sensitive placeholder for a matched secret value."""
    if not value:
        return value
    if len(value) <= 8:
        return '***REDACTED***'
    return f'{value[:4]}...{value[-4:]}'


def _compile_extra_patterns(extra_patterns: Iterable[str | re.Pattern[str]] | None) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in extra_patterns or []:
        try:
            compiled.append(pattern if isinstance(pattern, re.Pattern) else re.compile(pattern))
        except re.error:
            continue
    return compiled


def mask_text(text: str, extra_patterns: Iterable[str | re.Pattern[str]] | None = None) -> str:
    """Mask provider secrets and common assignment literals in arbitrary text."""
    if not text:
        return text

    masked = PRIVATE_KEY_BLOCK_RE.sub('***REDACTED_PRIVATE_KEY***', text)
    masked = SECRET_ASSIGN_RE.sub(lambda m: f'{m.group(1)}{mask_secret_value(m.group(2))}{m.group(3)}', masked)
    masked = PROVIDER_SECRET_RE.sub(lambda m: mask_secret_value(m.group(0)), masked)

    for pattern in _compile_extra_patterns(extra_patterns):
        masked = pattern.sub(lambda m: mask_secret_value(m.group(0)), masked)
    return masked


def mask_violation(violation: Violation, extra_patterns: Iterable[str | re.Pattern[str]] | None = None) -> Violation:
    """Return a copy of a violation safe for output or AI prompts."""
    return violation.model_copy(update={'code_snippet': mask_text(violation.code_snippet, extra_patterns=extra_patterns)})


def mask_violations(violations: Iterable[Violation], extra_patterns: Iterable[str | re.Pattern[str]] | None = None) -> list[Violation]:
    return [mask_violation(violation, extra_patterns=extra_patterns) for violation in violations]
