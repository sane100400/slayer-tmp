from __future__ import annotations

import re

SECRET_ASSIGN_RE = re.compile(
    r'(?ix)(\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential|access[_-]?key)\b\s*=\s*["\'])([^"\']{4,})(["\'])'
)
PROVIDER_SECRET_RE = re.compile(r'sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}')


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return '***REDACTED***'
    return f'{value[:4]}...{value[-4:]}'


def redact_secrets(source: str) -> str:
    def replace_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_secret(match.group(2))}{match.group(3)}"

    redacted = SECRET_ASSIGN_RE.sub(replace_assignment, source)
    return PROVIDER_SECRET_RE.sub(lambda m: _mask_secret(m.group(0)), redacted)
