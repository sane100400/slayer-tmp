import asyncio
import difflib
from pathlib import Path

from fastapi import HTTPException

try:
    from backend.models import AIChoice, SLARule, Violation, PatchResult
except ImportError:
    from models import AIChoice, SLARule, Violation, PatchResult

from slayer.ai_runner import AICliError, extract_code, run_ai
from slayer.patcher.llm_patcher import PatchValidationError, validate_syntax

PATCH_SYSTEM = """SLAyer security patch task.
Return only the full updated source file contents. Do not add markdown fences or explanations.
Fix only the listed security violations. Preserve unrelated behavior, names, comments, and formatting.
Use the smallest safe diff that removes the listed violations.
"""

GUIDANCE_BY_RULE_TYPE = {
    "SQL_INJECTION": "Replace string-built SQL with parameter binding.",
    "HARDCODED_SECRETS": "Replace hardcoded secrets with environment variable lookups.",
    "DEBUG_MODE_ON": "Disable debug mode for deployment-safe defaults.",
    "INSECURE_COOKIE": "Set secure cookie options such as httponly, secure, and samesite where applicable.",
    "WEAK_HASH": "Replace MD5/SHA1 password hashing with a modern password hashing approach.",
    "COMMAND_INJECTION": "Replace shell command execution with argument-list execution or block unsafe execution.",
    "OPEN_REDIRECT": "Validate redirect targets against an allowlist or keep redirects relative.",
    "CUSTOM": "Apply the custom rule description exactly and minimally.",
}


def _unified_diff(original: str, patched: str) -> str:
    lines = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile="original",
        tofile="patched",
        lineterm="",
    )
    return "".join(lines)


def _build_prompt(path: Path, code: str, violations: list[Violation], rules: list[SLARule]) -> str:
    rules_by_id = {rule.id: rule for rule in rules}
    violation_lines: list[str] = []
    for violation in violations:
        rule = rules_by_id.get(violation.rule_id)
        rule_name = rule.name if rule else violation.rule_id
        rule_type = rule.rule_type if rule else "CUSTOM"
        guidance = GUIDANCE_BY_RULE_TYPE.get(rule_type, GUIDANCE_BY_RULE_TYPE["CUSTOM"])
        violation_lines.append(
            f"- line {violation.line}, {rule_name} ({rule_type}): {violation.explanation}\n"
            f"  snippet: {violation.code_snippet}\n"
            f"  guidance: {guidance}"
        )

    return f"""{PATCH_SYSTEM}

File: {path}

Violations:
{chr(10).join(violation_lines)}

Source:
{code}
""".strip()


async def patch(
    code: str,
    violations: list[Violation],
    rules: list[SLARule],
    selected_ai: AIChoice,
    file_path: Path,
    timeout: int = 60,
) -> PatchResult:
    prompt = _build_prompt(file_path, code, violations, rules)
    try:
        raw_output, candidate = await asyncio.to_thread(
            run_ai,
            prompt,
            preferred=selected_ai,
            timeout=timeout,
            cwd=file_path.parent,
        )
        patched = extract_code(raw_output)
        validate_syntax(file_path, patched)
    except AICliError as e:
        raise HTTPException(status_code=502, detail=f"AI CLI 오류: {e}") from e
    except PatchValidationError as e:
        raise HTTPException(status_code=422, detail=f"패치 문법 검증 실패: {e}") from e

    return PatchResult(
        original_code=code,
        patched_code=patched,
        diff=_unified_diff(code, patched),
        remaining_violations=[],
        deployable=True,
        ai_used=candidate.name,
    )
