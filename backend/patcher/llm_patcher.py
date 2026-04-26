import asyncio
import difflib
from pathlib import Path

from fastapi import HTTPException

try:
    from backend.models import AIChoice, PatchExplanation, SLARule, Violation, PatchResult
except ImportError:
    from models import AIChoice, PatchExplanation, SLARule, Violation, PatchResult

from slayer.ai_runner import AICliError, extract_code, run_ai
from slayer.patch_explanations import build_patch_explanations
from slayer.patcher.llm_patcher import PatchValidationError, validate_syntax
from slayer.rules import PATCH_EXPLANATION_TEMPLATES, RULE_GUIDANCE, canonical_rule_id

PATCH_SYSTEM = """SLAyer security patch task.
Return only the full updated source file contents. Do not add markdown fences or explanations.
Fix only the listed security violations. Preserve unrelated behavior, names, comments, and formatting.
Use the smallest safe diff that removes the listed violations.
"""

GUIDANCE_BY_RULE_TYPE = {
    "NO_NETWORK": "Block dynamic/user-controlled external network calls or constrain them to an allowlist.",
    "NO_EXEC": "Replace shell command execution with argument-list execution or block unsafe execution.",
    "NO_HARDCODED_SECRETS": "Replace hardcoded secrets with environment variable lookups.",
    "SQL_PARAM_BINDING": "Replace string-built SQL with parameter binding.",
    "NO_DEBUG_MODE": "Disable debug mode for deployment-safe defaults.",
    "NO_INSECURE_HASH": "Replace MD5/SHA1 password hashing with PBKDF2-HMAC-SHA256 or a SHA-256+ alternative.",
    "NO_BARE_EXCEPT": "Replace empty exception handlers with explicit logging or error handling.",
    "SQL_INJECTION": "Replace string-built SQL with parameter binding.",
    "HARDCODED_SECRETS": "Replace hardcoded secrets with environment variable lookups.",
    "DEBUG_MODE_ON": "Disable debug mode for deployment-safe defaults.",
    "INSECURE_COOKIE": "Set secure cookie options such as httponly, secure, and samesite where applicable.",
    "WEAK_HASH": "Replace MD5/SHA1 password hashing with a modern password hashing approach.",
    "COMMAND_INJECTION": "Replace shell command execution with argument-list execution or block unsafe execution.",
    "OPEN_REDIRECT": "Validate redirect targets against an allowlist or keep redirects relative.",
    "CUSTOM": "Apply the custom rule description exactly and minimally.",
}
RULE_TYPE_ALIASES = {
    "SQL_INJECTION": "SQL_PARAM_BINDING",
    "HARDCODED_SECRETS": "NO_HARDCODED_SECRETS",
    "DEBUG_MODE_ON": "NO_DEBUG_MODE",
    "WEAK_HASH": "NO_INSECURE_HASH",
    "COMMAND_INJECTION": "NO_EXEC",
}


def _canonical_rule(rule: SLARule | None, violation: Violation) -> str:
    candidate = rule.rule_type if rule else violation.rule_id
    return canonical_rule_id(RULE_TYPE_ALIASES.get(candidate, candidate))


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
        rule_type = _canonical_rule(rule, violation)
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


def _patch_explanation_for_backend(violation: Violation, rule: SLARule | None) -> PatchExplanation:
    canonical = _canonical_rule(rule, violation)
    title, summary, guidance = PATCH_EXPLANATION_TEMPLATES.get(
        canonical,
        (
            "보안 위반을 안전한 구현으로 바꿨어요",
            "탐지된 취약 코드만 최소 범위로 수정해 기존 동작을 최대한 유지했어요.",
            RULE_GUIDANCE.get(canonical, "탐지된 위반을 안전한 대안으로 바꾸세요."),
        ),
    )
    return PatchExplanation(
        file=violation.file,
        rule_id=canonical,
        rule_name=canonical,
        line=violation.line,
        title=title,
        summary=summary,
        guidance=guidance,
        reference=f"spec.md#{canonical}",
    )


async def patch(
    code: str,
    violations: list[Violation],
    rules: list[SLARule],
    selected_ai: AIChoice,
    file_path: Path,
    timeout: int = 60,
) -> PatchResult:
    prompt = _build_prompt(file_path, code, violations, rules)
    rules_by_id = {rule.id: rule for rule in rules}
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
        patch_explanations=[
            item.model_dump()
            for item in build_patch_explanations(
                violations,
                {rule.id: rule for rule in rules},
            )
        ],
        remaining_violations=[],
        deployable=True,
        ai_used=candidate.name,
        patch_explanations=[
            _patch_explanation_for_backend(violation, rules_by_id.get(violation.rule_id))
            for violation in violations
        ],
    )
