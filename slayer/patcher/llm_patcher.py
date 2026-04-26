from __future__ import annotations

import ast
import difflib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from slayer.ai_runner import detect_ai_cli, extract_code, run_ai
from slayer.models import AIChoice, PatchExplanation, PatchResult, Violation
from slayer.rules import RULE_GUIDANCE, patch_explanation_for
from slayer.scanner import detect_language, group_violations_by_file, scan_path

MAX_PATCH_ROUNDS = 2
SECRET_ASSIGN_RE = re.compile(
    r'(?ix)(\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential|access[_-]?key)\b\s*=\s*["\'])([^"\']{4,})(["\'])'
)
PROVIDER_SECRET_RE = re.compile(r'sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}')


class PatchValidationError(RuntimeError):
    pass


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return '***REDACTED***'
    return f'{value[:4]}...{value[-4:]}'


def redact_secrets(source: str) -> str:
    def replace_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_secret(match.group(2))}{match.group(3)}"

    redacted = SECRET_ASSIGN_RE.sub(replace_assignment, source)
    return PROVIDER_SECRET_RE.sub(lambda match: _mask_secret(match.group(0)), redacted)


def _unified_diff(original: str, patched: str, file_path: str) -> str:
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=file_path,
        tofile=file_path,
        lineterm='',
    )
    return ''.join(diff)


def build_patch_prompt(path: Path, source: str, violations: list[Violation]) -> str:
    language = detect_language(path)
    unique_violations = {violation.rule_name: violation for violation in violations}
    rule_guidance = '\n'.join(
        f"- {violation.rule_name}: {RULE_GUIDANCE.get(violation.rule_name, 'Replace the violation with a safe alternative.')}"
        for violation in unique_violations.values()
    )
    violations_json = json.dumps([violation.model_dump() for violation in violations], ensure_ascii=False, indent=2)
    return f"""
You are patching one {language} source file for SLAyer.
Return only the full updated file contents for this file. Do not add markdown fences or explanations.
Only fix the violations listed below. Do not change code that is unrelated to those violations.
Keep variable names, comments, formatting, and behavior unchanged unless a listed violation requires a security fix.

File: {path}
Violations:
{violations_json}

Patch guidance:
{rule_guidance}
- If secrets are masked in the prompt, replace them with environment variable lookups instead of restoring the original value.
- Prefer the smallest working diff that removes the listed violations.
- Do not change unrelated lines.

Code:
{source}
""".strip()


def _validate_python(code: str, path: Path) -> None:
    try:
        ast.parse(code, filename=str(path))
    except SyntaxError as exc:
        raise PatchValidationError(f'Python syntax validation failed: {exc}') from exc


def _validate_with_command(command: list[str], suffix: str, code: str) -> None:
    executable = shutil.which(command[0])
    if executable is None:
        return
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / f'candidate{suffix}'
        file_path.write_text(code, encoding='utf-8')
        result = subprocess.run(
            [executable, *command[1:], str(file_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False,
        )
        if result.returncode != 0:
            raise PatchValidationError(result.stderr.strip() or result.stdout.strip() or 'Syntax validation failed')


def validate_syntax(path: Path, code: str) -> None:
    suffix = path.suffix.lower()
    if suffix == '.py':
        _validate_python(code, path)
        return
    if suffix == '.js':
        _validate_with_command(['node', '--check'], suffix, code)
        return
    if suffix in {'.ts', '.tsx'}:
        _validate_with_command(['tsc', '--pretty', 'false', '--noEmit'], suffix, code)
        return
    # JSX/TSX without tsc and other file types are best-effort only.


def patch_path(target: str | Path, selected_ai: AIChoice = 'auto', timeout: int = 60) -> PatchResult:
    target_path = Path(target)
    scan_result = scan_path(target_path)
    if scan_result.deployable:
        return PatchResult(
            patched_files=[],
            diffs={},
            remaining_violations=[],
            deployable=True,
            ai_used='none',
            scanned_files=scan_result.scanned_files,
            syntax_errors=scan_result.syntax_errors,
        )

    candidate = detect_ai_cli(preferred=selected_ai)
    patched_files: list[str] = []
    diffs: dict[str, str] = {}
    patch_explanations: list[PatchExplanation] = []
    explained_keys: set[tuple[str, str, int]] = set()

    for _ in range(MAX_PATCH_ROUNDS):
        changes_this_round = 0
        for file_name, violations in group_violations_by_file(scan_result.violations).items():
            path = Path(file_name)
            original = path.read_text(encoding='utf-8', errors='replace')
            prompt = build_patch_prompt(path, redact_secrets(original), violations)
            raw_output, _ = run_ai(prompt, preferred=selected_ai, timeout=timeout, cwd=path.parent, candidate=candidate)
            patched = extract_code(raw_output)
            validate_syntax(path, patched)
            diff = _unified_diff(original, patched, file_name)
            if diff:
                path.write_text(patched, encoding='utf-8')
                if file_name not in patched_files:
                    patched_files.append(file_name)
                diffs[file_name] = diff
                for violation in violations:
                    key = (file_name, violation.rule_id, violation.line)
                    if key not in explained_keys:
                        patch_explanations.append(patch_explanation_for(violation, file=file_name))
                        explained_keys.add(key)
                changes_this_round += 1

        scan_result = scan_path(target_path)
        if scan_result.deployable or changes_this_round == 0:
            break

    return PatchResult(
        patched_files=patched_files,
        diffs=diffs,
        patch_explanations=patch_explanations,
        remaining_violations=scan_result.violations,
        deployable=scan_result.deployable,
        ai_used=candidate.name,
        scanned_files=scan_result.scanned_files,
        syntax_errors=scan_result.syntax_errors,
    )
