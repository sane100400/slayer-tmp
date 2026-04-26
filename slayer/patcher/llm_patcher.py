from __future__ import annotations

import ast
import difflib
import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from slayer.ai_runner import AICliError, detect_ai_cli, extract_code, run_ai
from slayer.models import AIChoice, PatchExplanation, PatchResult, Violation
from slayer.redact import redact_secrets
from slayer.rules import RULE_GUIDANCE, patch_explanation_for
from slayer.scanner import detect_language, group_violations_by_file, scan_path

# Max AI calls per file (safety valve against infinite loops)
MAX_ATTEMPTS_PER_FILE = 20

ProgressFn = Callable[[str, Violation, str], None]


class PatchValidationError(RuntimeError):
    pass


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

    def _redact_violation(v: Violation) -> dict:
        d = v.model_dump()
        d['code_snippet'] = redact_secrets(d['code_snippet'])
        return d

    violations_json = json.dumps([_redact_violation(v) for v in violations], ensure_ascii=False, indent=2)
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


def _patch_file_incremental(
    path: Path,
    file_name: str,
    candidate,
    selected_ai: AIChoice,
    timeout: int,
    scan_root: Path,
    patched_files: list[str],
    combined_diffs: dict[str, str],
    patch_explanations: list[PatchExplanation],
    explained_keys: set[tuple[str, str, int]],
    progress_fn: ProgressFn | None,
) -> None:
    """Patch a single file one violation at a time, rescanning after each patch."""
    attempted: set[tuple[str, int, str]] = set()

    for _ in range(MAX_ATTEMPTS_PER_FILE):
        # Fresh scan of this file to get current violations with correct line numbers
        file_scan = scan_path(path)
        current_violations = [v for v in file_scan.violations if v.file == file_name]

        # Filter out violations we've already attempted but couldn't fix
        pending = [
            v for v in current_violations
            if (v.rule_id, v.line, v.code_snippet[:60]) not in attempted
        ]
        if not pending:
            break

        violation = pending[0]
        attempt_key = (violation.rule_id, violation.line, violation.code_snippet[:60])
        attempted.add(attempt_key)

        source = path.read_text(encoding='utf-8', errors='replace')
        prompt = build_patch_prompt(path, redact_secrets(source), [violation])

        try:
            raw_output, _ = run_ai(
                prompt,
                preferred=selected_ai,
                timeout=timeout,
                cwd=path.parent,
                candidate=candidate,
            )
            patched = extract_code(raw_output)
            validate_syntax(path, patched)
        except PatchValidationError as exc:
            if progress_fn:
                progress_fn('error', violation, str(exc))
            continue
        except AICliError as exc:
            if progress_fn:
                progress_fn('error', violation, str(exc))
            # Don't retry on AI errors (timeout, execution error)
            break

        diff = _unified_diff(source, patched, file_name)
        if diff:
            path.write_text(patched, encoding='utf-8')

            # Accumulate diff (append for same file across multiple patches)
            combined_diffs[file_name] = combined_diffs.get(file_name, '') + diff

            if file_name not in patched_files:
                patched_files.append(file_name)

            key = (file_name, violation.rule_id, violation.line)
            if key not in explained_keys:
                patch_explanations.append(patch_explanation_for(violation, file=file_name))
                explained_keys.add(key)

            if progress_fn:
                progress_fn('patched', violation, diff)
        else:
            # AI returned unchanged code — violation may be unfixable, move on
            if progress_fn:
                progress_fn('unchanged', violation, '')


def patch_path(
    target: str | Path,
    selected_ai: AIChoice = 'auto',
    timeout: int = 120,
    progress_fn: ProgressFn | None = None,
) -> PatchResult:
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
    scan_root = target_path.resolve()
    patched_files: list[str] = []
    combined_diffs: dict[str, str] = {}
    patch_explanations: list[PatchExplanation] = []
    explained_keys: set[tuple[str, str, int]] = set()

    for file_name in list(group_violations_by_file(scan_result.violations).keys()):
        path = Path(file_name)
        # Guard: refuse to write outside scan root (symlink traversal defence)
        try:
            path.resolve().relative_to(scan_root if scan_root.is_dir() else scan_root.parent)
        except ValueError:
            continue

        _patch_file_incremental(
            path=path,
            file_name=file_name,
            candidate=candidate,
            selected_ai=selected_ai,
            timeout=timeout,
            scan_root=scan_root,
            patched_files=patched_files,
            combined_diffs=combined_diffs,
            patch_explanations=patch_explanations,
            explained_keys=explained_keys,
            progress_fn=progress_fn,
        )

    final_scan = scan_path(target_path)

    return PatchResult(
        patched_files=patched_files,
        diffs=combined_diffs,
        patch_explanations=patch_explanations,
        remaining_violations=final_scan.violations,
        deployable=final_scan.deployable,
        ai_used=candidate.name,
        scanned_files=final_scan.scanned_files,
        syntax_errors=final_scan.syntax_errors,
    )
