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
from slayer.artifact_store import DEFAULT_ARTIFACT_VERSION, RuntimeArtifactBundle, load_runtime_artifacts
from slayer.models import AIChoice, PatchResult, Violation
from slayer.redaction import mask_text, mask_violations
from slayer.rules import RULE_GUIDANCE
from slayer.scanner import detect_language, group_violations_by_file, scan_path

MAX_PATCH_ROUNDS = 2
SECRET_ASSIGN_RE = re.compile(r'(?ix)(\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential|access[_-]?key)\b\s*=\s*["\'])([^"\']{4,})(["\'])')
PROVIDER_SECRET_RE = re.compile(r'sk-[A-Za-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}')


class PatchValidationError(RuntimeError):
    pass


def _mask_secret(value: str) -> str:
    return '***REDACTED***' if len(value) <= 8 else f'{value[:4]}...{value[-4:]}'


def _artifact_secret_regexes(bundle: RuntimeArtifactBundle | None) -> list[str]:
    return [artifact.regex for artifact in (bundle.secret_patterns if bundle else [])]


def redact_secrets(source: str, artifact_bundle: RuntimeArtifactBundle | None = None) -> str:
    def replace_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_secret(match.group(2))}{match.group(3)}"
    redacted = SECRET_ASSIGN_RE.sub(replace_assignment, source)
    redacted = PROVIDER_SECRET_RE.sub(lambda match: _mask_secret(match.group(0)), redacted)
    return mask_text(redacted, extra_patterns=_artifact_secret_regexes(artifact_bundle))


def _unified_diff(original: str, patched: str, file_path: str) -> str:
    return ''.join(difflib.unified_diff(original.splitlines(keepends=True), patched.splitlines(keepends=True), fromfile=file_path, tofile=file_path, lineterm=''))


def _artifact_recipe_lines(bundle: RuntimeArtifactBundle, language: str, rule_names: list[str]) -> list[str]:
    return [
        f"- {recipe.rule_id}: {recipe.instructions}"
        for recipe in bundle.patch_recipes
        if recipe.language in {language, 'shared'} and recipe.rule_id in rule_names
    ]


def _artifact_fewshot_blocks(bundle: RuntimeArtifactBundle, language: str, rule_names: list[str]) -> list[str]:
    extra_patterns = _artifact_secret_regexes(bundle)
    blocks: list[str] = []
    for example in bundle.patch_fewshots:
        if example.language not in {language, 'shared'} or example.rule_id not in rule_names:
            continue
        before = mask_text(example.before.strip(), extra_patterns=extra_patterns)
        after = mask_text(example.after.strip(), extra_patterns=extra_patterns)
        blocks.append("\n".join([f"Rule: {example.rule_id}", "Before:", before, "After:", after]))
        if len(blocks) >= 4:
            break
    return blocks


def build_patch_prompt(path: Path, source: str, violations: list[Violation], artifact_bundle: RuntimeArtifactBundle) -> str:
    language = detect_language(path)
    unique_violations = {violation.rule_name: violation for violation in violations}
    rule_names = list(unique_violations)
    base_guidance = [f"- {violation.rule_name}: {RULE_GUIDANCE.get(violation.rule_name, '위반을 안전한 대안으로 바꾸세요.')}" for violation in unique_violations.values()]
    base_guidance.extend(_artifact_recipe_lines(artifact_bundle, language, rule_names))
    fewshot_blocks = _artifact_fewshot_blocks(artifact_bundle, language, rule_names)
    safe_violations = mask_violations(violations, extra_patterns=_artifact_secret_regexes(artifact_bundle))
    violations_json = json.dumps([violation.model_dump() for violation in safe_violations], ensure_ascii=False, indent=2)
    fewshot_section = "\n\nPatch examples:\n" + "\n\n".join(fewshot_blocks) if fewshot_blocks else ""
    return f"""
You are patching one {language} source file for SLAyer.
Return only the full updated file contents for this file. Do not add markdown fences or explanations.
Keep changes minimal and preserve behavior unless a rule explicitly requires blocking unsafe behavior.
Artifact bundle version: {artifact_bundle.version}

File: {path}
Violations:
{violations_json}

Patch guidance:
{'\n'.join(base_guidance)}
- If secrets are masked in the prompt, replace them with environment variable lookups instead of restoring the original value.
- Prefer the smallest working diff that removes the listed violations.
- Do not change unrelated lines.{fewshot_section}

Code:
{source}
""".strip()


def _validate_python(code: str, path: Path) -> None:
    try:
        ast.parse(code, filename=str(path))
    except SyntaxError as exc:
        raise PatchValidationError(f'Python 문법 검증 실패: {exc}') from exc


def _validate_with_command(command: list[str], suffix: str, code: str) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / f'candidate{suffix}'
        file_path.write_text(code, encoding='utf-8')
        result = subprocess.run([*command, str(file_path)], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise PatchValidationError(result.stderr.strip() or result.stdout.strip() or '문법 검증 실패')


def validate_patch_candidate(path: Path, original: str, patched: str) -> None:
    if not patched.strip():
        raise PatchValidationError(f'{path}: AI CLI returned empty patch output')
    if original.strip() and len(patched.strip()) < 8:
        raise PatchValidationError(f'{path}: AI CLI returned suspiciously small patch output')


def validate_syntax(path: Path, code: str) -> None:
    suffix = path.suffix.lower()
    if suffix == '.py':
        _validate_python(code, path)
        return
    if suffix == '.js' and shutil.which('node'):
        _validate_with_command(['node', '--check'], suffix, code)
        return
    if suffix in {'.ts', '.tsx'} and shutil.which('tsc'):
        _validate_with_command(['tsc', '--pretty', 'false', '--noEmit'], suffix, code)
        return


def _rollback_files(original_files: dict[Path, str]) -> None:
    for path, original in original_files.items():
        path.write_text(original, encoding='utf-8')


def patch_path(
    target: str | Path,
    selected_ai: AIChoice = 'auto',
    timeout: int = 60,
    artifact_version: str = DEFAULT_ARTIFACT_VERSION,
    artifact_bundle: RuntimeArtifactBundle | None = None,
) -> PatchResult:
    target_path = Path(target)
    bundle = artifact_bundle or load_runtime_artifacts(version=artifact_version)
    scan_result = scan_path(target_path, artifact_version=bundle.version, artifact_bundle=bundle)
    if scan_result.deployable:
        return PatchResult(
            patched_files=[],
            diffs={},
            remaining_violations=[],
            deployable=True,
            ai_used='none',
            scanned_files=scan_result.scanned_files,
            syntax_errors=scan_result.syntax_errors,
            artifact_version=bundle.version,
        )
    candidate = detect_ai_cli(preferred=selected_ai)
    patched_files: list[str] = []
    diffs: dict[str, str] = {}
    original_files: dict[Path, str] = {}
    try:
        for _ in range(MAX_PATCH_ROUNDS):
            changes_this_round = 0
            pending_writes: list[tuple[Path, str, str, str]] = []
            for file_name, violations in group_violations_by_file(scan_result.violations).items():
                path = Path(file_name)
                original = path.read_text(encoding='utf-8', errors='replace')
                prompt = build_patch_prompt(path, redact_secrets(original, artifact_bundle=bundle), violations, artifact_bundle=bundle)
                raw_output, _ = run_ai(prompt, preferred=selected_ai, timeout=timeout, cwd=path.parent, candidate=candidate)
                patched = extract_code(raw_output)
                validate_patch_candidate(path, original, patched)
                validate_syntax(path, patched)
                diff = _unified_diff(original, patched, file_name)
                if diff:
                    pending_writes.append((path, original, patched, mask_text(diff, extra_patterns=_artifact_secret_regexes(bundle))))

            for path, original, patched, safe_diff in pending_writes:
                resolved = path.resolve()
                original_files.setdefault(resolved, original)
                path.write_text(patched, encoding='utf-8')
                file_name = str(resolved)
                if file_name not in patched_files:
                    patched_files.append(file_name)
                diffs[file_name] = safe_diff
                changes_this_round += 1

            scan_result = scan_path(target_path, artifact_version=bundle.version, artifact_bundle=bundle)
            if scan_result.deployable or changes_this_round == 0:
                break
    except Exception:
        _rollback_files(original_files)
        raise

    return PatchResult(
        patched_files=patched_files,
        diffs=diffs,
        remaining_violations=scan_result.violations,
        deployable=scan_result.deployable,
        ai_used=candidate.name,
        scanned_files=scan_result.scanned_files,
        syntax_errors=scan_result.syntax_errors,
        artifact_version=bundle.version,
    )
