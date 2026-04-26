from __future__ import annotations

from collections import defaultdict
import os
from pathlib import Path

from slayer.analyzers import analyze_javascript, analyze_python
from slayer.artifact_store import DEFAULT_ARTIFACT_VERSION, RuntimeArtifactBundle, load_runtime_artifacts
from slayer.models import SLARule, ScanResult, SyntaxIssue, Violation
from slayer.rules import default_rules

SUPPORTED_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx'}
IGNORED_DIRECTORIES = {
    '.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '.next', 'coverage', '__pycache__', '.omx', '.pytest_cache',
}


def detect_language(path: Path) -> str:
    suffix = path.suffix.lower()
    return {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
    }.get(suffix, 'unknown')


def collect_supported_files(target: Path) -> list[Path]:
    resolved = target.resolve()
    if resolved.is_file():
        return [resolved] if resolved.suffix.lower() in SUPPORTED_EXTENSIONS else []
    files: list[Path] = []
    for root, dirnames, filenames in os.walk(resolved):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in IGNORED_DIRECTORIES]
        root_path = Path(root)
        for filename in filenames:
            candidate = root_path / filename
            if candidate.suffix.lower() in SUPPORTED_EXTENSIONS:
                files.append(candidate.resolve())
    return sorted(files)


def scan_file(path: Path, artifact_bundle: RuntimeArtifactBundle) -> tuple[list[Violation], list[SyntaxIssue]]:
    try:
        source = path.read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        return [], [SyntaxIssue(file=str(path.resolve()), message=str(exc))]
    language = detect_language(path)
    if language == 'python':
        return analyze_python(path, source, artifact_bundle=artifact_bundle)
    if language in {'javascript', 'typescript'}:
        return analyze_javascript(path, source, artifact_bundle=artifact_bundle), []
    return [], []


def scan_path(
    target: str | Path,
    rules: list[SLARule] | None = None,
    artifact_version: str = DEFAULT_ARTIFACT_VERSION,
    artifact_bundle: RuntimeArtifactBundle | None = None,
) -> ScanResult:
    rule_set = rules or default_rules()
    bundle = artifact_bundle or load_runtime_artifacts(version=artifact_version)
    files = collect_supported_files(Path(target))
    violations: list[Violation] = []
    syntax_errors: list[SyntaxIssue] = []
    for file_path in files:
        file_violations, file_syntax_errors = scan_file(file_path, bundle)
        violations.extend(file_violations)
        syntax_errors.extend(file_syntax_errors)
    failed_rule_ids = {violation.rule_id for violation in violations}
    pass_count = sum(1 for rule in rule_set if rule.id not in failed_rule_ids)
    return ScanResult(
        rules=rule_set,
        violations=violations,
        pass_count=pass_count,
        fail_count=len(violations) + len(syntax_errors),
        deployable=len(violations) == 0 and len(syntax_errors) == 0,
        scanned_files=[str(path) for path in files],
        syntax_errors=syntax_errors,
        artifact_version=bundle.version,
    )


def group_violations_by_file(violations: list[Violation]) -> dict[str, list[Violation]]:
    grouped: dict[str, list[Violation]] = defaultdict(list)
    for violation in violations:
        grouped[violation.file].append(violation)
    return dict(grouped)
