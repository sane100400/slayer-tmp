from __future__ import annotations

import json
from pathlib import Path

from slayer.models import PatchResult, ScanResult


def render_json(payload: ScanResult | PatchResult) -> str:
    return json.dumps(payload.model_dump(), ensure_ascii=False, indent=2) + '\n'


def render_scan_text(target: str | Path, result: ScanResult) -> str:
    lines = [f'SLAyer  Scanning {Path(target)}', '']
    if not result.scanned_files:
        lines.append('No supported source files found')
    for issue in result.syntax_errors:
        location = f'{issue.file}:{issue.line}' if issue.line else issue.file
        lines.append(f'⚠ syntax error  {location}  {issue.message}')
    for violation in result.violations:
        lines.append(
            f"✗  {violation.rule_name:<20} {Path(violation.file).name}:{violation.line:<4} {violation.code_snippet.strip()}"
        )
    lines.append('')
    lines.append('🚀 Deployment Approved' if result.deployable else 'Deployment BLOCKED')
    return '\n'.join(lines) + '\n'


def render_patch_text(target: str | Path, result: PatchResult) -> str:
    lines = [f'SLAyer  Patching {Path(target)}', '']
    if result.ai_used != 'none':
        lines.append(f'Patching via {result.ai_used}...')
    for patched in result.patched_files:
        lines.append(f'Patched: {patched}')
    for issue in result.syntax_errors:
        location = f'{issue.file}:{issue.line}' if issue.line else issue.file
        lines.append(f'⚠ syntax error  {location}  {issue.message}')
    if result.deployable:
        lines.append('')
        lines.append('🚀 Deployment Approved')
    else:
        lines.append('')
        lines.append('Remaining violations:')
        for violation in result.remaining_violations:
            lines.append(
                f"✗  {violation.rule_name:<20} {Path(violation.file).name}:{violation.line:<4} {violation.code_snippet.strip()}"
            )
    return '\n'.join(lines) + '\n'
