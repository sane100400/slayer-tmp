from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.text import Text
from rich.rule import Rule

from slayer.models import PatchResult, ScanResult
from slayer.rules import RULE_DETAILS, DEFAULT_RULES_BY_ID

_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    'critical': ('bold red',    '● CRITICAL'),
    'high':     ('bold yellow', '▲ HIGH'),
    'medium':   ('bold cyan',   '■ MEDIUM'),
    'low':      ('dim',         '▪ LOW'),
}


def render_json(payload: ScanResult | PatchResult) -> str:
    return json.dumps(payload.model_dump(), ensure_ascii=False, indent=2) + '\n'


def _severity_of(rule_id: str) -> str:
    rule = DEFAULT_RULES_BY_ID.get(rule_id)
    return rule.severity if rule else 'medium'


def print_scan_rich(target: str | Path, result: ScanResult, console: Console | None = None) -> None:
    c = console or Console()

    c.print(f'\n[bold]SLAyer[/]  Scanning [cyan]{Path(target)}[/]\n')

    if not result.scanned_files:
        c.print('[dim]No supported source files found.[/]')
        c.print()
        return

    for issue in result.syntax_errors:
        loc = f'{issue.file}:{issue.line}' if issue.line else issue.file
        c.print(f'[yellow]⚠ syntax error[/]  {loc}  {issue.message}')

    if not result.violations:
        c.print(Rule(style='dim'))
        c.print('[bold green]✓ No violations found — 🚀 Deployment Approved[/]\n')
        return

    # Group violations by file for cleaner output
    by_file: dict[str, list] = {}
    for v in result.violations:
        by_file.setdefault(v.file, []).append(v)

    for file_path, violations in by_file.items():
        rel = Path(file_path).name
        for v in violations:
            severity = _severity_of(v.rule_id)
            sty, label = _SEVERITY_STYLE.get(severity, ('dim', '▪'))
            details = RULE_DETAILS.get(v.rule_id, {})

            # Header line
            header = Text()
            header.append(f' {label}', style=sty)
            header.append(f'  {v.rule_name}', style='bold white')
            header.append(f'  {rel}:{v.line}', style='dim')
            c.print(header)

            # Code snippet
            if v.code_snippet:
                c.print(f'   [dim on default]  {v.code_snippet.strip()[:120]}[/]')

            # Why
            if details.get('why'):
                c.print()
                for why_line in details['why'].splitlines():
                    c.print(f'   [dim]{why_line}[/]')

            # Fix
            if details.get('fix'):
                c.print()
                c.print(f'   [green]→[/] [green]{details["fix"]}[/]')

            c.print()

    c.print(Rule(style='dim'))
    count = len(result.violations)
    if result.deployable:
        c.print('[bold green]🚀 Deployment Approved[/]\n')
    else:
        c.print(
            f'[bold red] {count} violation{"s" if count != 1 else ""}[/]  ·  '
            f'[bold red]🔒 Deployment BLOCKED[/]'
        )
        c.print(
            f'\n   [dim]Run [bold]slayer patch {Path(target)}[/] to fix automatically.[/]\n'
        )


def print_patch_rich(target: str | Path, result: PatchResult, console: Console | None = None) -> None:
    c = console or Console()

    c.print(f'\n[bold]SLAyer[/]  Patching [cyan]{Path(target)}[/]\n')

    if result.ai_used != 'none':
        c.print(f'[dim]Patching via [bold]{result.ai_used}[/]...[/]\n')

    for issue in result.syntax_errors:
        loc = f'{issue.file}:{issue.line}' if issue.line else issue.file
        c.print(f'[yellow]⚠ syntax error[/]  {loc}  {issue.message}')

    for patched in result.patched_files:
        c.print(f'[green]✓[/]  {patched} patched')

    c.print()
    c.print(Rule(style='dim'))

    if result.deployable:
        c.print('[bold green]🚀 Deployment Approved[/]\n')
    else:
        c.print('[bold red]Remaining violations:[/]')
        for v in result.remaining_violations:
            severity = _severity_of(v.rule_id)
            sty, label = _SEVERITY_STYLE.get(severity, ('dim', '▪'))
            c.print(f'  [{sty}]{label}[/]  [bold]{v.rule_name}[/]  [dim]{Path(v.file).name}:{v.line}[/]')
        c.print()


# ── Legacy string-based renderers (used for --format json; text path now uses Rich) ──

def render_scan_text(target: str | Path, result: ScanResult) -> str:
    """Fallback plain-text renderer (used only when Rich is unavailable)."""
    lines = [f'SLAyer  Scanning {Path(target)}', '']
    if not result.scanned_files:
        lines.append('No supported source files found')
    for issue in result.syntax_errors:
        location = f'{issue.file}:{issue.line}' if issue.line else issue.file
        lines.append(f'⚠ syntax error  {location}  {issue.message}')
    for violation in result.violations:
        lines.append(
            f"✗  {violation.rule_name:<22} {Path(violation.file).name}:{violation.line:<4} {violation.code_snippet.strip()}"
        )
        details = RULE_DETAILS.get(violation.rule_id, {})
        if details.get('why'):
            lines.append(f"   {details['why'].splitlines()[0]}")
        if details.get('fix'):
            lines.append(f"   → {details['fix']}")
        lines.append('')
    lines.append('🚀 Deployment Approved' if result.deployable else f'Deployment BLOCKED — {len(result.violations)} violation(s)')
    return '\n'.join(lines) + '\n'


def render_patch_text(target: str | Path, result: PatchResult) -> str:
    """Fallback plain-text renderer."""
    lines = [f'SLAyer  Patching {Path(target)}', '']
    if result.ai_used != 'none':
        lines.append(f'Patching via {result.ai_used}...')
    for patched in result.patched_files:
        lines.append(f'✓  {patched} patched')
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
                f"✗  {violation.rule_name:<22} {Path(violation.file).name}:{violation.line:<4} {violation.code_snippet.strip()}"
            )
    return '\n'.join(lines) + '\n'
