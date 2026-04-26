from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.text import Text
from rich.rule import Rule
from rich.panel import Panel
from rich.padding import Padding
from rich.columns import Columns

from slayer.models import PatchResult, ScanResult
from slayer.redact import redact_secrets
from slayer.rules import RULE_DETAILS, DEFAULT_RULES_BY_ID

_SEVERITY_CONF: dict[str, tuple[str, str, str]] = {
    'critical': ('white on red',     'bold red',    '● CRITICAL'),
    'high':     ('black on yellow',  'bold yellow', '▲ HIGH'),
    'medium':   ('white on blue',    'bold blue',   '■ MEDIUM'),
    'low':      ('dim',              'dim',         '▪ LOW'),
}


def render_json(payload: ScanResult | PatchResult) -> str:
    return json.dumps(payload.model_dump(), ensure_ascii=False, indent=2) + '\n'


def _severity_of(rule_id: str) -> str:
    rule = DEFAULT_RULES_BY_ID.get(rule_id)
    return rule.severity if rule else 'medium'


def _badge(severity: str) -> Text:
    badge_style, _, label = _SEVERITY_CONF.get(severity, ('dim', 'dim', '▪'))
    t = Text()
    t.append(f' {label} ', style=badge_style)
    return t


def print_scan_rich(target: str | Path, result: ScanResult, console: Console | None = None) -> None:
    c = console or Console()

    # ── Header ──────────────────────────────────────────────────────────────
    file_count = len(result.scanned_files)
    header = Text()
    header.append('  SLAyer', style='bold white')
    header.append('  ·  ', style='dim')
    header.append(str(Path(target)), style='cyan')
    if file_count:
        header.append(f'  ·  {file_count} file{"s" if file_count != 1 else ""}', style='dim')
    c.print()
    c.print(header)
    c.print()

    if not result.scanned_files:
        c.print(Padding('[dim]No supported source files found.[/]', (0, 2)))
        c.print()
        return

    for issue in result.syntax_errors:
        loc = f'{issue.file}:{issue.line}' if issue.line else issue.file
        c.print(Padding(f'[yellow]⚠ syntax error[/]  [dim]{loc}[/]  {issue.message}', (0, 2)))

    if not result.violations:
        c.print(Rule(style='dim'))
        c.print()
        c.print(Padding('[bold green]✓  No violations found[/]', (0, 2)))
        c.print(Padding('[bold green]🚀 Deployment Approved[/]', (0, 2)))
        c.print()
        return

    # ── Violations ──────────────────────────────────────────────────────────
    by_file: dict[str, list] = {}
    for v in result.violations:
        by_file.setdefault(v.file, []).append(v)

    for file_path, violations in by_file.items():
        rel = Path(file_path).name
        for v in violations:
            severity = _severity_of(v.rule_id)
            _, accent, _ = _SEVERITY_CONF.get(severity, ('dim', 'dim', '▪'))
            details = RULE_DETAILS.get(v.rule_id, {})

            # Severity badge + rule + location
            line = Text()
            line.append_text(_badge(severity))
            line.append(f'  {v.rule_name}', style='bold white')
            line.append(f'  {rel}:{v.line}', style='dim')
            c.print(Padding(line, (1, 2, 0, 2)))

            # Code snippet box (secrets masked before display)
            if v.code_snippet:
                snippet = redact_secrets(v.code_snippet.strip())[:120]
                c.print(Padding(
                    Panel(f'[dim]{snippet}[/]', border_style='dim', padding=(0, 1), expand=False),
                    (0, 4),
                ))

            # Why (first line only, compact)
            if details.get('why'):
                why_first = details['why'].splitlines()[0].strip()
                c.print(Padding(f'[dim]⚠  {why_first}[/]', (0, 4)))

            # Fix
            if details.get('fix'):
                c.print(Padding(f'[{accent}]→[/]  [green]{details["fix"]}[/]', (0, 4)))

    # ── Footer ──────────────────────────────────────────────────────────────
    c.print()
    c.print(Rule(style='dim'))
    count = len(result.violations)
    if result.deployable:
        c.print()
        c.print(Padding('[bold green]🚀 Deployment Approved[/]', (0, 2)))
        c.print()
    else:
        viol_text = Text()
        viol_text.append(f'  {count} violation{"s" if count != 1 else ""}', style='bold red')
        viol_text.append('  ·  ', style='dim')
        viol_text.append('🔒 Deployment BLOCKED', style='bold red')
        c.print()
        c.print(viol_text)
        c.print(Padding(f'[dim]Run: [bold]slayer patch {Path(target)}[/][/]', (0, 2)))
        c.print()


def _print_diff(diff: str, console: Console) -> None:
    for line in diff.splitlines():
        if line.startswith(('--- ', '+++ ')):
            continue
        if line.startswith('@@'):
            console.print(Padding(Text(line, style='cyan dim'), (0, 6)))
        elif line.startswith('-'):
            t = Text(f'  {line}', style='red', no_wrap=True)
            console.print(Padding(t, (0, 4)))
        elif line.startswith('+'):
            t = Text(f'  {line}', style='bold green', no_wrap=True)
            console.print(Padding(t, (0, 4)))
        else:
            console.print(Padding(Text(f'  {line}', style='dim', no_wrap=True), (0, 4)))


def print_patch_rich(target: str | Path, result: PatchResult, console: Console | None = None, *, skip_diffs: bool = False) -> None:
    c = console or Console()

    if not skip_diffs:
        # ── Header ──────────────────────────────────────────────────────────────
        header = Text()
        header.append('  SLAyer', style='bold white')
        header.append('  ·  ', style='dim')
        header.append(str(Path(target)), style='cyan')
        c.print()
        c.print(header)
        c.print()

        if result.ai_used != 'none':
            c.print(Padding(f'[dim]Patching via [bold]{result.ai_used}[/]...[/]', (0, 2)))
            c.print()

        for issue in result.syntax_errors:
            loc = f'{issue.file}:{issue.line}' if issue.line else issue.file
            c.print(Padding(f'[yellow]⚠ syntax error[/]  [dim]{loc}[/]  {issue.message}', (0, 2)))

        for patched in result.patched_files:
            c.print(Padding(f'[green]✓[/]  [bold]{Path(patched).name}[/]  [dim]patched[/]', (0, 2)))
            if patched in result.diffs:
                _print_diff(result.diffs[patched], c)
                c.print()

    if result.patch_explanations:
        c.print()
        c.print(Padding('[bold]Patch explanations:[/]', (0, 2)))
        for exp in result.patch_explanations:
            loc = f'{Path(exp.file).name}:{exp.line}' if exp.line else Path(exp.file).name
            c.print(Padding(
                f'[cyan]•[/] [bold]{exp.rule_name}[/]  [dim]{loc}[/]  [italic]— {exp.title}[/]',
                (0, 4),
            ))
            c.print(Padding(f'[dim]{exp.summary}[/]', (0, 6)))

    c.print()
    c.print(Rule(style='dim'))

    if result.deployable:
        c.print()
        c.print(Padding('[bold green]🚀 Deployment Approved[/]', (0, 2)))
        c.print()
    else:
        c.print()
        c.print(Padding('[bold red]Remaining violations:[/]', (0, 2)))
        for v in result.remaining_violations:
            severity = _severity_of(v.rule_id)
            line = Text()
            line.append_text(_badge(severity))
            line.append(f'  {v.rule_name}', style='bold')
            line.append(f'  {Path(v.file).name}:{v.line}', style='dim')
            c.print(Padding(line, (0, 4)))
        c.print()


# ── Legacy string-based renderers (fallback when Rich is unavailable) ────────

def render_scan_text(target: str | Path, result: ScanResult) -> str:
    lines = [f'SLAyer  Scanning {Path(target)}', '']
    if not result.scanned_files:
        lines.append('No supported source files found')
    for issue in result.syntax_errors:
        location = f'{issue.file}:{issue.line}' if issue.line else issue.file
        lines.append(f'⚠ syntax error  {location}  {issue.message}')
    for violation in result.violations:
        lines.append(
            f"✗  {violation.rule_name:<22} {Path(violation.file).name}:{violation.line:<4} {redact_secrets(violation.code_snippet.strip())}"
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
    lines = [f'SLAyer  Patching {Path(target)}', '']
    if result.ai_used != 'none':
        lines.append(f'Patching via {result.ai_used}...')
    for patched in result.patched_files:
        lines.append(f'✓  {Path(patched).name} patched')
        if patched in result.diffs:
            for dl in result.diffs[patched].splitlines():
                if not dl.startswith(('--- ', '+++ ')):
                    lines.append(f'    {dl}')
            lines.append('')
    if result.patch_explanations:
        lines.append('')
        lines.append('Patch explanations:')
        for exp in result.patch_explanations:
            loc = f'{Path(exp.file).name}:{exp.line}' if exp.line else Path(exp.file).name
            lines.append(f'• {exp.rule_name}  {loc} — {exp.title}')
            lines.append(f'  {exp.summary}')
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
