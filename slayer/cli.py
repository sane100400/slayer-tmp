from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from slayer.ai_runner import AICliError, AI_CANDIDATES, _is_available, detect_ai_cli, AICliNotFoundError
from slayer.models import Violation
from slayer.patcher.llm_patcher import patch_path
from slayer.reporter import render_json, render_patch_text, render_scan_text, print_scan_rich, print_patch_rich, _print_diff
from slayer.scanner import scan_path

app = typer.Typer(add_completion=False, help='SLAyer security scanner and patcher')
console = Console(stderr=True)

_CONFIG_FILE = Path('.slayer.yml')
_VALID_AI_CHOICES = ('claude', 'codex', 'gemini', 'auto')


class OutputFormatEnum(str, Enum):
    text = 'text'
    json = 'json'


class SlayerConfigError(RuntimeError):
    pass


def _read_ai_value() -> str | None:
    if not _CONFIG_FILE.exists():
        return None
    for line in _CONFIG_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith('ai:'):
            return line.split(':', 1)[1].strip()
    return None


def _read_saved_ai() -> str | None:
    value = _read_ai_value()
    return value if value in _VALID_AI_CHOICES else None


def _read_required_ai() -> str:
    if not _CONFIG_FILE.exists():
        return 'auto'

    value = _read_ai_value()
    if value is None:
        return 'auto'
    if value not in _VALID_AI_CHOICES:
        raise SlayerConfigError(f'Invalid ai value in .slayer.yml: {value!r}. Use one of: claude, codex, gemini, auto.')
    return value


def _write_saved_ai(ai_name: str) -> None:
    lines: list[str] = []
    replaced = False
    if _CONFIG_FILE.exists():
        for line in _CONFIG_FILE.read_text().splitlines():
            if line.strip().startswith('ai:'):
                lines.append(f'ai: {ai_name}')
                replaced = True
            else:
                lines.append(line)
    if not replaced:
        lines.append(f'ai: {ai_name}')
    _CONFIG_FILE.write_text('\n'.join(lines) + '\n')


def _print_scan(target: Path, result, output_format: OutputFormatEnum) -> None:
    if output_format == OutputFormatEnum.json:
        typer.echo(render_json(result), nl=False)
    else:
        print_scan_rich(target, result)  # Console() defaults to stdout


def _print_patch(target: Path, result, output_format: OutputFormatEnum) -> None:
    if output_format == OutputFormatEnum.json:
        typer.echo(render_json(result), nl=False)
    else:
        print_patch_rich(target, result)  # Console() defaults to stdout


@app.command()
def start(
    path: str = typer.Argument('.', help='Target file or directory'),
    output_format: OutputFormatEnum = typer.Option(OutputFormatEnum.text, '--format', help='Output format'),
) -> None:
    target = Path(path)
    try:
        result = scan_path(target)
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        console.print(f'[red]Scan failed:[/red] {exc}')
        raise typer.Exit(code=2)

    _print_scan(target, result, output_format)
    raise typer.Exit(code=0 if result.deployable else 1)


@app.command()
def patch(
    path: str = typer.Argument('.', help='Target file or directory'),
    output_format: OutputFormatEnum = typer.Option(OutputFormatEnum.text, '--format', help='Output format'),
) -> None:
    target = Path(path)
    rich_console = Console()

    def _progress(event: str, violation: Violation, detail: str) -> None:
        if output_format == OutputFormatEnum.json:
            return
        loc = f'{Path(violation.file).name}:{violation.line}'
        if event == 'patched':
            line = Text()
            line.append('  ✓ ', style='bold green')
            line.append(violation.rule_name, style='bold white')
            line.append(f'  {loc}', style='dim')
            rich_console.print(line)
            if detail:
                _print_diff(detail, rich_console)
                rich_console.print()
        elif event == 'unchanged':
            rich_console.print(Padding(
                f'[dim]  ↷  {violation.rule_name}  {loc}  (no change)[/]', (0, 0)
            ))
        elif event == 'error':
            rich_console.print(Padding(
                f'[red]  ✗  {violation.rule_name}  {loc}  {detail}[/]', (0, 0)
            ))

    try:
        selected_ai = _read_required_ai()

        if output_format == OutputFormatEnum.text:
            header = Text()
            header.append('  SLAyer', style='bold white')
            header.append('  ·  ', style='dim')
            header.append(str(target), style='cyan')
            rich_console.print()
            rich_console.print(header)
            rich_console.print()

        result = patch_path(target, selected_ai=selected_ai, progress_fn=_progress)
    except SlayerConfigError as exc:
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)
    except AICliError as exc:
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)

    if output_format == OutputFormatEnum.json:
        typer.echo(render_json(result), nl=False)
    else:
        print_patch_rich(target, result, rich_console, skip_diffs=True)
    raise typer.Exit(code=1 if result.remaining_violations else 0)


@app.command()
def model(
    ai_name: Optional[str] = typer.Argument(None, help='AI CLI to use: claude | codex | gemini | auto'),
) -> None:
    """Show or set the AI CLI used for patching."""
    if ai_name is not None:
        if ai_name not in _VALID_AI_CHOICES:
            console.print(f'[red]Unknown AI CLI:[/red] {ai_name!r}. Choose from: {", ".join(_VALID_AI_CHOICES)}')
            raise typer.Exit(code=2)
        _write_saved_ai(ai_name)
        console.print(f'[green]✓[/green] Saved: ai = {ai_name} → .slayer.yml')
        return

    saved = _read_saved_ai()
    typer.echo('')
    typer.echo('  AI CLI Status')
    typer.echo('  ─────────────────────────────────────')
    for candidate in AI_CANDIDATES:
        available = _is_available(candidate)
        mark = '[green]✓[/green]' if available else '[dim]✗[/dim]'
        console.print(f'  {mark}  {candidate.name}')

    typer.echo('')
    if saved and saved != 'auto':
        typer.echo(f'  Saved preference : {saved}  (from .slayer.yml)')
    else:
        typer.echo('  Saved preference : auto  (first available)')

    try:
        active = detect_ai_cli()
        typer.echo(f'  Active AI CLI    : {active.name}')
    except AICliNotFoundError:
        typer.echo('  Active AI CLI    : none — install Claude Code / Codex / Gemini CLI')
    typer.echo('')


def main() -> None:
    app()


if __name__ == '__main__':
    main()
