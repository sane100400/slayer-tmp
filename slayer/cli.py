from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from slayer.ai_runner import AICliError, AI_CANDIDATES, _is_available, detect_ai_cli, AICliNotFoundError
from slayer.patcher.llm_patcher import patch_path
from slayer.reporter import render_json, render_patch_text, render_scan_text
from slayer.scanner import scan_path

app = typer.Typer(add_completion=False, help='SLAyer security scanner and patcher')
console = Console(stderr=True)

_CONFIG_FILE = Path('.slayer.yml')


class OutputFormatEnum(str, Enum):
    text = 'text'
    json = 'json'


def _read_saved_ai() -> str | None:
    if not _CONFIG_FILE.exists():
        return None
    for line in _CONFIG_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith('ai:'):
            value = line.split(':', 1)[1].strip()
            if value in ('claude', 'codex', 'gemini', 'auto'):
                return value
    return None


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
        typer.echo(render_scan_text(target, result), nl=False)


def _print_patch(target: Path, result, output_format: OutputFormatEnum) -> None:
    if output_format == OutputFormatEnum.json:
        typer.echo(render_json(result), nl=False)
    else:
        typer.echo(render_patch_text(target, result), nl=False)


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
    raise typer.Exit(code=1 if result.violations else 0)


@app.command()
def patch(
    path: str = typer.Argument('.', help='Target file or directory'),
    output_format: OutputFormatEnum = typer.Option(OutputFormatEnum.text, '--format', help='Output format'),
) -> None:
    selected_ai = _read_saved_ai() or 'auto'
    target = Path(path)
    try:
        result = patch_path(target, selected_ai=selected_ai)
    except AICliError as exc:
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)

    _print_patch(target, result, output_format)
    raise typer.Exit(code=1 if result.remaining_violations else 0)


@app.command()
def model(
    ai_name: Optional[str] = typer.Argument(None, help='AI CLI to use: claude | codex | gemini | auto'),
) -> None:
    """Show or set the AI CLI used for patching."""
    valid = ('claude', 'codex', 'gemini', 'auto')

    if ai_name is not None:
        if ai_name not in valid:
            console.print(f'[red]Unknown AI CLI:[/red] {ai_name!r}. Choose from: {", ".join(valid)}')
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
