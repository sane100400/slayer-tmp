from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from slayer.ai_runner import AICliError
from slayer.patcher.llm_patcher import patch_path
from slayer.reporter import render_json, render_patch_text, render_scan_text
from slayer.scanner import scan_path
from slayer.tui import SLayerTUI

app = typer.Typer(add_completion=False, help='SLAyer security scanner and patcher')
console = Console(stderr=True)


class OutputFormatEnum(str, Enum):
    text = 'text'
    json = 'json'


class AIChoiceEnum(str, Enum):
    auto = 'auto'
    claude = 'claude'
    codex = 'codex'
    gemini = 'gemini'


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
    ai: AIChoiceEnum = typer.Option(AIChoiceEnum.auto, '--ai', help='AI CLI selection for TUI Fix All'),
) -> None:
    target = Path(path)
    try:
        result = scan_path(target)
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        console.print(f'[red]Scan failed:[/red] {exc}')
        raise typer.Exit(code=2)

    should_launch_tui = (
        output_format == OutputFormatEnum.text
        and sys.stdout.isatty()
        and bool(result.scanned_files)
    )
    if should_launch_tui:
        tui = SLayerTUI(target=target, selected_ai=ai.value)
        tui.run()
        result = tui.scan_result
    else:
        _print_scan(target, result, output_format)

    raise typer.Exit(code=1 if result.violations else 0)


@app.command()
def patch(
    path: str = typer.Argument('.', help='Target file or directory'),
    output_format: OutputFormatEnum = typer.Option(OutputFormatEnum.text, '--format', help='Output format'),
    ai: AIChoiceEnum = typer.Option(AIChoiceEnum.auto, '--ai', help='Patch AI CLI selection (auto|claude|codex|gemini)'),
) -> None:
    target = Path(path)
    try:
        result = patch_path(target, selected_ai=ai.value)
    except AICliError as exc:
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        console.print(f'[red]Patch failed:[/red] {exc}')
        raise typer.Exit(code=2)

    _print_patch(target, result, output_format)
    raise typer.Exit(code=1 if result.remaining_violations else 0)


def main() -> None:
    app()


if __name__ == '__main__':
    main()
