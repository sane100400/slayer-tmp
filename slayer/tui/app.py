from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, Static

from slayer.ai_runner import AICliError
from slayer.models import AIChoice
from slayer.patcher.llm_patcher import patch_path
from slayer.scanner import scan_path


class SLayerTUI(App[None]):
    BINDINGS = [
        ('q', 'quit', 'Quit'),
        ('r', 'rescan', 'Rescan'),
        ('f', 'fix_all', 'Fix All'),
    ]
    CSS = """
    Screen {
        layout: vertical;
    }
    #summary {
        border: round $accent;
        padding: 1;
        margin: 1 1 0 1;
        height: auto;
    }
    #body {
        border: round $panel;
        padding: 1;
        margin: 1;
        height: 1fr;
        overflow: auto;
    }
    """

    def __init__(self, target: Path, selected_ai: AIChoice = 'auto') -> None:
        super().__init__()
        self.target = Path(target)
        self.selected_ai = selected_ai
        self.scan_result = scan_path(self.target)
        self.status_message = ''

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id='summary')
        yield Static(id='body')
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_view()

    def _refresh_view(self) -> None:
        self.query_one('#summary', Static).update(self._summary_text())
        self.query_one('#body', Static).update(self._body_text())

    def _summary_text(self) -> str:
        if self.scan_result.deployable:
            state = '🚀 Deployment Approved'
        else:
            state = f'Deployment BLOCKED — {len(self.scan_result.violations)} violation(s)'
        scanned = len(self.scan_result.scanned_files)
        return f'SLAyer\nTarget: {self.target}\nFiles: {scanned}\n{state}\n{self.status_message}'.strip()

    def _body_text(self) -> str:
        if not self.scan_result.scanned_files:
            return 'No supported source files found\n\nPress q to quit.'
        lines = ['Files:']
        file_counts: dict[str, int] = {}
        for violation in self.scan_result.violations:
            file_counts[violation.file] = file_counts.get(violation.file, 0) + 1
        for file_path in self.scan_result.scanned_files:
            lines.append(f"- {file_path}  ({file_counts.get(file_path, 0)} violation(s))")
        if self.scan_result.syntax_errors:
            lines.append('')
            lines.append('Syntax issues:')
            for issue in self.scan_result.syntax_errors:
                lines.append(f"- {issue.file}:{issue.line or 0} {issue.message}")
        if self.scan_result.violations:
            lines.append('')
            lines.append('Violations:')
            for violation in self.scan_result.violations:
                lines.append(
                    f"- {violation.rule_name}  {Path(violation.file).name}:{violation.line}  {violation.code_snippet.strip()}"
                )
        lines.append('')
        lines.append('[F] Fix All   [R] Rescan   [Q] Quit')
        return '\n'.join(lines)

    def action_rescan(self) -> None:
        self.scan_result = scan_path(self.target)
        self.status_message = 'Rescanned current target.'
        self._refresh_view()

    def action_fix_all(self) -> None:
        try:
            result = patch_path(self.target, selected_ai=self.selected_ai)
        except AICliError as exc:
            self.status_message = str(exc)
        except Exception as exc:
            self.status_message = f'Patch failed: {exc}'
        else:
            self.scan_result = scan_path(self.target)
            self.status_message = (
                '🚀 Deployment Approved' if result.deployable else f'Patching via {result.ai_used} complete.'
            )
        self._refresh_view()
