from __future__ import annotations

import shutil
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from slayer.models import AIChoice

AI_INSTALL_GUIDANCE = """✗ No AI CLI detected.

Install one of the following:
  • Claude Code   https://claude.ai/code
  • Codex CLI     npm install -g @openai/codex
  • Gemini CLI    npm install -g @google/gemini-cli

Scanning (detection only) works without any AI CLI.
"""

CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\n(.*?)```", re.DOTALL)


class AICliError(RuntimeError):
    pass


class AICliNotFoundError(AICliError):
    def __init__(self, preferred: str | None = None):
        detail = f"The selected AI CLI ({preferred}) was not found." if preferred else "No available AI CLI was found."
        super().__init__(f"{detail}\n\n{AI_INSTALL_GUIDANCE}".strip())


class AICliTimeoutError(AICliError):
    pass


class AICliExecutionError(AICliError):
    pass


@dataclass(frozen=True)
class AICandidate:
    name: str
    executable: str
    check_args: tuple[str, ...]
    runner: Callable[[str, str, Path | None], list[str]]
    captures_last_message: bool = False

    @property
    def check(self) -> tuple[str, ...]:
        return (self.executable, *self.check_args)


def _claude_runner(executable: str, prompt: str, _: Path | None = None) -> list[str]:
    return [executable, "-p", prompt, "--output-format", "text"]


def _codex_runner(executable: str, prompt: str, output_file: Path | None = None) -> list[str]:
    command = [
        executable,
        "exec",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--color",
        "never",
        "--ephemeral",
    ]
    if output_file is not None:
        command.extend(["--output-last-message", str(output_file)])
    command.append(prompt)
    return command


def _gemini_runner(executable: str, prompt: str, _: Path | None = None) -> list[str]:
    return [executable, "--prompt", prompt]


AI_CANDIDATES: tuple[AICandidate, ...] = (
    AICandidate("claude", "claude", ("--version",), _claude_runner),
    AICandidate("codex", "codex", ("--version",), _codex_runner, captures_last_message=True),
    AICandidate("gemini", "gemini", ("--version",), _gemini_runner),
)


def _resolve_executable(candidate: AICandidate) -> str | None:
    return shutil.which(candidate.executable)


def _is_available(candidate: AICandidate) -> bool:
    executable = _resolve_executable(candidate)
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, *candidate.check_args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def detect_ai_cli(preferred: AIChoice = "auto") -> AICandidate:
    if preferred != "auto":
        for candidate in AI_CANDIDATES:
            if candidate.name == preferred:
                if _is_available(candidate):
                    return candidate
                raise AICliNotFoundError(preferred=preferred)
        raise AICliNotFoundError(preferred=preferred)

    for candidate in AI_CANDIDATES:
        if _is_available(candidate):
            return candidate
    raise AICliNotFoundError()


def run_ai(
    prompt: str,
    preferred: AIChoice = "auto",
    timeout: int = 60,
    cwd: Path | None = None,
    candidate: AICandidate | None = None,
) -> tuple[str, AICandidate]:
    selected = candidate or detect_ai_cli(preferred=preferred)
    executable = _resolve_executable(selected)
    if executable is None:
        raise AICliNotFoundError(preferred=selected.name)

    with tempfile.TemporaryDirectory(prefix="slayer-ai-") as temp_dir:
        output_file = Path(temp_dir) / "last-message.txt" if selected.captures_last_message else None
        command = selected.runner(executable, prompt, output_file)
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AICliNotFoundError(preferred=selected.name) from exc
        except subprocess.TimeoutExpired as exc:
            raise AICliTimeoutError(f"{selected.name} did not finish within {timeout} seconds.") from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            suffix = ("\n" + stderr) if stderr else ""
            raise AICliExecutionError(
                f"{selected.name} exited with error (exit={result.returncode}).{suffix}"
            )

        output = result.stdout
        if output_file is not None and output_file.exists():
            output = output_file.read_text(encoding="utf-8", errors="replace")
        return output, selected


def extract_code(text: str) -> str:
    matches = CODE_BLOCK_RE.findall(text)
    if matches:
        return max(matches, key=len).strip() + "\n"
    return text.strip() + ("\n" if text.strip() else "")
