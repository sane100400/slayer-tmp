from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from slayer.models import AIChoice

AI_INSTALL_GUIDANCE = """✗ AI CLI가 감지되지 않았습니다.

다음 중 하나를 설치하세요:
  • Claude Code   https://claude.ai/code
  • Codex CLI     npm install -g @openai/codex
  • Gemini CLI    npm install -g @google/gemini-cli

AST 기반 스캔(탐지만)은 AI 없이도 동작합니다.
"""

CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\n(.*?)```", re.DOTALL)


class AICliError(RuntimeError):
    pass


class AICliNotFoundError(AICliError):
    def __init__(self, preferred: str | None = None):
        detail = f"선택한 AI CLI({preferred})를 찾을 수 없습니다." if preferred else "사용 가능한 AI CLI를 찾을 수 없습니다."
        super().__init__(f"{detail}\n\n{AI_INSTALL_GUIDANCE}".strip())


class AICliTimeoutError(AICliError):
    pass


class AICliExecutionError(AICliError):
    pass


@dataclass(frozen=True)
class AICandidate:
    name: str
    check: tuple[str, ...]
    runner: Callable[[str], list[str]]


AI_CANDIDATES: tuple[AICandidate, ...] = (
    AICandidate("claude", ("claude", "--version"), lambda prompt: ["claude", "-p", prompt]),
    AICandidate("codex", ("codex", "--version"), lambda prompt: ["codex", "exec", prompt]),
    AICandidate("gemini", ("gemini", "--version"), lambda prompt: ["gemini", prompt]),
)


def _is_available(candidate: AICandidate) -> bool:
    try:
        result = subprocess.run(candidate.check, capture_output=True, text=True, check=False)
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
    try:
        result = subprocess.run(
            selected.runner(prompt),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AICliNotFoundError(preferred=selected.name) from exc
    except subprocess.TimeoutExpired as exc:
        raise AICliTimeoutError(f"{selected.name} 실행이 {timeout}초 안에 끝나지 않았습니다.") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise AICliExecutionError(
            f"{selected.name} 실행이 실패했습니다 (exit={result.returncode}).{('\n' + stderr) if stderr else ''}"
        )

    return result.stdout, selected


def extract_code(text: str) -> str:
    matches = CODE_BLOCK_RE.findall(text)
    if matches:
        return max(matches, key=len).strip() + "\n"
    return text.strip() + ("\n" if text.strip() else "")
