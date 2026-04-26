from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest


def write_fake_ai_bin(bin_dir: Path, name: str) -> None:
    script = bin_dir / f"{name}.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "if '--version' in sys.argv:\n"
        "    print('fake-ai 1.0')\n"
        "    raise SystemExit(0)\n"
        "output = os.environ.get('SLAYER_FAKE_AI_OUTPUT', '')\n"
        "if '--output-last-message' in sys.argv:\n"
        "    idx = sys.argv.index('--output-last-message')\n"
        "    Path(sys.argv[idx + 1]).write_text(output, encoding='utf-8')\n"
        "print(output)\n",
        encoding='utf-8',
    )
    script.chmod(0o755)
    if os.name == 'nt':
        launcher = bin_dir / f'{name}.cmd'
        launcher.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding='utf-8')
    else:
        launcher = bin_dir / name
        launcher.write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding='utf-8')
        launcher.chmod(0o755)


@pytest.fixture()
def fake_ai_env(tmp_path, monkeypatch):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('claude', 'codex', 'gemini'):
        write_fake_ai_bin(bin_dir, name)
    monkeypatch.setenv('PATH', f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bin_dir
