from __future__ import annotations

import os
from pathlib import Path

import pytest


def write_fake_ai_bin(bin_dir: Path, name: str) -> None:
    script = bin_dir / name
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('fake-ai 1.0')\n"
        "    raise SystemExit(0)\n"
        "print(os.environ.get('SLAYER_FAKE_AI_OUTPUT', ''))\n",
        encoding='utf-8',
    )
    script.chmod(0o755)


@pytest.fixture()
def fake_ai_env(tmp_path, monkeypatch):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('claude', 'codex', 'gemini'):
        write_fake_ai_bin(bin_dir, name)
    monkeypatch.setenv('PATH', f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bin_dir
