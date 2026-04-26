from __future__ import annotations

import json

from typer.testing import CliRunner

from slayer.cli import app
from slayer.patcher.llm_patcher import patch_path

runner = CliRunner()


def test_patch_uses_explicit_ai_selection_and_rescans_clean(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text(
        (
            'import sqlite3\n'
            'import subprocess\n'
            'API_KEY = "sk-prod-abc123secretkey9999"\n\n'
            'def search(query):\n'
            '    cursor = sqlite3.connect("db.sqlite3").cursor()\n'
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{query}\'")\n'
            '    return cursor.fetchall()\n\n'
            'def analyze(filename):\n'
            '    return subprocess.run(f"analyze {filename}", shell=True, capture_output=True)\n'
        ),
        encoding='utf-8',
    )
    patched_code = (
        'import os\n'
        'import sqlite3\n'
        'import subprocess\n'
        'API_KEY = os.environ.get("API_KEY", "")\n\n'
        'def search(query):\n'
        '    cursor = sqlite3.connect("db.sqlite3").cursor()\n'
        '    cursor.execute("SELECT * FROM users WHERE name = ?", (query,))\n'
        '    return cursor.fetchall()\n\n'
        'def analyze(filename):\n'
        '    return subprocess.run(["analyze", filename], shell=False, capture_output=True)\n'
    )
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', f'```python\n{patched_code}```')

    result = patch_path(target, selected_ai='codex')

    assert result.ai_used == 'codex'
    assert result.deployable is True
    assert result.remaining_violations == []
    assert 'os.environ.get' in target.read_text(encoding='utf-8')
    assert str(target.resolve()) in result.diffs


def test_patch_cli_json_output(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    patched_code = 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n'
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', patched_code)

    result = runner.invoke(app, ['patch', str(target), '--format', 'json'])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload['deployable'] is True
