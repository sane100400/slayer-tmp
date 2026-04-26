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
    assert [item.rule_name for item in result.patch_explanations] == [
        'NO_HARDCODED_SECRETS',
        'SQL_PARAM_BINDING',
        'NO_EXEC',
    ]
    assert result.patch_explanations[0].title
    assert 'spec.md' in result.patch_explanations[0].reference
    assert 'os.environ.get' in target.read_text(encoding='utf-8')
    assert str(target.resolve()) in result.diffs


def test_patch_handles_paths_with_spaces(tmp_path, fake_ai_env, monkeypatch):
    project = tmp_path / 'project with spaces'
    project.mkdir()
    target = project / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n')

    result = patch_path(target, selected_ai='gemini')

    assert result.ai_used == 'gemini'
    assert result.deployable is True
    assert 'os.environ.get' in target.read_text(encoding='utf-8')


def test_patch_cli_json_output(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    config = tmp_path / '.slayer.yml'
    config.write_text('ai: codex\n', encoding='utf-8')
    patched_code = 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n'
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', patched_code)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ['patch', str(target), '--format', 'json'])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload['deployable'] is True
    assert payload['ai_used'] == 'codex'
    assert payload['patch_explanations'][0]['rule_name'] == 'NO_HARDCODED_SECRETS'
    assert 'secret' in payload['patch_explanations'][0]['title'].lower()


def test_patch_cli_text_output_includes_friendly_explanations(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    (tmp_path / '.slayer.yml').write_text('ai: codex\n', encoding='utf-8')
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n')
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ['patch', str(target)])

    assert result.exit_code == 0
    assert 'Patch explanations:' in result.output
    assert 'NO_HARDCODED_SECRETS' in result.output
    assert 'Moved secret values out of the code' in result.output


def test_patch_cli_falls_back_to_auto_without_slayer_yml(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    patched_code = 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n'
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', patched_code)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ['patch', str(target)])

    assert result.exit_code == 0
    assert 'os.environ.get' in target.read_text(encoding='utf-8')


def test_patch_cli_rejects_invalid_slayer_yml_ai(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    (tmp_path / '.slayer.yml').write_text('ai: nope\n', encoding='utf-8')
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ['patch', str(target)])

    assert result.exit_code == 2
    assert 'Invalid ai value' in result.stderr


def test_patch_cli_auto_uses_detection_when_configured(tmp_path, fake_ai_env, monkeypatch):
    target = tmp_path / 'demo.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    (tmp_path / '.slayer.yml').write_text('ai: auto\n', encoding='utf-8')
    patched_code = 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n'
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', patched_code)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ['patch', str(target), '--format', 'json'])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload['ai_used'] == 'claude'
