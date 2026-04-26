from __future__ import annotations

import json
from pathlib import Path

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


def test_patch_prompt_masks_violation_snippets(tmp_path):
    from slayer.artifact_store import load_runtime_artifacts
    from slayer.patcher.llm_patcher import build_patch_prompt, redact_secrets
    from slayer.scanner import scan_path

    secret = 'sk-prod-abc123secretkey9999'
    target = tmp_path / 'secret.py'
    target.write_text(f'API_KEY = "{secret}"\n', encoding='utf-8')
    bundle = load_runtime_artifacts('v1')
    scan = scan_path(target, artifact_bundle=bundle)

    prompt = build_patch_prompt(target, redact_secrets(target.read_text(encoding='utf-8'), artifact_bundle=bundle), scan.violations, bundle)

    assert secret not in prompt
    assert '...' in prompt or 'REDACTED' in prompt


def test_patch_result_diff_masks_original_secret(tmp_path, fake_ai_env, monkeypatch):
    secret = 'sk-prod-abc123secretkey9999'
    target = tmp_path / 'secret.py'
    target.write_text(f'API_KEY = "{secret}"\n', encoding='utf-8')
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n')

    result = patch_path(target, selected_ai='codex')

    diff = result.diffs[str(target.resolve())]
    assert secret not in diff
    assert '...' in diff or 'REDACTED' in diff


def test_patch_cli_ai_option_overrides_saved_model(tmp_path, fake_ai_env, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path('.slayer.yml').write_text('ai: claude\n', encoding='utf-8')
    target = tmp_path / 'secret.py'
    target.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', 'import os\nAPI_KEY = os.environ.get("API_KEY", "")\n')

    result = runner.invoke(app, ['patch', str(target), '--format', 'json', '--ai', 'codex'])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload['ai_used'] == 'codex'


def test_patch_rejects_empty_ai_output_without_modifying_file(tmp_path, fake_ai_env, monkeypatch):
    from slayer.patcher.llm_patcher import PatchValidationError

    target = tmp_path / 'secret.py'
    original = 'API_KEY = "sk-prod-abc123secretkey9999"\n'
    target.write_text(original, encoding='utf-8')
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', '')

    try:
        patch_path(target, selected_ai='codex')
    except PatchValidationError:
        pass
    else:
        raise AssertionError('empty AI output should fail validation')

    assert target.read_text(encoding='utf-8') == original


def test_patch_rolls_back_prior_writes_when_later_file_fails(tmp_path, fake_ai_env, monkeypatch):
    from slayer.patcher import llm_patcher
    from slayer.patcher.llm_patcher import PatchValidationError

    first = tmp_path / 'first.py'
    second = tmp_path / 'second.py'
    first_original = 'API_KEY = "sk-prod-abc123secretkey9999"\n'
    second_original = 'TOKEN = "sk-prod-def456secretkey8888"\n'
    first.write_text(first_original, encoding='utf-8')
    second.write_text(second_original, encoding='utf-8')
    calls = iter([
        ('import os\nAPI_KEY = os.environ.get("API_KEY", "")\n', None),
        ('', None),
    ])

    def fake_run_ai(*args, **kwargs):
        output, _ = next(calls)
        return output, kwargs['candidate']

    monkeypatch.setattr(llm_patcher, 'run_ai', fake_run_ai)

    try:
        patch_path(tmp_path, selected_ai='codex')
    except PatchValidationError:
        pass
    else:
        raise AssertionError('second empty AI output should fail validation')

    assert first.read_text(encoding='utf-8') == first_original
    assert second.read_text(encoding='utf-8') == second_original
