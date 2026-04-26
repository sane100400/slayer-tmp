from __future__ import annotations

import pytest

from slayer.ai_runner import AI_CANDIDATES, AICliNotFoundError, detect_ai_cli, run_ai


def _candidate(name: str):
    return next(candidate for candidate in AI_CANDIDATES if candidate.name == name)


def test_auto_detect_prefers_spec_priority(fake_ai_env):
    assert detect_ai_cli('auto').name == 'claude'


def test_explicit_selection_is_honored(fake_ai_env):
    assert detect_ai_cli('codex').name == 'codex'
    assert detect_ai_cli('gemini').name == 'gemini'


def test_missing_explicit_cli_raises(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', str(tmp_path))
    with pytest.raises(AICliNotFoundError):
        detect_ai_cli('claude')


def test_cli_runners_use_headless_cross_platform_arguments(tmp_path):
    claude = _candidate('claude').runner('claude', 'patch this', None)
    codex = _candidate('codex').runner('codex', 'patch this', tmp_path / 'last.txt')
    gemini = _candidate('gemini').runner('gemini', 'patch this', None)

    assert claude == ['claude', '-p', 'patch this', '--output-format', 'text']
    assert codex[:2] == ['codex', 'exec']
    assert '--skip-git-repo-check' in codex
    assert codex[codex.index('--sandbox') + 1] == 'read-only'
    assert codex[codex.index('--output-last-message') + 1] == str(tmp_path / 'last.txt')
    assert codex[-1] == 'patch this'
    assert gemini == ['gemini', '--prompt', 'patch this']


def test_run_ai_reads_codex_last_message_file(fake_ai_env, monkeypatch, tmp_path):
    monkeypatch.setenv('SLAYER_FAKE_AI_OUTPUT', 'patched code from codex')

    output, candidate = run_ai('patch this file', preferred='codex', cwd=tmp_path)

    assert candidate.name == 'codex'
    assert output == 'patched code from codex'
