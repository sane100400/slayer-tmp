from __future__ import annotations

import pytest

from slayer.ai_runner import AICliNotFoundError, detect_ai_cli


def test_auto_detect_prefers_spec_priority(fake_ai_env):
    assert detect_ai_cli('auto').name == 'claude'


def test_explicit_selection_is_honored(fake_ai_env):
    assert detect_ai_cli('codex').name == 'codex'
    assert detect_ai_cli('gemini').name == 'gemini'


def test_missing_explicit_cli_raises(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', str(tmp_path))
    with pytest.raises(AICliNotFoundError):
        detect_ai_cli('claude')
