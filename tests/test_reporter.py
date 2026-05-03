from __future__ import annotations

from rich.console import Console

from slayer.models import PatchResult
from slayer.reporter import print_patch_rich, render_patch_text


def _build_patch_result(diff: str) -> PatchResult:
    return PatchResult(
        patched_files=['/tmp/demo.py'],
        diffs={'/tmp/demo.py': diff},
        deployable=True,
        ai_used='none',
        scanned_files=['/tmp/demo.py'],
    )


def test_render_patch_text_redacts_diff_secrets() -> None:
    raw_secret = 'sk-ABCDEFGHIJKLMNOPQRSTUV123456'
    diff = (
        '--- /tmp/demo.py\n'
        '+++ /tmp/demo.py\n'
        '@@ -1 +1 @@\n'
        f'-api_key = "{raw_secret}"\n'
        '+api_key = os.environ.get("API_KEY", "")\n'
    )

    rendered = render_patch_text('/tmp', _build_patch_result(diff))

    assert raw_secret not in rendered
    assert 'sk-A...3456' in rendered


def test_print_patch_rich_redacts_diff_secrets() -> None:
    raw_secret = 'sk-ABCDEFGHIJKLMNOPQRSTUV123456'
    diff = (
        '--- /tmp/demo.py\n'
        '+++ /tmp/demo.py\n'
        '@@ -1 +1 @@\n'
        f'-api_key = "{raw_secret}"\n'
        '+api_key = os.environ.get("API_KEY", "")\n'
    )
    console = Console(record=True, force_terminal=False, color_system=None)

    print_patch_rich('/tmp', _build_patch_result(diff), console)
    rendered = console.export_text()

    assert raw_secret not in rendered
    assert 'sk-A...3456' in rendered
