from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.eval import compute_patch_metrics, load_slayer_benchmark_cases
from slayer.patcher.llm_patcher import patch_path


def _fake_ai_bin(bin_dir: Path) -> None:
    script = "#!/usr/bin/env python3\nimport os, sys\nif '--version' in sys.argv:\n    print('fixture-ai 1.0')\n    raise SystemExit(0)\nprint(os.environ.get('SLAYER_FAKE_AI_OUTPUT', ''))\n"
    for name in ('claude', 'codex', 'gemini'):
        path = bin_dir / name
        path.write_text(script, encoding='utf-8')
        path.chmod(path.stat().st_mode | stat.S_IEXEC)


def evaluate_patcher(dataset_root: Path, artifact_version: str) -> dict:
    cases = [case for case in load_slayer_benchmark_cases(dataset_root) if case.patchable and case.expected_count > 0 and case.fixed_file]
    syntax_passes = rescan_passes = minimal_diffs = 0
    case_results: list[dict] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        bin_dir = temp_path / 'bin'; bin_dir.mkdir(); _fake_ai_bin(bin_dir)
        env_path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        old_path = os.environ.get('PATH', '')
        old_output = os.environ.get('SLAYER_FAKE_AI_OUTPUT')
        os.environ['PATH'] = env_path
        try:
            for case in cases:
                source_path = dataset_root / case.file
                target = temp_path / Path(case.file).name
                shutil.copy2(source_path, target)
                fixed_code = (dataset_root / case.fixed_file).read_text(encoding='utf-8')
                os.environ['SLAYER_FAKE_AI_OUTPUT'] = f'```python\n{fixed_code}```' if case.language == 'python' else fixed_code
                original = target.read_text(encoding='utf-8')
                result = patch_path(target, selected_ai='codex', artifact_version=artifact_version)
                syntax_ok = len(result.syntax_errors) == 0
                rescan_ok = result.deployable
                diff_lines = len(result.diffs.get(str(target.resolve()), '').splitlines())
                minimal_ok = diff_lines <= max(12, len(original.splitlines()) + 3)
                syntax_passes += int(syntax_ok); rescan_passes += int(rescan_ok); minimal_diffs += int(minimal_ok)
                case_results.append({'case_id': case.case_id, 'artifact_version': result.artifact_version, 'deployable': result.deployable, 'ai_used': result.ai_used, 'syntax_ok': syntax_ok, 'rescan_ok': rescan_ok, 'minimal_ok': minimal_ok})
        finally:
            os.environ['PATH'] = old_path
            if old_output is None:
                os.environ.pop('SLAYER_FAKE_AI_OUTPUT', None)
            else:
                os.environ['SLAYER_FAKE_AI_OUTPUT'] = old_output
    metrics = compute_patch_metrics(syntax_passes, rescan_passes, minimal_diffs, len(cases) or 1)
    return {'dataset': dataset_root.name, 'artifact_version': artifact_version, 'patcher': metrics.model_dump(), 'cases': case_results, 'summary': {'cases': len(cases)}}


def main() -> None:
    parser = argparse.ArgumentParser(description='Evaluate the SLAyer patcher with fixture-backed AI outputs')
    parser.add_argument('--dataset-root', type=Path, default=ROOT / 'dataset' / 'slayer-bench-v0')
    parser.add_argument('--artifact-version', default='v1')
    args = parser.parse_args()
    print(json.dumps(evaluate_patcher(args.dataset_root, args.artifact_version), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
