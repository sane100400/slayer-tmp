from __future__ import annotations

import json
import subprocess
import sys


def test_dataset_fixture_fetch_normalize_and_build_pipeline(tmp_path):
    fetch = subprocess.run([sys.executable, 'tools/datasets/fetch_dataset.py', '--dataset', 'cvefixes', 'secretbench'], capture_output=True, text=True, check=True)
    assert 'Fetched cvefixes via fixture' in fetch.stdout
    normalize = subprocess.run([sys.executable, 'tools/datasets/normalize_dataset.py', '--dataset', 'cvefixes', 'secretbench'], capture_output=True, text=True, check=True)
    assert 'Normalized cvefixes' in normalize.stdout
    build = subprocess.run([sys.executable, 'tools/build_runtime_artifacts.py', '--version', 'test-v1', '--root', str(tmp_path)], capture_output=True, text=True, check=True)
    assert 'Wrote runtime artifact bundle' in build.stdout
    manifest = json.loads((tmp_path / 'test-v1' / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['version'] == 'test-v1'
    assert manifest['sources'][0]['access_mode']
    secret_patterns = json.loads((tmp_path / 'test-v1' / 'secret_patterns.json').read_text(encoding='utf-8'))
    assert secret_patterns['patterns']
