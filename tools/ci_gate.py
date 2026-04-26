from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.artifact_store import load_runtime_artifacts
from tools.evaluate_ai_generated_code import evaluate_ai_generated_code
from tools.evaluate_patcher import evaluate_patcher
from tools.evaluate_scanner import evaluate_scanner
from tools.evaluate_secrets import evaluate_secrets


def run_gate(artifact_version: str) -> dict:
    bundle = load_runtime_artifacts(version=artifact_version)
    thresholds = bundle.thresholds
    scanner = evaluate_scanner(ROOT / 'dataset' / 'slayer-bench-v0', artifact_version)
    patcher = evaluate_patcher(ROOT / 'dataset' / 'slayer-bench-v0', artifact_version)
    secrets = evaluate_secrets(ROOT / 'dataset' / 'slayer-bench-v0', artifact_version)
    ai_code = evaluate_ai_generated_code(ROOT / 'dataset' / 'ai-bench-v0', artifact_version)
    checks = {
        'scanner_precision': scanner['scanner']['precision'] >= thresholds.scanner_precision_min,
        'scanner_recall': scanner['scanner']['recall'] >= thresholds.scanner_recall_min,
        'patch_rescan_pass': patcher['patcher']['rescan_pass_rate'] >= thresholds.patch_rescan_pass_min,
        'patch_syntax_pass': patcher['patcher']['syntax_pass_rate'] >= thresholds.patch_syntax_pass_min,
        'secret_precision': secrets['secrets']['precision'] >= thresholds.secret_precision_min,
        'ai_code_recall': ai_code['ai_code']['recall'] >= thresholds.ai_code_recall_min,
    }
    return {'artifact_version': artifact_version, 'checks': checks, 'passed': all(checks.values()), 'scanner': scanner, 'patcher': patcher, 'secrets': secrets, 'ai_code': ai_code}


def main() -> None:
    parser = argparse.ArgumentParser(description='Run the SLAyer evaluator gate against the pinned runtime artifact bundle')
    parser.add_argument('--artifact-version', default='v1')
    args = parser.parse_args()
    payload = run_gate(args.artifact_version)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    raise SystemExit(0 if payload['passed'] else 1)


if __name__ == '__main__':
    main()
