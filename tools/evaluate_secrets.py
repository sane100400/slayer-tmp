from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.eval import compute_scorecard, load_slayer_benchmark_cases
from slayer.scanner import scan_path


def evaluate_secrets(dataset_root: Path, artifact_version: str) -> dict:
    cases = [case for case in load_slayer_benchmark_cases(dataset_root) if case.rule == 'NO_HARDCODED_SECRETS']
    tp = fp = fn = 0
    case_results: list[dict] = []
    for case in cases:
        target = dataset_root / case.file
        result = scan_path(target, artifact_version=artifact_version)
        predicted = [v for v in result.violations if v.rule_name == case.rule and Path(v.file).resolve() == target.resolve()]
        predicted_count = len(predicted)
        tp += min(predicted_count, case.expected_count)
        fp += max(predicted_count - case.expected_count, 0)
        fn += max(case.expected_count - predicted_count, 0)
        case_results.append({'case_id': case.case_id, 'predicted': predicted_count, 'expected': case.expected_count})
    return {'dataset': dataset_root.name, 'artifact_version': artifact_version, 'secrets': compute_scorecard(tp, fp, fn).model_dump(), 'cases': case_results}


def main() -> None:
    parser = argparse.ArgumentParser(description='Evaluate SLAyer secret detection precision/recall against curated fixtures')
    parser.add_argument('--dataset-root', type=Path, default=ROOT / 'dataset' / 'slayer-bench-v0')
    parser.add_argument('--artifact-version', default='v1')
    args = parser.parse_args()
    print(json.dumps(evaluate_secrets(args.dataset_root, args.artifact_version), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
