from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.eval import compute_localization_metrics, compute_scorecard, load_slayer_benchmark_cases
from slayer.scanner import scan_path


def evaluate_scanner(dataset_root: Path, artifact_version: str) -> dict:
    cases = load_slayer_benchmark_cases(dataset_root)
    by_rule_counts: dict[str, dict[str, int]] = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'localized': 0, 'expected': 0})
    tp = fp = fn = localized = expected = 0
    for case in cases:
        target = dataset_root / case.file
        result = scan_path(target, artifact_version=artifact_version)
        predicted = [v for v in result.violations if v.rule_name == case.rule and Path(v.file).resolve() == target.resolve()]
        predicted_count = len(predicted)
        case_tp = min(predicted_count, case.expected_count)
        case_fp = max(predicted_count - case.expected_count, 0)
        case_fn = max(case.expected_count - predicted_count, 0)
        expected += case.expected_count
        localized_hits = sum(1 for violation in predicted if violation.line in case.expected_lines)
        localized += localized_hits
        tp += case_tp; fp += case_fp; fn += case_fn
        by_rule = by_rule_counts[case.rule]
        by_rule['tp'] += case_tp; by_rule['fp'] += case_fp; by_rule['fn'] += case_fn; by_rule['localized'] += localized_hits; by_rule['expected'] += case.expected_count
    return {
        'dataset': dataset_root.name,
        'artifact_version': artifact_version,
        'scanner': compute_scorecard(tp, fp, fn).model_dump() | compute_localization_metrics(localized, expected).model_dump(),
        'by_rule': {rule: compute_scorecard(counts['tp'], counts['fp'], counts['fn']).model_dump() | compute_localization_metrics(counts['localized'], counts['expected']).model_dump() for rule, counts in by_rule_counts.items()},
        'summary': {'cases': len(cases), 'tp': tp, 'fp': fp, 'fn': fn},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Evaluate the SLAyer scanner against curated benchmark fixtures')
    parser.add_argument('--dataset-root', type=Path, default=ROOT / 'dataset' / 'slayer-bench-v0')
    parser.add_argument('--artifact-version', default='v1')
    args = parser.parse_args()
    print(json.dumps(evaluate_scanner(args.dataset_root, args.artifact_version), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
