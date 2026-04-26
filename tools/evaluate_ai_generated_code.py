from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.eval import compute_localization_metrics, compute_scorecard, load_ai_benchmark_cases
from slayer.scanner import scan_path


def evaluate_ai_generated_code(dataset_root: Path, artifact_version: str) -> dict:
    cases = load_ai_benchmark_cases(dataset_root)
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'localized': 0, 'expected': 0})
    tp = fp = fn = localized = expected = 0
    for case in cases:
        target = dataset_root / case.file
        result = scan_path(target, artifact_version=artifact_version)
        predicted = [v for v in result.violations if v.rule_name == case.rule and Path(v.file).resolve() == target.resolve()]
        predicted_count = len(predicted)
        case_tp = min(predicted_count, case.expected_count)
        case_fp = max(predicted_count - case.expected_count, 0)
        case_fn = max(case.expected_count - predicted_count, 0)
        localized_hits = sum(1 for violation in predicted if violation.line in case.expected_lines)
        tp += case_tp; fp += case_fp; fn += case_fn; localized += localized_hits; expected += case.expected_count
        for source in case.source_datasets:
            bucket = by_source[source]
            bucket['tp'] += case_tp; bucket['fp'] += case_fp; bucket['fn'] += case_fn; bucket['localized'] += localized_hits; bucket['expected'] += case.expected_count
    return {'dataset': dataset_root.name, 'artifact_version': artifact_version, 'ai_code': compute_scorecard(tp, fp, fn).model_dump() | compute_localization_metrics(localized, expected).model_dump(), 'by_source_dataset': {source: compute_scorecard(counts['tp'], counts['fp'], counts['fn']).model_dump() | compute_localization_metrics(counts['localized'], counts['expected']).model_dump() for source, counts in by_source.items()}}


def main() -> None:
    parser = argparse.ArgumentParser(description='Evaluate SLAyer scanner performance on curated AI-generated-code fixtures')
    parser.add_argument('--dataset-root', type=Path, default=ROOT / 'dataset' / 'ai-bench-v0')
    parser.add_argument('--artifact-version', default='v1')
    args = parser.parse_args()
    print(json.dumps(evaluate_ai_generated_code(args.dataset_root, args.artifact_version), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
