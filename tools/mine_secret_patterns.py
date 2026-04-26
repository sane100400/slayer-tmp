from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.artifact_store import SecretPatternArtifact
from tools.datasets.common import normalized_dataset_path

DEFAULT_SECRET_DATASETS = ["creddata", "secretbench", "fpsecretbench"]


def load_records(dataset_ids: list[str]) -> list[dict]:
    records: list[dict] = []
    for dataset_id in dataset_ids:
        path = normalized_dataset_path(dataset_id)
        if not path.exists():
            continue
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


def mine_secret_patterns(dataset_ids: list[str] | None = None) -> dict:
    records = load_records(dataset_ids or DEFAULT_SECRET_DATASETS)
    patterns: list[SecretPatternArtifact] = []
    placeholders: set[str] = set()
    for record in records:
        if record['record_type'] == 'secret_pattern':
            patterns.append(SecretPatternArtifact(pattern_id=record['record_id'], rule_id=record['rule_id'], regex=record['regex'], languages=[record.get('language', 'shared')], provider=record.get('provider'), source_datasets=record.get('source_datasets', [record['dataset_id']]), description=record.get('notes', '')))
        elif record['record_type'] == 'secret_fp':
            placeholders.add(record.get('placeholder', '').lower())
    return {'patterns': [item.model_dump() for item in patterns], 'placeholder_words': sorted(placeholders)}


def main() -> None:
    parser = argparse.ArgumentParser(description='Mine runtime secret patterns from normalized dataset fixtures')
    parser.add_argument('--dataset', nargs='*', default=DEFAULT_SECRET_DATASETS)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    payload = mine_secret_patterns(args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
