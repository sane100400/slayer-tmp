from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.datasets.common import dataset_meta, dump_jsonl, load_json, normalized_dataset_path, raw_dataset_path
from tools.datasets.registry import DATASET_REGISTRY


def normalize_records(dataset_id: str) -> list[dict]:
    payload = load_json(raw_dataset_path(dataset_id))
    normalizer = dataset_meta(dataset_id)['normalizer']
    normalized: list[dict] = []
    for index, record in enumerate(payload.get('records', []), start=1):
        base = {
            'dataset_id': dataset_id,
            'record_id': record.get('record_id', f'{dataset_id}-{index:03d}'),
            'record_type': record.get('record_type', normalizer),
            'language': record.get('language', 'python'),
            'rule_id': record.get('rule_id', ''),
            'source_datasets': record.get('source_datasets', [dataset_id]),
            'notes': record.get('notes', ''),
        }
        base.update(record)
        normalized.append(base)
    return normalized


def normalize_dataset(dataset_id: str) -> Path:
    output = normalized_dataset_path(dataset_id)
    dump_jsonl(output, normalize_records(dataset_id))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description='Normalize bundled raw dataset fixtures into JSONL records')
    parser.add_argument('--dataset', choices=sorted(DATASET_REGISTRY), nargs='*', default=sorted(DATASET_REGISTRY))
    args = parser.parse_args()
    for dataset_id in args.dataset:
        print(f'Normalized {dataset_id}: {normalize_dataset(dataset_id)}')


if __name__ == '__main__':
    main()
