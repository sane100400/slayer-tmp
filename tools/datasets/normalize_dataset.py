from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.datasets.common import dataset_meta, dump_jsonl, load_json, normalized_dataset_path, raw_dataset_path, raw_dataset_dir
from tools.datasets.normalizers import NORMALIZER_ADAPTERS
from tools.datasets.registry import DATASET_REGISTRY


def normalize_records(dataset_id: str) -> list[dict]:
    meta = dataset_meta(dataset_id)
    adapter_name = str(meta['normalizer_adapter'])
    if adapter_name not in NORMALIZER_ADAPTERS:
        raise KeyError(f'Unknown normalizer adapter: {adapter_name}')
    payload = load_json(raw_dataset_path(dataset_id))
    adapter = NORMALIZER_ADAPTERS[adapter_name]
    return adapter(dataset_id, payload, raw_dataset_dir(dataset_id))


def normalize_dataset(dataset_id: str) -> Path:
    output = normalized_dataset_path(dataset_id)
    dump_jsonl(output, normalize_records(dataset_id))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description='Normalize raw dataset inputs into JSONL records via dataset-specific adapters')
    parser.add_argument('--dataset', choices=sorted(DATASET_REGISTRY), nargs='*', default=sorted(DATASET_REGISTRY))
    args = parser.parse_args()
    for dataset_id in args.dataset:
        print(f'Normalized {dataset_id}: {normalize_dataset(dataset_id)}')


if __name__ == '__main__':
    main()
