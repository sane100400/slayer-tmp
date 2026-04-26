from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.datasets.common import dump_json, fixture_path, raw_dataset_path
from tools.datasets.registry import DATASET_REGISTRY


def fetch_fixture(dataset_id: str) -> Path:
    payload = json.loads(fixture_path(dataset_id).read_text(encoding='utf-8'))
    target = raw_dataset_path(dataset_id)
    dump_json(target, payload)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description='Populate raw dataset inputs from bundled fixtures')
    parser.add_argument('--dataset', choices=sorted(DATASET_REGISTRY), nargs='*', default=sorted(DATASET_REGISTRY))
    args = parser.parse_args()
    for dataset_id in args.dataset:
        print(f'Fetched fixture for {dataset_id}: {fetch_fixture(dataset_id)}')


if __name__ == '__main__':
    main()
