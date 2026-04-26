from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from tools.datasets.registry import DATASET_REGISTRY, dataset_meta

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = Path(__file__).resolve().parent / 'fixtures'
RAW_ROOT = ROOT / 'dataset' / 'sources' / 'raw'
NORMALIZED_ROOT = ROOT / 'dataset' / 'sources' / 'normalized'
CACHE_ROOT = ROOT / '.cache' / 'slayer-datasets'
MANUAL_DROP_ROOT = ROOT / 'dataset' / 'sources' / 'manual'
LOCAL_IMPORT_ROOT = ROOT / 'dataset' / 'sources' / 'local'


def fixture_path(dataset_id: str) -> Path:
    return FIXTURE_ROOT / str(dataset_meta(dataset_id)['fixture_file'])


def raw_dataset_dir(dataset_id: str) -> Path:
    return RAW_ROOT / dataset_id


def raw_dataset_path(dataset_id: str) -> Path:
    return raw_dataset_dir(dataset_id) / 'raw.json'


def normalized_dataset_path(dataset_id: str) -> Path:
    return NORMALIZED_ROOT / f'{dataset_id}.jsonl'


def cache_dir(dataset_id: str) -> Path:
    return CACHE_ROOT / dataset_id


def cache_file_path(dataset_id: str, download: dict[str, object] | None = None) -> Path:
    meta = dataset_meta(dataset_id)
    download = download or meta.get('download', {})
    filename = str(download.get('filename') or Path(urlparse(str(download.get('url', 'dataset.bin'))).path).name or f'{dataset_id}.bin')
    return cache_dir(dataset_id) / filename


def manual_drop_path(dataset_id: str) -> Path:
    meta = dataset_meta(dataset_id)
    return MANUAL_DROP_ROOT / str(meta.get('manual_drop_name') or f'{dataset_id}.json')


def local_import_path(dataset_id: str) -> Path:
    meta = dataset_meta(dataset_id)
    return LOCAL_IMPORT_ROOT / str(meta.get('manual_drop_name') or f'{dataset_id}.json')


def dataset_meta_map() -> dict[str, dict[str, object]]:
    return {key: dataset_meta(key) for key in DATASET_REGISTRY}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def dump_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records), encoding='utf-8')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()
