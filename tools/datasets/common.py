from __future__ import annotations

import json
from pathlib import Path

from tools.datasets.registry import DATASET_REGISTRY

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
RAW_ROOT = ROOT / "dataset" / "sources" / "raw"
NORMALIZED_ROOT = ROOT / "dataset" / "sources" / "normalized"


def dataset_meta(dataset_id: str) -> dict[str, object]:
    if dataset_id not in DATASET_REGISTRY:
        raise KeyError(f"Unknown dataset id: {dataset_id}")
    return DATASET_REGISTRY[dataset_id]


def fixture_path(dataset_id: str) -> Path:
    return FIXTURE_ROOT / str(dataset_meta(dataset_id)["fixture_file"])


def raw_dataset_dir(dataset_id: str) -> Path:
    return RAW_ROOT / dataset_id


def raw_dataset_path(dataset_id: str) -> Path:
    return raw_dataset_dir(dataset_id) / "raw.json"


def normalized_dataset_path(dataset_id: str) -> Path:
    return NORMALIZED_ROOT / f"{dataset_id}.jsonl"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def dump_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), encoding="utf-8")
