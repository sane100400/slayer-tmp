from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class BenchmarkCase(BaseModel):
    case_id: str
    dataset: str
    category: str
    language: str
    rule: str
    file: str
    expected_lines: list[int] = Field(default_factory=list)
    expected_count: int = 0
    patchable: bool = True
    source_datasets: list[str] = Field(default_factory=list)
    fixed_file: str | None = None
    notes: str = ""


ROOT = Path(__file__).resolve().parents[2]
SLAYER_BENCH_ROOT = ROOT / "dataset" / "slayer-bench-v0"
AI_BENCH_ROOT = ROOT / "dataset" / "ai-bench-v0"


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def load_slayer_benchmark_cases(root: Path | None = None) -> list[BenchmarkCase]:
    bench_root = root or SLAYER_BENCH_ROOT
    return [BenchmarkCase(**record) for record in _load_jsonl(bench_root / "metadata.jsonl")]


def load_ai_benchmark_cases(root: Path | None = None) -> list[BenchmarkCase]:
    bench_root = root or AI_BENCH_ROOT
    return [BenchmarkCase(**record) for record in _load_jsonl(bench_root / "metadata.jsonl")]
