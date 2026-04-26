from __future__ import annotations

from pathlib import Path

from slayer.scanner import scan_path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "dataset" / "slayer-bench-v0"
SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}


def _source_files(folder: Path) -> list[Path]:
    return sorted(path for path in folder.rglob("*") if path.suffix in SUPPORTED_EXTENSIONS)


def test_benchmark_vulnerable_cases_are_blocked():
    files = _source_files(BENCH / "vulnerable")
    assert files
    for path in files:
        result = scan_path(path)
        assert not result.deployable, path


def test_benchmark_fixed_and_false_positive_cases_are_approved():
    files = _source_files(BENCH / "fixed") + _source_files(BENCH / "false_positive")
    assert files
    for path in files:
        result = scan_path(path)
        assert result.deployable, path
