from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.datasets.adapters import ADAPTERS, DatasetFetchError
from tools.datasets.registry import DATASET_REGISTRY, dataset_meta


def resolved_mode(dataset_id: str, *, mode_override: str | None = None, use_registry_mode: bool = False) -> str:
    meta = dataset_meta(dataset_id)
    return mode_override or (str(meta['access_mode']) if use_registry_mode else 'fixture')


def fetch_dataset(
    dataset_id: str,
    *,
    mode_override: str | None = None,
    source_path: Path | None = None,
    force: bool = False,
    use_registry_mode: bool = False,
) -> Path:
    mode = resolved_mode(dataset_id, mode_override=mode_override, use_registry_mode=use_registry_mode)
    if mode not in ADAPTERS:
        raise DatasetFetchError(f'Unsupported access mode for {dataset_id}: {mode}')
    adapter = ADAPTERS[mode]
    if mode in {'local', 'manual'}:
        return adapter(dataset_id, source_path=source_path)
    return adapter(dataset_id, force=force)


def main() -> None:
    parser = argparse.ArgumentParser(description='Populate raw dataset inputs from fixture/remote/local/manual sources')
    parser.add_argument('--dataset', choices=sorted(DATASET_REGISTRY), nargs='*', default=sorted(DATASET_REGISTRY))
    parser.add_argument('--mode-override', choices=sorted(ADAPTERS), default=None)
    parser.add_argument('--source-path', type=Path, default=None, help='Used for local/manual imports (single dataset only)')
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--use-registry-mode', action='store_true', help="Use each dataset's declared access_mode instead of the CI-safe fixture default")
    args = parser.parse_args()
    if args.source_path and len(args.dataset) != 1:
        raise SystemExit('--source-path requires exactly one dataset')
    for dataset_id in args.dataset:
        mode = resolved_mode(dataset_id, mode_override=args.mode_override, use_registry_mode=args.use_registry_mode)
        path = fetch_dataset(dataset_id, mode_override=args.mode_override, source_path=args.source_path, force=args.force, use_registry_mode=args.use_registry_mode)
        print(f'Fetched {dataset_id} via {mode}: {path}')


if __name__ == '__main__':
    main()
