from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from tools.datasets.registry import DATASET_REGISTRY


def render_mapping() -> str:
    lines = [
        '# Dataset → start / patch / evaluator mapping',
        '',
        '| Dataset | Access mode | Feeds start | Feeds patch | Evaluator/reference | Runtime use |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for dataset_id, meta in DATASET_REGISTRY.items():
        feeds = set(meta['feeds'])
        lines.append(
            f"| `{dataset_id}` | `{meta['access_mode']}` | {'✓' if 'start' in feeds else '—'} | {'✓' if 'patch' in feeds else '—'} | {'✓' if any(flag.startswith('evaluator') for flag in feeds) else '—'} | {meta['runtime_use']} |"
        )
    lines.extend([
        '',
        '## Access mode meanings',
        '',
        '- `fixture`: bundled deterministic sample payload used for CI/local reproducibility.',
        '- `remote`: publicly downloadable source with cache/checksum/resume support.',
        '- `local`: user-supplied local export or snapshot imported into the raw-data contract.',
        '- `manual`: approval- or policy-gated dataset imported via a manual drop-in path.',
    ])
    return '\n'.join(lines) + '\n'


def main() -> None:
    parser = argparse.ArgumentParser(description='Render the dataset-to-consumer/access-mode mapping as Markdown')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_mapping(), encoding='utf-8')
    print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
