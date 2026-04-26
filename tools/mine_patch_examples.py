from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.artifact_store import PatchFewShotArtifact, PatchRecipeArtifact
from slayer.rules import RULE_GUIDANCE
from tools.datasets.common import normalized_dataset_path

DEFAULT_PATCH_DATASETS = ["cvefixes", "bigvul", "vul4j", "vulnpatchpairs", "vulrepair"]


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


def mine_patch_examples(dataset_ids: list[str] | None = None) -> dict:
    recipes: dict[tuple[str, str], PatchRecipeArtifact] = {}
    fewshots: list[PatchFewShotArtifact] = []
    for record in load_records(dataset_ids or DEFAULT_PATCH_DATASETS):
        if record['record_type'] != 'patch_example':
            continue
        key = (record['rule_id'], record.get('language', 'python'))
        if key not in recipes:
            recipes[key] = PatchRecipeArtifact(rule_id=record['rule_id'], language=record.get('language', 'python'), instructions=RULE_GUIDANCE.get(record['rule_id'], 'Keep the diff minimal and remove the listed vulnerability.'), source_datasets=record.get('source_datasets', [record['dataset_id']]))
        fewshots.append(PatchFewShotArtifact(example_id=record['record_id'], rule_id=record['rule_id'], language=record.get('language', 'python'), before=record['before'], after=record['after'], source_datasets=record.get('source_datasets', [record['dataset_id']]), notes=record.get('notes', '')))
    return {'recipes': [item.model_dump() for item in recipes.values()], 'examples': [item.model_dump() for item in fewshots]}


def main() -> None:
    parser = argparse.ArgumentParser(description='Mine patch recipes and few-shots from normalized dataset fixtures')
    parser.add_argument('--dataset', nargs='*', default=DEFAULT_PATCH_DATASETS)
    parser.add_argument('--recipes-output', type=Path, required=True)
    parser.add_argument('--fewshots-output', type=Path, required=True)
    args = parser.parse_args()
    payload = mine_patch_examples(args.dataset)
    args.recipes_output.parent.mkdir(parents=True, exist_ok=True)
    args.recipes_output.write_text(json.dumps({'recipes': payload['recipes']}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    args.fewshots_output.write_text(json.dumps({'examples': payload['examples']}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Wrote {args.recipes_output}')
    print(f'Wrote {args.fewshots_output}')


if __name__ == '__main__':
    main()
