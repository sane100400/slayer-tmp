from __future__ import annotations

import argparse
from datetime import datetime, timezone
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slayer.artifact_store import ArtifactSource, RuntimeArtifactBundle, ThresholdProfile, dump_runtime_artifacts, PatchRecipeArtifact, PatchFewShotArtifact, ScannerPatternArtifact, SecretPatternArtifact
from tools.datasets.registry import DATASET_REGISTRY, P1_DATASETS, P2_DATASETS
from tools.mine_patch_examples import mine_patch_examples
from tools.mine_scanner_patterns import mine_scanner_patterns
from tools.mine_secret_patterns import mine_secret_patterns


def build_bundle(version: str = 'v1') -> RuntimeArtifactBundle:
    secret_payload = mine_secret_patterns()
    scanner_payload = mine_scanner_patterns()
    patch_payload = mine_patch_examples()
    sources = [ArtifactSource(dataset_id=dataset_id, role=str(DATASET_REGISTRY[dataset_id]['role']), home=str(DATASET_REGISTRY[dataset_id]['home']), languages=list(DATASET_REGISTRY[dataset_id]['languages']), notes=str(DATASET_REGISTRY[dataset_id]['notes'])) for dataset_id in dict.fromkeys(P1_DATASETS + P2_DATASETS)]
    return RuntimeArtifactBundle(
        version=version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        sources=sources,
        secret_patterns=[SecretPatternArtifact(**item) for item in secret_payload['patterns']],
        scanner_patterns=[ScannerPatternArtifact(**item) for item in scanner_payload['patterns']],
        patch_recipes=[PatchRecipeArtifact(**item) for item in patch_payload['recipes']],
        patch_fewshots=[PatchFewShotArtifact(**item) for item in patch_payload['examples']],
        thresholds=ThresholdProfile(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description='Build versioned SLAyer runtime artifact bundles from normalized datasets')
    parser.add_argument('--version', default='v1')
    parser.add_argument('--root', type=Path, default=None)
    args = parser.parse_args()
    out_dir = dump_runtime_artifacts(build_bundle(version=args.version), root=args.root)
    print(f'Wrote runtime artifact bundle: {out_dir}')


if __name__ == '__main__':
    main()
