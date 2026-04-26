from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_RUNTIME_ARTIFACT_ROOT = PACKAGE_ROOT / 'runtime_artifacts'
DEFAULT_ARTIFACT_VERSION = 'v1'


class ArtifactSource(BaseModel):
    dataset_id: str
    role: str
    home: str
    languages: list[str] = Field(default_factory=list)
    access_mode: str = 'fixture'
    feeds: list[str] = Field(default_factory=list)
    runtime_use: str = ''
    notes: str = ''


class SecretPatternArtifact(BaseModel):
    pattern_id: str
    rule_id: str
    regex: str
    languages: list[str] = Field(default_factory=lambda: ['shared'])
    provider: str | None = None
    source_datasets: list[str] = Field(default_factory=list)
    description: str = ''


class ScannerPatternArtifact(BaseModel):
    pattern_id: str
    rule_id: str
    language: str
    regex: str
    source_datasets: list[str] = Field(default_factory=list)
    description: str = ''
    context_keywords: list[str] = Field(default_factory=list)


class PatchRecipeArtifact(BaseModel):
    rule_id: str
    language: str
    instructions: str
    source_datasets: list[str] = Field(default_factory=list)


class PatchFewShotArtifact(BaseModel):
    example_id: str
    rule_id: str
    language: str
    before: str
    after: str
    source_datasets: list[str] = Field(default_factory=list)
    notes: str = ''


class ThresholdProfile(BaseModel):
    scanner_precision_min: float = 0.7
    scanner_recall_min: float = 0.7
    patch_rescan_pass_min: float = 0.7
    patch_syntax_pass_min: float = 0.9
    secret_precision_min: float = 0.85
    ai_code_recall_min: float = 0.7


class RuntimeArtifactBundle(BaseModel):
    version: str
    generated_at: str
    sources: list[ArtifactSource] = Field(default_factory=list)
    secret_patterns: list[SecretPatternArtifact] = Field(default_factory=list)
    scanner_patterns: list[ScannerPatternArtifact] = Field(default_factory=list)
    patch_recipes: list[PatchRecipeArtifact] = Field(default_factory=list)
    patch_fewshots: list[PatchFewShotArtifact] = Field(default_factory=list)
    thresholds: ThresholdProfile = Field(default_factory=ThresholdProfile)


def _artifact_root(root: str | Path | None = None) -> Path:
    if root is not None:
        return Path(root).resolve()
    env_root = os.environ.get('SLAYER_ARTIFACT_ROOT')
    if env_root:
        return Path(env_root).resolve()
    return DEFAULT_RUNTIME_ARTIFACT_ROOT


def artifact_version_dir(version: str = DEFAULT_ARTIFACT_VERSION, root: str | Path | None = None) -> Path:
    return _artifact_root(root) / version


def load_runtime_artifacts(version: str = DEFAULT_ARTIFACT_VERSION, root: str | Path | None = None) -> RuntimeArtifactBundle:
    version_dir = artifact_version_dir(version, root)
    manifest = json.loads((version_dir / 'manifest.json').read_text(encoding='utf-8'))
    secret_patterns = json.loads((version_dir / 'secret_patterns.json').read_text(encoding='utf-8'))
    scanner_patterns = json.loads((version_dir / 'scanner_patterns.json').read_text(encoding='utf-8'))
    patch_recipes = json.loads((version_dir / 'patch_recipes.json').read_text(encoding='utf-8'))
    patch_fewshots = json.loads((version_dir / 'patch_fewshots.json').read_text(encoding='utf-8'))
    thresholds = json.loads((version_dir / 'thresholds.json').read_text(encoding='utf-8'))
    return RuntimeArtifactBundle(
        version=manifest.get('version', version),
        generated_at=manifest.get('generated_at', ''),
        sources=[ArtifactSource(**item) for item in manifest.get('sources', [])],
        secret_patterns=[SecretPatternArtifact(**item) for item in secret_patterns.get('patterns', [])],
        scanner_patterns=[ScannerPatternArtifact(**item) for item in scanner_patterns.get('patterns', [])],
        patch_recipes=[PatchRecipeArtifact(**item) for item in patch_recipes.get('recipes', [])],
        patch_fewshots=[PatchFewShotArtifact(**item) for item in patch_fewshots.get('examples', [])],
        thresholds=ThresholdProfile(**thresholds),
    )


def dump_runtime_artifacts(bundle: RuntimeArtifactBundle, root: str | Path | None = None) -> Path:
    version_dir = artifact_version_dir(bundle.version, root)
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / 'manifest.json').write_text(json.dumps({'version': bundle.version, 'generated_at': bundle.generated_at, 'sources': [item.model_dump() for item in bundle.sources]}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (version_dir / 'secret_patterns.json').write_text(json.dumps({'patterns': [item.model_dump() for item in bundle.secret_patterns]}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (version_dir / 'scanner_patterns.json').write_text(json.dumps({'patterns': [item.model_dump() for item in bundle.scanner_patterns]}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (version_dir / 'patch_recipes.json').write_text(json.dumps({'recipes': [item.model_dump() for item in bundle.patch_recipes]}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (version_dir / 'patch_fewshots.json').write_text(json.dumps({'examples': [item.model_dump() for item in bundle.patch_fewshots]}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (version_dir / 'thresholds.json').write_text(json.dumps(bundle.thresholds.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return version_dir
