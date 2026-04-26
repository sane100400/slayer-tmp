from __future__ import annotations

from slayer.artifact_store import DEFAULT_ARTIFACT_VERSION, artifact_version_dir, load_runtime_artifacts


def test_load_runtime_artifacts_default_bundle_exists():
    bundle = load_runtime_artifacts(DEFAULT_ARTIFACT_VERSION)
    assert bundle.version == DEFAULT_ARTIFACT_VERSION
    assert bundle.secret_patterns
    assert bundle.scanner_patterns
    assert bundle.patch_recipes
    assert bundle.patch_fewshots
    assert artifact_version_dir(DEFAULT_ARTIFACT_VERSION).exists()
