# Dataset mapping and access-mode review

This document describes how SLAyer's dataset fixtures currently flow into runtime artifacts, which datasets feed `slayer start` vs `slayer patch` vs evaluator-only paths, and where future remote/local/manual adapters should attach.

## 1. Current implemented pipeline

The current repository implements a **fixture-first** dataset pipeline:

1. Bundled fixture JSON lives in `tools/datasets/fixtures/<dataset>.json`.
2. `python3 tools/datasets/fetch_dataset.py --dataset ...` copies the bundled fixture into `dataset/sources/raw/<dataset>/raw.json`.
3. `python3 tools/datasets/normalize_dataset.py --dataset ...` converts that raw payload into `dataset/sources/normalized/<dataset>.jsonl`.
4. `python3 tools/build_runtime_artifacts.py --version <v>` mines normalized records into `slayer/runtime_artifacts/<v>/`.
5. `slayer start` and `slayer patch` load the built bundle through `slayer.artifact_store.load_runtime_artifacts()`.

### Source-of-truth files

- Dataset registry: `tools/datasets/registry.py`
- Raw/normalized path helpers: `tools/datasets/common.py`
- Runtime bundle builder: `tools/build_runtime_artifacts.py`
- Runtime consumers:
  - `slayer/scanner.py`
  - `slayer/patcher/llm_patcher.py`
- Evaluator fixture loader:
  - `slayer/eval/fixture_loader.py`

## 2. Which datasets feed which consumer?

### `slayer start` runtime inputs

`slayer start` uses the runtime artifact bundle's secret-pattern and scanner-pattern payloads.

#### Secret-pattern datasets

These feed `tools/mine_secret_patterns.py` and therefore the runtime secret matcher used during scanning:

- `creddata`
- `secretbench`
- `fpsecretbench`

#### Scanner-pattern datasets

These feed `tools/mine_scanner_patterns.py` and therefore the runtime scanner overlays used during scanning:

- `cvefixes`
- `primevul`
- `megavul`
- `diversevul`
- `securityeval`

### `slayer patch` runtime inputs

`slayer patch` first reuses the same scan bundle as `slayer start`, then extends the patch prompt with patch recipes and few-shot examples mined by `tools/mine_patch_examples.py`.

Patch-example datasets:

- `cvefixes`
- `bigvul`
- `vul4j`
- `vulnpatchpairs`
- `vulrepair`

### Evaluator-only / provenance-only datasets

These datasets are currently used for benchmark provenance, evaluator documentation, or curated local benchmark cases rather than direct runtime mining defaults:

- `owasp_benchmark`
- `sard_juliet`
- `codexglue_defect_detection`
- `seccodebench`
- `aicgseceval`
- `securevibebench`
- `susvibes`
- `patcheval`

### Cross-over datasets

A few datasets span more than one concern:

- `cvefixes` feeds both scanner-pattern mining and patch-example mining.
- `securityeval` feeds runtime scanner mining and also appears throughout evaluator provenance / benchmark metadata.
- `build_runtime_artifacts.py` records all `P1_DATASETS + P2_DATASETS` in `manifest.json` for provenance, even though the mined runtime payloads come from narrower default dataset subsets.

## 3. Dataset-to-consumer matrix

| Dataset | Registry role | Normalizer tag | Feeds `start` | Feeds `patch` | Evaluator/reference only |
| --- | --- | --- | --- | --- | --- |
| `cvefixes` | `runtime_scanner_patch` | `generic_vuln` | ✓ | ✓ | — |
| `bigvul` | `runtime_patch_reference` | `generic_vuln` | — | ✓ | — |
| `primevul` | `runtime_scanner_reference` | `generic_vuln` | ✓ | — | — |
| `megavul` | `runtime_scanner_reference` | `generic_vuln` | ✓ | — | — |
| `diversevul` | `runtime_scanner_reference` | `generic_vuln` | ✓ | — | — |
| `vul4j` | `runtime_patch_reference` | `generic_patch` | — | ✓ | — |
| `vulnpatchpairs` | `runtime_patch_reference` | `generic_patch` | — | ✓ | — |
| `vulrepair` | `runtime_patch_reference` | `generic_patch` | — | ✓ | — |
| `owasp_benchmark` | `scanner_eval` | `benchmark_meta` | — | — | ✓ |
| `sard_juliet` | `scanner_eval` | `benchmark_meta` | — | — | ✓ |
| `codexglue_defect_detection` | `scanner_eval_reference` | `benchmark_meta` | — | — | ✓ |
| `seccodebench` | `ai_code_eval` | `benchmark_meta` | — | — | ✓ |
| `aicgseceval` | `ai_code_eval` | `benchmark_meta` | — | — | ✓ |
| `securevibebench` | `ai_code_eval` | `benchmark_meta` | — | — | ✓ |
| `susvibes` | `ai_code_eval` | `benchmark_meta` | — | — | ✓ |
| `securityeval` | `scanner_patch_ai_eval` | `generic_vuln` | ✓ | — | runtime + evaluator provenance |
| `creddata` | `secret_runtime_eval` | `secret_patterns` | ✓ | — | — |
| `secretbench` | `secret_runtime_eval` | `secret_patterns` | ✓ | — | — |
| `fpsecretbench` | `secret_runtime_eval` | `secret_patterns` | ✓ | — | — |
| `patcheval` | `patch_eval` | `benchmark_meta` | — | — | ✓ |

## 4. Normalizer design

The current normalizer path is intentionally simple:

- `normalize_dataset.py` does **not** dispatch to per-dataset parser modules.
- Instead, `tools/datasets/registry.py` assigns a `normalizer` tag and `normalize_records()` stamps each record with shared fields such as `dataset_id`, `record_id`, `record_type`, `language`, `rule_id`, and `source_datasets`.
- In practice, the bundled fixture payloads already carry most dataset-specific shaping, while the normalizer tag acts as a schema/default label:
  - `generic_vuln`
  - `generic_patch`
  - `benchmark_meta`
  - `secret_patterns`

### Review note

This is sufficient for bundled fixtures, but a future live-ingest pipeline will likely need an explicit adapter layer if upstream sources arrive in incompatible raw formats. The stable contract to preserve is:

- raw source material lands in `dataset/sources/raw/<dataset>/raw.json`
- normalized records land in `dataset/sources/normalized/<dataset>.jsonl`
- miners only read normalized JSONL

## 5. Access-mode design review

## Implemented today

### 1. Bundled fixture mode

This is the only fully implemented dataset-ingest path today.

- Storage: `tools/datasets/fixtures/*.json`
- Entry point: `tools/datasets/fetch_dataset.py`
- Use case: reproducible local builds and CI artifact generation
- Verification path: `.github/workflows/slayer-eval.yml`

### 2. Curated local benchmark mode

Evaluator fixtures are already stored locally and loaded directly from committed benchmark directories:

- `dataset/slayer-bench-v0/metadata.jsonl`
- `dataset/ai-bench-v0/metadata.jsonl`
- Loader: `slayer/eval/fixture_loader.py`

This is effectively the current "manual/curated" path for evaluator data.

## Reviewed boundary for future adapters

The following adapter modes are **not implemented yet**, but the current code shape suggests where they should attach.

### Remote + cache + resume adapter

Recommended contract:

1. Fetch from an upstream remote source into a dataset-specific cache directory.
2. Support resume/retry at the cache layer rather than inside the normalizer.
3. Materialize a canonical `dataset/sources/raw/<dataset>/raw.json` payload before calling `normalize_dataset.py`.

Why this boundary fits the current code:

- miners already depend only on normalized JSONL
- `build_runtime_artifacts.py` is access-mode agnostic once normalization is complete
- keeping remote state out of the normalizer preserves deterministic fixture tests

### Local import adapter

Recommended contract:

1. Accept a user-supplied local export / snapshot.
2. Copy or transform it into `dataset/sources/raw/<dataset>/raw.json`.
3. Reuse the existing normalization + mining pipeline unchanged.

This keeps "where the data came from" separate from "how SLAyer expects normalized records to look".

### Manual import adapter

Recommended contract:

- Use manual import for hand-curated cases that do not map cleanly to an upstream bulk export.
- If the goal is runtime artifact generation, the manual path should still end in the same raw/normalized contract.
- If the goal is evaluator coverage, the existing `dataset/slayer-bench-v0` / `dataset/ai-bench-v0` layout is already the right home.

## 6. Practical guidance

- If you want to change which datasets affect `slayer start`, update the defaults in `tools/mine_secret_patterns.py` and/or `tools/mine_scanner_patterns.py`.
- If you want to change which datasets affect `slayer patch`, update the defaults in `tools/mine_patch_examples.py`.
- If you want to adjust provenance shown in runtime manifests, update `P1_DATASETS` / `P2_DATASETS` in `tools/datasets/registry.py` and rebuild the bundle.
- If you add a new access mode, keep the adapter before normalization rather than teaching miners about remote/local/manual source types.

## 7. Branch-health verification checklist

The current CI-equivalent dataset pipeline is:

```bash
python3 tools/datasets/fetch_dataset.py
python3 tools/datasets/normalize_dataset.py
python3 tools/build_runtime_artifacts.py --version v1
pytest -q
python3 tools/ci_gate.py --artifact-version v1
```

That sequence verifies that bundled fixtures still normalize cleanly, the runtime artifact bundle can be rebuilt, and the evaluator gate remains healthy.
