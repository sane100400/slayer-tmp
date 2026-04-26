# Dataset mapping and access-mode review

This document states **which datasets feed `slayer start`**, **which feed `slayer patch`**, which remain evaluator/reference-only, and how each dataset enters the pipeline through `fixture | remote | local | manual` ingestion modes.

## 1. Runtime flow overview

```text
dataset source
  -> fetch/import adapter (fixture | remote | local | manual)
  -> dataset/sources/raw/<dataset>/raw.json
  -> dataset-specific normalizer adapter
  -> dataset/sources/normalized/<dataset>.jsonl
  -> miners
      - mine_secret_patterns.py
      - mine_scanner_patterns.py
      - mine_patch_examples.py
  -> slayer/runtime_artifacts/<version>/
  -> slayer start / slayer patch
```

### Current code touchpoints

- Registry: `tools/datasets/registry.py`
- Fetch/import adapters: `tools/datasets/adapters.py`
- Path helpers/cache/checksum: `tools/datasets/common.py`
- Dataset-specific normalizers: `tools/datasets/normalizers.py`
- Runtime bundle build: `tools/build_runtime_artifacts.py`
- Runtime consumers:
  - `slayer/scanner.py`
  - `slayer/patcher/llm_patcher.py`

## 2. Which datasets feed `slayer start`?

`slayer start` consumes the runtime bundle's **secret patterns** and **scanner patterns**.

### Secret-pattern datasets used by `start`

These flow through `tools/mine_secret_patterns.py` and strengthen `NO_HARDCODED_SECRETS` detection:

- `creddata`
- `secretbench`
- `fpsecretbench`

### Scanner-pattern datasets used by `start`

These flow through `tools/mine_scanner_patterns.py` and contribute scanner overlays / provenance:

- `cvefixes`
- `primevul`
- `megavul`
- `diversevul`
- `securityeval`

## 3. Which datasets feed `slayer patch`?

`slayer patch` first reuses the same scan bundle as `start`, then extends the patch prompt with **patch recipes** and **few-shot before/after examples** mined by `tools/mine_patch_examples.py`.

Patch recipe / few-shot datasets:

- `cvefixes`
- `bigvul`
- `vul4j`
- `vulnpatchpairs`
- `vulrepair`

## 4. Which datasets are evaluator-only / reference-only?

These datasets are part of evaluator provenance or curated benchmark coverage, not direct runtime mining defaults:

- `owasp_benchmark`
- `sard_juliet`
- `codexglue_defect_detection`
- `seccodebench`
- `aicgseceval`
- `securevibebench`
- `susvibes`
- `patcheval`

## 5. Dataset-to-consumer matrix

| Dataset | Access mode | Feeds `start` | Feeds `patch` | Evaluator/reference | Runtime use |
| --- | --- | --- | --- | --- | --- |
| `cvefixes` | `manual` | ✓ | ✓ | ✓ (patch provenance) | Scanner overlays + patch exemplars |
| `bigvul` | `manual` | — | ✓ | — | Patch exemplar provenance |
| `primevul` | `manual` | ✓ | — | — | Scanner overlay provenance |
| `megavul` | `manual` | ✓ | — | — | Scanner overlay provenance |
| `diversevul` | `manual` | ✓ | — | ✓ (reference) | Additional scanner overlay provenance |
| `vul4j` | `remote` | — | ✓ | — | Human patch/PoV patch recipes |
| `vulnpatchpairs` | `remote` | — | ✓ | — | Before/after patch few-shots |
| `vulrepair` | `remote` | — | ✓ | — | Patch recipe + few-shot provenance |
| `creddata` | `manual` | ✓ | — | ✓ | Secret regex/provider coverage |
| `secretbench` | `manual` | ✓ | — | ✓ | Secret regex/provider coverage |
| `fpsecretbench` | `manual` | ✓ | — | ✓ | Secret false-positive suppression provenance |
| `securityeval` | `remote` | ✓ | — | ✓ | Scanner overlay provenance + evaluator provenance |
| `owasp_benchmark` | `remote` | — | — | ✓ | Scanner evaluator provenance |
| `sard_juliet` | `manual` | — | — | ✓ | Scanner evaluator provenance |
| `codexglue_defect_detection` | `remote` | — | — | ✓ | Scanner evaluator reference |
| `seccodebench` | `remote` | — | — | ✓ | AI-code evaluator provenance |
| `aicgseceval` | `remote` | — | — | ✓ | AI-code evaluator provenance |
| `securevibebench` | `manual` | — | — | ✓ | AI-code evaluator provenance |
| `susvibes` | `manual` | — | — | ✓ | AI-code evaluator provenance |
| `patcheval` | `remote` | — | — | ✓ | Patch evaluator provenance |

## 6. Access-mode meanings

### `fixture`
- deterministic bundled sample payload
- used for CI/local reproducibility
- source lives in `tools/datasets/fixtures/*.json`

### `remote`
- public upstream URL declared in the registry
- fetched into `.cache/slayer-datasets/<dataset>/`
- supports cache reuse, checksum validation, and resume-aware download logic
- may optionally extract archives into `dataset/sources/raw/<dataset>/extracted/`

### `local`
- user supplies a local export or snapshot path
- imported into the common raw-data contract
- intended for users who already mirrored a dataset locally

### `manual`
- approval- or policy-gated dataset
- user drops an approved export into `dataset/sources/manual/`
  or passes `--source-path`
- then the normalizer/miner pipeline proceeds normally

## 7. Policy review notes

- `SecretBench` / `FPSecretBench` are intentionally `manual` because access is gated by researcher contact and data-protection requirements.
- `CVEfixes`, `PrimeVul`, and `MegaVul` are also `manual` by default because their practical raw-corpus workflows rely on separate exports, tokens, Drive releases, or long-running collection jobs rather than one stable public file URL.
- Public repo/archive-backed datasets such as `PatchEval`, `AICGSecEval`, `VulRepair`, and `OWASP BenchmarkPython` are modeled as `remote`.
- `local` is supported by the adapter layer even where no dataset defaults to it; it is there for user-maintained mirrors and offline corpora.

## 8. Commands

Build the current fixture-backed bundle:

```bash
python tools/datasets/fetch_dataset.py
python tools/datasets/normalize_dataset.py
python tools/build_runtime_artifacts.py --version v1
```

Import a manual-gated dataset export:

```bash
python tools/datasets/fetch_dataset.py --dataset secretbench --source-path /path/to/secretbench-export.json
python tools/datasets/normalize_dataset.py --dataset secretbench
```

Use a remote/public dataset adapter:

```bash
python tools/datasets/fetch_dataset.py --dataset patcheval
python tools/datasets/normalize_dataset.py --dataset patcheval
```

Render the mapping from the registry itself:

```bash
python tools/datasets/render_mapping.py --output docs/generated-dataset-mapping.md
```
