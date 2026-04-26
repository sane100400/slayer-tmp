# Dataset → start / patch / evaluator mapping

| Dataset | Access mode | Feeds start | Feeds patch | Evaluator/reference | Runtime use |
| --- | --- | --- | --- | --- | --- |
| `cvefixes` | `manual` | ✓ | ✓ | — | Scanner overlays and patch exemplars (CVE/fix provenance). |
| `bigvul` | `manual` | — | ✓ | — | Patch exemplar provenance only; target-language mismatch is documented. |
| `primevul` | `manual` | ✓ | — | — | Scanner overlay provenance only. |
| `megavul` | `manual` | ✓ | — | — | Scanner overlay provenance only. |
| `diversevul` | `manual` | ✓ | — | — | Additional scanner pattern provenance. |
| `vul4j` | `remote` | — | ✓ | — | Human patch/PoV patch recipe provenance. |
| `vulnpatchpairs` | `remote` | — | ✓ | — | Before/after patch few-shot provenance. |
| `vulrepair` | `remote` | — | ✓ | — | Patch recipe and few-shot provenance. |
| `owasp_benchmark` | `remote` | — | — | ✓ | Evaluator provenance only. |
| `sard_juliet` | `manual` | — | — | ✓ | Evaluator provenance only. |
| `codexglue_defect_detection` | `remote` | — | — | ✓ | Documentation/reference only for evaluator methodology. |
| `seccodebench` | `remote` | — | — | ✓ | AI-code evaluator provenance only. |
| `aicgseceval` | `remote` | — | — | ✓ | AI-code evaluator provenance only. |
| `securevibebench` | `manual` | — | — | ✓ | AI-code evaluator provenance only. |
| `susvibes` | `manual` | — | — | ✓ | AI-code evaluator provenance only. |
| `securityeval` | `remote` | ✓ | ✓ | ✓ | Scanner pattern provenance and evaluator provenance. |
| `creddata` | `manual` | ✓ | — | ✓ | Secret regex/provider coverage and evaluator provenance. |
| `secretbench` | `manual` | ✓ | — | ✓ | Secret regex/provider coverage and evaluator provenance. |
| `fpsecretbench` | `manual` | ✓ | — | ✓ | Secret false-positive suppression provenance. |
| `patcheval` | `remote` | — | — | ✓ | Patch evaluator provenance only. |

## Access mode meanings

- `fixture`: bundled deterministic sample payload used for CI/local reproducibility.
- `remote`: publicly downloadable source with cache/checksum/resume support.
- `local`: user-supplied local export or snapshot imported into the raw-data contract.
- `manual`: approval- or policy-gated dataset imported via a manual drop-in path.
