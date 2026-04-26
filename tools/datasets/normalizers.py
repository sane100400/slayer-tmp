from __future__ import annotations

from pathlib import Path


def _base_records(dataset_id: str, payload: dict) -> list[dict]:
    normalized: list[dict] = []
    for index, record in enumerate(payload.get('records', []), start=1):
        base = {
            'dataset_id': dataset_id,
            'record_id': record.get('record_id', f'{dataset_id}-{index:03d}'),
            'record_type': record.get('record_type', payload.get('record_type', 'generic')),
            'language': record.get('language', 'python'),
            'rule_id': record.get('rule_id', ''),
            'source_datasets': record.get('source_datasets', [dataset_id]),
            'notes': record.get('notes', ''),
        }
        base.update(record)
        normalized.append(base)
    return normalized


def normalize_generic_vuln(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]:
    return _base_records(dataset_id, payload)


def normalize_generic_patch(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]:
    return _base_records(dataset_id, payload)


def normalize_secret_patterns(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]:
    return _base_records(dataset_id, payload)


def normalize_benchmark_meta(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]:
    return _base_records(dataset_id, payload)


def normalize_cvefixes(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_bigvul(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_primevul(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_megavul(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_diversevul(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_vul4j(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_patch(dataset_id, payload, raw_dir)
def normalize_vulnpatchpairs(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_patch(dataset_id, payload, raw_dir)
def normalize_vulrepair(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_patch(dataset_id, payload, raw_dir)
def normalize_owasp_benchmark(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_sard_juliet(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_codexglue_defect_detection(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_seccodebench(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_aicgseceval(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_securevibebench(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_susvibes(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)
def normalize_securityeval(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_generic_vuln(dataset_id, payload, raw_dir)
def normalize_creddata(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_secret_patterns(dataset_id, payload, raw_dir)
def normalize_secretbench(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_secret_patterns(dataset_id, payload, raw_dir)
def normalize_fpsecretbench(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_secret_patterns(dataset_id, payload, raw_dir)
def normalize_patcheval(dataset_id: str, payload: dict, raw_dir: Path) -> list[dict]: return normalize_benchmark_meta(dataset_id, payload, raw_dir)

NORMALIZER_ADAPTERS = {name: obj for name, obj in globals().items() if name.startswith('normalize_')}
