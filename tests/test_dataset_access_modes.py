from __future__ import annotations

import functools
import hashlib
import http.server
import json
import socketserver
import threading
from pathlib import Path

import pytest

from tools.datasets.adapters import DatasetFetchError
from tools.datasets.fetch_dataset import fetch_dataset
from tools.datasets.registry import DATASET_REGISTRY


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


@pytest.fixture()
def temp_registry_dataset(tmp_path, monkeypatch):
    dataset_id = 'temp_remote_dataset'
    meta = {
        'dataset_id': dataset_id,
        'role': 'test',
        'feeds': ['evaluator'],
        'runtime_use': 'test',
        'home': 'http://localhost',
        'languages': ['python'],
        'fixture_file': 'cvefixes.json',
        'access_mode': 'remote',
        'download': {},
        'normalizer_adapter': 'normalize_cvefixes',
        'notes': 'temporary test dataset',
    }
    monkeypatch.setitem(DATASET_REGISTRY, dataset_id, meta)
    return dataset_id, meta


def test_local_and_manual_import_support_jsonl_and_json(tmp_path):
    local_jsonl = tmp_path / 'local.jsonl'
    local_jsonl.write_text(json.dumps({'record_type': 'scanner_pattern', 'rule_id': 'NO_NETWORK'}) + '\n', encoding='utf-8')
    raw_path = fetch_dataset('cvefixes', mode_override='local', source_path=local_jsonl)
    payload = json.loads(raw_path.read_text(encoding='utf-8'))
    assert payload['records'][0]['rule_id'] == 'NO_NETWORK'

    manual_json = tmp_path / 'manual.json'
    manual_json.write_text(json.dumps({'records': [{'record_type': 'secret_pattern', 'rule_id': 'NO_HARDCODED_SECRETS'}]}), encoding='utf-8')
    raw_path = fetch_dataset('secretbench', mode_override='manual', source_path=manual_json)
    payload = json.loads(raw_path.read_text(encoding='utf-8'))
    assert payload['records'][0]['rule_id'] == 'NO_HARDCODED_SECRETS'


def test_remote_fetch_downloads_with_cache_and_checksum(tmp_path, monkeypatch, temp_registry_dataset):
    dataset_id, meta = temp_registry_dataset
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    source_file = source_dir / 'remote.json'
    source_file.write_text(json.dumps({'records': [{'record_type': 'benchmark_case', 'rule_id': 'NO_EXEC'}]}), encoding='utf-8')
    checksum = hashlib.sha256(source_file.read_bytes()).hexdigest()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(source_dir))
    with ReusableTCPServer(('127.0.0.1', 0), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        meta['download'] = {
            'url': f'http://127.0.0.1:{httpd.server_address[1]}/remote.json',
            'format': 'json',
            'filename': 'remote.json',
            'sha256': checksum,
        }
        path = fetch_dataset(dataset_id, force=True, use_registry_mode=True)
        payload = json.loads(path.read_text(encoding='utf-8'))
        assert payload['records'][0]['rule_id'] == 'NO_EXEC'
        cached = Path('.cache/slayer-datasets') / dataset_id / 'remote.json'
        assert cached.exists()
        # second fetch should reuse cache without error
        path = fetch_dataset(dataset_id, use_registry_mode=True)
        assert path.exists()
        httpd.shutdown()
        thread.join(timeout=2)


def test_remote_fetch_checksum_failure_raises(tmp_path, monkeypatch, temp_registry_dataset):
    dataset_id, meta = temp_registry_dataset
    source_dir = tmp_path / 'source_bad'
    source_dir.mkdir()
    source_file = source_dir / 'remote.json'
    source_file.write_text(json.dumps({'records': []}), encoding='utf-8')
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(source_dir))
    with ReusableTCPServer(('127.0.0.1', 0), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        meta['download'] = {
            'url': f'http://127.0.0.1:{httpd.server_address[1]}/remote.json',
            'format': 'json',
            'filename': 'remote.json',
            'sha256': '0' * 64,
        }
        with pytest.raises(DatasetFetchError):
            fetch_dataset(dataset_id, force=True, use_registry_mode=True)
        httpd.shutdown()
        thread.join(timeout=2)
