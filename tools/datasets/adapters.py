from __future__ import annotations

import json
import shutil
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from tools.datasets.common import cache_file_path, dump_json, fixture_path, load_json, local_import_path, manual_drop_path, raw_dataset_dir, raw_dataset_path, sha256_file
from tools.datasets.registry import dataset_meta


class DatasetFetchError(RuntimeError):
    pass


def _download_with_resume(url: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + '.part')
    downloaded = temp.stat().st_size if temp.exists() else 0
    headers = {'Range': f'bytes={downloaded}-'} if downloaded else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:
            status = getattr(response, 'status', 200)
            if downloaded and status != 206:
                temp.unlink(missing_ok=True)
                downloaded = 0
                response.close()
                with urllib.request.urlopen(url) as restarted, temp.open('wb') as handle:
                    shutil.copyfileobj(restarted, handle)
            else:
                with temp.open('ab' if downloaded else 'wb') as handle:
                    shutil.copyfileobj(response, handle)
    except Exception:
        if downloaded and temp.exists():
            temp.unlink(missing_ok=True)
            with urllib.request.urlopen(url) as response, temp.open('wb') as handle:
                shutil.copyfileobj(response, handle)
        else:
            raise
    temp.replace(destination)
    return destination


def _verify_checksum(path: Path, expected: str | None) -> None:
    if expected and sha256_file(path) != expected:
        raise DatasetFetchError(f'Checksum mismatch for {path.name}')


def _extract(downloaded: Path, destination: Path, archive_format: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if archive_format == 'zip':
        with zipfile.ZipFile(downloaded) as archive:
            archive.extractall(destination)
        return
    if archive_format in {'tar', 'tar.gz', 'tgz'}:
        mode = 'r:gz' if archive_format in {'tar.gz', 'tgz'} else 'r:'
        with tarfile.open(downloaded, mode) as archive:
            archive.extractall(destination)
        return
    raise DatasetFetchError(f'Unsupported archive format: {archive_format}')


def _jsonl_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def _materialize_source_file(source_path: Path, target: Path, mode: str) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    suffix = source_path.suffix.lower()
    if suffix == '.json':
        shutil.copy2(source_path, target)
        return target
    if suffix == '.jsonl':
        dump_json(target, {'records': _jsonl_records(source_path), 'record_type': f'{mode}_jsonl'})
        return target
    if suffix == '.zip':
        extracted = target.parent / 'extracted'
        if extracted.exists():
            shutil.rmtree(extracted)
        _extract(source_path, extracted, 'zip')
        dump_json(target, {'records': [], 'source_archive': str(source_path.resolve()), 'source_dir': str(extracted.resolve()), 'record_type': f'{mode}_archive'})
        return target
    raise DatasetFetchError(f'Unsupported {mode} source file type: {source_path.name}')


def fetch_fixture(dataset_id: str, *, force: bool = False) -> Path:
    target = raw_dataset_path(dataset_id)
    dump_json(target, load_json(fixture_path(dataset_id)))
    return target


def fetch_remote(dataset_id: str, *, force: bool = False) -> Path:
    meta = dataset_meta(dataset_id)
    download = dict(meta.get('download', {}))
    if not download.get('url'):
        raise DatasetFetchError(f'{dataset_id} does not declare a remote download URL')
    cached = cache_file_path(dataset_id, download)
    if force or not cached.exists():
        _download_with_resume(str(download['url']), cached)
    _verify_checksum(cached, download.get('sha256'))
    target = raw_dataset_path(dataset_id)
    fmt = str(download.get('format', 'json')).lower()
    if fmt == 'json':
        shutil.copy2(cached, target)
        return target
    if fmt == 'jsonl':
        dump_json(target, {'records': _jsonl_records(cached), 'record_type': 'remote_jsonl', 'source_url': download['url']})
        return target
    if download.get('extract'):
        extracted = raw_dataset_dir(dataset_id) / 'extracted'
        if force and extracted.exists():
            shutil.rmtree(extracted)
        if not extracted.exists():
            _extract(cached, extracted, fmt)
        dump_json(target, {'records': [], 'source_archive': str(cached.resolve()), 'source_dir': str(extracted.resolve()), 'source_url': download['url'], 'record_type': 'remote_archive'})
        return target
    dump_json(target, {'records': [], 'source_archive': str(cached.resolve()), 'source_url': download['url'], 'record_type': 'remote_blob'})
    return target


def import_from_path(dataset_id: str, source_path: Path, *, mode: str) -> Path:
    if not source_path.exists():
        raise DatasetFetchError(f'{mode} source path does not exist: {source_path}')
    target = raw_dataset_path(dataset_id)
    if source_path.is_dir():
        dump_json(target, {'records': [], 'source_dir': str(source_path.resolve()), 'record_type': f'{mode}_manifest'})
        return target
    return _materialize_source_file(source_path, target, mode)


def import_local(dataset_id: str, *, source_path: Path | None = None) -> Path:
    return import_from_path(dataset_id, source_path or local_import_path(dataset_id), mode='local')


def import_manual(dataset_id: str, *, source_path: Path | None = None) -> Path:
    return import_from_path(dataset_id, source_path or manual_drop_path(dataset_id), mode='manual')


ADAPTERS = {'fixture': fetch_fixture, 'remote': fetch_remote, 'local': import_local, 'manual': import_manual}
