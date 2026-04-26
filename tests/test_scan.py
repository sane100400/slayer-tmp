from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from slayer.cli import app
from slayer.scanner import scan_path

runner = CliRunner()


def test_scan_detects_python_and_js_rules(tmp_path):
    python_file = tmp_path / 'demo.py'
    python_file.write_text(
        (
            'import hashlib\n'
            'import requests\n'
            'import sqlite3\n'
            'import subprocess\n'
            'API_KEY = "sk-prod-abc123secretkey9999"\n'
            'DEBUG = True\n\n'
            'def proxy_user(user_id):\n'
            '    return requests.get(f"https://api.example.com/user/{user_id}")\n\n'
            'def search(query):\n'
            '    cursor = sqlite3.connect("db.sqlite3").cursor()\n'
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{query}\'")\n'
            '    return cursor.fetchall()\n\n'
            'def analyze(filename):\n'
            '    return subprocess.run(f"analyze {filename}", shell=True, capture_output=True)\n\n'
            'def hash_password(password):\n'
            '    return hashlib.md5(password.encode()).hexdigest()\n\n'
            'def process():\n'
            '    try:\n'
            '        return 1\n'
            '    except:\n'
            '        pass\n'
        ),
        encoding='utf-8',
    )
    js_file = tmp_path / 'demo.js'
    js_file.write_text(
        (
            'const API_KEY = "sk-prod-abc123secretkey9999";\n'
            'const debug = true;\n'
            'async function proxy(req, res) {\n'
            '  return fetch(`${req.query.url}`);\n'
            '}\n'
            'function search(name) {\n'
            '  const sql = `SELECT * FROM users WHERE name = \'${name}\'`;\n'
            '  return db.query(sql);\n'
            '}\n'
            'function analyze(filename) {\n'
            '  return require("child_process").exec(`analyze ${filename}`);\n'
            '}\n'
            'function hashPassword(password) {\n'
            '  const digest = createHash("md5").update(password).digest("hex");\n'
            '  return digest;\n'
            '}\n'
            'try {\n'
            '  work();\n'
            '} catch (error) {}\n'
        ),
        encoding='utf-8',
    )

    result = scan_path(tmp_path)
    rule_names = {violation.rule_name for violation in result.violations}

    assert 'NO_HARDCODED_SECRETS' in rule_names
    assert 'NO_NETWORK' in rule_names
    assert 'NO_EXEC' in rule_names
    assert 'SQL_PARAM_BINDING' in rule_names
    assert 'NO_DEBUG_MODE' in rule_names
    assert 'NO_INSECURE_HASH' in rule_names
    assert 'NO_BARE_EXCEPT' in rule_names


def test_default_rules_match_spec_vulnerability_ids():
    result = scan_path(__file__)
    rule_ids = [rule.id for rule in result.rules]

    assert rule_ids == [
        'NO_HARDCODED_SECRETS',
        'NO_NETWORK',
        'NO_EXEC',
        'SQL_PARAM_BINDING',
        'NO_DEBUG_MODE',
        'NO_INSECURE_HASH',
        'NO_BARE_EXCEPT',
    ]
    assert 'NO_WEAK_RANDOM' not in rule_ids


def test_scan_reduces_common_false_positives(tmp_path):
    source = tmp_path / 'safe.py'
    source.write_text(
        (
            'import hashlib\n'
            'import logging\n'
            'import subprocess\n\n'
            'def file_checksum(blob):\n'
            '    return hashlib.md5(blob).hexdigest()\n\n'
            'def git_status():\n'
            '    return subprocess.run("git status", shell=False, check=True)\n\n'
            'def recover():\n'
            '    try:\n'
            '        return risky()\n'
            '    except:\n'
            '        logging.warning("recovered from non-security failure")\n'
            '        return None\n'
        ),
        encoding='utf-8',
    )

    result = scan_path(source)

    assert result.deployable is True
    assert result.violations == []


def test_scan_detects_insecure_hash_only_in_security_context(tmp_path):
    source = tmp_path / 'hashes.py'
    source.write_text(
        (
            'import hashlib\n\n'
            'def file_checksum(blob):\n'
            '    return hashlib.md5(blob).hexdigest()\n\n'
            'def hash_password(password):\n'
            '    return hashlib.sha1(password.encode()).hexdigest()\n'
        ),
        encoding='utf-8',
    )

    result = scan_path(source)

    assert [violation.rule_name for violation in result.violations] == ['NO_INSECURE_HASH']
    assert result.violations[0].line == 7


def test_benchmark_dataset_follows_spec_expectations():
    root = Path('dataset/slayer-bench-v0')
    metadata = [json.loads(line) for line in (root / 'metadata.jsonl').read_text(encoding='utf-8').splitlines()]

    for item in metadata:
        result = scan_path(root / item['file'])
        matches = [
            violation
            for violation in result.violations
            if violation.rule_name == item['rule']
        ]

        assert len(matches) == item['expected_count'], item['case_id']
        assert [violation.line for violation in matches] == item['expected_lines'], item['case_id']

    assert scan_path(root / 'fixed').deployable is True
    assert scan_path(root / 'false_positive').deployable is True


def test_start_json_output_and_exit_code(tmp_path):
    vulnerable = tmp_path / 'vulnerable.py'
    vulnerable.write_text('API_KEY = "sk-prod-abc123secretkey9999"\n', encoding='utf-8')

    result = runner.invoke(app, ['start', str(vulnerable), '--format', 'json'])
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload['deployable'] is False
    assert payload['violations'][0]['rule_name'] == 'NO_HARDCODED_SECRETS'


def test_start_handles_syntax_error_without_crashing(tmp_path):
    broken = tmp_path / 'broken.py'
    broken.write_text('def nope(:\n    pass\n', encoding='utf-8')
    vulnerable = tmp_path / 'vulnerable.py'
    vulnerable.write_text('DEBUG = True\n', encoding='utf-8')

    result = scan_path(tmp_path)

    assert any(issue.file.endswith('broken.py') for issue in result.syntax_errors)
    assert any(violation.rule_name == 'NO_DEBUG_MODE' for violation in result.violations)


def test_start_empty_directory_reports_no_supported_files(tmp_path):
    result = runner.invoke(app, ['start', str(tmp_path)])
    assert result.exit_code == 0
    assert 'No supported source files found' in result.stdout
