from __future__ import annotations

import json

from typer.testing import CliRunner

from slayer.cli import app
from slayer.scanner import scan_path

runner = CliRunner()


def test_scan_detects_python_and_js_rules(tmp_path):
    python_file = tmp_path / 'demo.py'
    python_file.write_text(
        (
            'import random\n'
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
            'def generate_reset_token():\n'
            '    alphabet = "abcdef0123456789"\n'
            '    return "".join(random.choice(alphabet) for _ in range(16))\n\n'
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
            'function makeResetToken() {\n'
            '  const sessionToken = Math.random().toString(16);\n'
            '  return sessionToken;\n'
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
    assert 'NO_WEAK_RANDOM' in rule_names
    assert 'NO_BARE_EXCEPT' in rule_names


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


def test_syntax_error_blocks_deployment(tmp_path):
    broken = tmp_path / 'broken.py'
    broken.write_text('def nope(:\n    pass\n', encoding='utf-8')

    result = scan_path(tmp_path)

    assert result.syntax_errors
    assert result.deployable is False


def test_syntax_error_exit_code(tmp_path):
    broken = tmp_path / 'broken.py'
    broken.write_text('def nope(:\n    pass\n', encoding='utf-8')

    result = runner.invoke(app, ['start', str(broken)])
    assert result.exit_code == 1


def test_start_empty_directory_reports_no_supported_files(tmp_path):
    result = runner.invoke(app, ['start', str(tmp_path)])
    assert result.exit_code == 0
    assert 'No supported source files found' in result.stdout
