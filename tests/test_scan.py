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
            'def generate_reset_token():\n'
            '    password = "user-password"\n'
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
            'function makeResetToken() {\n'
            '  const password = "user-password";\n'
            '  return crypto.createHash("md5").update(password).digest("hex");\n'
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


def test_scan_avoids_spec_false_positive_examples(tmp_path):
    safe_file = tmp_path / 'safe.py'
    safe_js_file = tmp_path / 'safe.js'
    safe_file.write_text(
        (
            'import hashlib\n'
            'import subprocess\n'
            'import requests\n'
            'API_KEY = "your_api_key_example"\n'
            'DEBUG = False\n\n'
            'def ping():\n'
            '    requests.get("https://api.example.com/health")\n'
            '    subprocess.run(["echo", "ok"], shell=False)\n'
            '    return hashlib.md5(b"asset-cache").hexdigest()\n\n'
            'try:\n'
            '    ping()\n'
            'except Exception as exc:\n'
            '    print(exc)\n'
        ),
        encoding='utf-8',
    )
    safe_js_file.write_text(
        (
            'async function healthcheck() { return fetch("https://api.example.com/health"); }\n'
            'function checksum(fileBytes) { return crypto.createHash("md5").update(fileBytes).digest("hex"); }\n'
            'function regexTest(pattern, value) { return pattern.exec(value); }\n'
            'try { work(); } catch (error) { console.error(error); }\n'
        ),
        encoding='utf-8',
    )

    result = scan_path(tmp_path)

    assert result.deployable is True
    assert result.violations == []


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
