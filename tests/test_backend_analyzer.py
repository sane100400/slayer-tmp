from __future__ import annotations

from backend.analyzers import ast_analyzer
from backend.models import SLARule


def _rule(rule_id: str, rule_type: str) -> SLARule:
    return SLARule(
        id=rule_id,
        name=rule_id,
        description=rule_id,
        raw_nl=rule_id,
        rule_type=rule_type,  # type: ignore[arg-type]
        severity='high',
    )


def test_backend_analyzer_uses_spec_rule_types_and_filters_safe_hashes():
    code = (
        'import hashlib\n'
        'import requests\n'
        'import subprocess\n\n'
        'def proxy(user_url):\n'
        '    return requests.get(user_url)\n\n'
        'def hash_password(password):\n'
        '    return hashlib.sha1(password.encode()).hexdigest()\n\n'
        'def checksum(file_bytes):\n'
        '    return hashlib.md5(file_bytes).hexdigest()\n\n'
        'def safe_exec(filename):\n'
        '    return subprocess.run(["analyze", filename], shell=False)\n'
    )

    network = ast_analyzer.analyze(code, _rule('NO_NETWORK', 'NO_NETWORK'), 'app.py')
    insecure_hash = ast_analyzer.analyze(code, _rule('NO_INSECURE_HASH', 'NO_INSECURE_HASH'), 'app.py')
    exec_issues = ast_analyzer.analyze(code, _rule('NO_EXEC', 'NO_EXEC'), 'app.py')

    assert len(network) == 1
    assert len(insecure_hash) == 1
    assert insecure_hash[0].line == 9
    assert exec_issues == []


def test_backend_analyzer_avoids_false_positive_examples():
    code = (
        'import hashlib\n'
        'import requests\n'
        'import subprocess\n\n'
        'API_KEY = "your_api_key_example"\n\n'
        'def ping():\n'
        '    requests.get("https://api.example.com/health")\n'
        '    subprocess.run(["echo", "ok"], shell=False)\n'
        '    return hashlib.md5(b"asset-cache").hexdigest()\n\n'
        'def build_display_text(name):\n'
        '    return f"SELECT this label for {name}"\n\n'
        'try:\n'
        '    ping()\n'
        'except Exception as exc:\n'
        '    print(exc)\n'
    )

    for rule_type in (
        'NO_HARDCODED_SECRETS',
        'NO_NETWORK',
        'NO_EXEC',
        'SQL_PARAM_BINDING',
        'NO_DEBUG_MODE',
        'NO_INSECURE_HASH',
        'NO_BARE_EXCEPT',
    ):
        assert ast_analyzer.analyze(code, _rule(rule_type, rule_type), 'safe.py') == []
