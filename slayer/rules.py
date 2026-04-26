from __future__ import annotations

from slayer.models import SLARule

DEFAULT_RULES: tuple[SLARule, ...] = (
    SLARule(
        id="NO_HARDCODED_SECRETS",
        name="NO_HARDCODED_SECRETS",
        description="비밀번호나 API 키를 코드에 직접 넣으면 저장소가 노출될 때 인증 정보가 바로 악용됩니다.",
        raw_nl="하드코딩된 비밀정보 금지",
        rule_type="NO_HARDCODED_SECRETS",
        severity="critical",
    ),
    SLARule(
        id="NO_NETWORK",
        name="NO_NETWORK",
        description="검증되지 않은 주소로 외부 요청을 보내면 내부망 조회나 민감정보 전달이 일어날 수 있습니다.",
        raw_nl="검증되지 않은 외부 네트워크 호출 금지",
        rule_type="NO_NETWORK",
        severity="critical",
    ),
    SLARule(
        id="NO_EXEC",
        name="NO_EXEC",
        description="쉘 명령을 문자열로 실행하면 입력 한 줄로 서버 명령이 실행될 수 있습니다.",
        raw_nl="쉘 실행 금지",
        rule_type="NO_EXEC",
        severity="critical",
    ),
    SLARule(
        id="SQL_PARAM_BINDING",
        name="SQL_PARAM_BINDING",
        description="사용자 값을 SQL 문자열에 직접 끼워 넣으면 데이터 조회나 수정이 공격자 입력대로 바뀔 수 있습니다.",
        raw_nl="SQL 파라미터 바인딩 강제",
        rule_type="SQL_PARAM_BINDING",
        severity="high",
    ),
    SLARule(
        id="NO_DEBUG_MODE",
        name="NO_DEBUG_MODE",
        description="디버그 모드를 켜고 배포하면 서버 내부 정보와 환경설정이 그대로 노출될 수 있습니다.",
        raw_nl="디버그 모드 배포 금지",
        rule_type="NO_DEBUG_MODE",
        severity="high",
    ),
    SLARule(
        id="NO_WEAK_RANDOM",
        name="NO_WEAK_RANDOM",
        description="토큰이나 인증값을 약한 난수로 만들면 공격자가 값을 예측해 세션을 탈취할 수 있습니다.",
        raw_nl="보안 컨텍스트에서 약한 난수 금지",
        rule_type="NO_WEAK_RANDOM",
        severity="high",
    ),
    SLARule(
        id="NO_BARE_EXCEPT",
        name="NO_BARE_EXCEPT",
        description="예외를 비워 두고 삼키면 공격 징후와 장애 원인이 숨겨져 위험한 동작이 계속될 수 있습니다.",
        raw_nl="빈 예외 처리 금지",
        rule_type="NO_BARE_EXCEPT",
        severity="medium",
    ),
)

RULE_GUIDANCE: dict[str, str] = {
    "NO_HARDCODED_SECRETS": 'Replace the secret with an environment variable lookup. Do not put the real value back in the code.',
    "NO_NETWORK": 'Do not call user-supplied URLs directly. Use an allow-list of trusted domains or a fixed endpoint.',
    "NO_EXEC": 'Remove the shell string execution. Use a safe argument list (shell=False) or block the operation.',
    "SQL_PARAM_BINDING": 'Replace string-interpolated SQL with parameterized queries (placeholders + bound values).',
    "NO_DEBUG_MODE": 'Replace the hardcoded debug=True with an environment variable check.',
    "NO_WEAK_RANDOM": 'Use the secrets or crypto module for tokens, sessions, and OTPs instead of the math random functions.',
    "NO_BARE_EXCEPT": 'Replace the empty except/catch with specific error handling and a log statement.',
}

DEFAULT_RULES_BY_ID = {rule.id: rule for rule in DEFAULT_RULES}


RULE_DETAILS: dict[str, dict[str, str]] = {
    "NO_HARDCODED_SECRETS": {
        "why": (
            "Putting a password or API key in your code is like taping your house key to the front door.\n"
            "  Bots scan GitHub and steal exposed secrets in under 3 minutes (GitGuardian)."
        ),
        "fix": "Use os.environ.get('API_KEY') or process.env.API_KEY — keep secrets out of the code.",
    },
    "NO_EXEC": {
        "why": (
            "Running a shell command as a string lets an attacker sneak in extra commands with a semicolon.\n"
            "  One bad input → full server takeover. (CVSS 9.8 / Remote Code Execution)"
        ),
        "fix": "Use subprocess.run(['cmd', arg], shell=False) — pass arguments as a list, never a string.",
    },
    "SQL_PARAM_BINDING": {
        "why": (
            "Putting user input inside a SQL string lets attackers type '; DROP TABLE users;--\n"
            "  and delete your entire database. (OWASP #3 — SQL Injection)"
        ),
        "fix": "Use cursor.execute('SELECT ... WHERE name=?', (name,)) — let the driver handle quoting.",
    },
    "NO_NETWORK": {
        "why": (
            "Fetching a URL typed by a user lets attackers hit private servers inside your cloud.\n"
            "  One request to 169.254.169.254 can steal your AWS credentials. (SSRF)"
        ),
        "fix": "Check the URL against an allow-list of trusted domains before making the request.",
    },
    "NO_DEBUG_MODE": {
        "why": (
            "Shipping with debug=True turns on an interactive console anyone on the internet can reach.\n"
            "  They can run any Python or JS code they want on your server. (CWE-16)"
        ),
        "fix": "Use DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true' so it is off by default.",
    },
    "NO_WEAK_RANDOM": {
        "why": (
            "Math.random() and random.random() are guessable — like rolling a dice with a pattern.\n"
            "  An attacker can predict your tokens and take over accounts. (CWE-330)"
        ),
        "fix": "Use secrets.token_hex(32) in Python or crypto.randomUUID() in JS for security tokens.",
    },
    "NO_BARE_EXCEPT": {
        "why": (
            "An empty catch block hides errors like sweeping dirt under a rug.\n"
            "  Attacks and crashes go unnoticed — average breach detection time: 207 days (IBM)."
        ),
        "fix": "Use except Exception as e: logger.warning(e) so every problem gets logged.",
    },
}


def default_rules() -> list[SLARule]:
    return [rule.model_copy(deep=True) for rule in DEFAULT_RULES]
