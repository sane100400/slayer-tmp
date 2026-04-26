from __future__ import annotations

from slayer.models import PatchExplanation, SLARule, Violation

DEFAULT_RULES: tuple[SLARule, ...] = (
    SLARule(
        id="NO_HARDCODED_SECRETS",
        name="NO_HARDCODED_SECRETS",
        description="Passwords and API keys in code can be stolen if the repository is exposed.",
        raw_nl="Do not hardcode secrets",
        rule_type="NO_HARDCODED_SECRETS",
        severity="critical",
    ),
    SLARule(
        id="NO_NETWORK",
        name="NO_NETWORK",
        description="Unverified external requests can expose internal services or send sensitive data to untrusted systems.",
        raw_nl="Do not call unverified external networks",
        rule_type="NO_NETWORK",
        severity="critical",
    ),
    SLARule(
        id="NO_EXEC",
        name="NO_EXEC",
        description="Shell command strings can let user input run server commands.",
        raw_nl="Do not run shell commands from strings",
        rule_type="NO_EXEC",
        severity="critical",
    ),
    SLARule(
        id="SQL_PARAM_BINDING",
        name="SQL_PARAM_BINDING",
        description="Putting user values directly into SQL lets input change what the query does.",
        raw_nl="Use SQL parameter binding",
        rule_type="SQL_PARAM_BINDING",
        severity="high",
    ),
    SLARule(
        id="NO_DEBUG_MODE",
        name="NO_DEBUG_MODE",
        description="Debug mode in production can expose server details and settings.",
        raw_nl="Do not deploy with debug mode",
        rule_type="NO_DEBUG_MODE",
        severity="high",
    ),
    SLARule(
        id="NO_WEAK_RANDOM",
        name="NO_WEAK_RANDOM",
        description="Weak random numbers can make tokens and session values predictable.",
        raw_nl="Do not use weak random values for security",
        rule_type="NO_WEAK_RANDOM",
        severity="high",
    ),
    SLARule(
        id="NO_BARE_EXCEPT",
        name="NO_BARE_EXCEPT",
        description="Empty exception handlers hide errors and possible attacks.",
        raw_nl="Do not swallow exceptions",
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
            "Passwords and API keys in code are visible to anyone who can read the repository.\n"
            "  Public scans can find exposed secrets quickly."
        ),
        "fix": "Use os.environ.get('API_KEY') or process.env.API_KEY. Keep secrets out of the code.",
    },
    "NO_EXEC": {
        "why": (
            "Running a shell command as a string can let user input add extra commands.\n"
            "  This can lead to remote command execution. (CVSS 9.8)"
        ),
        "fix": "Use subprocess.run(['cmd', arg], shell=False). Pass arguments as a list, never a string.",
    },
    "SQL_PARAM_BINDING": {
        "why": (
            "Putting user input inside a SQL string can change the query.\n"
            "  Use bound values so input is treated as data. (OWASP #3 SQL Injection)"
        ),
        "fix": "Use cursor.execute('SELECT ... WHERE name=?', (name,)). Let the driver handle quoting.",
    },
    "NO_NETWORK": {
        "why": (
            "Calling a user-provided URL can reach private cloud or internal network services.\n"
            "  Restrict requests to approved destinations. (SSRF)"
        ),
        "fix": "Check the URL against an allow-list of trusted domains before making the request.",
    },
    "NO_DEBUG_MODE": {
        "why": (
            "Debug mode can expose internal details and interactive tools.\n"
            "  Keep it off unless the local developer has enabled it. (CWE-16)"
        ),
        "fix": "Use DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true' so it is off by default.",
    },
    "NO_WEAK_RANDOM": {
        "why": (
            "Math.random() and random.random() are predictable for security use.\n"
            "  Predictable tokens can let attackers access accounts. (CWE-330)"
        ),
        "fix": "Use secrets.token_hex(32) in Python or crypto.randomUUID() in JS for security tokens.",
    },
    "NO_BARE_EXCEPT": {
        "why": (
            "An empty catch or except block hides errors.\n"
            "  Log or handle the error so failures are visible."
        ),
        "fix": "Use except Exception as e: logger.warning(e) so every problem gets logged.",
    },
}


RULE_ALIASES: dict[str, str] = {
    "HARDCODED_SECRETS": "NO_HARDCODED_SECRETS",
    "COMMAND_INJECTION": "NO_EXEC",
    "SQL_INJECTION": "SQL_PARAM_BINDING",
    "DEBUG_MODE_ON": "NO_DEBUG_MODE",
    "WEAK_HASH": "NO_WEAK_RANDOM",
    "NO_INSECURE_HASH": "NO_WEAK_RANDOM",
}

PATCH_EXPLANATION_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "NO_HARDCODED_SECRETS": (
        "Moved secrets out of code",
        "The patch uses an environment variable instead of a hardcoded key or password, so the real secret is not stored in the repository.",
        RULE_GUIDANCE["NO_HARDCODED_SECRETS"],
    ),
    "NO_NETWORK": (
        "Blocked unverified external calls",
        "The patch stops user input from directly choosing a network destination or limits it to a trusted endpoint.",
        RULE_GUIDANCE["NO_NETWORK"],
    ),
    "NO_EXEC": (
        "Removed shell command injection path",
        "The patch replaces string shell execution with argument-list execution or a blocked action, so input is not interpreted as a server command.",
        RULE_GUIDANCE["NO_EXEC"],
    ),
    "SQL_PARAM_BINDING": (
        "Changed SQL to parameter binding",
        "The patch sends user values as driver parameters instead of joining them into the SQL string, so input cannot change the query structure.",
        RULE_GUIDANCE["SQL_PARAM_BINDING"],
    ),
    "NO_DEBUG_MODE": (
        "Turned off debug mode by default",
        "The patch replaces hardcoded debug=True with an environment check or a production-safe default, so internal details are not exposed to users.",
        RULE_GUIDANCE["NO_DEBUG_MODE"],
    ),
    "NO_WEAK_RANDOM": (
        "Changed predictable random values to secure random values",
        "The patch uses secrets or crypto for security tokens, sessions, or OTP values, so attackers cannot predict them.",
        RULE_GUIDANCE["NO_WEAK_RANDOM"],
    ),
    "NO_BARE_EXCEPT": (
        "Made swallowed exceptions visible",
        "The patch adds specific handling or logging to empty except or catch blocks, so failures and possible attacks are visible.",
        RULE_GUIDANCE["NO_BARE_EXCEPT"],
    ),
}


def default_rules() -> list[SLARule]:
    return [rule.model_copy(deep=True) for rule in DEFAULT_RULES]


def canonical_rule_id(rule_id: str) -> str:
    return RULE_ALIASES.get(rule_id, rule_id)


def patch_explanation_for(violation: Violation, file: str | None = None) -> PatchExplanation:
    canonical = canonical_rule_id(violation.rule_id)
    if canonical not in PATCH_EXPLANATION_TEMPLATES:
        canonical = canonical_rule_id(violation.rule_name)
    title, summary, guidance = PATCH_EXPLANATION_TEMPLATES.get(
        canonical,
        (
            "Changed unsafe code to a safe implementation",
            "The patch updates only the detected vulnerable code and keeps existing behavior where possible.",
            "Replace the detected violation with a safe alternative.",
        ),
    )
    return PatchExplanation(
        file=file or violation.file,
        rule_id=canonical,
        rule_name=canonical,
        line=violation.line,
        title=title,
        summary=summary,
        guidance=guidance,
        reference=f"spec.md#{canonical}",
    )
