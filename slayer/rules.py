from __future__ import annotations

from slayer.models import PatchExplanation, SLARule, Violation

DEFAULT_RULES: tuple[SLARule, ...] = (
    SLARule(
        id="NO_HARDCODED_SECRETS",
        name="NO_HARDCODED_SECRETS",
        description="Hardcoding passwords or API keys exposes credentials immediately when the repository is accessed.",
        raw_nl="No hardcoded secrets",
        rule_type="NO_HARDCODED_SECRETS",
        severity="critical",
    ),
    SLARule(
        id="NO_NETWORK",
        name="NO_NETWORK",
        description="Sending requests to unvalidated addresses can allow internal network scanning or leaking sensitive data.",
        raw_nl="No unvalidated external network calls",
        rule_type="NO_NETWORK",
        severity="critical",
    ),
    SLARule(
        id="NO_EXEC",
        name="NO_EXEC",
        description="Running shell commands as strings allows a single input to execute arbitrary server commands.",
        raw_nl="No shell execution",
        rule_type="NO_EXEC",
        severity="critical",
    ),
    SLARule(
        id="SQL_PARAM_BINDING",
        name="SQL_PARAM_BINDING",
        description="Embedding user values directly in SQL strings allows attackers to alter query structure with their input.",
        raw_nl="SQL parameter binding required",
        rule_type="SQL_PARAM_BINDING",
        severity="high",
    ),
    SLARule(
        id="NO_DEBUG_MODE",
        name="NO_DEBUG_MODE",
        description="Deploying with debug mode enabled exposes internal server state and configuration.",
        raw_nl="No debug mode in production",
        rule_type="NO_DEBUG_MODE",
        severity="high",
    ),
    SLARule(
        id="NO_WEAK_RANDOM",
        name="NO_WEAK_RANDOM",
        description="Generating tokens or credentials with weak random allows attackers to predict values and hijack sessions.",
        raw_nl="No weak random in security context",
        rule_type="NO_WEAK_RANDOM",
        severity="high",
    ),
    SLARule(
        id="NO_BARE_EXCEPT",
        name="NO_BARE_EXCEPT",
        description="Swallowing exceptions silently hides attack indicators and failure causes, allowing dangerous behavior to continue.",
        raw_nl="No bare except blocks",
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
        "Moved secret values out of the code",
        "Replaced hardcoded keys or passwords with environment variable lookups so no actual secret remains in the code even if the repository is exposed.",
        RULE_GUIDANCE["NO_HARDCODED_SECRETS"],
    ),
    "NO_NETWORK": (
        "Blocked unvalidated external network calls",
        "Prevented user input from flowing directly to network destinations by blocking or restricting to a fixed safe endpoint.",
        RULE_GUIDANCE["NO_NETWORK"],
    ),
    "NO_EXEC": (
        "Removed shell command injection path",
        "Replaced string-based shell execution with list-argument execution or a block so user input cannot be interpreted as server commands.",
        RULE_GUIDANCE["NO_EXEC"],
    ),
    "SQL_PARAM_BINDING": (
        "Switched SQL to parameterized queries",
        "Passed user values as bound parameters to the DB driver instead of interpolating them into the SQL string, keeping the query structure fixed.",
        RULE_GUIDANCE["SQL_PARAM_BINDING"],
    ),
    "NO_DEBUG_MODE": (
        "Disabled debug mode in the production default",
        "Replaced the hardcoded debug=True with an environment variable or production-safe condition so internal details are not exposed to users.",
        RULE_GUIDANCE["NO_DEBUG_MODE"],
    ),
    "NO_WEAK_RANDOM": (
        "Replaced predictable random with cryptographically secure random",
        "Replaced weak random used for security tokens, sessions, or OTPs with the secrets or crypto module so values cannot be predicted.",
        RULE_GUIDANCE["NO_WEAK_RANDOM"],
    ),
    "NO_BARE_EXCEPT": (
        "Made silently swallowed exceptions visible",
        "Added specific error handling or logging to empty except/catch blocks so failures and attack signals are no longer hidden.",
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
            "Replaced security violation with a safe implementation",
            "Fixed only the detected vulnerable code with the smallest change needed, preserving existing behavior as much as possible.",
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
