"""Generate AI-bench-v1: vibe-coded web service files produced by claude-haiku-4-5.

Usage:
    python tools/gen_ai_bench.py

Outputs files to dataset/ai-bench-v1/ then runs slayer scanner to record results.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

BENCH_DIR = Path("dataset/ai-bench-v1")
MODEL = "claude-haiku-4-5-20251001"

PROMPTS = [
    {
        "id": "user-auth-service-py",
        "language": "python",
        "prompt": (
            "Write a realistic Python Flask user authentication service. "
            "It should have routes for /login, /register, /reset-password, and /profile. "
            "Include database access, password handling, and session tokens. "
            "Write it the way a fast-moving startup developer would — functional but not security-hardened. "
            "Return ONLY the Python code, no explanation."
        ),
    },
    {
        "id": "data-pipeline-py",
        "language": "python",
        "prompt": (
            "Write a realistic Python data pipeline script that: "
            "reads config from a settings file, fetches data from an external API using a URL from config, "
            "processes it, and stores results in a SQLite database with user-provided filters. "
            "Include subprocess calls for data transformation tools. "
            "Write it like a data engineer who just discovered AI coding tools. "
            "Return ONLY the Python code, no explanation."
        ),
    },
    {
        "id": "rest-api-js",
        "language": "javascript",
        "prompt": (
            "Write a realistic Node.js/Express REST API for a task management app. "
            "Include endpoints for creating, reading, updating, deleting tasks. "
            "Add user authentication with tokens, database queries, and some admin utilities. "
            "Write it the way a developer using Cursor or GitHub Copilot would — gets the job done quickly. "
            "Return ONLY the JavaScript code, no explanation."
        ),
    },
    {
        "id": "webhook-handler-ts",
        "language": "typescript",
        "prompt": (
            "Write a realistic TypeScript webhook handler service. "
            "It receives webhooks from external services, validates them, "
            "stores events in a database, and forwards them to configured callback URLs. "
            "Include API key management and some debug utilities. "
            "Write it like a backend developer moving fast. "
            "Return ONLY the TypeScript code, no explanation."
        ),
    },
]


def generate_file(spec: dict) -> str:
    result = subprocess.run(
        ["claude", "-p", spec["prompt"], "--model", MODEL],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude CLI failed: {result.stderr[:200]}")
    code = result.stdout.strip()
    # strip markdown fences if present
    if code.startswith("```"):
        lines = code.splitlines()
        code = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
    return code


def run_scanner(filepath: Path) -> list[dict]:
    out = subprocess.run(
        ["slayer", "start", str(filepath), "--format", "json"],
        capture_output=True, text=True,
    )
    if not out.stdout.strip():
        return []
    return json.loads(out.stdout).get("violations", [])


def main() -> None:
    ext = {"python": "py", "javascript": "js", "typescript": "ts"}

    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    for spec in PROMPTS:
        lang = spec["language"]
        filename = f"{spec['id']}.{ext[lang]}"
        filepath = BENCH_DIR / filename

        print(f"Generating {filename} via {MODEL}...")
        code = generate_file(spec)
        filepath.write_text(code)
        print(f"  Saved ({len(code)} chars)")

        violations = run_scanner(filepath)
        detected = [{"rule": v["rule_id"], "line": v["line"]} for v in violations]
        print(f"  Detected: {len(detected)} violations")
        for d in detected:
            print(f"    line {d['line']:>3}: {d['rule']}")

        results.append({
            "file": filename,
            "language": lang,
            "source": MODEL,
            "violations_detected": detected,
        })

    # save summary
    summary_path = BENCH_DIR / "results.json"
    summary_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\nDone. Results → {summary_path}")

    total = sum(len(r["violations_detected"]) for r in results)
    print(f"Total violations detected across {len(PROMPTS)} AI-generated files: {total}")


if __name__ == "__main__":
    main()
