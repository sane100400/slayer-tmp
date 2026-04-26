# SLAyer Patch Quality Reference

This reference turns `spec.md` into an implementation checklist for the patch-quality work:
reduce false-positive-driven patches, explain every patch in friendly language, and keep the
CLI/backend/frontend results compatible with existing deploy gates.

## Source-of-truth rules

`spec.md` defines the seven SLAyer vulnerability classes. Patch code and documentation should
use these identifiers for the CLI ruleset:

| Rule | Friendly patch summary | Patch strategy from `spec.md` |
| --- | --- | --- |
| `NO_HARDCODED_SECRETS` | Replaced hardcoded secret with environment variable lookup. | Python `os.environ.get("VAR", "")`; JS/TS `process.env.VAR ?? ""`. |
| `NO_NETWORK` | Blocked or restricted external calls driven by user input. | Python `raise NotImplementedError("external call blocked")`; JS/TS `throw new Error("external call blocked")`. |
| `NO_EXEC` | Replaced string shell execution with safe argument-list execution. | Python `shell=False` + list args; JS/TS `execFile("cmd", [arg], cb)`. |
| `SQL_PARAM_BINDING` | Replaced interpolated SQL with parameterized queries. | Python `cursor.execute("... WHERE x=?", (val,))`; JS/TS `query("... WHERE x=$1", [val])`. |
| `NO_DEBUG_MODE` | Disabled debug mode in the production default. | Python env-based debug flag; JS/TS `process.env.NODE_ENV !== "production"`. |
| `NO_WEAK_RANDOM` | Replaced weak random with cryptographically secure random. | Python `secrets.token_hex(32)`; JS/TS `crypto.randomUUID()`. |
| `NO_BARE_EXCEPT` | Added logging to silently swallowed exceptions. | Python `except Exception as e: logger.warning(e)`; JS/TS `catch(e){ console.error(e) }`. |

Review note: older code paths may use backend names such as `WEAK_HASH` or rule experiments such
as weak randomness. The public patch-quality contract should still present the spec-defined seven
classes above unless a later spec revision changes the taxonomy.

## False-positive gate before patching

The patcher must only send validated or likely-true findings to the AI CLI. A safe implementation
uses these pre-patch gates:

1. **Patch only listed violations.** The AI prompt must include the exact file, line, rule, snippet,
   and guidance, and must tell the model not to edit unrelated lines.
2. **Ignore placeholders and examples.** Values containing `example`, `dummy`, `test`, `changeme`,
   `your_api_key`, `xxxxx`, `sample`, or `placeholder` should not trigger secret patches.
3. **Network calls need a dynamic or user-controlled target.** Static first-party literals should
   not be treated as SSRF-style violations; dynamic URL construction and request-derived values
   should be patched.
4. **Command execution needs command-injection risk.** `shell=True`, `os.system`, string commands,
   and JS `exec`/`execSync` are patch candidates; benign list-argument execution is not.
5. **SQL findings must be actual query construction.** Interpolated SQL inside `execute`/`query`
   calls is a patch candidate; ordinary strings mentioning SQL are not.
6. **Debug findings are hard-coded deployment defaults.** `debug=True`, `DEBUG=True`, and JS
   `debug: true` are patch candidates; environment-derived flags are not.
7. **Weak random findings are predictable randomness in security contexts.** Prefer findings tied
   to password reset tokens, sessions, OTPs, or auth flows. Avoid changing non-security randomness.
8. **Bare exception findings should swallow errors.** Empty handlers and `pass`/empty `catch` blocks
   are patch candidates; handlers that log, raise, return an explicit failure, or narrow exceptions
   should not be patched.
9. **Validate generated code before writing.** Keep Python `ast.parse`, JS `node --check`, and TS
   `tsc --noEmit` validation where available; roll back on syntax errors, AI errors, or oversized
   diffs.
10. **Rescan after patching.** Deployment is approved only when the same deterministic scanner finds
    no remaining violations.

## Friendly patch explanation contract

Patch explanations should be additive and backward-compatible. Existing fields such as
`patched_files`, `diffs`/`diff`, `remaining_violations`, `deployable`, and `ai_used` remain stable.
Add a collection named `patch_explanations` for CLI JSON and backend/frontend responses.

Recommended item shape:

```json
{
  "file": "/abs/path/app.py",
  "rule_id": "SQL_PARAM_BINDING",
  "rule_name": "SQL_PARAM_BINDING",
  "line": 13,
  "title": "Switched SQL to parameterized queries",
  "summary": "Passed user values as bound parameters to the DB driver instead of interpolating them into the SQL string, keeping the query structure fixed.",
  "guidance": "Replace string-interpolated SQL with parameterized queries (placeholders + bound values).",
  "reference": "spec.md#SQL_PARAM_BINDING"
}
```

Rendering guidance:

- **CLI text:** show explanations under each patched file, grouped by rule, after the `Patched:` line.
- **CLI JSON:** include `patch_explanations` while preserving existing top-level fields.
- **Backend API:** return the same field from `/api/patch` so the UI does not need to infer intent
  from raw diff lines.
- **Frontend:** display explanation cards beside the diff: rule badge, human summary, and why it
  matters. Keep the raw unified diff visible for review.

## Useful extra patching features

These are intentionally documentation/reference items rather than required dependencies:

- **Dry-run mode:** `slayer patch --dry-run` could produce diffs and explanations without writing
  files, useful for CI comments and local review.
- **Rule allowlist/suppressions:** a line-level `# slayer: ignore RULE_ID reason` mechanism would
  make intentional exceptions auditable while preventing broad directory excludes.
- **Patch provenance:** record AI CLI name, rule id, and validation result per file so teams can
  debug failed patch attempts without storing secret-bearing prompts.
- **Benchmark command:** keep `dataset/slayer-bench-v0/{vulnerable,fixed,false_positive}` as the
  regression fixture for AC-08: vulnerable files block, fixed and false-positive files approve.
  Copy vulnerable examples to a temporary directory before running patch demos.
- **Reference links in UI:** link each rule card to the relevant `spec.md` section and this file so
  non-security users can understand why a patch was made.

## Verification checklist for patch-quality changes

Before marking the patch-quality work complete:

1. `python -m pytest` passes.
2. `npm run build` passes for the frontend/typecheck path.
3. Modified documentation has no trailing whitespace and does not include local cache artifacts.
4. A focused test confirms `patch_explanations` is present in JSON/API output once the schema lands.
5. A focused false-positive fixture confirms benign examples are not patched before AI invocation.
