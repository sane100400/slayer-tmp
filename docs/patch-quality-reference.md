# SLAyer Patch Quality Reference

This reference turns `spec.md` into an implementation checklist for the patch-quality work:
reduce false-positive-driven patches, explain every patch in friendly language, and keep the
CLI/backend/frontend results compatible with existing deploy gates.

## Source-of-truth rules

`spec.md` defines the seven SLAyer vulnerability classes. Patch code and documentation should
use these identifiers for the CLI ruleset:

| Rule | Friendly patch summary | Patch strategy from `spec.md` |
| --- | --- | --- |
| `NO_HARDCODED_SECRETS` | 하드코딩된 비밀값을 환경 변수 조회로 바꿨어요. | Python `os.environ.get("VAR", "")`; JS/TS `process.env.VAR ?? ""`. |
| `NO_NETWORK` | 사용자 입력으로 가는 외부 호출을 차단하거나 허용된 주소로 제한했어요. | Python `raise NotImplementedError("외부 호출 차단")`; JS/TS `throw new Error("외부 호출 차단")`. |
| `NO_EXEC` | 쉘 문자열 실행을 안전한 인수 리스트 실행으로 바꿨어요. | Python `shell=False` + list args; JS/TS `execFile("cmd", [arg], cb)`. |
| `SQL_PARAM_BINDING` | 문자열로 만든 SQL을 파라미터 바인딩으로 바꿨어요. | Python `cursor.execute("... WHERE x=?", (val,))`; JS/TS `query("... WHERE x=$1", [val])`. |
| `NO_DEBUG_MODE` | 배포 기본값에서 debug 모드가 꺼지도록 바꿨어요. | Python env-based debug flag; JS/TS `process.env.NODE_ENV !== "production"`. |
| `NO_INSECURE_HASH` | MD5/SHA1 해싱을 SHA-256 이상 또는 비밀번호 전용 해싱으로 바꿨어요. | Python `hashlib.pbkdf2_hmac("sha256", ...)`; JS/TS `crypto.createHash("sha256")`. |
| `NO_BARE_EXCEPT` | 예외를 조용히 삼키지 않고 기록하도록 바꿨어요. | Python `except Exception as e: logger.warning(e)`; JS/TS `catch(e){ console.error(e) }`. |

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
7. **Weak hash findings are MD5/SHA1 security use.** Prefer findings tied to password, token,
   credential, or authentication context to avoid changing non-security checksums.
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
  "file": "/abs/path/demo_vuln.py",
  "rule_id": "SQL_PARAM_BINDING",
  "rule_name": "SQL_PARAM_BINDING",
  "line": 13,
  "summary": "문자열로 만든 SQL을 파라미터 바인딩으로 바꿨어요.",
  "why": "사용자 입력이 SQL 명령으로 해석되지 않게 막습니다.",
  "before": "cursor.execute(f\"SELECT * FROM users WHERE name='{query}'\")",
  "after": "cursor.execute(\"SELECT * FROM users WHERE name=?\", (query,))"
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
- **Reference links in UI:** link each rule card to the relevant `spec.md` section and this file so
  non-security users can understand why a patch was made.

## Verification checklist for patch-quality changes

Before marking the patch-quality work complete:

1. `python -m pytest` passes.
2. `npm run build` passes for the frontend/typecheck path.
3. Modified documentation has no trailing whitespace and does not include `.cache` artifacts.
4. A focused test confirms `patch_explanations` is present in JSON/API output once the schema lands.
5. A focused false-positive fixture confirms benign examples are not patched before AI invocation.
