import difflib
import anthropic
from models import SLARule, Violation, PatchResult
from fastapi import HTTPException

PATCH_SYSTEM = """Python 코드의 보안 위반을 최소한으로 수정하세요.
기존 로직은 유지하고, 위반 구문만 안전한 대안으로 교체합니다.
수정된 전체 코드만 반환하세요 (설명, 마크다운 없이).

수정 지침:
- NO_NETWORK: 네트워크 호출 → raise NotImplementedError("외부 호출이 SLA에 의해 차단됨")
- NO_EXEC: subprocess/os.system → raise NotImplementedError("시스템 명령 실행이 SLA에 의해 차단됨")
- NO_HARDCODED_SECRETS: 하드코딩 값 → os.environ.get("VAR_NAME", "")
- SQL_PARAM_BINDING: f-string/% 포맷 SQL → 파라미터 바인딩 (?, %s)
- NO_EVAL: eval/exec → ast.literal_eval 또는 raise NotImplementedError
"""


def _unified_diff(original: str, patched: str) -> str:
    lines = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile="original",
        tofile="patched",
        lineterm="",
    )
    return "".join(lines)


async def patch(
    code: str,
    violations: list[Violation],
    rules: list[SLARule],
    client: anthropic.AsyncAnthropic,
) -> PatchResult:
    summary = "\n".join(f"- 라인 {v.line}: {v.explanation}" for v in violations)
    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8192,
            system=PATCH_SYSTEM,
            messages=[{"role": "user", "content": f"위반 목록:\n{summary}\n\n원본 코드:\n{code}"}],
        )
    except anthropic.APIError as e:
        raise HTTPException(status_code=502, detail=f"Claude API 오류: {e}")
    patched = response.content[0].text.strip()
    return PatchResult(
        original_code=code,
        patched_code=patched,
        diff=_unified_diff(code, patched),
        remaining_violations=[],
        deployable=True,
    )
