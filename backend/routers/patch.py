import os
from pathlib import Path
import anthropic
from fastapi import APIRouter, Header, HTTPException
from models import PatchRequest, PatchResult, ScanRequest, Violation
from patcher import llm_patcher

router = APIRouter()


def get_client(api_key: str) -> anthropic.Anthropic:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise HTTPException(status_code=401, detail="ANTHROPIC_API_KEY 없음. 앱 설정에서 입력해주세요.")
    return anthropic.Anthropic(api_key=key)


@router.post("/patch")
async def patch_files(
    body: PatchRequest,
    x_api_key: str = Header(default="", alias="X-API-Key"),
):
    client = get_client(x_api_key)
    results = []

    for filepath in body.files:
        code = Path(filepath).read_text(encoding="utf-8")
        file_violations = [v for v in body.violations if v.file == filepath]
        if not file_violations:
            continue
        result = await llm_patcher.patch(code, file_violations, body.rules, client)
        Path(filepath).write_text(result.patched_code, encoding="utf-8")
        results.append(result)

    if not results:
        raise HTTPException(status_code=400, detail="패치할 위반이 없습니다.")

    # rescan after patch
    from routers.scan import scan as do_scan
    rescan = await do_scan(ScanRequest(files=body.files, rules=body.rules), x_api_key=x_api_key)

    return PatchResult(
        original_code=results[0].original_code,
        patched_code=results[0].patched_code,
        diff=results[0].diff,
        remaining_violations=rescan.violations,
        deployable=rescan.deployable,
    )
