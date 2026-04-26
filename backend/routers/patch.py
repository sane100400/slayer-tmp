from pathlib import Path
from fastapi import APIRouter, Header, HTTPException

try:
    from backend.models import PatchRequest, PatchResult, ScanRequest
    from backend.patcher import llm_patcher
except ImportError:
    from models import PatchRequest, PatchResult, ScanRequest
    from patcher import llm_patcher

router = APIRouter()


@router.post("/patch")
async def patch_files(
    body: PatchRequest,
    x_api_key: str = Header(default="", alias="X-API-Key"),
):
    results = []

    for filepath in body.files:
        path = Path(filepath)
        try:
            code = path.read_text(encoding="utf-8")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"파일을 읽을 수 없어요: {filepath} — {e}")
        file_violations = [v for v in body.violations if v.file == filepath]
        if not file_violations:
            continue
        result = await llm_patcher.patch(code, file_violations, body.rules, body.ai_cli, path)
        path.write_text(result.patched_code, encoding="utf-8")
        results.append(result)

    if not results:
        raise HTTPException(status_code=400, detail="패치할 위반이 없습니다.")

    # rescan after patch
    try:
        from routers.scan import scan as do_scan
    except ModuleNotFoundError:
        from backend.routers.scan import scan as do_scan

    rescan = await do_scan(ScanRequest(files=body.files, rules=body.rules), x_api_key=x_api_key)

    combined_diff = "\n".join(r.diff for r in results if r.diff)
    return PatchResult(
        original_code=results[0].original_code,
        patched_code=results[0].patched_code,
        diff=combined_diff,
        remaining_violations=rescan.violations,
        deployable=rescan.deployable,
        ai_used=results[0].ai_used,
    )
