import os
from pathlib import Path
import anthropic
from fastapi import APIRouter, Header

try:
    from backend.models import ScanRequest, ScanResult, Violation
    from backend.analyzers import ast_analyzer, llm_analyzer
except ImportError:
    from models import ScanRequest, ScanResult, Violation
    from analyzers import ast_analyzer, llm_analyzer

router = APIRouter()


def get_client(api_key: str) -> anthropic.AsyncAnthropic | None:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    return anthropic.AsyncAnthropic(api_key=key) if key else None


@router.post("/scan")
async def scan(
    body: ScanRequest,
    x_api_key: str = Header(default="", alias="X-API-Key"),
):
    client = get_client(x_api_key)
    all_violations: list[Violation] = []

    for filepath in body.files:
        try:
            code = Path(filepath).read_text(encoding="utf-8")
        except Exception as e:
            all_violations.append(Violation(
                rule_id="__file_error__", file=filepath,
                line=0, col=0, code_snippet="",
                explanation=f"파일을 읽을 수 없어요: {e}",
            ))
            continue

        for rule in body.rules:
            vs = ast_analyzer.analyze(code, rule, filepath)
            if vs:
                all_violations.extend(vs)
            elif rule.rule_type == "CUSTOM" and client:
                vs2 = await llm_analyzer.analyze(code, rule, filepath, client)
                all_violations.extend(vs2)

    has_file_errors = any(v.rule_id == "__file_error__" for v in all_violations)
    fail_ids = {v.rule_id for v in all_violations if v.rule_id != "__file_error__"}
    pass_count = sum(1 for r in body.rules if r.id not in fail_ids)
    fail_count = len(body.rules) - pass_count

    return ScanResult(
        rules=body.rules,
        violations=all_violations,
        pass_count=pass_count,
        fail_count=fail_count,
        deployable=(fail_count == 0 and not has_file_errors),
    )
