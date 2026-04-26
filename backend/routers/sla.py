import json
import os
import anthropic
from fastapi import APIRouter, Header, HTTPException
from models import ParseRequest, SLARule

router = APIRouter()

PARSE_SYSTEM = """보안을 전혀 모르는 개발자도 이해할 수 있게 설명하는 보안 전문가.
자연어 보안 조건을 JSON으로 변환한다.
출력: JSON 배열만 (마크다운, 코드블록 없음).

각 항목:
{"id":"rule_N","name":"짧은 이름","description":"보안 용어 없이 '누가 ~을 할 수 있어요' 또는 '~이 노출돼요' 형식 한국어 한 문장","raw_nl":"원본 입력","rule_type":"(아래 매핑 참고)","severity":"critical|high|medium"}

rule_type 매핑:
- SQL / 쿼리 / 인젝션 → SQL_INJECTION (critical)
- 비밀번호·API 키·시크릿·토큰 하드코딩 → HARDCODED_SECRETS (critical)
- 디버그·debug=True → DEBUG_MODE_ON (high)
- 쿠키·cookie·세션 보안 → INSECURE_COOKIE (high)
- MD5·SHA1·약한 해싱 → WEAK_HASH (high)
- 명령어·subprocess·exec → COMMAND_INJECTION (critical)
- 리다이렉트·redirect·open redirect → OPEN_REDIRECT (medium)
- 그 외 → CUSTOM (medium)"""


def get_client(api_key: str) -> anthropic.AsyncAnthropic:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise HTTPException(status_code=401, detail="ANTHROPIC_API_KEY 없음. 앱 설정에서 입력해주세요.")
    return anthropic.AsyncAnthropic(api_key=key)


@router.post("/sla/parse")
async def parse_sla(
    body: ParseRequest,
    x_api_key: str = Header(default="", alias="X-API-Key"),
):
    client = get_client(x_api_key)
    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=PARSE_SYSTEM,
            messages=[{"role": "user", "content": body.nl_rules}],
        )
    except anthropic.APIError as e:
        raise HTTPException(status_code=502, detail=f"Claude API 오류: {e}")
    raw = response.content[0].text.strip()
    try:
        items = json.loads(raw)
        rules = [SLARule(**item) for item in items]
    except (json.JSONDecodeError, Exception) as e:
        raise HTTPException(status_code=400, detail=f"룰 파싱 실패: {e}\n응답: {raw[:200]}")
    return {"rules": [r.model_dump() for r in rules]}
