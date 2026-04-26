import json
import anthropic

try:
    from backend.models import SLARule, Violation
except ImportError:
    from models import SLARule, Violation

ANALYZE_SYSTEM = """Python 코드를 주어진 보안 룰에 따라 검사하세요.
위반 발견 시 JSON 배열 반환, 없으면 빈 배열 [] 반환.
출력: JSON만 (마크다운, 코드블록 없음).

각 위반 항목:
{"line": <1-indexed 줄 번호>, "col": 0, "code_snippet": "<해당 줄>", "explanation": "<보안 용어 없이 이 코드는 ~을 해서 ~이 일어날 수 있어요. 형식 한국어>"}
"""


async def analyze(code: str, rule: SLARule, filepath: str, client: anthropic.AsyncAnthropic) -> list[Violation]:
    try:
        prompt = f"룰: {rule.description}\n\n코드:\n{code}"
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=ANALYZE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        items = json.loads(raw)
        return [
            Violation(
                rule_id=rule.id, file=filepath,
                line=it["line"], col=it.get("col", 0),
                code_snippet=it.get("code_snippet", ""),
                explanation=it["explanation"],
            )
            for it in items
        ]
    except Exception:
        return []
