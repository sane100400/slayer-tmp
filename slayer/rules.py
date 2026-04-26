from __future__ import annotations

from slayer.models import PatchExplanation, SLARule, Violation

DEFAULT_RULES: tuple[SLARule, ...] = (
    SLARule(
        id="NO_HARDCODED_SECRETS",
        name="NO_HARDCODED_SECRETS",
        description="비밀번호나 API 키를 코드에 직접 넣으면 저장소가 노출될 때 인증 정보가 바로 악용됩니다.",
        raw_nl="하드코딩된 비밀정보 금지",
        rule_type="NO_HARDCODED_SECRETS",
        severity="critical",
    ),
    SLARule(
        id="NO_NETWORK",
        name="NO_NETWORK",
        description="검증되지 않은 주소로 외부 요청을 보내면 내부망 조회나 민감정보 전달이 일어날 수 있습니다.",
        raw_nl="검증되지 않은 외부 네트워크 호출 금지",
        rule_type="NO_NETWORK",
        severity="critical",
    ),
    SLARule(
        id="NO_EXEC",
        name="NO_EXEC",
        description="쉘 명령을 문자열로 실행하면 입력 한 줄로 서버 명령이 실행될 수 있습니다.",
        raw_nl="쉘 실행 금지",
        rule_type="NO_EXEC",
        severity="critical",
    ),
    SLARule(
        id="SQL_PARAM_BINDING",
        name="SQL_PARAM_BINDING",
        description="사용자 값을 SQL 문자열에 직접 끼워 넣으면 데이터 조회나 수정이 공격자 입력대로 바뀔 수 있습니다.",
        raw_nl="SQL 파라미터 바인딩 강제",
        rule_type="SQL_PARAM_BINDING",
        severity="high",
    ),
    SLARule(
        id="NO_DEBUG_MODE",
        name="NO_DEBUG_MODE",
        description="디버그 모드를 켜고 배포하면 서버 내부 정보와 환경설정이 그대로 노출될 수 있습니다.",
        raw_nl="디버그 모드 배포 금지",
        rule_type="NO_DEBUG_MODE",
        severity="high",
    ),
    SLARule(
        id="NO_INSECURE_HASH",
        name="NO_INSECURE_HASH",
        description="비밀번호나 토큰을 MD5/SHA1로 해싱하면 유출 시 매우 빠르게 원문이 추측될 수 있습니다.",
        raw_nl="MD5/SHA1 기반 비밀번호·토큰 해싱 금지",
        rule_type="NO_INSECURE_HASH",
        severity="high",
    ),
    SLARule(
        id="NO_BARE_EXCEPT",
        name="NO_BARE_EXCEPT",
        description="예외를 비워 두고 삼키면 공격 징후와 장애 원인이 숨겨져 위험한 동작이 계속될 수 있습니다.",
        raw_nl="빈 예외 처리 금지",
        rule_type="NO_BARE_EXCEPT",
        severity="medium",
    ),
)

RULE_GUIDANCE: dict[str, str] = {
    "NO_HARDCODED_SECRETS": '환경 변수 조회로 바꾸고 실제 비밀값은 복원하지 마세요.',
    "NO_NETWORK": '사용자 입력 URL을 직접 호출하지 말고 차단하거나 허용 목록/고정 엔드포인트로 바꾸세요.',
    "NO_EXEC": '쉘 문자열 실행을 제거하고 안전한 인수 리스트 또는 차단 동작으로 바꾸세요.',
    "SQL_PARAM_BINDING": '문자열 보간 SQL을 파라미터 바인딩으로 바꾸세요.',
    "NO_DEBUG_MODE": '하드코딩된 debug/DEBUG true를 환경 변수 기반 설정으로 바꾸세요.',
    "NO_INSECURE_HASH": '비밀번호/토큰 해싱에 MD5/SHA1을 쓰지 말고 pbkdf2_hmac 또는 SHA-256 이상으로 바꾸세요.',
    "NO_BARE_EXCEPT": '빈 except/catch를 구체적인 예외 처리와 로깅으로 바꾸세요.',
}

RULE_ALIASES: dict[str, str] = {
    "HARDCODED_SECRETS": "NO_HARDCODED_SECRETS",
    "COMMAND_INJECTION": "NO_EXEC",
    "SQL_INJECTION": "SQL_PARAM_BINDING",
    "DEBUG_MODE_ON": "NO_DEBUG_MODE",
    "WEAK_HASH": "NO_INSECURE_HASH",
    "NO_WEAK_RANDOM": "NO_INSECURE_HASH",
}

PATCH_EXPLANATION_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "NO_HARDCODED_SECRETS": (
        "비밀값을 코드 밖으로 옮겼어요",
        "하드코딩된 키나 비밀번호 대신 환경 변수 조회를 사용하도록 바꿔 저장소 노출 시에도 실제 비밀값이 남지 않게 했어요.",
        RULE_GUIDANCE["NO_HARDCODED_SECRETS"],
    ),
    "NO_NETWORK": (
        "검증되지 않은 외부 호출을 막았어요",
        "사용자 입력이 네트워크 목적지로 직접 흘러가지 않도록 차단하거나 고정된 안전 경로만 쓰도록 패치했어요.",
        RULE_GUIDANCE["NO_NETWORK"],
    ),
    "NO_EXEC": (
        "쉘 명령 주입 경로를 제거했어요",
        "문자열 쉘 실행을 인수 리스트 기반 실행이나 차단 동작으로 바꿔 입력값이 서버 명령으로 해석되지 않게 했어요.",
        RULE_GUIDANCE["NO_EXEC"],
    ),
    "SQL_PARAM_BINDING": (
        "SQL을 파라미터 바인딩으로 바꿨어요",
        "사용자 값을 SQL 문자열에 직접 붙이지 않고 DB 드라이버의 바인딩 인자로 전달해 쿼리 구조가 바뀌지 않게 했어요.",
        RULE_GUIDANCE["SQL_PARAM_BINDING"],
    ),
    "NO_DEBUG_MODE": (
        "배포 기본값에서 디버그 모드를 껐어요",
        "하드코딩된 debug=true를 환경 변수나 production-safe 조건으로 바꿔 내부 정보가 사용자에게 노출되지 않게 했어요.",
        RULE_GUIDANCE["NO_DEBUG_MODE"],
    ),
    "NO_INSECURE_HASH": (
        "취약한 MD5/SHA1 해시를 교체했어요",
        "비밀번호·토큰 같은 보안값에 빠르게 깨지는 MD5/SHA1을 쓰지 않도록 더 강한 해시/키 유도 방식으로 바꿨어요.",
        RULE_GUIDANCE["NO_INSECURE_HASH"],
    ),
    "NO_BARE_EXCEPT": (
        "삼켜지던 예외를 드러나게 했어요",
        "빈 except/catch 블록에 구체적인 예외 처리나 로깅을 추가해 장애와 공격 징후가 숨지 않게 했어요.",
        RULE_GUIDANCE["NO_BARE_EXCEPT"],
    ),
}

DEFAULT_RULES_BY_ID = {rule.id: rule for rule in DEFAULT_RULES}


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
            "보안 위반을 안전한 구현으로 바꿨어요",
            "탐지된 취약 코드만 최소 범위로 수정해 기존 동작을 최대한 유지했어요.",
            "탐지된 위반을 안전한 대안으로 바꾸세요.",
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
