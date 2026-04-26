from __future__ import annotations

from slayer.models import SLARule

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
        id="NO_WEAK_RANDOM",
        name="NO_WEAK_RANDOM",
        description="토큰이나 인증값을 약한 난수로 만들면 공격자가 값을 예측해 세션을 탈취할 수 있습니다.",
        raw_nl="보안 컨텍스트에서 약한 난수 금지",
        rule_type="NO_WEAK_RANDOM",
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
    "NO_WEAK_RANDOM": '보안 토큰/세션/OTP 생성에는 secrets 또는 crypto 기반 API를 사용하세요.',
    "NO_BARE_EXCEPT": '빈 except/catch를 구체적인 예외 처리와 로깅으로 바꾸세요.',
}

DEFAULT_RULES_BY_ID = {rule.id: rule for rule in DEFAULT_RULES}


def default_rules() -> list[SLARule]:
    return [rule.model_copy(deep=True) for rule in DEFAULT_RULES]
