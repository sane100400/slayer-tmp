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


RULE_DETAILS: dict[str, dict[str, str]] = {
    "NO_HARDCODED_SECRETS": {
        "why": (
            "API 키·비밀번호가 코드에 있으면 git push 한 순간 전 세계에 노출됩니다.\n"
            "  GitGuardian 통계: 노출 후 평균 3분 내 봇이 수집합니다."
        ),
        "fix": "os.environ.get('API_KEY', '') 또는 python-dotenv / process.env.API_KEY 로 교체하세요.",
    },
    "NO_EXEC": {
        "why": (
            "shell=True 는 명령어 문자열을 sh -c 로 해석합니다.\n"
            "  세미콜론 하나로 서버 전체 명령 실행이 가능합니다. (CVSS 9.8 / RCE)"
        ),
        "fix": "subprocess.run(['cmd', arg], shell=False) — 인수 리스트로 교체하세요.",
    },
    "SQL_PARAM_BINDING": {
        "why": (
            "f\"SELECT ... '{name}'\" 에서 name='; DROP TABLE users;--' 을 입력하면\n"
            "  DB 전체가 삭제됩니다. (OWASP A03 SQL Injection)"
        ),
        "fix": "cursor.execute('SELECT ... WHERE name=?', (name,)) — 파라미터 바인딩으로 교체하세요.",
    },
    "NO_NETWORK": {
        "why": (
            "사용자 입력 URL을 그대로 요청하면 내부망(169.254.169.254 등) 조회로\n"
            "  AWS 자격증명이 탈취됩니다. (SSRF / CWE-918)"
        ),
        "fix": "허용 도메인 목록을 검증하거나 고정 엔드포인트를 사용하세요.",
    },
    "NO_DEBUG_MODE": {
        "why": (
            "debug=True 로 배포하면 Flask/Django 인터랙티브 디버거가 활성화되어\n"
            "  임의 Python 코드를 원격 실행할 수 있습니다. (CWE-16)"
        ),
        "fix": "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true' 로 교체하세요.",
    },
    "NO_WEAK_RANDOM": {
        "why": (
            "random.random()은 메르센 트위스터 기반으로, 출력 값에서 내부 상태를\n"
            "  역산해 OTP·토큰을 예측할 수 있습니다. (CWE-330)"
        ),
        "fix": "secrets.token_hex(32) 또는 secrets.token_urlsafe() / crypto.randomUUID() 로 교체하세요.",
    },
    "NO_BARE_EXCEPT": {
        "why": (
            "예외를 비워 삼키면 공격 침입·비정상 데이터가 로그 없이 통과됩니다.\n"
            "  IBM 보고서: 침해 평균 감지 시간 207일."
        ),
        "fix": "except Exception as e: logger.warning('...', exc_info=True) 로 교체하세요.",
    },
}


def default_rules() -> list[SLARule]:
    return [rule.model_copy(deep=True) for rule in DEFAULT_RULES]
