from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from slayer.models import PatchExplanation

_ALIASES: dict[str, str] = {
    "SQL_INJECTION": "SQL_PARAM_BINDING",
    "HARDCODED_SECRETS": "NO_HARDCODED_SECRETS",
    "COMMAND_INJECTION": "NO_EXEC",
    "DEBUG_MODE_ON": "NO_DEBUG_MODE",
    "WEAK_HASH": "NO_INSECURE_HASH",
}

_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "NO_HARDCODED_SECRETS": (
        "비밀값을 코드 밖으로 옮겼어요",
        "하드코딩된 키·비밀번호를 환경 변수 조회로 바꿔 저장소 노출 시 바로 악용되지 않게 합니다.",
        "spec.md §0.6 V-01 / patch strategy: environment variables",
    ),
    "NO_NETWORK": (
        "사용자 입력 URL 호출을 막았어요",
        "검증되지 않은 주소로 나가는 요청은 SSRF나 민감정보 유출로 이어질 수 있어 차단 또는 허용 목록 방식으로 바꿉니다.",
        "spec.md §0.6 V-02 / patch strategy: block external calls",
    ),
    "NO_EXEC": (
        "쉘 문자열 실행을 안전하게 바꿨어요",
        "사용자 값이 섞인 명령 문자열 대신 인수 리스트 실행이나 차단 동작을 사용해 명령 주입 가능성을 줄입니다.",
        "spec.md §0.6 V-03 / patch strategy: shell=False + argv",
    ),
    "SQL_PARAM_BINDING": (
        "SQL 문자열 보간을 파라미터 바인딩으로 바꿨어요",
        "사용자 입력이 쿼리 문법으로 해석되지 않도록 플레이스홀더와 별도 파라미터 배열/튜플로 전달합니다.",
        "spec.md §0.6 V-04 / patch strategy: parameter binding",
    ),
    "NO_DEBUG_MODE": (
        "배포 기본값에서 디버그 모드를 껐어요",
        "디버그 화면이 내부 경로·환경변수·스택트레이스를 노출하지 않도록 환경 변수 기반 설정으로 바꿉니다.",
        "spec.md §0.6 V-05 / patch strategy: environment-controlled debug",
    ),
    "NO_INSECURE_HASH": (
        "MD5/SHA1 해싱을 더 안전한 방식으로 바꿨어요",
        "비밀번호나 토큰이 유출됐을 때 빠르게 역추측되지 않도록 spec.md의 안전한 해시 대안으로 교체합니다.",
        "spec.md §0.6 V-06 / patch strategy: pbkdf2_hmac or SHA-256",
    ),
    "NO_BARE_EXCEPT": (
        "빈 예외 삼키기를 기록 가능한 처리로 바꿨어요",
        "공격 징후나 장애 원인이 조용히 사라지지 않도록 구체적인 예외 처리와 로깅을 남깁니다.",
        "spec.md §0.6 V-07 / patch strategy: log handled exceptions",
    ),
    "CUSTOM": (
        "사용자 정의 보안 조건을 반영했어요",
        "지정된 보안 설명에 맞춰 관련 코드만 최소 수정합니다.",
        "spec.md §7 / patch principle: listed violations only",
    ),
}


def _field(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _canonical_rule_id(violation: Any, rules_by_id: Mapping[str, Any] | None) -> str:
    rule_id = str(_field(violation, "rule_id", "CUSTOM"))
    rule = rules_by_id.get(rule_id) if rules_by_id else None
    rule_type = str(_field(rule, "rule_type", rule_id)) if rule is not None else rule_id
    return _ALIASES.get(rule_type, _ALIASES.get(rule_id, rule_type))


def build_patch_explanations(
    violations: Iterable[Any],
    rules_by_id: Mapping[str, Any] | None = None,
) -> list[PatchExplanation]:
    explanations: list[PatchExplanation] = []
    seen: set[tuple[str, str, int, str]] = set()
    for violation in violations:
        rule_id = _canonical_rule_id(violation, rules_by_id)
        template = _TEMPLATES.get(rule_id, _TEMPLATES["CUSTOM"])
        original_rule_id = str(_field(violation, "rule_id", rule_id))
        rule = rules_by_id.get(original_rule_id) if rules_by_id else None
        rule_name = str(_field(violation, "rule_name", "") or _field(rule, "name", "") or rule_id)
        file = str(_field(violation, "file", ""))
        line = int(_field(violation, "line", 0) or 0)
        key = (file, original_rule_id, line, template[0])
        if key in seen:
            continue
        seen.add(key)
        explanations.append(
            PatchExplanation(
                file=file,
                rule_id=original_rule_id,
                rule_name=rule_name,
                line=line,
                title=template[0],
                summary=template[1],
                reference=template[2],
            )
        )
    return explanations
