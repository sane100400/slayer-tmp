from pydantic import BaseModel
from typing import Literal, List

RuleType = Literal[
    "SQL_INJECTION",        # f-string / % 포맷 SQL
    "HARDCODED_SECRETS",    # 비밀번호·키 하드코딩
    "DEBUG_MODE_ON",        # debug=True / DEBUG=True
    "INSECURE_COOKIE",      # httponly·secure 없는 쿠키
    "WEAK_HASH",            # MD5·SHA1 패스워드 해싱
    "COMMAND_INJECTION",    # subprocess·os.system
    "OPEN_REDIRECT",        # redirect(user_input)
    "CUSTOM",               # LLM 자유 판단
]
Severity = Literal["critical", "high", "medium"]
AIChoice = Literal["auto", "claude", "codex", "gemini"]


class SLARule(BaseModel):
    id: str
    name: str
    description: str
    raw_nl: str
    rule_type: RuleType
    severity: Severity


class Violation(BaseModel):
    rule_id: str
    file: str
    line: int
    col: int
    code_snippet: str
    explanation: str


class ScanRequest(BaseModel):
    files: List[str]
    rules: List[SLARule]


class ScanResult(BaseModel):
    rules: List[SLARule]
    violations: List[Violation]
    pass_count: int
    fail_count: int
    deployable: bool


class PatchRequest(BaseModel):
    files: List[str]
    violations: List[Violation]
    rules: List[SLARule]
    ai_cli: AIChoice = "auto"


class PatchResult(BaseModel):
    original_code: str
    patched_code: str
    diff: str
    remaining_violations: List[Violation]
    deployable: bool
    ai_used: str = "none"


class ParseRequest(BaseModel):
    nl_rules: str
