from pydantic import BaseModel, Field
from typing import Literal, List

RuleType = Literal[
    "NO_NETWORK",
    "NO_EXEC",
    "NO_HARDCODED_SECRETS",
    "SQL_PARAM_BINDING",
    "NO_DEBUG_MODE",
    "NO_INSECURE_HASH",
    "NO_BARE_EXCEPT",
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


class PatchExplanation(BaseModel):
    file: str
    rule_id: str
    rule_name: str
    line: int
    title: str
    summary: str
    reference: str


class PatchResult(BaseModel):
    original_code: str
    patched_code: str
    diff: str
    patch_explanations: List[PatchExplanation] = Field(default_factory=list)
    remaining_violations: List[Violation]
    deployable: bool
    ai_used: str = "none"
    patch_explanations: List[PatchExplanation] = Field(default_factory=list)


class ParseRequest(BaseModel):
    nl_rules: str
