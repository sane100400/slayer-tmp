from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RuleType = Literal[
    "NO_NETWORK",
    "NO_EXEC",
    "NO_HARDCODED_SECRETS",
    "SQL_PARAM_BINDING",
    "NO_DEBUG_MODE",
    "NO_WEAK_RANDOM",
    "NO_BARE_EXCEPT",
    "CUSTOM",
]
Severity = Literal["critical", "high", "medium"]
AIChoice = Literal["auto", "claude", "codex", "gemini"]
OutputFormat = Literal["text", "json"]


class SLARule(BaseModel):
    id: str
    name: str
    description: str
    raw_nl: str
    rule_type: RuleType
    severity: Severity


class Violation(BaseModel):
    rule_id: str
    rule_name: str
    file: str
    line: int
    col: int = 0
    code_snippet: str
    explanation: str


class SyntaxIssue(BaseModel):
    file: str
    message: str
    line: int = 0
    col: int = 0


class ScanResult(BaseModel):
    rules: list[SLARule]
    violations: list[Violation] = Field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    deployable: bool = True
    scanned_files: list[str] = Field(default_factory=list)
    syntax_errors: list[SyntaxIssue] = Field(default_factory=list)


class PatchExplanation(BaseModel):
    file: str
    rule_id: str
    rule_name: str
    line: int
    title: str
    summary: str
    guidance: str
    reference: str = "spec.md"


class PatchResult(BaseModel):
    patched_files: list[str] = Field(default_factory=list)
    diffs: dict[str, str] = Field(default_factory=dict)
    patch_explanations: list[PatchExplanation] = Field(default_factory=list)
    remaining_violations: list[Violation] = Field(default_factory=list)
    deployable: bool = True
    ai_used: str = "none"
    scanned_files: list[str] = Field(default_factory=list)
    syntax_errors: list[SyntaxIssue] = Field(default_factory=list)
