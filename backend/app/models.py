from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low"]
Language = Literal["solidity", "vyper", "rust", "move"]
PipelineName = Literal[
    "solidity-security", "vyper-security", "rust-security", "move-security"
]


class Finding(BaseModel):
    rule_id: str = Field(max_length=200)
    title: str = Field(max_length=500)
    category: str = Field(max_length=200)
    severity: Severity
    confidence: float
    line: int
    code: str = Field(max_length=20_000)
    explanation: str = Field(max_length=5_000)
    recommendation: str = Field(max_length=5_000)
    source_tool: str = "securexai-pattern-detector"
    source_tools: list[str] = []


class ToolRun(BaseModel):
    tool: str
    status: Literal["completed", "unavailable", "skipped", "error"]
    finding_count: int
    message: str = ""


class AnalysisResponse(BaseModel):
    filename: str
    language: Language
    pipeline: PipelineName
    finding_count: int
    findings: list[Finding]
    tool_runs: list[ToolRun]


class ValidationResponse(BaseModel):
    filename: str
    status: Literal["improved", "unchanged", "regressed", "inconclusive"]
    original_finding_count: int
    revised_finding_count: int
    original_findings: list[Finding]
    revised_findings: list[Finding]
    tool_runs: list[ToolRun]
    message: str


class AutoFixResponse(BaseModel):
    filename: str
    provider: str
    status: Literal["fully-patched", "partially-patched", "failed"]
    original_finding_count: int
    remaining_finding_count: int
    iterations: int
    patched_source: str
    diff: str
    remaining_findings: list[Finding]
    tool_runs: list[ToolRun]
    message: str


class FinalReport(BaseModel):
    filename: str
    provider: str
    title: str
    executive_summary: str
    risk_summary: dict[str, int]
    recommended_actions: list[str]
    validation_note: str
    finding_count: int
    tool_runs: list[ToolRun]
    detailed_report: str = ""
    findings: list[Finding] = []
    manual_review_findings: list[Finding] = []
    manual_review_required: bool = True
    regeneration_status: str = "not-run"


