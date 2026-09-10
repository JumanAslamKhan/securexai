from typing import Literal

from pydantic import BaseModel


Severity = Literal["critical", "high", "medium", "low"]
Language = Literal["solidity", "vyper", "rust", "move"]
PipelineName = Literal[
    "solidity-security", "vyper-security", "rust-security", "move-security"
]


class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: float
    line: int
    code: str
    explanation: str
    recommendation: str
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


class RemediationResponse(BaseModel):
    rule_id: str
    provider: str
    summary: str
    patch_guidance: str
    patch: str | None = None
    validation_steps: list[str]
    auto_apply: bool


class VulnerabilityReport(BaseModel):
    provider: str
    title: str
    executive_summary: str
    risk_summary: dict[str, int]
    recommended_actions: list[str]
    validation_note: str
