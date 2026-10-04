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


class RemediationResponse(BaseModel):
    rule_id: str
    provider: str
    summary: str
    patch_guidance: str
    patch: str | None = None
    validation_steps: list[str]
    auto_apply: bool


class RepairRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    language: Language = "solidity"
    source: str = Field(min_length=1, max_length=500_000)
    findings: list[Finding] = []


class RepairResponse(BaseModel):
    filename: str
    provider: str
    status: Literal["generated", "rejected", "unavailable", "invalid"]
    fixed_source: str | None = None
    report: str
    compile_status: Literal["compiled", "error", "unavailable"]
    compile_message: str
    validation_status: Literal["improved", "unchanged", "regressed", "inconclusive"]
    original_finding_count: int
    revised_finding_count: int
    original_risk_summary: dict[str, int]
    revised_risk_summary: dict[str, int]
    unresolved_findings: list[Finding] = []
    validation_steps: list[str]


class VulnerabilityReport(BaseModel):
    provider: str
    title: str
    executive_summary: str
    risk_summary: dict[str, int]
    recommended_actions: list[str]
    validation_note: str
