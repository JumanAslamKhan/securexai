from typing import Literal

from pydantic import BaseModel


Severity = Literal["critical", "high", "medium", "low"]


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


class ToolRun(BaseModel):
    tool: str
    status: Literal["completed", "unavailable", "error"]
    finding_count: int
    message: str = ""


class AnalysisResponse(BaseModel):
    filename: str
    finding_count: int
    findings: list[Finding]
    tool_runs: list[ToolRun]
