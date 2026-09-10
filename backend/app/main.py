from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.models import (
    AnalysisResponse,
    Finding,
    Language,
    RemediationResponse,
    ValidationResponse,
    VulnerabilityReport,
)
from app.pipelines import analyze_other_language, analyze_solidity
from app.remediation import build_remediation
from app.reporting import generate_report
from app.rate_limit import RateLimitMiddleware

app = FastAPI(
    title="SecureXAI API",
    version="0.1.0",
    description="Multi-tool smart contract vulnerability analysis API.",
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    source: str = Field(min_length=1)
    language: Language = "solidity"


class RemediationRequest(Finding):
    source: str | None = None


class ValidationRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    language: Language = "solidity"
    original_source: str = Field(min_length=1)
    revised_source: str = Field(min_length=1)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "securexai-api"}


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
def analyze_contract(request: AnalyzeRequest) -> AnalysisResponse:
    if request.language == "solidity":
        findings, tool_runs, pipeline = analyze_solidity(
            request.source, request.filename
        )
    else:
        findings, tool_runs, pipeline = analyze_other_language(
            request.source, request.filename, request.language
        )
    return AnalysisResponse(
        filename=request.filename,
        language=request.language,
        pipeline=pipeline,
        finding_count=len(findings),
        findings=findings,
        tool_runs=tool_runs,
    )


@app.post("/api/v1/remediate", response_model=RemediationResponse)
def remediate_finding(request: RemediationRequest) -> RemediationResponse:
    return build_remediation(request, request.source)


@app.post("/api/v1/validate-remediation", response_model=ValidationResponse)
def validate_remediation(request: ValidationRequest) -> ValidationResponse:
    if request.language == "solidity":
        original_findings, _, _ = analyze_solidity(
            request.original_source, request.filename
        )
        revised_findings, tool_runs, _ = analyze_solidity(
            request.revised_source, request.filename
        )
    else:
        original_findings, _, _ = analyze_other_language(
            request.original_source, request.filename, request.language
        )
        revised_findings, tool_runs, _ = analyze_other_language(
            request.revised_source, request.filename, request.language
        )

    if any(tool.status in {"error", "unavailable"} for tool in tool_runs):
        status = "inconclusive"
        message = "One or more analyzers did not complete; review the tool statuses before accepting the revision."
    elif len(revised_findings) < len(original_findings):
        status = "improved"
        message = "The revised source has fewer normalized findings, but still requires human review."
    elif len(revised_findings) > len(original_findings):
        status = "regressed"
        message = "The revised source has more normalized findings and should not be accepted without review."
    else:
        status = "unchanged"
        message = "The normalized finding count is unchanged; review the revised findings manually."

    return ValidationResponse(
        filename=request.filename,
        status=status,
        original_finding_count=len(original_findings),
        revised_finding_count=len(revised_findings),
        original_findings=original_findings,
        revised_findings=revised_findings,
        tool_runs=tool_runs,
        message=message,
    )


@app.post("/api/v1/report", response_model=VulnerabilityReport)
def vulnerability_report(request: AnalysisResponse) -> VulnerabilityReport:
    return generate_report(request)
