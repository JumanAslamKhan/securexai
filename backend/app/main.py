from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.models import (
    AnalysisResponse,
    Finding,
    Language,
    RemediationResponse,
    VulnerabilityReport,
)
from app.pipelines import analyze_other_language, analyze_solidity
from app.remediation import build_remediation
from app.reporting import generate_report

app = FastAPI(
    title="SecureXAI API",
    version="0.1.0",
    description="Multi-tool smart contract vulnerability analysis API.",
)

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


@app.post("/api/v1/report", response_model=VulnerabilityReport)
def vulnerability_report(request: AnalysisResponse) -> VulnerabilityReport:
    return generate_report(request)
