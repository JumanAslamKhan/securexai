from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.detector import analyze_source
from app.analyzers import run_external_analyzers
from app.normalizer import deduplicate_findings
from app.models import AnalysisResponse

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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "securexai-api"}


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
def analyze_contract(request: AnalyzeRequest) -> AnalysisResponse:
    findings = analyze_source(request.filename, request.source)
    external_findings, tool_runs = run_external_analyzers(request.source)
    findings.extend(external_findings)
    findings = deduplicate_findings(findings)
    return AnalysisResponse(
        filename=request.filename,
        finding_count=len(findings),
        findings=findings,
        tool_runs=tool_runs,
    )
