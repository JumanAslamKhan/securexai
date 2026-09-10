from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.detector import analyze_source
from app.models import AnalysisResponse

app = FastAPI(
    title="SecureXAI API",
    version="0.1.0",
    description="Multi-tool smart contract vulnerability analysis API.",
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
    return AnalysisResponse(
        filename=request.filename,
        finding_count=len(findings),
        findings=findings,
    )
