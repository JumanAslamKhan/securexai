import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

from app.models import (
    AnalysisResponse,
    AutoFixResponse,
    Finding,
    FinalReport,
    Language,
    ValidationResponse,
)
from app.codegen import run_autofix
from app.pipelines import analyze_other_language, analyze_solidity
from app.rate_limit import RateLimitMiddleware
from app.reporting import build_final_report

app = FastAPI(
    title="SecureXAI API",
    version="0.1.0",
    description="Multi-tool smart contract vulnerability analysis API.",
    docs_url=None if os.getenv("SECUREXAI_API_KEY") else "/docs",
    redoc_url=None if os.getenv("SECUREXAI_API_KEY") else "/redoc",
    openapi_url=None if os.getenv("SECUREXAI_API_KEY") else "/openapi.json",
)


class ApiSecurityMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api/v1/"):
            await self.app(scope, receive, send)
            return
        expected = os.getenv("SECUREXAI_API_KEY")
        if expected:
            headers = dict(scope.get("headers", []))
            supplied = headers.get(b"x-api-key", b"").decode()
            authorization = headers.get(b"authorization", b"").decode()
            if supplied != expected and authorization != f"Bearer {expected}":
                response = JSONResponse({"detail": "API key required."}, status_code=401)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(ApiSecurityMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


class AnalyzeRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    source: str = Field(min_length=1, max_length=500_000)
    language: Language = "solidity"


class ValidationRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    language: Language = "solidity"
    original_source: str = Field(min_length=1, max_length=500_000)
    revised_source: str = Field(min_length=1, max_length=500_000)


class AutoFixRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    source: str = Field(min_length=1, max_length=500_000)
    language: Language = "solidity"
    max_iterations: int = Field(default=2, ge=1, le=5)
    model: str | None = None


class FinalReportRequest(BaseModel):
    analysis: AnalysisResponse
    original_source: str = Field(default="", max_length=500_000)
    revised_source: str = Field(default="", max_length=500_000)
    revised_findings: list[Finding] = []
    regeneration_status: str = "not-run"


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


@app.post("/api/v1/autofix", response_model=AutoFixResponse)
def autofix_contract(request: AutoFixRequest) -> AutoFixResponse:
    return run_autofix(
        filename=request.filename,
        language=request.language,
        source=request.source,
        max_iterations=request.max_iterations,
        model=request.model,
    )


@app.post("/api/v1/report", response_model=FinalReport)
def final_report(request: AnalysisResponse) -> FinalReport:
    return build_final_report(request)


@app.post("/api/v1/final-report", response_model=FinalReport)
def detailed_final_report(request: FinalReportRequest) -> FinalReport:
    return build_final_report(
        request.analysis,
        original_source=request.original_source,
        revised_source=request.revised_source,
        revised_findings=request.revised_findings,
        regeneration_status=request.regeneration_status,
    )


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
