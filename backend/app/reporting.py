"""Layer 4: final reporting from normalized results and optional Gemini detail."""

from __future__ import annotations

import json
import os
from urllib import request as http_request
from urllib.error import HTTPError
from urllib.parse import quote

from app.models import AnalysisResponse, FinalReport, Finding


def _gemini_detail(analysis: AnalysisResponse, original_source: str, revised_source: str) -> str | None:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    base_url = os.getenv(
        "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    ).rstrip("/")
    if base_url.endswith("/openai"):
        base_url = base_url[:-len("/openai")]
    endpoint = f"{base_url}/models/{quote(model, safe='')}:generateContent?key={quote(api_key)}"
    prompt = {
        "filename": analysis.filename,
        "pipeline": analysis.pipeline,
        "findings": [finding.model_dump() for finding in analysis.findings],
        "original_vulnerable_source": original_source,
        "regenerated_source": revised_source,
    }
    system = (
        "You are the final smart-contract security report reviewer. Return a detailed Markdown report. "
        "Explain each examined vulnerability with severity, evidence, affected line, and remediation. "
        "Compare the vulnerable source with the regenerated source, identify what changed and what remains, "
        "and clearly state that generated code requires human review. Do not invent findings."
    )
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": json.dumps(prompt)}]}],
        "generationConfig": {"temperature": 0.1},
    }
    request = http_request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with http_request.urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode("utf-8"))
        parts = payload["candidates"][0]["content"]["parts"]
        detail = "".join(part["text"] for part in parts if isinstance(part, dict))
        return detail.strip() or None
    except (HTTPError, OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None


def build_final_report(
    analysis: AnalysisResponse,
    original_source: str = "",
    revised_source: str = "",
    revised_findings: list[Finding] | None = None,
    regeneration_status: str = "not-run",
) -> FinalReport:
    original_findings = analysis.findings
    remaining_findings = revised_findings if revised_findings is not None else original_findings
    remaining_keys = {
        (finding.rule_id, finding.category, finding.title)
        for finding in remaining_findings
    }
    resolved_findings = [
        finding for finding in original_findings
        if (finding.rule_id, finding.category, finding.title) not in remaining_keys
    ]
    risk_summary = {
        severity: sum(finding.severity == severity for finding in original_findings)
        for severity in ("critical", "high", "medium", "low")
    }
    recommended_actions = [
        finding.recommendation
        for finding in original_findings
        if finding.recommendation
    ]
    if not recommended_actions:
        recommended_actions = ["No normalized findings require remediation."]

    unavailable_tools = [
        tool.tool for tool in analysis.tool_runs if tool.status in {"unavailable", "error"}
    ]
    validation_note = (
        "All reported analyzer runs completed. Review the source and evidence before deployment."
        if not unavailable_tools
        else "Incomplete analyzer runs: " + ", ".join(unavailable_tools) + ". Results require manual review."
    )
    if analysis.findings:
        executive_summary = (
            f"{analysis.filename} contains {analysis.finding_count} normalized finding(s) "
            f"across the {analysis.pipeline} pipeline."
        )
    else:
        executive_summary = f"No normalized findings were reported for {analysis.filename}."

    manual_review_findings = remaining_findings
    detailed_report = _gemini_detail(analysis, original_source, revised_source)
    if not detailed_report:
        detailed_report = (
            f"## Examined vulnerabilities\n\n{executive_summary}\n\n"
            f"## Resolved findings\n\n{len(resolved_findings)} finding(s) were no longer reported after regeneration.\n\n"
            f"## Manual review required\n\n{len(manual_review_findings)} finding(s) remain after regeneration.\n\n"
            + "\n".join(
                f"- **{finding.severity}** {finding.title} (line {finding.line}); "
                f"detected by {', '.join(finding.source_tools)}. {finding.recommendation}"
                for finding in manual_review_findings
            )
            + "\n\nReview every listed finding and analyzer evidence before accepting changes."
        )
    return FinalReport(
        filename=analysis.filename,
        provider="securexai-final-report",
        title=f"SecureXAI final report: {analysis.filename}",
        executive_summary=executive_summary,
        risk_summary=risk_summary,
        recommended_actions=list(dict.fromkeys(recommended_actions)),
        validation_note=validation_note,
        finding_count=analysis.finding_count,
        tool_runs=analysis.tool_runs,
        detailed_report=detailed_report,
        findings=original_findings,
        resolved_findings=resolved_findings,
        manual_review_findings=manual_review_findings,
        manual_review_required=bool(manual_review_findings) or regeneration_status != "fully-patched",
        regeneration_status=regeneration_status,
    )