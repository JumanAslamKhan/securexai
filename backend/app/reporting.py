import json
import os
from urllib import request as http_request

from app.models import AnalysisResponse, VulnerabilityReport


def _fallback_report(analysis: AnalysisResponse) -> VulnerabilityReport:
    if not analysis.findings:
        summary = "No normalized vulnerabilities were identified by the configured analyzers."
    else:
        summary = (
            f"{analysis.finding_count} normalized finding(s) were identified. "
            "Prioritize critical and high severity findings before deployment."
        )
    return VulnerabilityReport(
        provider="securexai-local-report",
        title=f"Vulnerability report: {analysis.filename}",
        executive_summary=summary,
        risk_summary={
            severity: sum(1 for finding in analysis.findings if finding.severity == severity)
            for severity in ("critical", "high", "medium", "low")
        },
        recommended_actions=[
            "Review every critical and high severity finding.",
            "Apply fixes as reviewed diffs, then compile the contract.",
            "Re-run Semgrep and Slither after remediation.",
        ],
        validation_note="This report is advisory and requires human review.",
    )


def generate_report(analysis: AnalysisResponse) -> VulnerabilityReport:
    base_url = os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
    model = os.getenv("OPENAI_MODEL", "qwen2.5-coder:7b")
    api_key = os.getenv("OPENAI_API_KEY", "ollama")
    prompt = {
        "filename": analysis.filename,
        "language": analysis.language,
        "pipeline": analysis.pipeline,
        "findings": [finding.model_dump() for finding in analysis.findings],
        "tool_runs": [tool.model_dump() for tool in analysis.tool_runs],
    }
    body = json.dumps({
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a smart-contract security auditor. Return only JSON with "
                    "title, executive_summary, risk_summary, recommended_actions, and validation_note. "
                    "Do not invent findings or claim fixes were validated."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ],
    }).encode("utf-8")
    try:
        endpoint = base_url.rstrip("/") + "/chat/completions"
        request = http_request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with http_request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        generated = json.loads(content)
        risk_summary = generated.get("risk_summary", {})
        if isinstance(risk_summary, str):
            risk_summary = json.loads(risk_summary)
        if not isinstance(risk_summary, dict):
            raise ValueError("risk_summary must be an object")
        return VulnerabilityReport(
            provider=f"local-ollama:{model}" if "11434" in base_url else f"openai:{model}",
            title=str(generated["title"]),
            executive_summary=str(generated["executive_summary"]),
            risk_summary={str(key): int(value) for key, value in risk_summary.items()},
            recommended_actions=[str(action) for action in generated["recommended_actions"]],
            validation_note=str(generated["validation_note"]),
        )
    except (KeyError, TypeError, ValueError, OSError, TimeoutError, json.JSONDecodeError):
        return _fallback_report(analysis)
