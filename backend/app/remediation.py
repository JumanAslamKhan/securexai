import json
import os
from urllib import request as http_request

from app.models import Finding, RemediationResponse


_GUIDANCE = {
    "SEC-REENTRANCY-001": (
        "Apply checks-effects-interactions and protect the function with a reentrancy guard.",
        "Move the state update before the external call, then add a nonReentrant modifier if the call remains necessary.",
    ),
    "SEC-ACCESS-001": (
        "Replace tx.origin authorization with msg.sender and explicit ownership or role checks.",
        "Use an access-control modifier such as onlyOwner or a role-based permission check.",
    ),
    "SEC-EXTERNAL-001": (
        "Handle the external call result explicitly.",
        "Capture the returned boolean and revert or handle the failure path before continuing.",
    ),
    "SEC-DESTRUCT-001": (
        "Remove selfdestruct where possible or restrict it behind strong access control.",
        "Treat contract destruction as an emergency-only operation with an explicit owner or role check.",
    ),
}


def _llm_remediation(finding: Finding, source: str) -> RemediationResponse | None:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    endpoint = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/chat/completions"
    prompt = {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "line": finding.line,
        "code": finding.code,
        "explanation": finding.explanation,
        "source": source,
    }
    body = json.dumps({
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": "You are a Solidity security reviewer. Return JSON with summary, patch_guidance, and patch. Never claim the patch is validated.",
            },
            {"role": "user", "content": json.dumps(prompt)},
        ],
    }).encode("utf-8")
    try:
        http_request_obj = http_request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with http_request.urlopen(http_request_obj, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        generated = json.loads(content)
        return RemediationResponse(
            rule_id=finding.rule_id,
            provider=f"openai:{model}",
            summary=str(generated["summary"]),
            patch_guidance=str(generated["patch_guidance"]),
            patch=str(generated.get("patch", "")),
            validation_steps=[
                "Review the generated patch as a diff.",
                "Compile the modified contract with the declared Solidity version.",
                "Re-run Semgrep and Slither after the change.",
            ],
            auto_apply=False,
        )
    except (KeyError, json.JSONDecodeError, OSError, TimeoutError):
        return None


def build_remediation(finding: Finding, source: str | None = None) -> RemediationResponse:
    if source and os.getenv("OPENAI_API_KEY"):
        generated = _llm_remediation(finding, source)
        if generated:
            return generated

    summary, patch_guidance = _GUIDANCE.get(
        finding.rule_id,
        (
            "Review this finding with a Solidity security specialist.",
            finding.recommendation,
        ),
    )
    return RemediationResponse(
        rule_id=finding.rule_id,
        provider="securexai-rule-guidance",
        summary=summary,
        patch_guidance=patch_guidance,
        validation_steps=[
            "Review the generated change as a diff.",
            "Compile the modified contract with the declared Solidity version.",
            "Re-run Semgrep and Slither after the change.",
        ],
        auto_apply=False,
    )
