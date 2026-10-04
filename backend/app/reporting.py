import json
import os
from urllib import request as http_request
from urllib.parse import quote

from app.models import AnalysisResponse, VulnerabilityReport


def _is_gemini_base_url(base_url: str) -> bool:
    return "generativelanguage.googleapis.com" in base_url or "googleapis.com" in base_url


def _build_chat_request_body(base_url: str, model: str, messages: list[dict], *, temperature: float = 0.1) -> dict:
    if _is_gemini_base_url(base_url):
        prompt_parts: list[dict[str, str]] = []
        for message in messages:
            role = str(message.get("role", "user"))
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content)
            if role == "system":
                prompt_parts.append({"text": f"System: {content}"})
            else:
                prompt_parts.append({"text": f"{role.title()}: {content}"})
        return {
            "contents": [{"role": "user", "parts": prompt_parts}],
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            },
        }

    body: dict[str, object] = {
        "model": model,
        "temperature": temperature,
        "messages": messages,
        "response_format": {"type": "json_object"},
    }
    return body


def _gemini_response_payload_to_text(payload: dict) -> str:
    candidates = payload.get("candidates")
    if isinstance(candidates, list) and candidates:
        content = candidates[0].get("content", {}) if isinstance(candidates[0], dict) else {}
        if isinstance(content, dict):
            parts = content.get("parts")
            if isinstance(parts, list):
                text_parts: list[str] = []
                for item in parts:
                    if isinstance(item, dict) and isinstance(item.get("text"), str):
                        text_parts.append(item["text"])
                if text_parts:
                    return "".join(text_parts)
    raise ValueError("Provider response did not include a Gemini content payload")


def _extract_message_content(payload: dict) -> str:
    if "candidates" in payload:
        return _gemini_response_payload_to_text(payload)
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ValueError("Provider response did not include a chat completion payload")
    if isinstance(content, list):
        pieces: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    pieces.append(item["text"])
                elif isinstance(item.get("content"), str):
                    pieces.append(item["content"])
            elif isinstance(item, str):
                pieces.append(item)
        content = "".join(pieces)
    if not isinstance(content, str):
        content = json.dumps(content)
    return content


def _fallback_report(analysis: AnalysisResponse) -> VulnerabilityReport:
    if not analysis.findings:
        summary = "Warning: Gemini AI report generation is unavailable; no AI-generated summary was produced."
    else:
        summary = (
            f"Warning: Gemini AI report generation is unavailable for {analysis.filename}. "
            f"{analysis.finding_count} normalized finding(s) were identified by local analyzers."
        )
    return VulnerabilityReport(
        provider="gemini-warning",
        title=f"Warning: AI report unavailable for {analysis.filename}",
        executive_summary=summary,
        risk_summary={
            severity: sum(1 for finding in analysis.findings if finding.severity == severity)
            for severity in ("critical", "high", "medium", "low")
        },
        recommended_actions=[
            "Check the Gemini API key and model configuration.",
            "Restart the backend after setting the Gemini environment variables.",
            "Retry the report request once the provider is available.",
        ],
        validation_note="Warning: the Gemini provider was unavailable; this report is advisory and was not AI-generated.",
    )


def generate_report(analysis: AnalysisResponse) -> VulnerabilityReport:
    base_url = os.getenv(
        "OPENAI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    )
    model = os.getenv("OPENAI_MODEL", "gemini-2.5-flash")
    api_key = os.getenv("OPENAI_API_KEY", "")
    prompt = {
        "filename": analysis.filename,
        "language": analysis.language,
        "pipeline": analysis.pipeline,
        "findings": [finding.model_dump() for finding in analysis.findings],
        "tool_runs": [tool.model_dump() for tool in analysis.tool_runs],
    }
    body = json.dumps(
        _build_chat_request_body(
            base_url,
            model,
            [
                {
                    "role": "system",
                    "content": (
                        "You are a smart-contract security auditor. Return only one valid JSON object, "
                        "with exactly these keys: title (string), executive_summary (string), "
                        "risk_summary (object with integer keys critical, high, medium, low), "
                        "recommended_actions (array of strings), and validation_note (string). "
                        "Count risk_summary from the supplied findings. Use zero for missing severities. "
                        "Do not use markdown, add extra keys, invent findings, or claim fixes were validated. "
                        'Example: {"title":"Report","executive_summary":"Summary",'
                        '"risk_summary":{"critical":0,"high":0,"medium":0,"low":0},'
                        '"recommended_actions":["Review findings"],"validation_note":"Advisory only."}'
                    ),
                },
                {"role": "user", "content": json.dumps(prompt)},
            ],
        )
    ).encode("utf-8")
    try:
        if _is_gemini_base_url(base_url):
            normalized_base = base_url.rstrip("/")
            if normalized_base.endswith("/openai"):
                normalized_base = normalized_base[:-len("/openai")]
            endpoint = f"{normalized_base}/models/{model}:generateContent"
            if api_key:
                endpoint = f"{endpoint}?key={quote(api_key)}"
            headers = {"Content-Type": "application/json"}
        else:
            endpoint = base_url.rstrip("/") + "/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        request = http_request.Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        with http_request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = _extract_message_content(payload)
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        generated = json.loads(content)
        risk_summary = generated.get("risk_summary", {})
        if isinstance(risk_summary, str):
            risk_summary = json.loads(risk_summary)
        if not isinstance(risk_summary, dict):
            raise ValueError("risk_summary must be an object")
        return VulnerabilityReport(
            provider=f"gemini:{model}",
            title=str(generated["title"]),
            executive_summary=str(generated["executive_summary"]),
            risk_summary={str(key): int(value) for key, value in risk_summary.items()},
            recommended_actions=[str(action) for action in generated["recommended_actions"]],
            validation_note=str(generated["validation_note"]),
        )
    except Exception as error:
        print(f"\n[GEMINI ERROR] {type(error).__name__}: {error}")
        return _fallback_report(analysis)
