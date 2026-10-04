"""Layer 3: Gemini-assisted source generation with analyzer feedback."""

from __future__ import annotations

import difflib
import json
import os
from urllib import request as http_request
from urllib.error import HTTPError
from urllib.parse import quote

from app.models import AutoFixResponse, Finding, Language, ToolRun
from app.pipelines import analyze_other_language, analyze_solidity

DEFAULT_MAX_ITERATIONS = 5
DEFAULT_MODEL = "gemini-3.8-flash"
DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
RETIRED_MODELS = {"gemini-2.5-flash"}


class PatchGenerationError(Exception):
    """Raised when Gemini fails or returns unusable source."""


def _configured_model(model: str | None = None) -> str:
    selected = model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
    return DEFAULT_MODEL if selected in RETIRED_MODELS else selected


def _gemini_endpoint(model: str, api_key: str) -> str:
    base_url = os.getenv("GEMINI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    if base_url.endswith("/openai"):
        base_url = base_url[:-len("/openai")]
    endpoint = f"{base_url}/models/{quote(model, safe='')}:generateContent"
    if api_key:
        endpoint = f"{endpoint}?key={quote(api_key)}"
    return endpoint


def _extract_text(payload: dict) -> str:
    if isinstance(payload.get("error"), dict):
        error = payload["error"]
        raise PatchGenerationError(
            f"Gemini returned {error.get('status', 'an error')}: "
            f"{error.get('message', 'unknown provider error')}"
        )

    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        feedback = payload.get("promptFeedback")
        detail = f" Prompt feedback: {feedback}." if feedback else ""
        raise PatchGenerationError(f"Gemini returned no candidates.{detail}")

    candidate = candidates[0]
    if not isinstance(candidate, dict):
        raise PatchGenerationError("Gemini returned an invalid candidate.")
    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    text_parts = [
        part.get("text")
        for part in parts or []
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    ]
    text = "".join(text_parts)
    if not text.strip():
        finish_reason = candidate.get("finishReason", "unknown")
        safety_ratings = candidate.get("safetyRatings")
        raise PatchGenerationError(
            f"Gemini returned no text (finish reason: {finish_reason}; "
            f"safety ratings: {safety_ratings or 'none'})."
        )
    return text


def _chat_completion(messages: list[dict], model: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise PatchGenerationError("GEMINI_API_KEY is not set.")

    system_message = next(
        (message["content"] for message in messages if message.get("role") == "system"),
        "",
    )
    user_messages = [
        {"role": "user", "parts": [{"text": message["content"]}]}
        for message in messages
        if message.get("role") != "system"
    ]
    body: dict[str, object] = {
        "contents": user_messages,
        "generationConfig": {"temperature": 0.1},
    }
    if system_message:
        body["systemInstruction"] = {"parts": [{"text": system_message}]}

    request = http_request.Request(
        _gemini_endpoint(model, api_key),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with http_request.urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")[:1_000]
        raise PatchGenerationError(
            f"Gemini request failed with HTTP {error.code}: {details or error.reason}"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise PatchGenerationError(f"Gemini request failed: {error}") from error
    return _extract_text(payload)


def _strip_code_fences(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        lines = lines[1:] if lines else lines
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines)
    return cleaned.strip()


def _build_prompt(
    filename: str, language: Language, source: str, findings: list[Finding]
) -> list[dict]:
    findings_payload = [finding.model_dump() for finding in findings]
    system = (
        "You are the remediation engine in a security pipeline. Rewrite the entire source "
        "file and address EVERY listed finding, including findings from securexai-ml, "
        "Semgrep, Slither, and the pattern detector. Treat each finding as a checklist: "
        "reentrancy requires checks-effects-interactions plus a guard where appropriate; "
        "tx.origin requires msg.sender and explicit access control; low-level calls require "
        "checked results; compiler-version findings require a safe supported pragma; ML "
        "signals must be reconciled against the source instead of ignored. Preserve public "
        "interfaces and business logic where possible. Do not remove functionality merely "
        "to hide a finding. Return ONLY the complete corrected source code, with no markdown "
        "fences or explanation. The source will be re-analyzed after this pass, so make a "
        "concrete fix for every checklist item."
    )
    user = json.dumps(
        {"filename": filename, "language": language, "source": source, "findings": findings_payload}
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def generate_patched_source(
    filename: str,
    language: Language,
    source: str,
    findings: list[Finding],
    model: str | None = None,
) -> str:
    if not findings:
        return source
    content = _chat_completion(
        _build_prompt(filename, language, source, findings),
        _configured_model(model),
    )
    patched = _strip_code_fences(content)
    if not patched:
        raise PatchGenerationError("Gemini returned an empty patch.")
    return patched


def build_diff(original: str, patched: str, filename: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )


def run_autofix(
    filename: str,
    language: Language,
    source: str,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    model: str | None = None,
) -> AutoFixResponse:
    def analyze_fn(src: str) -> tuple[list[Finding], list[ToolRun], str]:
        if language == "solidity":
            return analyze_solidity(src, filename)
        return analyze_other_language(src, filename, language)

    original_findings, tool_runs, _ = analyze_fn(source)
    current_source = source
    current_findings = original_findings
    iterations_used = 0
    model_name = _configured_model(model)

    for _ in range(max_iterations):
        if not current_findings:
            break
        iterations_used += 1
        try:
            candidate = generate_patched_source(
                filename, language, current_source, current_findings, model=model_name
            )
        except PatchGenerationError as error:
            return AutoFixResponse(
                filename=filename,
                provider=f"gemini:{model_name}",
                status="failed",
                original_finding_count=len(original_findings),
                remaining_finding_count=len(current_findings),
                iterations=iterations_used,
                patched_source=current_source,
                diff=build_diff(source, current_source, filename),
                remaining_findings=current_findings,
                tool_runs=tool_runs,
                message=str(error),
            )
        current_source = candidate
        current_findings, tool_runs, _ = analyze_fn(current_source)

    original_count = len(original_findings)
    remaining_count = len(current_findings)
    if remaining_count == 0:
        status = "fully-patched"
        message = f"All {original_count} finding(s) resolved after {iterations_used} generation pass(es)."
    elif remaining_count < original_count:
        status = "partially-patched"
        reduction = original_count - remaining_count
        percentage = round((reduction / original_count) * 100) if original_count else 100
        message = (
            f"Reduced findings from {original_count} to {remaining_count} ({percentage}% reduction) "
            f"after {iterations_used} of {max_iterations} allowed pass(es); manual review is required."
        )
    else:
        status = "failed"
        message = f"Findings did not decrease after {iterations_used} pass(es); manual review is required."

    return AutoFixResponse(
        filename=filename,
        provider=f"gemini:{model_name}",
        status=status,
        original_finding_count=original_count,
        remaining_finding_count=remaining_count,
        iterations=iterations_used,
        patched_source=current_source,
        diff=build_diff(source, current_source, filename),
        remaining_findings=current_findings,
        tool_runs=tool_runs,
        message=message,
    )