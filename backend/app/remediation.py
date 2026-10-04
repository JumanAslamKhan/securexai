import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote
from urllib import request as http_request
from urllib.error import HTTPError

from app.models import Finding, RemediationResponse, RepairRequest, RepairResponse


def _is_gemini_base_url(base_url: str) -> bool:
    return "generativelanguage.googleapis.com" in base_url or "googleapis.com" in base_url


def _build_chat_request_body(base_url: str, model: str, messages: list[dict], *, temperature: float = 0.1, stream: bool = False, extra_fields: dict | None = None) -> dict:
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
        body: dict[str, object] = {
            "contents": [{"role": "user", "parts": prompt_parts}],
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            },
        }
        if extra_fields:
            body.update(extra_fields)
        return body

    body = {
        "model": model,
        "temperature": temperature,
        "messages": messages,
        "response_format": {"type": "json_object"},
    }
    if stream:
        body["stream"] = False
    if extra_fields:
        body.update(extra_fields)
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

_AI_REPAIR_TIMEOUT = max(
    30, int(os.getenv("SECUREXAI_AI_REPAIR_TIMEOUT_SECONDS", "300"))
)


def _compile_solidity(source: str) -> tuple[str, str]:
    executable = shutil.which("solc")
    if not executable:
        local_executable = Path(__file__).resolve().parents[2] / ".tools-venv" / "Scripts" / "solc.exe"
        executable = str(local_executable) if local_executable.exists() else None
    if not executable:
        return "unavailable", "Solidity compiler was not found."
    with tempfile.TemporaryDirectory(prefix="securexai-repair-") as directory:
        contract = Path(directory) / "Repaired.sol"
        contract.write_text(source, encoding="utf-8")
        try:
            result = subprocess.run(
                [executable, "--bin", str(contract)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return "unavailable", str(error)
    if result.returncode != 0:
        return "error", (result.stderr or result.stdout).strip()[:2_000]
    return "compiled", "Solidity compiler accepted the generated source."


def _risk_summary(findings: list[Finding]) -> dict[str, int]:
    return {
        severity: sum(finding.severity == severity for finding in findings)
        for severity in ("critical", "high", "medium", "low")
    }


def _repair_validation(
    original: list[Finding], revised: list[Finding],
) -> tuple[str, str]:
    original_risk = _risk_summary(original)
    revised_risk = _risk_summary(revised)
    if revised_risk["critical"] > original_risk["critical"]:
        return "regressed", "Critical findings increased; the generated repair was rejected."
    if len(revised) < len(original) or (
        revised_risk["critical"] < original_risk["critical"]
        and revised_risk["high"] <= original_risk["high"]
    ):
        return "improved", "The rescanned repair has fewer or lower-severity findings."
    if len(revised) == len(original) and revised_risk == original_risk:
        return "unchanged", "The rescanned repair has the same normalized risk profile."
    return "regressed", "The rescanned repair did not improve the normalized risk profile."


def _parse_repair_response(content: str) -> tuple[str, str]:
    cleaned = content.strip()
    if "```" in cleaned:
        cleaned = re.sub(r"```(?:json|solidity)?", "", cleaned).replace("```", "").strip()
    try:
        generated = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        generated = json.loads(cleaned[start : end + 1])
    fixed_source = generated.get("fixed_source")
    report = generated.get("report")
    if not isinstance(fixed_source, str) or not fixed_source.strip() or not isinstance(report, str):
        raise ValueError("Gemini returned an invalid repair shape")
    if "contract " not in fixed_source and "library " not in fixed_source and "interface " not in fixed_source:
        raise ValueError("Gemini did not return a Solidity contract")
    if fixed_source.count("{") != fixed_source.count("}"):
        raise ValueError("Gemini returned unbalanced Solidity braces")
    return fixed_source, report


def _llm_remediation(finding: Finding, source: str) -> RemediationResponse | None:
    base_url = os.getenv(
        "OPENAI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    )
    api_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "gemini-2.5-flash")
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
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    prompt = {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "line": finding.line,
        "code": finding.code,
        "explanation": finding.explanation,
        "source": source,
    }
    body = json.dumps(
        _build_chat_request_body(
            base_url,
            model,
            [
                {
                    "role": "system",
                    "content": (
                        "You are a Solidity security reviewer. Return only one valid JSON object with "
                        "summary (string), patch_guidance (string), and patch (string or null). "
                        "Do not use markdown and never claim the patch is validated."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt)},
            ],
            stream=True,
        )
    ).encode("utf-8")
    try:
        http_request_obj = http_request.Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        with http_request.urlopen(http_request_obj, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = _extract_message_content(payload)
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        generated = json.loads(content)
        if not isinstance(generated.get("summary"), str) or not isinstance(
            generated.get("patch_guidance"), str
        ):
            return None
        patch = generated.get("patch")
        return RemediationResponse(
            rule_id=finding.rule_id,
            provider=f"gemini:{model}",
            summary=generated["summary"],
            patch_guidance=generated["patch_guidance"],
            patch=str(patch) if patch else None,
            validation_steps=[
                "Review the generated patch as a diff.",
                "Compile the modified contract with the declared Solidity version.",
                "Re-run Semgrep and Slither after the change.",
            ],
            auto_apply=False,
        )
    except HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        print(f"\n[GEMINI API ERROR] HTTP {error.code}: {details}")
        return None
    except Exception as error:
        print(f"\n[GEMINI ERROR] {type(error).__name__}: {error}")
        return None


def build_remediation(finding: Finding, source: str | None = None) -> RemediationResponse:
    if source:
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
        provider="gemini-warning",
        summary="Warning: Gemini AI remediation is unavailable. " + summary,
        patch_guidance=patch_guidance,
        validation_steps=[
            "Review the generated change as a diff.",
            "Compile the modified contract with the declared Solidity version.",
            "Re-run Semgrep and Slither after the change.",
        ],
        auto_apply=False,
    )


def build_repair(request: RepairRequest) -> RepairResponse:
    if request.language != "solidity":
        return RepairResponse(
            filename=request.filename,
            provider="securexai-rule-guidance",
            status="unavailable",
            report="Whole-file AI repair is currently available for Solidity only.",
            compile_status="unavailable",
            compile_message="Compilation is only configured for Solidity repairs.",
            validation_status="inconclusive",
            original_finding_count=0,
            revised_finding_count=0,
            original_risk_summary=_risk_summary([]),
            revised_risk_summary=_risk_summary([]),
            validation_steps=["Review the source manually and use the language-specific pipeline when available."],
        )

    base_url = os.getenv(
        "OPENAI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    )
    api_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "gemini-2.5-flash")
    repair_models = [model]
    normalized_base = base_url.rstrip("/")
    if normalized_base.endswith("/openai"):
        normalized_base = normalized_base[:-len("/openai")]
    prompt = {
        "filename": request.filename,
        "source": request.source,
        "findings": [finding.model_dump() for finding in request.findings],
    }
    system_message = (
        "You are a senior Solidity security engineer. Repair the supplied contract. "
        "Return only one JSON object with fixed_source (complete Solidity source string) "
        "and report (string). The fixed_source must include every closing brace and be a "
        "complete compilable-looking contract. Preserve behavior where possible, explain "
        "unresolved risks in the report, and never claim compilation or security validation occurred."
    )
    last_error = "unknown AI repair error"
    try:
        generated_model = model
        generated = False
        for candidate_model in repair_models:
            for attempt in range(2):
                if _is_gemini_base_url(base_url):
                    endpoint = f"{normalized_base}/models/{candidate_model}:generateContent"
                    if api_key:
                        endpoint = f"{endpoint}?key={quote(api_key)}"
                    headers = {"Content-Type": "application/json"}
                else:
                    endpoint = base_url.rstrip("/") + "/chat/completions"
                    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                body = json.dumps(
                    _build_chat_request_body(
                        base_url,
                        candidate_model,
                        [
                            {"role": "system", "content": system_message},
                            {"role": "user", "content": json.dumps(prompt)},
                        ],
                        stream=True,
                    )
                ).encode("utf-8")
                try:
                    http_request_obj = http_request.Request(
                        endpoint,
                        data=body,
                        headers=headers,
                        method="POST",
                    )
                    with http_request.urlopen(
                        http_request_obj, timeout=_AI_REPAIR_TIMEOUT
                    ) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                    content = _extract_message_content(payload)
                    fixed_source, report = _parse_repair_response(content)
                    generated_model = candidate_model
                    generated = True
                    break
                except HTTPError as error:
                    details = error.read().decode("utf-8", errors="replace")[:1_000]
                    last_error = f"{candidate_model}: HTTP {error.code}: {details or error.reason}"
                    if error.code != 503:
                        raise ValueError(last_error) from error
                    time.sleep(2 ** attempt)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                    last_error = f"{candidate_model}: {error}"
                    if attempt == 1:
                        break
                    time.sleep(1)
            if generated:
                break
        if not generated:
            raise ValueError(last_error)
        compile_status, compile_message = _compile_solidity(fixed_source)
        response_status = "generated" if compile_status == "compiled" else "invalid"
        if compile_status == "error":
            report = f"{report}\n\nCompiler rejected this generated source:\n{compile_message}"
        original_findings: list[Finding] = []
        revised_findings: list[Finding] = []
        validation_status = "inconclusive"
        validation_message = "Rescan was not attempted because compilation failed."
        if compile_status == "compiled":
            from app.pipelines import analyze_solidity

            original_findings, _, _ = analyze_solidity(request.source, request.filename)
            revised_findings, revised_tools, _ = analyze_solidity(fixed_source, request.filename)
            if any(tool.status in {"error", "unavailable"} for tool in revised_tools):
                validation_status = "inconclusive"
                validation_message = "One or more analyzers did not complete; the repair was not accepted."
                response_status = "rejected"
            else:
                validation_status, validation_message = _repair_validation(
                    original_findings, revised_findings
                )
                if validation_status != "improved":
                    response_status = "rejected"
            report = f"{report}\n\nRescan result: {validation_message}"
        original_risk_summary = _risk_summary(original_findings)
        revised_risk_summary = _risk_summary(revised_findings)
        return RepairResponse(
            filename=request.filename,
            provider=f"gemini:{generated_model}",
            status=response_status,
            fixed_source=fixed_source,
            report=report,
            compile_status=compile_status,
            compile_message=compile_message,
            validation_status=validation_status,
            original_finding_count=len(original_findings),
            revised_finding_count=len(revised_findings),
            original_risk_summary=original_risk_summary,
            revised_risk_summary=revised_risk_summary,
            unresolved_findings=revised_findings,
            validation_steps=[
                "Review the generated Solidity file as a diff.",
                "Compile it with the declared Solidity version.",
                "Re-run the custom detector, Semgrep, Slither, and SecureXAI ML.",
                "Accept the repair only after human review and a successful rescan.",
            ],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError, TimeoutError) as error:
        return RepairResponse(
            filename=request.filename,
            provider="gemini-warning",
            status="unavailable",
            report=(
                f"Warning: Gemini repair generation is unavailable. {error}. "
                "No source was changed. "
                "Verify the Gemini API key and model configuration, and retry after the provider is available."
            ),
            compile_status="unavailable",
            compile_message="Compilation was not attempted because repair generation failed.",
            validation_status="inconclusive",
            original_finding_count=0,
            revised_finding_count=0,
            original_risk_summary=_risk_summary([]),
            revised_risk_summary=_risk_summary([]),
            validation_steps=[
                "Do not accept an empty or unvalidated repair.",
                "Review findings manually and retry after the Gemini API is available.",
            ],
        )
