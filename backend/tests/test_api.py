from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.detector import analyze_source
from app.main import app
from app.models import Finding, ToolRun
from app.rate_limit import RateLimitMiddleware


client = TestClient(app)


def test_custom_detector_respects_reentrancy_guard() -> None:
    source = """contract Guarded {
    modifier nonReentrant() { _; }
    function withdraw() external nonReentrant {
        (bool ok,) = msg.sender.call{value: 1 ether}("");
        require(ok);
    }
}
"""

    findings = analyze_source("Guarded.sol", source)
    assert not any(finding.rule_id == "SEC-REENTRANCY-001" for finding in findings)


def test_custom_detector_requires_authorization_context_for_tx_origin() -> None:
    source = """contract ReadsOrigin {
    function readOrigin() external view returns (address) {
        return tx.origin;
    }
}
"""

    findings = analyze_source("ReadsOrigin.sol", source)
    assert not any(finding.rule_id == "SEC-ACCESS-001" for finding in findings)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_key_protects_versioned_routes_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("SECUREXAI_API_KEY", "test-key")
    unauthorized = client.post(
        "/api/v1/analyze",
        json={"filename": "Contract.sol", "source": "contract Empty {}"},
    )
    authorized = client.post(
        "/api/v1/analyze",
        headers={"X-API-Key": "test-key"},
        json={"filename": "Contract.sol", "source": "contract Empty {}"},
    )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_analysis_rejects_oversized_source() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"filename": "Contract.sol", "source": "x" * 500_001},
    )

    assert response.status_code == 422


def test_analyze_allows_frontend_preflight() -> None:
    response = client.options(
        "/api/v1/analyze",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_api_rate_limit_returns_headers_and_429(monkeypatch) -> None:
    monkeypatch.setenv("SECUREXAI_RATE_LIMIT", "2")
    limited_app = FastAPI()
    limited_app.add_middleware(RateLimitMiddleware)

    @limited_app.post("/api/v1/test")
    def limited_route() -> dict[str, str]:
        return {"status": "ok"}

    limited_client = TestClient(limited_app)

    first = limited_client.post("/api/v1/test")
    second = limited_client.post("/api/v1/test")
    third = limited_client.post("/api/v1/test")

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.headers["x-ratelimit-limit"] == "2"
    assert second.headers["x-ratelimit-remaining"] == "0"
    assert third.status_code == 429
    assert third.headers["retry-after"]


def test_validate_remediation_compares_original_and_revised(monkeypatch) -> None:
    finding = Finding(
        rule_id="SEC-REENTRANCY-001",
        title="Reentrancy",
        category="reentrancy",
        severity="critical",
        confidence=0.9,
        line=3,
        code="call",
        explanation="External call before state update.",
        recommendation="Use checks-effects-interactions.",
    )

    def fake_analyze(source: str, filename: str) -> tuple[list[Finding], list[ToolRun], str]:
        del filename
        findings = [finding] if "vulnerable" in source else []
        return findings, [ToolRun(tool="test-analyzer", status="completed", finding_count=len(findings))], "solidity-security"

    monkeypatch.setattr("app.main.analyze_solidity", fake_analyze)
    response = client.post(
        "/api/v1/validate-remediation",
        json={
            "filename": "Vault.sol",
            "original_source": "vulnerable source",
            "revised_source": "fixed source",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "improved"
    assert payload["original_finding_count"] == 1
    assert payload["revised_finding_count"] == 0


def test_analyze_returns_line_level_reentrancy_finding() -> None:
    source = """contract Vault {\n    function withdraw() external {\n        (bool ok,) = msg.sender.call{value: 1 ether}(\"\");\n        require(ok);\n    }\n}\n"""

    response = client.post(
        "/api/v1/analyze",
        json={"filename": "Vault.sol", "source": source},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_count"] >= 1
    assert payload["pipeline"] == "solidity-security"
    assert any(finding["category"] == "reentrancy" for finding in payload["findings"])
    assert any(finding["line"] == 3 for finding in payload["findings"])
    reentrancy = next(
        finding for finding in payload["findings"] if finding["category"] == "reentrancy"
    )
    assert set(reentrancy["source_tools"]) == {
        "securexai-pattern-detector",
        "semgrep",
    }


def test_slither_finds_reentrancy() -> None:
    source = """pragma solidity ^0.8.20;
contract Payments {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""

    response = client.post(
        "/api/v1/analyze",
        json={"filename": "Payments.sol", "source": source},
    )

    assert response.status_code == 200
    payload = response.json()
    slither_findings = [finding for finding in payload["findings"] if "slither" in finding["source_tools"]]
    assert slither_findings
    assert any(finding["line"] == 6 for finding in slither_findings)
    assert {tool["tool"] for tool in payload["tool_runs"]} == {
        "semgrep",
        "slither",
        "securexai-ml",
    }
    assert next(
        tool for tool in payload["tool_runs"] if tool["tool"] == "securexai-ml"
    )["status"] == "completed"


def test_rust_analysis_routes_unsupported_tools_honestly() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "filename": "lib.rs",
            "language": "rust",
            "source": "pub fn transfer() { unsafe { /* review */ } }",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["language"] == "rust"
    assert payload["pipeline"] == "rust-security"
    assert payload["finding_count"] == 0
    assert payload["tool_runs"][0]["tool"] == "language-specific-pipeline"
    assert payload["tool_runs"][0]["status"] == "skipped"


def test_remediation_returns_validated_guidance_without_auto_apply() -> None:
    response = client.post(
        "/api/v1/remediate",
        json={
            "rule_id": "SEC-REENTRANCY-001",
            "title": "External call may enable reentrancy",
            "category": "reentrancy",
            "severity": "critical",
            "confidence": 0.78,
            "line": 6,
            "code": "msg.sender.call{value: amount}(\"\");",
            "explanation": "External call before state update.",
            "recommendation": "Use checks-effects-interactions.",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] == "gemini-warning"
    assert payload["auto_apply"] is False
    assert payload["validation_steps"]


def test_repair_reports_ai_unavailable_without_changing_source(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
    response = client.post(
        "/api/v1/repair",
        json={"filename": "Contract.sol", "source": "pragma solidity ^0.8.20;"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "unavailable"
    assert payload["fixed_source"] is None
    assert payload["provider"] == "gemini-warning"
    assert "No source was changed" in payload["report"]
    assert "Warning: Gemini repair generation is unavailable" in payload["report"]
    assert payload["compile_status"] == "unavailable"


def test_repair_rejects_incomplete_generated_source(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
    from app.remediation import _parse_repair_response

    try:
        _parse_repair_response(
            '{"fixed_source":"contract Broken { function f() external {","report":"incomplete"}'
        )
    except ValueError as error:
        assert "unbalanced" in str(error)
    else:
        raise AssertionError("Incomplete Solidity must be rejected")


def test_solidity_compiler_rejects_invalid_generated_source() -> None:
    from app.remediation import _compile_solidity

    status, message = _compile_solidity(
        "pragma solidity ^0.8.20; contract Broken { function f() external {"
    )

    assert status == "error"
    assert message


def test_report_returns_audit_summary() -> None:
    response = client.post(
        "/api/v1/report",
        json={
            "filename": "Contract.sol",
            "language": "solidity",
            "pipeline": "solidity-security",
            "finding_count": 1,
            "findings": [],
            "tool_runs": [],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] in {"gemini-warning", "gemini:gemini-2.5-flash"}
    assert payload["recommended_actions"]


def test_report_falls_back_when_llm_returns_invalid_shape(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
    response = client.post(
        "/api/v1/report",
        json={
            "filename": "Contract.sol",
            "language": "solidity",
            "pipeline": "solidity-security",
            "finding_count": 0,
            "findings": [],
            "tool_runs": [],
        },
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "gemini-warning"


def test_provider_payload_uses_native_gemini_json_format_for_google_endpoints() -> None:
    from app.reporting import _build_chat_request_body

    body = _build_chat_request_body(
        "https://generativelanguage.googleapis.com/v1beta",
        "gemini-2.5-flash",
        [{"role": "user", "content": "hello"}],
    )

    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert body["contents"][0]["parts"][0]["text"].startswith("User:")
    assert "response_format" not in body
