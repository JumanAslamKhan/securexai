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
    assert {tool["tool"] for tool in payload["tool_runs"]} == {"semgrep", "slither"}


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
    assert payload["provider"] == "securexai-rule-guidance"
    assert payload["auto_apply"] is False
    assert payload["validation_steps"]


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
    assert payload["provider"] in {
        "local-ollama:llama3:latest",
        "local-ollama:qwen2.5-coder:7b",
        "securexai-local-report",
    }
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
    assert response.json()["provider"] == "securexai-local-report"
