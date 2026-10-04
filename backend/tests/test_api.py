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


def test_autofix_skips_gemini_when_analysis_has_no_findings() -> None:
    response = client.post(
        "/api/v1/autofix",
        json={"filename": "Empty.sol", "source": "contract Empty {}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "fully-patched"
    assert payload["iterations"] == 0
    assert payload["patched_source"] == "contract Empty {}"


def test_autofix_reanalyzes_gemini_candidate(monkeypatch) -> None:
    finding = Finding(
        rule_id="SEC-REENTRANCY-001",
        title="Reentrancy",
        category="reentrancy",
        severity="critical",
        confidence=0.9,
        line=3,
        code="external call",
        explanation="External call before state update.",
        recommendation="Use checks-effects-interactions.",
    )

    def fake_analyze(source: str, filename: str) -> tuple[list[Finding], list[ToolRun], str]:
        del filename
        current_findings = [finding] if "vulnerable" in source else []
        return current_findings, [ToolRun(tool="test-analyzer", status="completed", finding_count=len(current_findings))], "solidity-security"

    monkeypatch.setattr("app.codegen.analyze_solidity", fake_analyze)
    monkeypatch.setattr(
        "app.codegen._chat_completion",
        lambda messages, model: "contract Fixed {}",
    )
    response = client.post(
        "/api/v1/autofix",
        json={
            "filename": "Vault.sol",
            "source": "contract Vault { /* vulnerable */ }",
            "max_iterations": 2,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "fully-patched"
    assert payload["provider"] == "gemini:gemini-3.8-flash"
    assert payload["original_finding_count"] == 1
    assert payload["remaining_finding_count"] == 0
    assert "-contract Vault" in payload["diff"]


def test_autofix_upgrades_retired_gemini_model(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    from app.codegen import _configured_model

    assert _configured_model() == "gemini-3.8-flash"


def test_final_report_is_available_without_gemini() -> None:
    response = client.post(
        "/api/v1/report",
        json={
            "filename": "Clean.sol",
            "language": "solidity",
            "pipeline": "solidity-security",
            "finding_count": 0,
            "findings": [],
            "tool_runs": [],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] == "securexai-final-report"
    assert payload["finding_count"] == 0


def test_detailed_final_report_accepts_source_comparison(monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    response = client.post(
        "/api/v1/final-report",
        json={
            "analysis": {
                "filename": "Vault.sol",
                "language": "solidity",
                "pipeline": "solidity-security",
                "finding_count": 0,
                "findings": [],
                "tool_runs": [],
            },
            "original_source": "contract Vulnerable {}",
            "revised_source": "contract Repaired {}",
        },
    )

    assert response.status_code == 200
    assert "Regeneration comparison" in response.json()["detailed_report"]


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





