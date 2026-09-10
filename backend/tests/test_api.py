from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


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


def test_analyze_returns_line_level_reentrancy_finding() -> None:
    source = """contract Vault {\n    function withdraw() external {\n        (bool ok,) = msg.sender.call{value: 1 ether}(\"\");\n        require(ok);\n    }\n}\n"""

    response = client.post(
        "/api/v1/analyze",
        json={"filename": "Vault.sol", "source": source},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_count"] >= 1
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
