from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_returns_line_level_reentrancy_finding() -> None:
    source = """contract Vault {\n    function withdraw() external {\n        (bool ok,) = msg.sender.call{value: 1 ether}(\"\");\n        require(ok);\n    }\n}\n"""

    response = client.post(
        "/api/v1/analyze",
        json={"filename": "Vault.sol", "source": source},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["category"] == "reentrancy"
    assert payload["findings"][0]["line"] == 3
