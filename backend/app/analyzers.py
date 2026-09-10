import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.models import Finding, ToolRun

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEMGREP_RULES = PROJECT_ROOT / "rules" / "semgrep" / "solidity.yml"


def _executable(name: str, environment_name: str) -> str | None:
    configured = os.getenv(environment_name)
    if configured and Path(configured).exists():
        return configured
    discovered = shutil.which(name)
    if discovered:
        return discovered
    local_scripts = PROJECT_ROOT / ".tools-venv" / "Scripts"
    local_executable = local_scripts / f"{name}.exe"
    return str(local_executable) if local_executable.exists() else None


def _run(command: list[str], timeout: int = 90) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, "", str(error)
    return completed.returncode, completed.stdout, completed.stderr


def _line_from_semgrep(result: dict[str, Any]) -> int:
    return int(result.get("start", {}).get("line", 1))


def _semgrep_finding(result: dict[str, Any], source: str) -> Finding:
    raw_check_id = result.get("check_id", "securexai.semgrep.unknown")
    check_id = raw_check_id.split("securexai.", 1)[-1]
    check_id = f"semgrep.{check_id}"
    message = result.get("extra", {}).get("message", "Semgrep finding")
    line = _line_from_semgrep(result)
    category, severity = _semgrep_metadata(raw_check_id)
    return Finding(
        rule_id=check_id,
        title=message,
        category=category,
        severity=severity,
        confidence=0.85,
        line=line,
        code=source.splitlines()[line - 1].strip() if source.splitlines() else "",
        explanation=f"Semgrep matched rule {check_id} at this source location.",
        recommendation="Review the matched code and apply the recommended secure coding pattern.",
        source_tool="semgrep",
    )


def _semgrep_metadata(check_id: str) -> tuple[str, str]:
    if "reentrancy" in check_id:
        return "reentrancy", "critical"
    if "tx-origin" in check_id:
        return "access-control", "high"
    if "selfdestruct" in check_id:
        return "dangerous-operation", "high"
    return "unchecked-call", "high"


def run_semgrep(source: str) -> tuple[list[Finding], ToolRun]:
    executable = _executable("semgrep", "SEMGREP_PATH")
    if not executable:
        return [], ToolRun(tool="semgrep", status="unavailable", finding_count=0, message="Executable not found on PATH.")
    if not SEMGREP_RULES.exists():
        return [], ToolRun(tool="semgrep", status="error", finding_count=0, message="Semgrep rule file is missing.")

    with tempfile.TemporaryDirectory(prefix="securexai-") as directory:
        contract = Path(directory) / "Contract.sol"
        contract.write_text(source, encoding="utf-8")
        code, stdout, stderr = _run(
            [executable, "--config", str(SEMGREP_RULES), "--json", "--quiet", str(contract)]
        )
    if code not in (0, 1):
        return [], ToolRun(tool="semgrep", status="error", finding_count=0, message=stderr.strip() or "Semgrep failed.")
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], ToolRun(tool="semgrep", status="error", finding_count=0, message="Semgrep returned invalid JSON.")
    findings = [_semgrep_finding(item, source) for item in payload.get("results", [])]
    return findings, ToolRun(tool="semgrep", status="completed", finding_count=len(findings), message="")


def _slither_line(item: dict[str, Any]) -> int:
    source_mapping = item.get("source_mapping", {})
    lines = source_mapping.get("lines", [])
    return int(lines[0]) if lines else 1


def _slither_finding(item: dict[str, Any], source: str) -> Finding:
    check = item.get("check", "slither.unknown")
    description = item.get("description", check)
    line = _slither_line(item)
    category, severity = _slither_metadata(check, item.get("impact", "Medium"))
    lines = source.splitlines()
    return Finding(
        rule_id=f"slither.{check}",
        title=description.split("\n", 1)[0],
        category=category,
        severity=severity,
        confidence=0.9,
        line=line,
        code=lines[line - 1].strip() if line <= len(lines) else "",
        explanation=description,
        recommendation="Review the Slither finding and apply its remediation guidance.",
        source_tool="slither",
    )


def _slither_metadata(check: str, impact: str) -> tuple[str, str]:
    check_lower = check.lower()
    if "reentr" in check_lower:
        return "reentrancy", "critical"
    if "tx-origin" in check_lower or "access" in check_lower or "suicidal" in check_lower:
        return "access-control", "high"
    if "unchecked" in check_lower:
        return "unchecked-call", "high"
    impact_lower = impact.lower()
    return "static-analysis", "high" if impact_lower in {"high", "critical"} else "medium"


def run_slither(source: str) -> tuple[list[Finding], ToolRun]:
    executable = _executable("slither", "SLITHER_PATH")
    if not executable:
        return [], ToolRun(tool="slither", status="unavailable", finding_count=0, message="Executable not found on PATH.")

    with tempfile.TemporaryDirectory(prefix="securexai-") as directory:
        contract = Path(directory) / "Contract.sol"
        contract.write_text(source, encoding="utf-8")
        code, stdout, stderr = _run([executable, str(contract), "--json", "-"])
    if code not in (0, 1):
        return [], ToolRun(tool="slither", status="error", finding_count=0, message=stderr.strip() or "Slither failed.")
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], ToolRun(tool="slither", status="error", finding_count=0, message="Slither returned invalid JSON.")
    detectors = payload.get("results", {}).get("detectors", [])
    findings = [_slither_finding(item, source) for item in detectors]
    return findings, ToolRun(tool="slither", status="completed", finding_count=len(findings), message="")


def run_external_analyzers(source: str) -> tuple[list[Finding], list[ToolRun]]:
    semgrep_findings, semgrep_status = run_semgrep(source)
    slither_findings, slither_status = run_slither(source)
    return semgrep_findings + slither_findings, [semgrep_status, slither_status]
