from collections.abc import Iterable

from app.models import Finding


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding_key(finding: Finding) -> tuple[str, int]:
    return finding.category, finding.line


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, int], Finding] = {}
    tools: dict[tuple[str, int], set[str]] = {}

    for finding in findings:
        key = _finding_key(finding)
        if key not in merged:
            merged[key] = finding.model_copy(deep=True)
            tools[key] = {finding.source_tool}
            continue

        current = merged[key]
        tools[key].add(finding.source_tool)
        if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[current.severity]:
            current.severity = finding.severity
        if finding.confidence > current.confidence:
            current.confidence = finding.confidence
        if len(finding.explanation) > len(current.explanation):
            current.explanation = finding.explanation
        if len(finding.recommendation) > len(current.recommendation):
            current.recommendation = finding.recommendation

    normalized: list[Finding] = []
    for key, finding in merged.items():
        finding.source_tools = sorted(tools[key])
        normalized.append(finding)
    return normalized
