"""Layer 4: deterministic final reporting from normalized analyzer results."""

from app.models import AnalysisResponse, FinalReport


def build_final_report(analysis: AnalysisResponse) -> FinalReport:
    risk_summary = {
        severity: sum(finding.severity == severity for finding in analysis.findings)
        for severity in ("critical", "high", "medium", "low")
    }
    recommended_actions = [
        finding.recommendation
        for finding in analysis.findings
        if finding.recommendation
    ]
    if not recommended_actions:
        recommended_actions = ["No normalized findings require remediation."]

    unavailable_tools = [
        tool.tool for tool in analysis.tool_runs if tool.status in {"unavailable", "error"}
    ]
    validation_note = (
        "All reported analyzer runs completed. Review the source and evidence before deployment."
        if not unavailable_tools
        else "Incomplete analyzer runs: " + ", ".join(unavailable_tools) + ". Results require manual review."
    )
    if analysis.findings:
        executive_summary = (
            f"{analysis.filename} contains {analysis.finding_count} normalized finding(s) "
            f"across the {analysis.pipeline} pipeline."
        )
    else:
        executive_summary = f"No normalized findings were reported for {analysis.filename}."

    return FinalReport(
        filename=analysis.filename,
        provider="securexai-final-report",
        title=f"SecureXAI final report: {analysis.filename}",
        executive_summary=executive_summary,
        risk_summary=risk_summary,
        recommended_actions=list(dict.fromkeys(recommended_actions)),
        validation_note=validation_note,
        finding_count=analysis.finding_count,
        tool_runs=analysis.tool_runs,
    )