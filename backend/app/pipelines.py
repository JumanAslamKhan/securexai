from app.analyzers import run_external_analyzers
from app.detector import analyze_source
from app.models import Finding, Language, ToolRun
from app.normalizer import deduplicate_findings


def analyze_solidity(source: str, filename: str) -> tuple[list[Finding], list[ToolRun], str]:
    findings = analyze_source(filename, source)
    external_findings, tool_runs = run_external_analyzers(filename, source, "solidity")
    findings = deduplicate_findings(findings + external_findings)
    return findings, tool_runs, "solidity-security"


def analyze_other_language(
    source: str, filename: str, language: Language
) -> tuple[list[Finding], list[ToolRun], str]:
    del source, filename
    tool_runs = [
        ToolRun(
            tool="language-specific-pipeline",
            status="skipped",
            finding_count=0,
            message=(
                f"The {language} pipeline is reserved for language-specific rules; "
                "the Solidity workflow was not used."
            ),
        )
    ]
    return [], tool_runs, f"{language}-security"
