from app.models import Finding, RemediationResponse


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


def build_remediation(finding: Finding) -> RemediationResponse:
    summary, patch_guidance = _GUIDANCE.get(
        finding.rule_id,
        (
            "Review this finding with a Solidity security specialist.",
            finding.recommendation,
        ),
    )
    return RemediationResponse(
        rule_id=finding.rule_id,
        provider="securexai-rule-guidance",
        summary=summary,
        patch_guidance=patch_guidance,
        validation_steps=[
            "Review the generated change as a diff.",
            "Compile the modified contract with the declared Solidity version.",
            "Re-run Semgrep and Slither after the change.",
        ],
        auto_apply=False,
    )
