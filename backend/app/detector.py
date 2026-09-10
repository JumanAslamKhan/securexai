import re
from collections.abc import Callable

from app.models import Finding, Severity


Rule = tuple[str, str, str, Severity, float, str, str, str, Callable[[str], bool]]


def _contains(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern)
    return lambda line: bool(compiled.search(line))


RULES: tuple[Rule, ...] = (
    (
        "SEC-REENTRANCY-001",
        "External call may enable reentrancy",
        "reentrancy",
        "critical",
        0.78,
        "An external call is made from the contract and may transfer control before state is finalized.",
        "Apply checks-effects-interactions, update state before the call, and consider a reentrancy guard.",
        _contains(r"\.call\s*\{"),
    ),
    (
        "SEC-ACCESS-001",
        "tx.origin used for authorization",
        "access-control",
        "high",
        0.96,
        "tx.origin can be manipulated through an intermediate contract and is unsafe for authorization.",
        "Use msg.sender and explicit role or ownership checks instead.",
        _contains(r"\btx\.origin\b"),
    ),
    (
        "SEC-ARITH-001",
        "Potential unchecked arithmetic",
        "arithmetic",
        "medium",
        0.62,
        "Arithmetic in this expression may overflow or underflow depending on the compiler and context.",
        "Use Solidity 0.8+ checked arithmetic or SafeMath where legacy compatibility is required.",
        _contains(r"\b(?:uint|int)\w*\s+[A-Za-z_]\w*\s*[+\-]\s*"),
    ),
    (
        "SEC-EXTERNAL-001",
        "Return value from external call may be unchecked",
        "unchecked-call",
        "high",
        0.74,
        "The result of a low-level external call should be checked before execution continues.",
        "Capture the success value and revert or handle failure explicitly.",
        _contains(r"\.(?:send|transfer|delegatecall|staticcall)\s*\("),
    ),
    (
        "SEC-DESTRUCT-001",
        "Contract destruction capability detected",
        "dangerous-operation",
        "high",
        0.98,
        "selfdestruct can permanently remove contract code and transfer its balance.",
        "Restrict this operation with strong access control or remove it if it is not essential.",
        _contains(r"\bselfdestruct\s*\("),
    ),
)


def analyze_source(filename: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for (
            rule_id,
            title,
            category,
            severity,
            confidence,
            explanation,
            recommendation,
            matches,
        ) in RULES:
            if matches(stripped):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        line=line_number,
                        code=stripped,
                        explanation=explanation,
                        recommendation=recommendation,
                    )
                )
    return findings
