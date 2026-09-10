import re
from collections.abc import Callable
from dataclasses import dataclass

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
        _contains(r"\btx\.origin\b.*\b(?:require|if|assert)\b|\b(?:require|if|assert)\b.*\btx\.origin\b"),
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


@dataclass(frozen=True)
class FunctionContext:
    start: int
    end: int
    guarded: bool


def _function_contexts(lines: list[str]) -> list[FunctionContext]:
    contexts: list[FunctionContext] = []
    function_start: int | None = None
    function_depth = 0
    function_guarded = False

    for line_number, line in enumerate(lines, start=1):
        if function_start is None and re.search(r"\bfunction\b", line):
            function_start = line_number
            function_guarded = "nonReentrant" in line
            function_depth = 0
        if function_start is None:
            continue

        function_depth += line.count("{") - line.count("}")
        if function_depth <= 0 and "{" in line:
            contexts.append(
                FunctionContext(function_start, line_number, function_guarded)
            )
            function_start = None
            function_guarded = False

    if function_start is not None:
        contexts.append(FunctionContext(function_start, len(lines), function_guarded))
    return contexts


def _context_for_line(
    contexts: list[FunctionContext], line_number: int
) -> FunctionContext | None:
    return next(
        (context for context in contexts if context.start <= line_number <= context.end),
        None,
    )


def _state_write_after(lines: list[str], line_number: int, context: FunctionContext) -> bool:
    state_write = re.compile(r"(?:\+\+|--|\+=|-=|\*=|/=|\b(?:balances|mapping|owner)\b\s*=)")
    return any(
        state_write.search(lines[index - 1])
        for index in range(line_number + 1, context.end + 1)
    )


def analyze_source(filename: str, source: str) -> list[Finding]:
    del filename
    lines = source.splitlines()
    contexts = _function_contexts(lines)
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        context = _context_for_line(contexts, line_number)
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
            if not matches(stripped):
                continue
            if rule_id == "SEC-REENTRANCY-001":
                if context is not None and context.guarded:
                    continue
                if context is not None and not _state_write_after(lines, line_number, context):
                    confidence = 0.68
                    explanation = (
                        "An unguarded external call transfers control; review the function "
                        "for state changes and checks-effects-interactions ordering."
                    )
            if rule_id == "SEC-ACCESS-001" and not re.search(
                r"\b(?:require|if|assert)\b", stripped
            ):
                continue
            if rule_id == "SEC-EXTERNAL-001" and re.search(
                r"(?:require|assert)\s*\([^;]*\.(?:send|delegatecall|staticcall)\s*\(",
                stripped,
            ):
                continue
            if rule_id == "SEC-EXTERNAL-001" and ".transfer(" in stripped:
                continue
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
