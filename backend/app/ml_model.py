import os
import re
from pathlib import Path
from typing import Any

import joblib

from app.models import Finding, ToolRun


MODEL_PATH = Path(
    os.getenv(
        "SECUREXAI_ML_MODEL_PATH",
        str(Path(__file__).resolve().parents[1] / "artifacts" / "securexai_ml.joblib"),
    )
)
MIN_CONFIDENCE = float(os.getenv("SECUREXAI_ML_MIN_CONFIDENCE", "0.45"))
REENTRANCY_THRESHOLD = float(os.getenv("SECUREXAI_ML_REENTRANCY_THRESHOLD", "0.30"))

_MODEL: dict[str, Any] | None = None

_CATEGORY_MAP = {
    "Reentrancy": ("reentrancy", "critical", r"\.call\s*\{"),
    "Access Control": ("access-control", "high", r"\b(?:tx\.origin|onlyOwner|require)\b"),
    "Arithmetic Overflow/Underflow": ("arithmetic", "medium", r"[+\-*/]"),
    "Timestamp Dependence": ("timestamp-dependence", "medium", r"\b(?:block\.timestamp|now)\b"),
    "Unchecked External Call": ("unchecked-call", "high", r"\.(?:call|send|delegatecall|staticcall)\s*\("),
    "Other": ("other", "medium", r"\b(?:assembly|delegatecall|selfdestruct)\b"),
}


def _load_model() -> dict[str, Any] | None:
    global _MODEL
    if _MODEL is None and MODEL_PATH.exists():
        loaded = joblib.load(MODEL_PATH)
        if isinstance(loaded, dict) and "model" in loaded:
            _MODEL = loaded
    return _MODEL


def _function_segments(source: str) -> list[tuple[int, str]]:
    lines = source.splitlines()
    segments: list[tuple[int, str]] = []
    start: int | None = None
    depth = 0
    opened = False
    for line_number, line in enumerate(lines, start=1):
        if start is None and re.search(r"\b(?:function|constructor|receive|fallback)\b", line):
            start = line_number
            depth = 0
            opened = False
        if start is None:
            continue
        opening_count = line.count("{")
        closing_count = line.count("}")
        opened = opened or opening_count > 0
        depth += opening_count - closing_count
        if opened and depth <= 0:
            segments.append((start, "\n".join(lines[start - 1 : line_number])))
            start = None
            opened = False
    return segments or [(1, source)]


def _line_for_prediction(source: str, label: str, offset: int = 0) -> int:
    pattern = _CATEGORY_MAP.get(label, _CATEGORY_MAP["Other"])[2]
    for line_number, line in enumerate(source.splitlines(), start=1):
        if re.search(pattern, line, re.IGNORECASE):
            return offset + line_number
    return offset + 1


def run_ml_analyzer(source: str) -> tuple[list[Finding], ToolRun]:
    model_bundle = _load_model()
    if model_bundle is None:
        return [], ToolRun(
            tool="securexai-ml",
            status="unavailable",
            finding_count=0,
            message=f"Trained model not found at {MODEL_PATH}. Run scripts/train_ml_model.py.",
        )

    model = model_bundle["model"]
    labels = list(model_bundle["labels"])
    findings: list[Finding] = []
    for start_line, segment in _function_segments(source):
        probabilities = model.predict_proba([segment])[0]
        best_index = int(probabilities.argmax())
        label = labels[best_index]
        confidence = float(probabilities[best_index])
        if "Reentrancy" in labels:
            reentrancy_index = labels.index("Reentrancy")
            reentrancy_confidence = float(probabilities[reentrancy_index])
            if reentrancy_confidence >= REENTRANCY_THRESHOLD:
                label = "Reentrancy"
                confidence = reentrancy_confidence
        if label == "safe" or confidence < MIN_CONFIDENCE:
            continue

        category, severity, _ = _CATEGORY_MAP.get(label, _CATEGORY_MAP["Other"])
        line = _line_for_prediction(segment, label, start_line - 1)
        findings.append(Finding(
            rule_id=f"ML-{label.upper().replace(' ', '-').replace('/', '-')}"
            .replace("_", "-"),
            title=f"ML model detected possible {label.lower()}",
            category=category,
            severity=severity,
            confidence=confidence,
            line=line,
            code=source.splitlines()[line - 1].strip() if source.splitlines() else "",
            explanation=(
                f"The SecureXAI ML classifier predicted {label} for this function with "
                f"{confidence:.0%} confidence. Treat this as additional evidence "
                "alongside deterministic analyzers."
            ),
            recommendation="Review the ML signal with the source and analyzer findings before making changes.",
            source_tool="securexai-ml",
        ))

    if not findings:
        return [], ToolRun(
            tool="securexai-ml",
            status="completed",
            finding_count=0,
            message=f"No function prediction exceeded the {MIN_CONFIDENCE:.0%} confidence threshold.",
        )
    return findings, ToolRun(
        tool="securexai-ml",
        status="completed",
        finding_count=len(findings),
        message=f"Scored {len(_function_segments(source))} function segment(s); emitted {len(findings)} ML signal(s).",
    )