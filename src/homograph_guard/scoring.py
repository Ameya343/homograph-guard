"""Turn findings into a 0-100 score and a verdict.

The score is the sum of finding weights, clamped to 0..100. Weights are
deliberately explainable rather than "machine-learned": every point can be
traced back to one finding in the report.
"""

from __future__ import annotations

from .models import Finding

VERDICT_LABELS = {
    "high_risk": "HIGH RISK",
    "suspicious": "SUSPICIOUS",
    "caution": "CAUTION",
    "no_indicators": "NO INDICATORS FOUND",
    "error": "ERROR",
}

# Process exit codes (useful in SOAR playbooks and shell pipelines).
EXIT_CODES = {"no_indicators": 0, "caution": 0, "suspicious": 3, "high_risk": 4, "error": 1}


def score(findings: list[Finding]) -> tuple[int, str]:
    total = max(0, min(100, sum(f.weight for f in findings)))
    if any(f.severity == "critical" for f in findings):
        total = max(total, 70)
    if total >= 70:
        return total, "high_risk"
    if total >= 40:
        return total, "suspicious"
    if total >= 15:
        return total, "caution"
    return total, "no_indicators"


def exit_code(verdicts: list[str]) -> int:
    if "high_risk" in verdicts:
        return EXIT_CODES["high_risk"]
    if "suspicious" in verdicts:
        return EXIT_CODES["suspicious"]
    if "error" in verdicts:
        return EXIT_CODES["error"]
    return 0
