"""Small shared data types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """One explainable signal that contributed to (or reduced) the risk score.

    ``weight`` is added to the score. Negative weights are *mitigating*
    evidence, e.g. a look-alike domain that shares the real brand's
    nameservers (a typical defensive registration).
    """

    code: str
    severity: str
    weight: int
    title: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InputError(ValueError):
    """Raised when the input cannot be analysed at all (too long, NUL byte, ...)."""
