"""Shared data model for every security check result."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Outcome of a single control."""

    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    """Impact of the control when it is not satisfied."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Assessment categories (each carries a fixed share of the 100 points)."""

    DNS = "dns"
    TLS = "tls"
    HTTP = "http"

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self]


CATEGORY_LABELS: dict[Category, str] = {
    Category.DNS: "DNS & Email Security",
    Category.TLS: "TLS/HTTPS",
    Category.HTTP: "HTTP Security Headers",
}


@dataclass(frozen=True)
class CheckDefinition:
    """Static metadata of a control (see ``core.catalog``)."""

    id: str
    name: str
    category: Category
    weight: float
    severity: Severity
    description: str
    risk_explanation: str
    recommendation: str


@dataclass
class CheckResult:
    """Result of one control, as produced by a scanner module."""

    id: str
    name: str
    category: Category
    status: Status
    severity: Severity
    weight: float
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    risk_explanation: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation (enums become strings)."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "category_label": self.category.label,
            "status": self.status.value,
            "severity": self.severity.value,
            "weight": self.weight,
            "summary": self.summary,
            "evidence": self.evidence,
            "description": self.description,
            "risk_explanation": self.risk_explanation,
            "recommendation": self.recommendation,
        }
