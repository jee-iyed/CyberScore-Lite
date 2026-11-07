"""Pure presentation helpers used by the Streamlit UI (unit-testable)."""

from __future__ import annotations

import json
from typing import Any, Iterable

from core.models import CheckResult, Status

STATUS_ICONS: dict[str, str] = {
    Status.PASS.value: "✅ PASS",
    Status.WARNING.value: "⚠️ WARNING",
    Status.FAIL.value: "❌ FAIL",
    Status.ERROR.value: "⛔ ERROR",
    Status.NOT_APPLICABLE.value: "➖ N/A",
}

PRIORITY_LABELS = {
    "P1": "🔴 P1 · Fix now",
    "P2": "🟠 P2 · Plan soon",
    "P3": "🟡 P3 · Hardening",
}


def status_label(status: Status | str) -> str:
    value = status.value if isinstance(status, Status) else str(status)
    return STATUS_ICONS.get(value, value)


def format_score(score: float | None) -> str:
    """Render a 0-100 score with at most one decimal (82.5 -> "82.5", 80.0 -> "80")."""
    if score is None:
        return "N/A"
    return f"{score:.1f}".removesuffix(".0")


def evidence_preview(evidence: dict[str, Any], limit: int = 140) -> str:
    """Compact one-line rendering of evidence for tables."""
    shown = {k: v for k, v in evidence.items() if k not in ("evaluated_response", "sample_data")}
    if not shown:
        return "—"
    text = json.dumps(shown, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def controls_rows(results: Iterable[CheckResult]) -> list[dict[str, Any]]:
    """Rows for the controls table."""
    return [
        {
            "Control": r.name,
            "Category": r.category.label,
            "Status": status_label(r.status),
            "Severity": r.severity.value.capitalize(),
            "Weight": r.weight,
            "Finding": r.summary,
            "Evidence": evidence_preview(r.evidence),
            "Recommendation": "—" if r.status is Status.PASS else r.recommendation,
        }
        for r in results
    ]


def report_filename(domain: str, generated_at_utc: str) -> str:
    stamp = generated_at_utc.replace(":", "").replace("-", "")[:15]
    safe_domain = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in domain)
    return f"cyberscore-{safe_domain}-{stamp}.json"
