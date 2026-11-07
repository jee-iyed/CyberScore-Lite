"""Explainable weighted scoring engine.

Rules
-----
* Category weights: DNS & Email 25, TLS/HTTPS 40, HTTP headers 35 (= 100).
* A control earns ``weight x factor`` where PASS = 1.0, WARNING = 0.5,
  FAIL = 0.0.
* ERROR and NOT_APPLICABLE controls are excluded from the evaluable points.
* ``score = 100 x earned / evaluated`` (``None`` if nothing was evaluated).
* ``coverage = 100 x evaluated / applicable`` where *applicable* is the total
  weight minus NOT_APPLICABLE weight. ERROR therefore lowers coverage, while
  a control that genuinely does not apply does not.
* A score is flagged as not reliable (and gets no grade) when coverage is
  below ``MIN_RELIABLE_COVERAGE_PERCENT``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from core.catalog import CATEGORY_WEIGHTS
from core.config import MIN_RELIABLE_COVERAGE_PERCENT
from core.models import Category, CheckResult, Status

STATUS_FACTORS: dict[Status, float] = {
    Status.PASS: 1.0,
    Status.WARNING: 0.5,
    Status.FAIL: 0.0,
}

GRADE_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (0.0, "F"),
)


def _normalise(result: CheckResult | Mapping[str, Any]) -> tuple[Category, Status, float]:
    if isinstance(result, CheckResult):
        return result.category, result.status, float(result.weight)
    return Category(result["category"]), Status(result["status"]), float(result["weight"])


def grade_for(score: float | None) -> str | None:
    """Letter grade for a 0-100 score."""
    if score is None:
        return None
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _pct(numerator: float, denominator: float) -> float | None:
    return round(100.0 * numerator / denominator, 1) if denominator > 0 else None


def compute_score(results: Iterable[CheckResult | Mapping[str, Any]]) -> dict[str, Any]:
    """Compute global and per-category scores, coverage and status counts."""
    per_category: dict[Category, dict[str, float]] = {
        category: {"earned": 0.0, "evaluated": 0.0, "not_applicable": 0.0}
        for category in CATEGORY_WEIGHTS
    }
    counts = {status.value: 0 for status in Status}

    for result in results:
        category, status, weight = _normalise(result)
        counts[status.value] += 1
        bucket = per_category[category]
        if status in STATUS_FACTORS:
            bucket["evaluated"] += weight
            bucket["earned"] += weight * STATUS_FACTORS[status]
        elif status is Status.NOT_APPLICABLE:
            bucket["not_applicable"] += weight

    categories: dict[str, dict[str, Any]] = {}
    for category, max_weight in CATEGORY_WEIGHTS.items():
        bucket = per_category[category]
        applicable = max_weight - bucket["not_applicable"]
        categories[category.value] = {
            "label": category.label,
            "max_points": max_weight,
            "applicable_points": applicable,
            "evaluated_points": bucket["evaluated"],
            "earned_points": round(bucket["earned"], 2),
            "score": _pct(bucket["earned"], bucket["evaluated"]),
            "coverage_percent": _pct(bucket["evaluated"], applicable) or 0.0,
        }

    total = sum(CATEGORY_WEIGHTS.values())
    earned = sum(b["earned"] for b in per_category.values())
    evaluated = sum(b["evaluated"] for b in per_category.values())
    applicable = total - sum(b["not_applicable"] for b in per_category.values())

    score = _pct(earned, evaluated)
    coverage = _pct(evaluated, applicable) or 0.0
    reliable = score is not None and coverage >= MIN_RELIABLE_COVERAGE_PERCENT

    return {
        "score": score,
        "grade": grade_for(score) if reliable else None,
        "reliable": reliable,
        "coverage_percent": coverage,
        "earned_points": round(earned, 2),
        "evaluated_points": evaluated,
        "applicable_points": applicable,
        "total_points": total,
        "categories": categories,
        "counts": counts,
        "passed": counts[Status.PASS.value],
        "warnings": counts[Status.WARNING.value],
        "failed": counts[Status.FAIL.value],
        "errors": counts[Status.ERROR.value],
        "not_applicable": counts[Status.NOT_APPLICABLE.value],
    }
