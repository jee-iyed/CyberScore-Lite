"""Assessment orchestration: validate -> resolve once -> scan -> score -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from core import dns_checks, http_checks, tls_checks
from core.models import CheckResult, Status
from core.network import (
    NoAddressError,
    TargetResolutionError,
    UnsafeTargetError,
    build_target,
    resolve,
)
from core.report import build_report
from core.scoring import compute_score
from utils.validators import validate_domain

ProgressCallback = Callable[[str, float], None]


class AssessmentError(Exception):
    """The assessment was refused or aborted; the message is user-facing."""


@dataclass
class AssessmentResult:
    domain: str
    addresses: list[str]
    results: list[CheckResult]
    score: dict[str, Any]
    report: dict[str, Any]
    sample_data: bool = False
    notices: list[str] = field(default_factory=list)


def _noop(_message: str, _fraction: float) -> None:
    return None


def run_assessment(domain: str, progress: ProgressCallback | None = None) -> AssessmentResult:
    """Run the full, non-intrusive assessment of ``domain``.

    Raises:
        DomainValidationError: the input is not an acceptable domain.
        AssessmentError: the domain does not exist or resolves to a
            non-public address (no connection is attempted in that case).
    """
    report_progress = progress or _noop
    domain = validate_domain(domain)
    notices: list[str] = []

    report_progress("Resolving domain (A/AAAA)", 0.05)
    resolution = resolve(domain)
    if resolution.nxdomain:
        raise AssessmentError(f"The domain {domain} does not exist (NXDOMAIN).")

    target = None
    web_status, web_reason = Status.ERROR, ""
    try:
        target = build_target(resolution)
    except UnsafeTargetError as exc:
        raise AssessmentError(str(exc)) from exc
    except NoAddressError as exc:
        web_status, web_reason = Status.NOT_APPLICABLE, f"{exc} No web service to assess."
        notices.append(web_reason)
    except TargetResolutionError as exc:
        web_status, web_reason = Status.ERROR, str(exc)
        notices.append(web_reason)

    report_progress("Checking DNS & email security (SPF, DMARC, CAA, MX)", 0.20)
    results: list[CheckResult] = dns_checks.run_dns_checks(domain, resolution)

    if target is not None:
        report_progress("Inspecting TLS certificate and protocol", 0.50)
        results += tls_checks.run_tls_checks(target)
        report_progress("Analysing HTTP security headers and redirect", 0.75)
        results += http_checks.run_http_checks(target)
    else:
        results += tls_checks.not_assessed(web_status, web_reason)
        results += http_checks.not_assessed(web_status, web_reason)

    report_progress("Computing score and report", 0.95)
    score = compute_score(results)
    addresses = list(target.addresses) if target else []
    report = build_report(domain, results, score, addresses=addresses)
    report_progress("Assessment complete", 1.0)
    return AssessmentResult(domain, addresses, results, score, report, notices=notices)
