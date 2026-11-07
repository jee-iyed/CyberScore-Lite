"""Offline sample assessment for demonstrations without network access.

The data below is ILLUSTRATIVE ONLY: it was not collected from any host. It is
attached to the reserved documentation domain ``sample-company.example`` and the
report is flagged ``sample_data: true`` so it can never be mistaken for a real
scan.
"""

from __future__ import annotations

from core.assessment import AssessmentResult
from core.catalog import make_result
from core.models import Status
from core.report import build_report
from core.scoring import compute_score

SAMPLE_DOMAIN = "sample-company.example"
SAMPLE_ADDRESSES = ["192.0.2.10"]  # RFC 5737 documentation address
_NOTE = {"sample_data": True}


def build_sample_assessment() -> AssessmentResult:
    """Return a fully scored, clearly labelled sample assessment."""
    results = [
        make_result("dns_resolution", Status.PASS, "Resolves to 1 address(es).",
                    {**_NOTE, "ipv4": SAMPLE_ADDRESSES, "ipv6": []}),
        make_result("dns_mx", Status.PASS, "2 MX record(s) published.", _NOTE),
        make_result("dns_spf", Status.PASS, "Single valid SPF record with soft fail (~all).",
                    {**_NOTE, "all_qualifier": "~"}),
        make_result("dns_dmarc", Status.WARNING,
                    "DMARC policy is p=none (monitoring only): spoofed mail is not blocked.",
                    {**_NOTE, "policy": "none", "pct": 100}),
        make_result("dns_caa", Status.WARNING,
                    "No CAA record: any public certificate authority may issue certificates.",
                    _NOTE),
        make_result("tls_certificate_trust", Status.PASS,
                    "Certificate chain is trusted and matches the hostname.",
                    {**_NOTE, "validated": True}),
        make_result("tls_certificate_expiry", Status.WARNING,
                    "Certificate expires in 21 day(s).", {**_NOTE, "days_remaining": 21}),
        make_result("tls_protocol_version", Status.PASS,
                    "Negotiated TLSv1.3; TLS 1.0/1.1 are refused.",
                    {**_NOTE, "negotiated_version": "TLSv1.3"}),
        make_result("http_hsts", Status.FAIL,
                    "HSTS max-age=0 tells browsers to delete the HSTS policy.",
                    {**_NOTE, "max_age": 0}),
        make_result("http_csp", Status.WARNING,
                    "CSP is present but weak: 'unsafe-inline' allows inline scripts.",
                    {**_NOTE, "issues": ["'unsafe-inline' allows inline scripts"]}),
        make_result("http_frame_protection", Status.PASS, "X-Frame-Options: SAMEORIGIN.", _NOTE),
        make_result("http_content_type_options", Status.PASS,
                    "MIME sniffing disabled (nosniff).", _NOTE),
        make_result("http_referrer_policy", Status.WARNING,
                    "Referrer-Policy is missing (modern browsers default to "
                    "strict-origin-when-cross-origin, older ones may leak full URLs).", _NOTE),
        make_result("http_https_redirect", Status.ERROR,
                    "Plain HTTP endpoint could not be assessed.",
                    {**_NOTE, "error": "Connection to port 80 timed out."}),
    ]
    score = compute_score(results)
    report = build_report(
        SAMPLE_DOMAIN, results, score, addresses=SAMPLE_ADDRESSES, sample_data=True
    )
    return AssessmentResult(
        SAMPLE_DOMAIN,
        list(SAMPLE_ADDRESSES),
        results,
        score,
        report,
        sample_data=True,
        notices=["Sample data: illustrative only, no host was contacted."],
    )
