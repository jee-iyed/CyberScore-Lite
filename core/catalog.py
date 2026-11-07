"""Catalog of every control: weight, severity and remediation guidance.

The catalog is the single source of truth shared by the scanners, the scoring
engine and the report. Scanners only decide a status and collect evidence;
the descriptive fields come from here so that results stay homogeneous.
"""

from __future__ import annotations

from typing import Any

from core.models import Category, CheckDefinition, CheckResult, Severity, Status

CATEGORY_WEIGHTS: dict[Category, float] = {
    Category.DNS: 25.0,
    Category.TLS: 40.0,
    Category.HTTP: 35.0,
}

_DEFINITIONS: tuple[CheckDefinition, ...] = (
    # ------------------------------------------------------------- DNS (25)
    CheckDefinition(
        id="dns_resolution",
        name="DNS resolution (A/AAAA)",
        category=Category.DNS,
        weight=0.0,
        severity=Severity.INFO,
        description="Informational: public IPv4/IPv6 addresses published for the domain.",
        risk_explanation="Not scored. Determines whether web (TLS/HTTP) checks can run.",
        recommendation="Publish A/AAAA records only if the domain hosts a public service.",
    ),
    CheckDefinition(
        id="dns_mx",
        name="Mail exchangers (MX)",
        category=Category.DNS,
        weight=0.0,
        severity=Severity.INFO,
        description="Informational: whether the domain receives email (MX or Null MX).",
        risk_explanation=(
            "Not scored. A domain without MX can still be spoofed in the From: header, "
            "so SPF and DMARC remain relevant."
        ),
        recommendation=(
            "If the domain never receives mail, publish a Null MX record (RFC 7505): "
            '"0 ."'
        ),
    ),
    CheckDefinition(
        id="dns_spf",
        name="SPF record",
        category=Category.DNS,
        weight=10.0,
        severity=Severity.HIGH,
        description="Exactly one syntactically valid SPF record with a restrictive 'all'.",
        risk_explanation=(
            "Without a valid, restrictive SPF policy, receivers cannot tell which servers "
            "may send mail for the domain, which eases email spoofing and phishing."
        ),
        recommendation=(
            "Publish a single TXT record starting with 'v=spf1' listing authorised "
            "senders and ending with '-all' (or '~all'). Domains that send no mail "
            "should publish 'v=spf1 -all'."
        ),
    ),
    CheckDefinition(
        id="dns_dmarc",
        name="DMARC policy",
        category=Category.DNS,
        weight=10.0,
        severity=Severity.HIGH,
        description="A single DMARC record enforcing p=quarantine or p=reject at pct=100.",
        risk_explanation=(
            "DMARC tells receivers what to do with mail failing SPF/DKIM alignment. "
            "Without an enforcing policy, spoofed mail using the exact domain is "
            "delivered normally."
        ),
        recommendation=(
            "Publish '_dmarc.<domain>' TXT 'v=DMARC1; p=reject; rua=mailto:...'. Start "
            "with p=none to monitor, then move to quarantine/reject once legitimate "
            "senders are aligned."
        ),
    ),
    CheckDefinition(
        id="dns_caa",
        name="CAA record",
        category=Category.DNS,
        weight=5.0,
        severity=Severity.LOW,
        description="CAA records restrict which certificate authorities may issue certificates.",
        risk_explanation=(
            "Without CAA, any publicly trusted CA may issue a certificate for the "
            "domain, widening the impact of a CA mis-issuance or validation abuse."
        ),
        recommendation=(
            "Publish CAA 'issue' (and 'issuewild') records naming only the CAs you use, "
            'e.g. 0 issue "letsencrypt.org".'
        ),
    ),
    # ------------------------------------------------------------- TLS (40)
    CheckDefinition(
        id="tls_certificate_trust",
        name="Certificate trust & hostname",
        category=Category.TLS,
        weight=15.0,
        severity=Severity.CRITICAL,
        description="The HTTPS certificate chains to a trusted root and matches the hostname.",
        risk_explanation=(
            "An untrusted or mismatched certificate trains users to click through "
            "warnings and enables man-in-the-middle interception."
        ),
        recommendation=(
            "Serve a certificate from a publicly trusted CA covering the hostname, "
            "including the full intermediate chain."
        ),
    ),
    CheckDefinition(
        id="tls_certificate_expiry",
        name="Certificate validity period",
        category=Category.TLS,
        weight=10.0,
        severity=Severity.HIGH,
        description=(
            "The certificate is currently valid and not close to expiry "
            "(warning below 30 days)."
        ),
        risk_explanation=(
            "An expired certificate breaks HTTPS for every visitor and is a common "
            "cause of outages and unsafe user behaviour."
        ),
        recommendation="Automate certificate renewal (e.g. ACME) and monitor expiry dates.",
    ),
    CheckDefinition(
        id="tls_protocol_version",
        name="TLS protocol version",
        category=Category.TLS,
        weight=15.0,
        severity=Severity.HIGH,
        description="TLS 1.2 or 1.3 is negotiated and legacy TLS 1.0/1.1 is refused.",
        risk_explanation=(
            "TLS 1.0/1.1 are deprecated (RFC 8996) and rely on weak constructions; "
            "accepting them exposes clients to downgrade and cryptographic attacks."
        ),
        recommendation=(
            "Enable TLS 1.3 and TLS 1.2 only; disable SSLv3, TLS 1.0 and TLS 1.1 on "
            "the web server or load balancer."
        ),
    ),
    # ------------------------------------------------------------ HTTP (35)
    CheckDefinition(
        id="http_hsts",
        name="Strict-Transport-Security (HSTS)",
        category=Category.HTTP,
        weight=10.0,
        severity=Severity.HIGH,
        description="HSTS is sent over HTTPS with max-age of at least 6 months.",
        risk_explanation=(
            "Without HSTS, a network attacker can strip HTTPS on the first plaintext "
            "request (SSL stripping) and intercept traffic or cookies."
        ),
        recommendation=(
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on "
            "HTTPS responses once HTTPS works for the domain and its subdomains."
        ),
    ),
    CheckDefinition(
        id="http_https_redirect",
        name="HTTP to HTTPS redirect",
        category=Category.HTTP,
        weight=5.0,
        severity=Severity.MEDIUM,
        description="Plain HTTP requests are redirected to HTTPS on the same host.",
        risk_explanation=(
            "Serving content over plaintext HTTP exposes it to eavesdropping and "
            "tampering; redirecting to another host prevents HSTS on this host."
        ),
        recommendation=(
            "Answer every request on port 80 with a 301/308 redirect to "
            "https://<same host>/<same path>."
        ),
    ),
    CheckDefinition(
        id="http_csp",
        name="Content-Security-Policy",
        category=Category.HTTP,
        weight=8.0,
        severity=Severity.MEDIUM,
        description=(
            "An enforced CSP restricts script sources without unsafe-inline, "
            "unsafe-eval or wildcards."
        ),
        risk_explanation=(
            "CSP is the main defence-in-depth control against cross-site scripting "
            "(XSS); a permissive policy provides little protection."
        ),
        recommendation=(
            "Deploy a CSP such as \"default-src 'self'; object-src 'none'; base-uri "
            "'self'; frame-ancestors 'none'\" and use nonces or hashes instead of "
            "'unsafe-inline'. Test with Content-Security-Policy-Report-Only first."
        ),
    ),
    CheckDefinition(
        id="http_frame_protection",
        name="Clickjacking protection",
        category=Category.HTTP,
        weight=5.0,
        severity=Severity.MEDIUM,
        description="CSP frame-ancestors or X-Frame-Options prevents hostile framing.",
        risk_explanation=(
            "Pages that can be framed by any site are exposed to clickjacking, where "
            "users are tricked into clicking hidden UI elements."
        ),
        recommendation=(
            "Send \"Content-Security-Policy: frame-ancestors 'none'\" (or 'self') and "
            "'X-Frame-Options: DENY' for older browsers."
        ),
    ),
    CheckDefinition(
        id="http_content_type_options",
        name="X-Content-Type-Options",
        category=Category.HTTP,
        weight=4.0,
        severity=Severity.LOW,
        description="'X-Content-Type-Options: nosniff' disables MIME type sniffing.",
        risk_explanation=(
            "MIME sniffing can make browsers execute uploaded or user-controlled "
            "content as script or style."
        ),
        recommendation="Send 'X-Content-Type-Options: nosniff' on all responses.",
    ),
    CheckDefinition(
        id="http_referrer_policy",
        name="Referrer-Policy",
        category=Category.HTTP,
        weight=3.0,
        severity=Severity.LOW,
        description="A Referrer-Policy that does not leak full URLs to other origins.",
        risk_explanation=(
            "Full URLs sent in the Referer header can leak tokens, identifiers or "
            "internal paths to third-party sites."
        ),
        recommendation=(
            "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or 'no-referrer')."
        ),
    ),
)

CHECKS: dict[str, CheckDefinition] = {d.id: d for d in _DEFINITIONS}


def checks_for(category: Category) -> list[CheckDefinition]:
    """Return the definitions belonging to ``category`` in catalog order."""
    return [d for d in _DEFINITIONS if d.category == category]


def validate_catalog() -> None:
    """Ensure per-category weights add up to the published category weights."""
    for category, expected in CATEGORY_WEIGHTS.items():
        total = sum(d.weight for d in checks_for(category))
        if abs(total - expected) > 1e-9:
            raise AssertionError(
                f"Weights of {category.value} checks sum to {total}, expected {expected}"
            )


def make_result(
    check_id: str,
    status: Status,
    summary: str,
    evidence: dict[str, Any] | None = None,
    recommendation: str | None = None,
) -> CheckResult:
    """Build a :class:`CheckResult` from the catalog definition of ``check_id``.

    ``recommendation`` overrides the generic recommendation when the scanner
    can give more specific advice for the observed configuration.
    """
    definition = CHECKS[check_id]
    return CheckResult(
        id=definition.id,
        name=definition.name,
        category=definition.category,
        status=status,
        severity=definition.severity,
        weight=definition.weight,
        summary=summary,
        evidence=evidence or {},
        description=definition.description,
        risk_explanation=definition.risk_explanation,
        recommendation=recommendation or definition.recommendation,
    )


validate_catalog()
