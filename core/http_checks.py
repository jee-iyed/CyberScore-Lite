"""HTTP security header checks and HTTP-to-HTTPS redirect check.

Safety properties:
* requests go only to the pinned public addresses of the target, on port 80
  or 443, with the Host header / SNI set to the validated domain;
* HTTPS uses full certificate verification (never disabled);
* redirects are followed only when they stay on ``https://<same host>``;
  redirects to any other host are recorded but never followed;
* the number of requests is capped by a :class:`RequestBudget`;
* only security-relevant headers are kept as evidence (no cookies, bodies).
"""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

from core import config
from core.catalog import make_result
from core.models import CheckResult, Status
from core.network import Target, open_connection

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
HEADER_IDS = (
    "http_hsts",
    "http_csp",
    "http_frame_protection",
    "http_content_type_options",
    "http_referrer_policy",
)
HTTP_IDS = (*HEADER_IDS, "http_https_redirect")

# Only these response headers are retained (never Set-Cookie or similar).
_EVIDENCE_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "location",
)

Headers = Mapping[str, "str | Sequence[str]"]


class HttpFetchError(Exception):
    """A request could not be completed. ``kind`` classifies the failure."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class RequestBudget:
    """Hard cap on the number of HTTP requests sent during one assessment."""

    def __init__(self, limit: int = config.MAX_HTTP_REQUESTS) -> None:
        self.limit = limit
        self.used = 0

    def consume(self) -> None:
        if self.used >= self.limit:
            raise HttpFetchError("budget", f"HTTP request budget of {self.limit} exhausted.")
        self.used += 1


@dataclass
class HttpResponse:
    """Minimal view of an HTTP response (headers only)."""

    url: str
    method: str
    status_code: int
    headers: dict[str, list[str]] = field(default_factory=dict)

    def evidence_headers(self) -> dict[str, list[str]]:
        return {
            name: [_truncate(v) for v in self.headers[name]]
            for name in _EVIDENCE_HEADERS
            if name in self.headers
        }


def _truncate(value: str, limit: int = config.MAX_EVIDENCE_VALUE_LENGTH) -> str:
    return value if len(value) <= limit else value[:limit] + "...[truncated]"


def _values(headers: Headers, name: str) -> list[str]:
    """Return all values of ``name`` (case-insensitive) as a list of strings."""
    for key, value in headers.items():
        if key.lower() == name:
            if isinstance(value, str):
                return [value]
            return [str(v) for v in value]
    return []


def _safe_path(path: str) -> str:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or len(path) > config.MAX_REDIRECT_PATH_LENGTH
        or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in path)
    ):
        raise HttpFetchError("unsafe_path", "Redirect path rejected as unsafe.")
    return path


# ---------------------------------------------------------------- transport
def _request(target: Target, scheme: str, path: str, method: str, budget: RequestBudget) -> HttpResponse:
    budget.consume()
    port = config.HTTPS_PORT if scheme == "https" else config.HTTP_PORT
    path = _safe_path(path)
    try:
        sock, _address = open_connection(target, port)
    except ConnectionRefusedError as exc:
        raise HttpFetchError("refused", f"Port {port} refused the connection.") from exc
    except TimeoutError as exc:
        raise HttpFetchError("timeout", f"Connection to port {port} timed out.") from exc
    except OSError as exc:
        raise HttpFetchError("network", f"Network error on port {port}: {exc}") from exc

    connection = sock
    response: http.client.HTTPResponse | None = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()  # verification always on
            connection = context.wrap_socket(sock, server_hostname=target.domain)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {target.domain}\r\n"
            f"User-Agent: {config.USER_AGENT}\r\n"
            "Accept: text/html,*/*;q=0.8\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(connection, method=method)
        response.begin()  # reads status line and headers only, never the body
        headers: dict[str, list[str]] = {}
        for key, value in response.getheaders():
            headers.setdefault(key.lower(), []).append(value)
        return HttpResponse(f"{scheme}://{target.domain}{path}", method, response.status, headers)
    except ssl.SSLCertVerificationError as exc:
        raise HttpFetchError(
            "tls", f"HTTPS certificate verification failed: {exc.verify_message}"
        ) from exc
    except ssl.SSLError as exc:
        raise HttpFetchError("tls", f"TLS error: {exc.reason or exc}") from exc
    except TimeoutError as exc:
        raise HttpFetchError("timeout", "The server did not answer in time.") from exc
    except http.client.HTTPException as exc:
        raise HttpFetchError("malformed", f"Malformed HTTP response: {type(exc).__name__}") from exc
    except OSError as exc:
        raise HttpFetchError("network", f"Network error: {exc}") from exc
    finally:
        if response is not None:
            response.close()
        connection.close()


def fetch(target: Target, scheme: str, path: str, budget: RequestBudget) -> HttpResponse:
    """HEAD request, falling back to GET when HEAD is not supported (405/501)."""
    response = _request(target, scheme, path, "HEAD", budget)
    if response.status_code in (405, 501):
        response = _request(target, scheme, path, "GET", budget)
    return response


def _resolve_location(base_url: str, location: str) -> tuple[str, str | None, int | None, str]:
    absolute = urljoin(base_url, location.strip())
    parts = urlsplit(absolute)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        port = parts.port
    except ValueError:
        port = -1
    return parts.scheme.lower(), (parts.hostname or "").lower() or None, port, path


def _is_same_https_origin(scheme: str, host: str | None, port: int | None, domain: str) -> bool:
    return scheme == "https" and host == domain and port in (None, 443)


def fetch_https_final(target: Target, budget: RequestBudget) -> tuple[HttpResponse, list[dict[str, Any]]]:
    """Fetch ``https://<domain>/`` following same-host HTTPS redirects only."""
    path = "/"
    chain: list[dict[str, Any]] = []
    for _ in range(config.MAX_HTTP_REDIRECTS + 1):
        response = fetch(target, "https", path, budget)
        hop: dict[str, Any] = {"url": response.url, "status_code": response.status_code}
        chain.append(hop)
        location = (_values(response.headers, "location") or [""])[0]
        if response.status_code not in REDIRECT_CODES or not location:
            return response, chain
        scheme, host, port, next_path = _resolve_location(response.url, location)
        hop["location"] = _truncate(location, 300)
        if not _is_same_https_origin(scheme, host, port, target.domain):
            hop["note"] = "redirect to another origin not followed"
            return response, chain
        path = next_path
    chain[-1]["note"] = "redirect limit reached"
    return response, chain


# --------------------------------------------------------------- analysers
def _parse_directives(value: str, separator: str = ";") -> list[tuple[str, str]]:
    items = []
    for part in value.split(separator):
        name, _, arg = part.strip().partition("=")
        if name.strip():
            items.append((name.strip().lower(), arg.strip().strip('"')))
    return items


def check_hsts(headers: Headers) -> CheckResult:
    """Validate Strict-Transport-Security (RFC 6797)."""
    values = _values(headers, "strict-transport-security")
    if not values:
        return make_result("http_hsts", Status.FAIL, "HSTS header is missing.", {"header": None})

    value = values[0]  # browsers only process the first header (RFC 6797 8.1)
    evidence: dict[str, Any] = {"header": _truncate(value)}
    if len(values) > 1:
        evidence["note"] = f"{len(values)} HSTS headers sent; only the first is honoured."

    directives = _parse_directives(value)
    names = [name for name, _ in directives]
    if len(names) != len(set(names)):
        return make_result(
            "http_hsts",
            Status.FAIL,
            "HSTS header repeats a directive and is ignored by browsers.",
            evidence,
        )
    params = dict(directives)
    raw_max_age = params.get("max-age")
    if raw_max_age is None:
        return make_result(
            "http_hsts", Status.FAIL, "HSTS header has no max-age directive.", evidence
        )
    if not raw_max_age.isdigit():
        return make_result(
            "http_hsts",
            Status.FAIL,
            f"HSTS max-age '{raw_max_age}' is not a valid non-negative integer.",
            evidence,
        )

    max_age = int(raw_max_age)
    evidence.update(
        {
            "max_age": max_age,
            "include_subdomains": "includesubdomains" in params,
            "preload": "preload" in params,
        }
    )
    if max_age == 0:
        return make_result(
            "http_hsts",
            Status.FAIL,
            "HSTS max-age=0 tells browsers to delete the HSTS policy.",
            evidence,
        )
    if max_age < config.HSTS_MIN_MAX_AGE_SECONDS:
        return make_result(
            "http_hsts",
            Status.WARNING,
            f"HSTS max-age is {max_age}s (< 6 months).",
            evidence,
            "Increase max-age to at least 15768000 (6 months), ideally 31536000.",
        )
    summary = f"HSTS enabled with max-age={max_age}"
    if "includesubdomains" not in params:
        summary += " (without includeSubDomains)"
    return make_result("http_hsts", Status.PASS, summary + ".", evidence)


def parse_csp(value: str) -> list[dict[str, list[str]]]:
    """Parse a CSP header value into a list of policies (comma-separated)."""
    policies = []
    for raw_policy in value.split(","):
        directives: dict[str, list[str]] = {}
        for part in raw_policy.split(";"):
            tokens = part.split()
            if tokens:
                name = tokens[0].lower()
                directives.setdefault(name, [t.lower() for t in tokens[1:]])
        if directives:
            policies.append(directives)
    return policies


_UNSAFE_SOURCES = {"*", "http:", "https:", "data:", "blob:"}


def analyse_csp_policy(policy: dict[str, list[str]]) -> list[str]:
    """Return the weaknesses of a single CSP policy (empty list = robust)."""
    issues: list[str] = []
    script = policy.get("script-src", policy.get("default-src"))
    if script is None:
        issues.append("no script-src or default-src: scripts are not restricted")
    else:
        has_nonce_or_hash = any(
            t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script
        )
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            issues.append("'unsafe-inline' allows inline scripts")
        if "'unsafe-eval'" in script:
            issues.append("'unsafe-eval' allows eval()")
        if not strict_dynamic:
            wide = sorted(t for t in script if t in _UNSAFE_SOURCES)
            if wide:
                issues.append(f"script sources too broad: {', '.join(wide)}")
    if "object-src" not in policy and "default-src" not in policy:
        issues.append("object-src is not restricted")
    return issues


def check_csp(headers: Headers) -> CheckResult:
    """Evaluate Content-Security-Policy strength (presence is not enough)."""
    enforced = _values(headers, "content-security-policy")
    report_only = _values(headers, "content-security-policy-report-only")
    if not enforced:
        if report_only:
            return make_result(
                "http_csp",
                Status.WARNING,
                "CSP is only in report-only mode and is not enforced.",
                {"report_only": [_truncate(v) for v in report_only]},
                "Promote the report-only policy to Content-Security-Policy once "
                "violations are resolved.",
            )
        return make_result("http_csp", Status.FAIL, "Content-Security-Policy is missing.", {})

    policies = [p for value in enforced for p in parse_csp(value)]
    analyses = [analyse_csp_policy(p) for p in policies]
    evidence: dict[str, Any] = {
        "headers": [_truncate(v) for v in enforced],
        "issues": sorted({issue for issues in analyses for issue in issues}),
    }
    if any(not issues for issues in analyses):
        return make_result(
            "http_csp", Status.PASS, "An enforced CSP restricts script execution.", evidence
        )
    return make_result(
        "http_csp",
        Status.WARNING,
        "CSP is present but weak: " + "; ".join(evidence["issues"]) + ".",
        evidence,
    )


def check_frame_protection(headers: Headers) -> CheckResult:
    """CSP frame-ancestors (preferred) or X-Frame-Options."""
    policies = [p for v in _values(headers, "content-security-policy") for p in parse_csp(v)]
    ancestors = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    if ancestors:
        evidence = {"frame_ancestors": [" ".join(a) or "(empty)" for a in ancestors]}

        def _restrictive(sources: list[str]) -> bool:
            return not any(t in ("*", "http:", "https:") for t in sources)

        if any(_restrictive(a) for a in ancestors):
            return make_result(
                "http_frame_protection",
                Status.PASS,
                "CSP frame-ancestors restricts which sites may frame the page.",
                evidence,
            )
        return make_result(
            "http_frame_protection",
            Status.WARNING,
            "CSP frame-ancestors allows framing by any origin.",
            evidence,
        )

    values = _values(headers, "x-frame-options")
    evidence = {"x_frame_options": values}
    if not values:
        return make_result(
            "http_frame_protection",
            Status.FAIL,
            "Neither CSP frame-ancestors nor X-Frame-Options is set.",
            evidence,
        )
    tokens = {t.strip().lower() for v in values for t in v.split(",") if t.strip()}
    if len(tokens) > 1:
        return make_result(
            "http_frame_protection",
            Status.FAIL,
            "X-Frame-Options has conflicting values and is treated as invalid.",
            evidence,
        )
    token = next(iter(tokens), "")
    if token in ("deny", "sameorigin"):
        return make_result(
            "http_frame_protection",
            Status.PASS,
            f"X-Frame-Options: {token.upper()}.",
            evidence,
        )
    if token.startswith("allow-from"):
        return make_result(
            "http_frame_protection",
            Status.FAIL,
            "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers.",
            evidence,
            "Replace ALLOW-FROM with CSP frame-ancestors listing the allowed origins.",
        )
    return make_result(
        "http_frame_protection",
        Status.FAIL,
        f"Invalid X-Frame-Options value '{token}'.",
        evidence,
    )


def check_content_type_options(headers: Headers) -> CheckResult:
    """X-Content-Type-Options must be exactly ``nosniff``."""
    values = _values(headers, "x-content-type-options")
    evidence = {"header": values or None}
    if not values:
        return make_result(
            "http_content_type_options",
            Status.FAIL,
            "X-Content-Type-Options is missing.",
            evidence,
        )
    first = values[0].split(",")[0].strip().lower()
    if first == "nosniff":
        return make_result(
            "http_content_type_options", Status.PASS, "MIME sniffing disabled (nosniff).",
            evidence,
        )
    return make_result(
        "http_content_type_options",
        Status.FAIL,
        f"Invalid X-Content-Type-Options value '{values[0]}'.",
        evidence,
    )


_REFERRER_SAFE = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
_REFERRER_MODERATE = {"origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}
_REFERRER_UNSAFE = {"unsafe-url"}


def check_referrer_policy(headers: Headers) -> CheckResult:
    """Referrer-Policy: the last recognised token wins (W3C spec)."""
    values = _values(headers, "referrer-policy")
    if not values:
        return make_result(
            "http_referrer_policy",
            Status.WARNING,
            "Referrer-Policy is missing (modern browsers default to "
            "strict-origin-when-cross-origin, older ones may leak full URLs).",
            {"header": None},
        )
    tokens = [t.strip().lower() for v in values for t in v.split(",") if t.strip()]
    known = _REFERRER_SAFE | _REFERRER_MODERATE | _REFERRER_UNSAFE
    effective = next((t for t in reversed(tokens) if t in known), None)
    evidence = {"header": values, "effective_policy": effective}
    if effective is None:
        return make_result(
            "http_referrer_policy",
            Status.WARNING,
            "Referrer-Policy has no recognised value.",
            evidence,
        )
    if effective in _REFERRER_SAFE:
        return make_result(
            "http_referrer_policy", Status.PASS, f"Referrer-Policy: {effective}.", evidence
        )
    if effective in _REFERRER_UNSAFE:
        return make_result(
            "http_referrer_policy",
            Status.FAIL,
            "Referrer-Policy unsafe-url leaks full URLs, even to HTTP sites.",
            evidence,
        )
    return make_result(
        "http_referrer_policy",
        Status.WARNING,
        f"Referrer-Policy '{effective}' may leak URL information cross-origin.",
        evidence,
    )


def check_https_redirect(target: Target, budget: RequestBudget | None = None) -> CheckResult:
    """``http://<domain>/`` should redirect to ``https://<domain>/...``."""
    budget = budget or RequestBudget()
    try:
        response = fetch(target, "http", "/", budget)
    except HttpFetchError as exc:
        if exc.kind == "refused":
            return make_result(
                "http_https_redirect",
                Status.NOT_APPLICABLE,
                "Port 80 is closed: no plaintext HTTP service is exposed.",
                {"error": str(exc)},
            )
        return make_result(
            "http_https_redirect",
            Status.ERROR,
            "Plain HTTP endpoint could not be assessed.",
            {"error": str(exc)},
        )

    location = (_values(response.headers, "location") or [""])[0]
    evidence: dict[str, Any] = {
        "request": f"{response.method} http://{target.domain}/",
        "status_code": response.status_code,
        "location": _truncate(location, 300) or None,
    }
    if response.status_code in REDIRECT_CODES and location:
        scheme, host, port, _path = _resolve_location(f"http://{target.domain}/", location)
        if _is_same_https_origin(scheme, host, port, target.domain):
            return make_result(
                "http_https_redirect",
                Status.PASS,
                f"HTTP redirects ({response.status_code}) to HTTPS on the same host.",
                evidence,
            )
        if scheme == "https":
            return make_result(
                "http_https_redirect",
                Status.WARNING,
                f"HTTP redirects to HTTPS on another host ({host}); not followed.",
                evidence,
                "Redirect first to https://<same host>, then to the canonical host, so "
                "HSTS can be set for this host.",
            )
        return make_result(
            "http_https_redirect",
            Status.WARNING,
            "HTTP redirect does not upgrade to HTTPS.",
            evidence,
        )
    if 200 <= response.status_code < 300:
        return make_result(
            "http_https_redirect",
            Status.FAIL,
            "Content is served over plaintext HTTP without redirect to HTTPS.",
            evidence,
        )
    return make_result(
        "http_https_redirect",
        Status.WARNING,
        f"No HTTPS redirect observed (HTTP status {response.status_code}).",
        evidence,
    )


def not_assessed(status: Status, summary: str) -> list[CheckResult]:
    """Placeholder results when HTTP cannot be assessed at all."""
    return [make_result(check_id, status, summary) for check_id in HTTP_IDS]


def run_http_checks(target: Target) -> list[CheckResult]:
    """Run header checks on the HTTPS response and the redirect check on HTTP."""
    budget = RequestBudget()
    try:
        response, chain = fetch_https_final(target, budget)
    except HttpFetchError as exc:
        results = [
            make_result(
                check_id,
                Status.ERROR,
                "HTTPS response could not be retrieved; headers not assessed.",
                {"error": str(exc)},
            )
            for check_id in HEADER_IDS
        ]
    else:
        headers = response.headers
        results = [
            check_hsts(headers),
            check_csp(headers),
            check_frame_protection(headers),
            check_content_type_options(headers),
            check_referrer_policy(headers),
        ]
        context = {"url": response.url, "status_code": response.status_code, "chain": chain}
        for result in results:
            result.evidence["evaluated_response"] = context
    results.append(check_https_redirect(target, budget))
    return results
