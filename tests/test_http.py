import pytest

from core import http_checks
from core.http_checks import (
    HttpFetchError,
    HttpResponse,
    RequestBudget,
    check_content_type_options,
    check_csp,
    check_frame_protection,
    check_hsts,
    check_https_redirect,
    check_referrer_policy,
    fetch,
    fetch_https_final,
    run_http_checks,
)
from core.models import Status
from core.network import Target
from tests.conftest import LAB_DOMAIN, LabServer, read_request

TARGET = Target("example.com", ("93.184.215.14",))


# -------------------------------------------------------------------- HSTS
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({}, Status.FAIL),
        ({"strict-transport-security": "max-age=31536000; includeSubDomains"}, Status.PASS),
        ({"Strict-Transport-Security": "max-age=63072000; preload"}, Status.PASS),
        ({"strict-transport-security": 'max-age="31536000"'}, Status.PASS),
        ({"strict-transport-security": "max-age=0"}, Status.FAIL),
        ({"strict-transport-security": "max-age=abc"}, Status.FAIL),
        ({"strict-transport-security": "max-age=-5"}, Status.FAIL),
        ({"strict-transport-security": "includeSubDomains"}, Status.FAIL),
        ({"strict-transport-security": "max-age=1; max-age=31536000"}, Status.FAIL),
        ({"strict-transport-security": "max-age=86400"}, Status.WARNING),
    ],
)
def test_hsts(headers, status):
    assert check_hsts(headers).status == status


def test_hsts_max_age_zero_explained():
    result = check_hsts({"strict-transport-security": "max-age=0"})
    assert "max-age=0" in result.summary
    assert result.evidence["max_age"] == 0


def test_hsts_duplicated_header_uses_first():
    result = check_hsts({"strict-transport-security": ["max-age=0", "max-age=31536000"]})
    assert result.status == Status.FAIL
    assert "note" in result.evidence


# --------------------------------------------------------------------- CSP
@pytest.mark.parametrize(
    ("policy", "status"),
    [
        ("default-src 'self'", Status.PASS),
        ("default-src 'self'; object-src 'none'; frame-ancestors 'none'", Status.PASS),
        ("script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; object-src 'none'", Status.PASS),
        ("script-src 'strict-dynamic' 'nonce-r4nd' https:; object-src 'none'", Status.PASS),
        ("default-src 'self' 'unsafe-inline'", Status.WARNING),
        ("default-src 'self'; script-src 'self' 'unsafe-eval'", Status.WARNING),
        ("default-src *", Status.WARNING),
        ("script-src https:; object-src 'none'", Status.WARNING),
        ("upgrade-insecure-requests", Status.WARNING),
        ("img-src 'self'", Status.WARNING),
        ("script-src 'self'", Status.WARNING),  # object-src unrestricted
    ],
)
def test_csp(policy, status):
    assert check_csp({"content-security-policy": policy}).status == status


def test_csp_missing():
    assert check_csp({}).status == Status.FAIL


def test_csp_report_only_not_enforced():
    result = check_csp({"content-security-policy-report-only": "default-src 'self'"})
    assert result.status == Status.WARNING
    assert "report-only" in result.summary


def test_csp_weakness_listed_in_evidence():
    result = check_csp({"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    assert any("unsafe-inline" in issue for issue in result.evidence["issues"])


def test_multiple_csp_policies_strongest_counts():
    headers = {"content-security-policy": ["default-src *", "default-src 'self'"]}
    assert check_csp(headers).status == Status.PASS


# ------------------------------------------------------- frame protection
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"x-frame-options": "DENY"}, Status.PASS),
        ({"x-frame-options": "sameorigin"}, Status.PASS),
        ({"x-frame-options": "ALLOW-FROM https://a.example"}, Status.FAIL),
        ({"x-frame-options": "DENY, SAMEORIGIN"}, Status.FAIL),
        ({"x-frame-options": ["SAMEORIGIN", "SAMEORIGIN"]}, Status.PASS),
        ({"x-frame-options": "ALLOWALL"}, Status.FAIL),
        ({}, Status.FAIL),
        ({"content-security-policy": "frame-ancestors 'none'"}, Status.PASS),
        ({"content-security-policy": "frame-ancestors 'self' https://partner.example"}, Status.PASS),
        ({"content-security-policy": "frame-ancestors *"}, Status.WARNING),
        # CSP frame-ancestors takes precedence over X-Frame-Options
        ({"content-security-policy": "frame-ancestors *", "x-frame-options": "DENY"}, Status.WARNING),
        ({"content-security-policy": "default-src 'self'", "x-frame-options": "DENY"}, Status.PASS),
        # report-only CSP does not protect
        ({"content-security-policy-report-only": "frame-ancestors 'none'"}, Status.FAIL),
    ],
)
def test_frame_protection(headers, status):
    assert check_frame_protection(headers).status == status


# --------------------------------------------------------------- nosniff
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"x-content-type-options": "nosniff"}, Status.PASS),
        ({"X-Content-Type-Options": " NoSniff "}, Status.PASS),
        ({"x-content-type-options": "sniff"}, Status.FAIL),
        ({}, Status.FAIL),
    ],
)
def test_content_type_options(headers, status):
    assert check_content_type_options(headers).status == status


# -------------------------------------------------------- Referrer-Policy
@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("strict-origin-when-cross-origin", Status.PASS),
        ("no-referrer", Status.PASS),
        ("unsafe-url", Status.FAIL),
        ("no-referrer-when-downgrade", Status.WARNING),
        ("unsafe-url, strict-origin", Status.PASS),  # last recognised token wins
        ("no-referrer, bogus-value", Status.PASS),
        ("bogus", Status.WARNING),
    ],
)
def test_referrer_policy(value, status):
    assert check_referrer_policy({"referrer-policy": value}).status == status


def test_referrer_policy_missing_is_warning():
    assert check_referrer_policy({}).status == Status.WARNING


# ---------------------------------------------------------------- redirect
def fake_fetch_returning(response=None, exc=None):
    def _fetch(target, scheme, path, budget):
        if exc:
            raise exc
        return response

    return _fetch


@pytest.mark.parametrize(
    ("status_code", "location", "expected"),
    [
        (301, "https://example.com/", Status.PASS),
        (308, "https://example.com", Status.PASS),
        (302, "https://EXAMPLE.com:443/path?q=1", Status.PASS),
        (301, "https://www.example.com/", Status.WARNING),
        (301, "https://example.com.evil.net/", Status.WARNING),
        (301, "https://example.com@evil.net/", Status.WARNING),
        (301, "https://example.com:8443/", Status.WARNING),
        (301, "http://example.com/home", Status.WARNING),
        (301, "/home", Status.WARNING),  # relative: stays on http
        (200, "", Status.FAIL),
        (403, "", Status.WARNING),
    ],
)
def test_https_redirect(monkeypatch, status_code, location, expected):
    headers = {"location": [location]} if location else {}
    response = HttpResponse("http://example.com/", "HEAD", status_code, headers)
    monkeypatch.setattr(http_checks, "fetch", fake_fetch_returning(response))
    assert check_https_redirect(TARGET).status == expected


def test_port_80_closed_is_not_applicable(monkeypatch):
    monkeypatch.setattr(http_checks, "fetch", fake_fetch_returning(exc=HttpFetchError("refused", "closed")))
    assert check_https_redirect(TARGET).status == Status.NOT_APPLICABLE


def test_port_80_timeout_is_error(monkeypatch):
    monkeypatch.setattr(http_checks, "fetch", fake_fetch_returning(exc=HttpFetchError("timeout", "slow")))
    assert check_https_redirect(TARGET).status == Status.ERROR


# ----------------------------------------------------- redirect following
def test_external_redirect_is_not_followed(monkeypatch):
    calls = []

    def _fetch(target, scheme, path, budget):
        calls.append((scheme, path))
        return HttpResponse(f"https://example.com{path}", "HEAD", 301,
                            {"location": ["https://evil.example.net/steal"]})

    monkeypatch.setattr(http_checks, "fetch", _fetch)
    response, chain = fetch_https_final(TARGET, RequestBudget())
    assert calls == [("https", "/")]
    assert response.status_code == 301
    assert chain[0]["note"] == "redirect to another origin not followed"


def test_same_host_redirect_is_followed(monkeypatch):
    def _fetch(target, scheme, path, budget):
        if path == "/":
            return HttpResponse("https://example.com/", "HEAD", 302, {"location": ["/en/"]})
        return HttpResponse(f"https://example.com{path}", "HEAD", 200,
                            {"strict-transport-security": ["max-age=31536000"]})

    monkeypatch.setattr(http_checks, "fetch", _fetch)
    response, chain = fetch_https_final(TARGET, RequestBudget())
    assert response.url == "https://example.com/en/"
    assert [hop["status_code"] for hop in chain] == [302, 200]


def test_redirect_loop_is_bounded(monkeypatch):
    calls = []

    def _fetch(target, scheme, path, budget):
        calls.append(path)
        return HttpResponse("https://example.com/", "HEAD", 301, {"location": ["/loop"]})

    monkeypatch.setattr(http_checks, "fetch", _fetch)
    _response, chain = fetch_https_final(TARGET, RequestBudget())
    assert len(calls) == http_checks.config.MAX_HTTP_REDIRECTS + 1
    assert chain[-1]["note"] == "redirect limit reached"


def test_request_budget_is_enforced():
    budget = RequestBudget(limit=2)
    budget.consume()
    budget.consume()
    with pytest.raises(HttpFetchError) as info:
        budget.consume()
    assert info.value.kind == "budget"


@pytest.mark.parametrize("path", ["no-slash", "//evil.net/", "/a\r\nX-Injected: 1", "/" + "a" * 2000])
def test_unsafe_paths_rejected(path):
    with pytest.raises(HttpFetchError):
        http_checks._safe_path(path)


def test_head_not_supported_falls_back_to_get(monkeypatch):
    methods = []

    def _request(target, scheme, path, method, budget):
        methods.append(method)
        code = 405 if method == "HEAD" else 200
        return HttpResponse("https://example.com/", method, code, {})

    monkeypatch.setattr(http_checks, "_request", _request)
    assert fetch(TARGET, "https", "/", RequestBudget()).status_code == 200
    assert methods == ["HEAD", "GET"]


def test_https_failure_yields_errors_not_fails(monkeypatch):
    def _fetch(target, scheme, path, budget):
        raise HttpFetchError("tls", "certificate verify failed")

    monkeypatch.setattr(http_checks, "fetch", _fetch)
    results = run_http_checks(TARGET)
    assert [r.status for r in results[:5]] == [Status.ERROR] * 5
    assert len(results) == 6


# --------------------------------------------- loopback lab (real sockets)
LAB_TARGET = Target(LAB_DOMAIN, ("127.0.0.1",))


def http_server(responses: dict[str, bytes]) -> LabServer:
    """Serve a canned raw response per HTTP method."""

    def handler(conn):
        request = read_request(conn)
        method = request.split(" ", 1)[0]
        conn.sendall(responses.get(method, responses.get("*", b"")))

    return LabServer(handler)


def test_lab_redirect_same_host(lab_network):
    raw = (f"HTTP/1.1 301 Moved Permanently\r\nLocation: https://{LAB_DOMAIN}/\r\n"
           "Content-Length: 0\r\n\r\n").encode()
    with http_server({"*": raw}) as server:
        lab_network("http", server.port)
        result = check_https_redirect(LAB_TARGET)
    assert result.status == Status.PASS
    assert result.evidence["status_code"] == 301


def test_lab_external_redirect_refused(lab_network):
    raw = b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example.net/\r\nContent-Length: 0\r\n\r\n"
    with http_server({"*": raw}) as server:
        lab_network("http", server.port)
        result = check_https_redirect(LAB_TARGET)
        connections = server.connections
    assert result.status == Status.WARNING
    assert connections == 1  # the external location was never contacted


def test_lab_head_not_supported(lab_network):
    ok = (f"HTTP/1.1 308 Permanent Redirect\r\nLocation: https://{LAB_DOMAIN}/\r\n"
          "Content-Length: 0\r\n\r\n").encode()
    not_allowed = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
    with http_server({"HEAD": not_allowed, "GET": ok}) as server:
        lab_network("http", server.port)
        result = check_https_redirect(LAB_TARGET)
    assert result.status == Status.PASS
    assert result.evidence["request"].startswith("GET")


def test_lab_plaintext_content(lab_network):
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=secret\r\nContent-Length: 0\r\n\r\n"
    with http_server({"*": raw}) as server:
        lab_network("http", server.port)
        response = fetch(LAB_TARGET, "http", "/", RequestBudget())
        result = check_https_redirect(LAB_TARGET)
    assert result.status == Status.FAIL
    assert "set-cookie" not in response.evidence_headers()  # sensitive headers never kept


def test_lab_duplicate_headers_preserved(lab_network):
    raw = (b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\n"
           b"Strict-Transport-Security: max-age=31536000\r\nContent-Length: 0\r\n\r\n")
    with http_server({"*": raw}) as server:
        lab_network("http", server.port)
        response = fetch(LAB_TARGET, "http", "/", RequestBudget())
    assert response.headers["strict-transport-security"] == ["max-age=0", "max-age=31536000"]
    assert check_hsts(response.headers).status == Status.FAIL


def test_lab_malformed_response(lab_network):
    with http_server({"*": b"THIS IS NOT HTTP\r\n\r\n"}) as server:
        lab_network("http", server.port)
        result = check_https_redirect(LAB_TARGET)
    assert result.status == Status.ERROR
    assert "Malformed" in result.evidence["error"]


def test_lab_host_header_is_domain(lab_network):
    seen = {}

    def handler(conn):
        seen["request"] = read_request(conn)
        conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")

    with LabServer(handler) as server:
        lab_network("http", server.port)
        fetch(LAB_TARGET, "http", "/", RequestBudget())
    assert f"Host: {LAB_DOMAIN}\r\n" in seen["request"]
    assert seen["request"].startswith("HEAD / HTTP/1.1")
