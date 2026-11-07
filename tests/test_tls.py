from datetime import UTC, datetime, timedelta

import pytest

from core import tls_checks
from core.models import Status
from core.network import Target
from core.tls_checks import Handshake, describe_certificate, evaluate_expiry, run_tls_checks
from tests.conftest import LAB_DOMAIN, cert_der

TARGET = Target("example.com", ("93.184.215.14",))
NOW = datetime.now(UTC)


def by_id(results):
    return {r.id: r for r in results}


def patch_handshakes(monkeypatch, verified, diagnostic=None, legacy="rejected"):
    calls = []

    def fake_handshake(target, context):
        calls.append(context.verify_mode)
        if context.verify_mode == tls_checks.ssl.CERT_NONE:
            return diagnostic
        return verified

    monkeypatch.setattr(tls_checks, "handshake", fake_handshake)
    monkeypatch.setattr(tls_checks, "probe_legacy_protocols", lambda target: legacy)
    return calls


# --------------------------------------------------------------- mocked
def test_valid_certificate_all_pass(monkeypatch):
    ok = Handshake("ok", "93.184.215.14", "TLSv1.3", "TLS_AES_256_GCM_SHA384",
                   cert_der(hostname="example.com"))
    calls = patch_handshakes(monkeypatch, ok)
    results = by_id(run_tls_checks(TARGET))
    assert {r.status for r in results.values()} == {Status.PASS}
    assert results["tls_certificate_trust"].evidence["validated"] is True
    assert results["tls_protocol_version"].evidence["negotiated_version"] == "TLSv1.3"
    assert tls_checks.ssl.CERT_NONE not in calls  # no unverified handshake needed


def test_tls12_is_pass(monkeypatch):
    ok = Handshake("ok", "93.184.215.14", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", cert_der())
    patch_handshakes(monkeypatch, ok)
    assert by_id(run_tls_checks(TARGET))["tls_protocol_version"].status == Status.PASS


def test_legacy_protocol_accepted_fails(monkeypatch):
    ok = Handshake("ok", "93.184.215.14", "TLSv1.3", "x", cert_der())
    patch_handshakes(monkeypatch, ok, legacy="accepted")
    result = by_id(run_tls_checks(TARGET))["tls_protocol_version"]
    assert result.status == Status.FAIL
    assert "TLS 1.0/1.1" in result.summary


def test_legacy_probe_inconclusive_still_pass_with_note(monkeypatch):
    ok = Handshake("ok", "93.184.215.14", "TLSv1.3", "x", cert_der())
    patch_handshakes(monkeypatch, ok, legacy="unsupported_by_client")
    result = by_id(run_tls_checks(TARGET))["tls_protocol_version"]
    assert result.status == Status.PASS
    assert "could not be verified" in result.summary


def test_expired_untrusted_certificate(monkeypatch):
    expired = cert_der(not_before=NOW - timedelta(days=400), not_after=NOW - timedelta(days=5))
    failed = Handshake("cert_error", "93.184.215.14", error="certificate has expired", verify_code=10)
    diagnostic = Handshake("ok", "93.184.215.14", "TLSv1.3", "x", expired)
    patch_handshakes(monkeypatch, failed, diagnostic)
    results = by_id(run_tls_checks(TARGET))
    assert results["tls_certificate_trust"].status == Status.FAIL
    assert "expired" in results["tls_certificate_trust"].summary
    assert results["tls_certificate_expiry"].status == Status.FAIL
    # Protocol must never be PASS when the connection could not be trusted.
    assert results["tls_protocol_version"].status == Status.ERROR


def test_hostname_mismatch(monkeypatch):
    failed = Handshake("cert_error", "93.184.215.14", error="Hostname mismatch", verify_code=62)
    diagnostic = Handshake("ok", "93.184.215.14", "TLSv1.2", "x", cert_der(hostname="other.net"))
    patch_handshakes(monkeypatch, failed, diagnostic)
    trust = by_id(run_tls_checks(TARGET))["tls_certificate_trust"]
    assert trust.status == Status.FAIL
    assert "hostname mismatch" in trust.summary
    assert trust.evidence["served_certificate"]["san_dns_names"] == ["other.net"]


def test_handshake_error(monkeypatch):
    failed = Handshake("handshake_error", "93.184.215.14", error="TLSV1_ALERT_PROTOCOL_VERSION")
    patch_handshakes(monkeypatch, failed, legacy="rejected")
    results = by_id(run_tls_checks(TARGET))
    assert results["tls_certificate_trust"].status == Status.ERROR
    assert results["tls_protocol_version"].status == Status.ERROR


def test_handshake_error_with_legacy_only_server(monkeypatch):
    failed = Handshake("handshake_error", "93.184.215.14", error="UNSUPPORTED_PROTOCOL")
    patch_handshakes(monkeypatch, failed, legacy="accepted")
    assert by_id(run_tls_checks(TARGET))["tls_protocol_version"].status == Status.FAIL


def test_port_closed_means_no_https(monkeypatch):
    patch_handshakes(monkeypatch, Handshake("refused", error="refused"))
    assert {r.status for r in run_tls_checks(TARGET)} == {Status.FAIL}


@pytest.mark.parametrize("kind", ["timeout", "network_error"])
def test_network_errors_are_error_not_fail(monkeypatch, kind):
    patch_handshakes(monkeypatch, Handshake(kind, error="boom"))
    assert {r.status for r in run_tls_checks(TARGET)} == {Status.ERROR}


@pytest.mark.parametrize(
    ("days", "status"), [(-1, Status.FAIL), (5, Status.WARNING), (29, Status.WARNING), (200, Status.PASS)]
)
def test_expiry_thresholds(days, status):
    info = {
        "not_before": (NOW - timedelta(days=10)).isoformat(),
        "not_after": (NOW + timedelta(days=days, hours=1)).isoformat(),
    }
    assert evaluate_expiry(info, now=NOW).status == status


def test_not_yet_valid_certificate():
    info = {
        "not_before": (NOW + timedelta(days=2)).isoformat(),
        "not_after": (NOW + timedelta(days=90)).isoformat(),
    }
    assert evaluate_expiry(info, now=NOW).status == Status.FAIL


def test_describe_certificate():
    info = describe_certificate(cert_der(hostname="example.com"))
    assert info["subject_cn"] == "example.com"
    assert info["san_dns_names"] == ["example.com"]
    assert info["signature_hash"] == "sha256"


def test_verification_is_enabled_on_main_context():
    context = tls_checks.verified_context()
    assert context.check_hostname is True
    assert context.verify_mode == tls_checks.ssl.CERT_REQUIRED


# ------------------------------------------------- loopback lab (real TLS)
LAB_TARGET = Target(LAB_DOMAIN, ("127.0.0.1",))


def test_lab_untrusted_self_signed_certificate(lab_network, tls_lab):
    with tls_lab() as server:
        lab_network("https", server.port)
        results = by_id(run_tls_checks(LAB_TARGET))
    trust = results["tls_certificate_trust"]
    assert trust.status == Status.FAIL
    assert trust.evidence["validated"] is False
    assert trust.evidence["verify_code"] == 18  # self-signed
    assert trust.evidence["served_certificate"]["subject_cn"] == LAB_DOMAIN
    assert results["tls_certificate_expiry"].status == Status.PASS
    assert results["tls_protocol_version"].status != Status.PASS


def test_lab_expired_certificate(lab_network, tls_lab):
    with tls_lab(not_before=NOW - timedelta(days=100), not_after=NOW - timedelta(days=1)) as server:
        lab_network("https", server.port)
        results = by_id(run_tls_checks(LAB_TARGET))
    assert results["tls_certificate_trust"].status == Status.FAIL
    assert results["tls_certificate_expiry"].status == Status.FAIL


def test_lab_closed_port(lab_network):
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens on this port any more
    lab_network("https", port)
    assert {r.status for r in run_tls_checks(LAB_TARGET)} == {Status.FAIL}


def test_lab_legacy_probe_rejected_by_modern_server(lab_network, tls_lab):
    with tls_lab() as server:
        lab_network("https", server.port)
        outcome = tls_checks.probe_legacy_protocols(LAB_TARGET)
    assert outcome in ("rejected", "unsupported_by_client")


def test_lab_legacy_probe_detects_tls10_support(lab_network, tls_lab):
    with tls_lab(allow_legacy=True) as server:
        lab_network("https", server.port)
        outcome = tls_checks.probe_legacy_protocols(LAB_TARGET)
        results = by_id(run_tls_checks(LAB_TARGET))
    if outcome == "unsupported_by_client":
        pytest.skip("local OpenSSL build cannot offer TLS 1.0/1.1")
    assert outcome == "accepted"
    assert results["tls_protocol_version"].status == Status.FAIL
