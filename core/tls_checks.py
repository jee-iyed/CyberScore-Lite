"""TLS/HTTPS checks: certificate trust, validity period and protocol version.

Connections go to the pinned, validated addresses of a :class:`Target` with
SNI set to the domain. At most three handshakes are made:

1. a fully verified handshake (system trust store + hostname check). Only
   this handshake can lead to a PASS;
2. a legacy probe offering only TLS 1.0/1.1, to detect deprecated protocol
   support (it never awards points, it can only reveal a weakness);
3. if verification failed, a diagnostic handshake *without* verification,
   used solely to show the certificate that was served as evidence. Its
   outcome can never produce a PASS.
"""

from __future__ import annotations

import ssl
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from core import config
from core.catalog import make_result
from core.models import CheckResult, Status
from core.network import Target, open_connection

LEGACY_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
MODERN_VERSIONS = frozenset({"TLSv1.2", "TLSv1.3"})
TLS_IDS = ("tls_certificate_trust", "tls_certificate_expiry", "tls_protocol_version")

# OpenSSL verification error codes mapped to readable explanations.
_VERIFY_REASONS = {
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in the chain",
    20: "unable to get local issuer certificate (incomplete or untrusted chain)",
    21: "unable to verify the first certificate (missing intermediate)",
    62: "hostname mismatch",
}


@dataclass
class Handshake:
    """Outcome of one TLS handshake attempt."""

    kind: str  # ok | cert_error | refused | timeout | handshake_error | network_error
    address: str | None = None
    version: str | None = None
    cipher: str | None = None
    cert_der: bytes | None = None
    error: str | None = None
    verify_code: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def verified_context() -> ssl.SSLContext:
    """Standard client context: CA verification and hostname check enabled."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _diagnostic_context() -> ssl.SSLContext:
    """Evidence-only context; never used to award a PASS."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _legacy_context() -> ssl.SSLContext | None:
    """Context that only offers TLS 1.0/1.1, or None if the client cannot."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context = verified_context()
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


def handshake(target: Target, context: ssl.SSLContext) -> Handshake:
    """Perform one TLS handshake to the target on port 443."""
    try:
        sock, address = open_connection(target, config.HTTPS_PORT)
    except ConnectionRefusedError as exc:
        return Handshake("refused", error=str(exc) or "Connection refused")
    except TimeoutError:
        return Handshake("timeout", error="Connection timed out")
    except OSError as exc:
        return Handshake("network_error", error=str(exc))

    try:
        with context.wrap_socket(sock, server_hostname=target.domain) as tls:
            cipher = tls.cipher()
            return Handshake(
                "ok",
                address=address,
                version=tls.version(),
                cipher=cipher[0] if cipher else None,
                cert_der=tls.getpeercert(binary_form=True),
            )
    except ssl.SSLCertVerificationError as exc:
        return Handshake(
            "cert_error",
            address=address,
            error=exc.verify_message or str(exc),
            verify_code=exc.verify_code,
        )
    except ssl.SSLError as exc:
        return Handshake(
            "handshake_error",
            address=address,
            error=exc.reason or str(exc),
            extra={"library_reason": exc.reason},
        )
    except TimeoutError:
        return Handshake("timeout", address=address, error="TLS handshake timed out")
    except OSError as exc:
        # A reset during the handshake usually means the server refused it.
        return Handshake("handshake_error", address=address, error=str(exc))
    finally:
        sock.close()


_CLIENT_SIDE_REASONS = {"NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL", "NO_CIPHERS_AVAILABLE"}


def probe_legacy_protocols(target: Target) -> str:
    """Return ``accepted``, ``rejected``, ``inconclusive`` or ``unsupported_by_client``."""
    context = _legacy_context()
    if context is None:
        return "unsupported_by_client"
    result = handshake(target, context)
    if result.kind == "ok" or result.kind == "cert_error":
        # A certificate error happens after the protocol was negotiated.
        return "accepted"
    if result.kind == "handshake_error":
        if result.extra.get("library_reason") in _CLIENT_SIDE_REASONS:
            return "unsupported_by_client"
        return "rejected"
    return "inconclusive"


def describe_certificate(der: bytes) -> dict[str, Any]:
    """Extract public, non-sensitive certificate fields for evidence."""
    cert = x509.load_der_x509_certificate(der)

    def _cn(name: x509.Name) -> str | None:
        attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attributes[0].value) if attributes else None

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []

    return {
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "issuer": cert.issuer.rfc4514_string(),
        "san_dns_names": dns_names[:20],
        "san_count": len(dns_names),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial_number": format(cert.serial_number, "x"),
        "signature_hash": cert.signature_hash_algorithm.name
        if cert.signature_hash_algorithm
        else None,
    }


def evaluate_expiry(cert_info: dict[str, Any], now: datetime | None = None) -> CheckResult:
    """Grade the certificate validity window."""
    now = now or datetime.now(UTC)
    not_before = datetime.fromisoformat(cert_info["not_before"])
    not_after = datetime.fromisoformat(cert_info["not_after"])
    days_remaining = (not_after - now).total_seconds() / 86400
    evidence = {
        "not_before": cert_info["not_before"],
        "not_after": cert_info["not_after"],
        "days_remaining": int(days_remaining // 1),
    }
    if now < not_before:
        return make_result(
            "tls_certificate_expiry", Status.FAIL, "Certificate is not yet valid.", evidence
        )
    if days_remaining < 0:
        return make_result(
            "tls_certificate_expiry",
            Status.FAIL,
            f"Certificate expired {abs(int(days_remaining))} day(s) ago.",
            evidence,
            "Renew the certificate immediately and automate renewal (e.g. ACME).",
        )
    if days_remaining < config.CERT_EXPIRY_WARNING_DAYS:
        return make_result(
            "tls_certificate_expiry",
            Status.WARNING,
            f"Certificate expires in {int(days_remaining)} day(s).",
            evidence,
            "Renew the certificate before expiry and automate renewal.",
        )
    return make_result(
        "tls_certificate_expiry",
        Status.PASS,
        f"Certificate valid for another {int(days_remaining)} day(s).",
        evidence,
    )


def _all(status: Status, summary: str, evidence: dict[str, Any]) -> list[CheckResult]:
    return [make_result(check_id, status, summary, dict(evidence)) for check_id in TLS_IDS]


def not_assessed(status: Status, summary: str) -> list[CheckResult]:
    """Placeholder results when TLS cannot be assessed at all."""
    return _all(status, summary, {})


def run_tls_checks(target: Target) -> list[CheckResult]:
    """Run the TLS checks against a pinned target."""
    main = handshake(target, verified_context())

    if main.kind == "refused":
        return _all(
            Status.FAIL,
            "Port 443 refused the connection: the site is not available over HTTPS.",
            {"error": main.error, "port": config.HTTPS_PORT},
        )
    if main.kind in ("timeout", "network_error"):
        return _all(
            Status.ERROR,
            "HTTPS endpoint could not be reached (network error); TLS not assessed.",
            {"error": main.error, "port": config.HTTPS_PORT},
        )

    legacy = probe_legacy_protocols(target)
    protocol_evidence: dict[str, Any] = {
        "negotiated_version": main.version,
        "legacy_tls_1_0_1_1": legacy,
    }

    if main.kind == "ok":
        assert main.cert_der is not None
        cert_info = describe_certificate(main.cert_der)
        trust = make_result(
            "tls_certificate_trust",
            Status.PASS,
            "Certificate chain is trusted and matches the hostname.",
            {
                "validated": True,
                "address": main.address,
                "subject_cn": cert_info["subject_cn"],
                "issuer": cert_info["issuer"],
                "san_dns_names": cert_info["san_dns_names"],
                "signature_hash": cert_info["signature_hash"],
            },
        )
        expiry = evaluate_expiry(cert_info)
        protocol_evidence["cipher"] = main.cipher
        protocol = _protocol_result(main.version, legacy, trusted=True, evidence=protocol_evidence)
        return [trust, expiry, protocol]

    if main.kind == "cert_error":
        diagnostic = handshake(target, _diagnostic_context())
        cert_info = (
            describe_certificate(diagnostic.cert_der)
            if diagnostic.kind == "ok" and diagnostic.cert_der
            else None
        )
        reason = _VERIFY_REASONS.get(main.verify_code or -1, main.error or "verification failed")
        trust_evidence: dict[str, Any] = {
            "validated": False,
            "verify_code": main.verify_code,
            "verify_message": main.error,
            "address": main.address,
        }
        if cert_info:
            trust_evidence["served_certificate"] = cert_info
            trust_evidence["note"] = (
                "Certificate details were read on an unverified diagnostic connection "
                "for evidence only."
            )
        trust = make_result(
            "tls_certificate_trust",
            Status.FAIL,
            f"Certificate validation failed: {reason}.",
            trust_evidence,
        )
        if cert_info:
            expiry = evaluate_expiry(cert_info)
        else:
            expiry = make_result(
                "tls_certificate_expiry",
                Status.ERROR,
                "Certificate could not be retrieved for expiry analysis.",
                {"error": diagnostic.error},
            )
        protocol_evidence["negotiated_version"] = diagnostic.version
        protocol = _protocol_result(
            diagnostic.version, legacy, trusted=False, evidence=protocol_evidence
        )
        return [trust, expiry, protocol]

    # handshake_error: the server refused every modern handshake.
    evidence = {"error": main.error, "address": main.address}
    return [
        make_result(
            "tls_certificate_trust",
            Status.ERROR,
            "TLS handshake failed before a certificate was received.",
            evidence,
        ),
        make_result(
            "tls_certificate_expiry",
            Status.ERROR,
            "TLS handshake failed before a certificate was received.",
            evidence,
        ),
        _protocol_result(None, legacy, trusted=False, evidence={**protocol_evidence, **evidence}),
    ]


def _protocol_result(
    version: str | None, legacy: str, *, trusted: bool, evidence: dict[str, Any]
) -> CheckResult:
    if legacy == "accepted" or (version in LEGACY_VERSIONS):
        summary = (
            "Server accepts deprecated TLS 1.0/1.1."
            if version in MODERN_VERSIONS
            else "Server only negotiates deprecated TLS versions."
        )
        return make_result("tls_protocol_version", Status.FAIL, summary, evidence)
    if not trusted:
        # Never award a PASS from an unverified connection.
        return make_result(
            "tls_protocol_version",
            Status.ERROR,
            "Protocol version not scored: no trusted TLS connection could be established.",
            evidence,
        )
    if version in MODERN_VERSIONS:
        summary = f"Negotiated {version}"
        if legacy == "rejected":
            summary += "; TLS 1.0/1.1 are refused."
        else:
            summary += f"; legacy TLS support could not be verified ({legacy})."
        return make_result("tls_protocol_version", Status.PASS, summary, evidence)
    return make_result(
        "tls_protocol_version",
        Status.ERROR,
        f"Unexpected protocol version: {version}.",
        evidence,
    )

