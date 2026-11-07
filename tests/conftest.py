"""Shared fixtures: fake DNS answers, generated certificates, loopback lab servers.

Unit tests never touch the Internet. The "lab" fixtures start real servers on
127.0.0.1 and relax the public-IP guard *only inside the test* so that real
socket/TLS/HTTP code paths can be exercised against infrastructure we control.
"""

from __future__ import annotations

import socket
import ssl
import threading
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core import config, network
from core.dns_client import DnsAnswer

LAB_DOMAIN = "lab.cyberscore-lite.com"


# ------------------------------------------------------------------- DNS
def answer(name: str, rtype: str, status: str = "ok", records: list[str] | None = None) -> DnsAnswer:
    return DnsAnswer(name, rtype, status, records or [], "simulated" if status in ("timeout", "servfail", "error") else None)


class FakeDns:
    """Programmable replacement for ``lookup(name, rtype)``."""

    def __init__(self) -> None:
        self.zone: dict[tuple[str, str], DnsAnswer] = {}
        self.queries: list[tuple[str, str]] = []

    def set(self, name: str, rtype: str, records: list[str] | None = None, status: str = "ok") -> None:
        self.zone[(name, rtype)] = answer(name, rtype, status, records)

    def __call__(self, name: str, rtype: str) -> DnsAnswer:
        self.queries.append((name, rtype))
        return self.zone.get((name, rtype), answer(name, rtype, "no_answer"))


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> FakeDns:
    fake = FakeDns()
    monkeypatch.setattr("core.dns_checks.lookup", fake)
    monkeypatch.setattr("core.network.lookup", fake)
    return fake


# ----------------------------------------------------------- certificates
def make_certificate(
    hostname: str = LAB_DOMAIN,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[bytes, bytes]:
    """Return (cert PEM, key PEM) for a self-signed certificate."""
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def cert_der(**kwargs) -> bytes:
    pem, _ = make_certificate(**kwargs)
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


# -------------------------------------------------------------- lab mode
@pytest.fixture
def lab_network(monkeypatch: pytest.MonkeyPatch) -> Callable[[str, int], None]:
    """Allow loopback connections and redirect a well-known port to a lab port."""
    monkeypatch.setattr(network, "is_public_ip", lambda _ip: True)

    def route(kind: str, port: int) -> None:
        attribute = "HTTPS_PORT" if kind == "https" else "HTTP_PORT"
        monkeypatch.setattr(config, attribute, port)
        monkeypatch.setattr(config, "ALLOWED_PORTS", frozenset(config.ALLOWED_PORTS | {port}))

    return route


class LabServer:
    """Accept loop on 127.0.0.1 calling ``handler(conn)`` for each client."""

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self.handler = handler
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                continue
            self.connections += 1
            conn.settimeout(3)
            try:
                self.handler(conn)
            except Exception:  # noqa: BLE001 - lab server must keep running
                pass
            finally:
                conn.close()

    def __enter__(self) -> LabServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.listener.close()


def read_request(conn: socket.socket) -> str:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1")


@pytest.fixture
def tls_lab(tmp_path: Path) -> Callable[..., LabServer]:
    """Factory starting a TLS server presenting the given certificate."""

    def start(
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        allow_legacy: bool = False,
    ) -> LabServer:
        cert_pem, key_pem = make_certificate(not_before=not_before, not_after=not_after)
        cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        if allow_legacy:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = ssl.TLSVersion.TLSv1
            context.set_ciphers("DEFAULT:@SECLEVEL=0")

        def handler(conn: socket.socket) -> None:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)

        return LabServer(handler)

    return start


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail loudly if any code tries to open a real connection."""

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    yield
