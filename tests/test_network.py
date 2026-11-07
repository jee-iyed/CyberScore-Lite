import pytest

from core import network
from core.network import (
    NoAddressError,
    Target,
    TargetResolutionError,
    UnsafeTargetError,
    build_target,
    open_connection,
    resolve,
    resolve_target,
)
from utils.validators import DomainValidationError

DOMAIN = "example.com"


def test_public_addresses_are_pinned(fake_dns):
    fake_dns.set(DOMAIN, "A", ["93.184.215.14"])
    fake_dns.set(DOMAIN, "AAAA", ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
    target = resolve_target(DOMAIN)
    assert target == Target(DOMAIN, ("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"))


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254"])
def test_private_resolution_blocked(fake_dns, ip):
    fake_dns.set(DOMAIN, "A", [ip])
    with pytest.raises(UnsafeTargetError, match="non-public"):
        resolve_target(DOMAIN)


def test_mixed_public_and_private_blocked(fake_dns):
    """A single internal address is enough to refuse (DNS rebinding pattern)."""
    fake_dns.set(DOMAIN, "A", ["93.184.215.14", "192.168.0.10"])
    with pytest.raises(UnsafeTargetError):
        resolve_target(DOMAIN)


def test_non_public_ipv6_blocked(fake_dns):
    fake_dns.set(DOMAIN, "AAAA", ["fd00::1"])
    with pytest.raises(UnsafeTargetError):
        resolve_target(DOMAIN)


def test_nxdomain(fake_dns):
    fake_dns.set(DOMAIN, "A", status="nxdomain")
    fake_dns.set(DOMAIN, "AAAA", status="nxdomain")
    resolution = resolve(DOMAIN)
    assert resolution.nxdomain
    with pytest.raises(TargetResolutionError, match="does not exist"):
        build_target(resolution)


def test_no_address(fake_dns):
    with pytest.raises(NoAddressError):
        resolve_target(DOMAIN)


def test_dns_timeout_is_resolution_error(fake_dns):
    fake_dns.set(DOMAIN, "A", status="timeout")
    fake_dns.set(DOMAIN, "AAAA", status="timeout")
    with pytest.raises(TargetResolutionError) as info:
        resolve_target(DOMAIN)
    assert not isinstance(info.value, NoAddressError)


def test_invalid_domain_rejected_before_dns(fake_dns):
    with pytest.raises(DomainValidationError):
        resolve_target("localhost")
    assert fake_dns.queries == []


def test_disallowed_port_refused(no_network):
    with pytest.raises(ValueError, match="not allowed"):
        open_connection(Target(DOMAIN, ("93.184.215.14",)), 22)


def test_connection_to_private_pinned_address_refused(no_network):
    with pytest.raises(UnsafeTargetError):
        open_connection(Target(DOMAIN, ("10.0.0.1",)), 443)


def test_connection_uses_pinned_ip_only(monkeypatch):
    calls = []

    class FakeSocket:
        def settimeout(self, _t):
            pass

    def fake_create_connection(address, timeout):
        calls.append((address, timeout))
        return FakeSocket()

    monkeypatch.setattr(network.socket, "create_connection", fake_create_connection)
    _sock, used = open_connection(Target(DOMAIN, ("93.184.215.14",)), 443)
    assert used == "93.184.215.14"
    assert calls == [(("93.184.215.14", 443), network.config.CONNECT_TIMEOUT_SECONDS)]


def test_connection_falls_back_to_second_address(monkeypatch):
    attempts = []

    class FakeSocket:
        def settimeout(self, _t):
            pass

    def fake_create_connection(address, timeout):
        attempts.append(address[0])
        if address[0] == "93.184.215.14":
            raise ConnectionRefusedError()
        return FakeSocket()

    monkeypatch.setattr(network.socket, "create_connection", fake_create_connection)
    _sock, used = open_connection(Target(DOMAIN, ("93.184.215.14", "1.1.1.1")), 443)
    assert used == "1.1.1.1"
    assert attempts == ["93.184.215.14", "1.1.1.1"]
