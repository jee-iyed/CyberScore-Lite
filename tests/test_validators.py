import pytest

from utils.validators import DomainValidationError, is_public_ip, validate_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("mail.example.com", "mail.example.com"),
        ("  example.com  ", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("example.xn--p1ai", "example.xn--p1ai"),
        ("a-b.example.org", "a-b.example.org"),
    ],
)
def test_valid_domains(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com",
        "http://example.com",
        "example.com/admin",
        "example.com?x=1",
        "user@example.com",
        "example.com:8080",
        "exa mple.com",
        "",
        "   ",
        "example",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "example..com",
        "example.c0m",
        "127.1",
        "0x7f.0x1",
        "a" * 64 + ".com",
        ("a" * 60 + ".") * 5 + "com",
    ],
)
def test_malformed_domains_rejected(raw):
    with pytest.raises(DomainValidationError):
        validate_domain(raw)


@pytest.mark.parametrize("raw", ["127.0.0.1", "8.8.8.8", "::1", "[2001:db8::1]"])
def test_ip_literals_rejected(raw):
    with pytest.raises(DomainValidationError, match="IP addresses are not accepted"):
        validate_domain(raw)


@pytest.mark.parametrize(
    "raw",
    ["localhost", "app.localhost", "printer.local", "db.internal", "router.home.arpa",
     "x.test", "foo.example", "bar.invalid", "hidden.onion", "srv.corp", "nas.lan"],
)
def test_reserved_and_internal_names_rejected(raw):
    with pytest.raises(DomainValidationError):
        validate_domain(raw)


def test_non_string_rejected():
    with pytest.raises(DomainValidationError):
        validate_domain(None)


def test_validation_error_is_value_error():
    assert issubclass(DomainValidationError, ValueError)


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",  # cloud metadata endpoint
        "100.64.0.1",  # carrier-grade NAT
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "255.255.255.255",
        "192.0.2.1",  # documentation
        "::1",
        "::",
        "fe80::1",
        "fe80::1%eth0",
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.1.2.3",
        "2002:c0a8:0101::1",  # 6to4 embedding 192.168.1.1
        "64:ff9b::7f00:1",  # NAT64 embedding 127.0.0.1
        "64:ff9b:1::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
        "not-an-ip",
        "",
    ],
)
def test_non_public_addresses_blocked(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    ["8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "::ffff:8.8.8.8",
     "64:ff9b::808:808"],
)
def test_public_addresses_allowed(ip):
    assert is_public_ip(ip) is True
