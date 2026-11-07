"""Input validation: domain names and public IP addresses.

These functions are the first line of defence against the tool being used to
reach internal infrastructure (SSRF). They are deliberately strict.
"""

from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# Special-use / internal names that must never be assessed (RFC 6761, 6762,
# 8375, 9476 and common private conventions).
BLOCKED_SUFFIXES: tuple[str, ...] = (
    "localhost",
    "localdomain",
    "local",
    "internal",
    "intranet",
    "private",
    "corp",
    "home",
    "lan",
    "home.arpa",
    "arpa",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
)

_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_PREFIX = ipaddress.ip_network("64:ff9b:1::/48")


class DomainValidationError(ValueError):
    """Raised when user input is not an acceptable public domain name."""


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def validate_domain(domain: object) -> str:
    """Validate and normalise a user-supplied domain name.

    Only bare hostnames are accepted: no scheme, port, path, credentials or IP
    literal, so that the user cannot steer requests to arbitrary endpoints.
    Internationalised names are converted to their ASCII (punycode) form.

    Returns:
        The lower-case ASCII domain without trailing dot.

    Raises:
        DomainValidationError: with a message suitable for end users.
    """
    if not isinstance(domain, str):
        raise DomainValidationError("Domain must be a string.")

    candidate = domain.strip()
    if not candidate:
        raise DomainValidationError("Please enter a domain name.")
    if len(candidate) > 300:
        raise DomainValidationError("Domain name is too long.")
    if "://" in candidate or candidate.lower().startswith(("http:", "https:")):
        raise DomainValidationError(
            "Enter a bare domain name such as example.com, without http:// or https://."
        )
    if any(ch.isspace() for ch in candidate):
        raise DomainValidationError("Domain name must not contain spaces.")
    if any(ch in candidate for ch in "/\\?#@"):
        raise DomainValidationError(
            "Enter a bare domain name only: paths, query strings and credentials "
            "are not accepted."
        )
    if _looks_like_ip(candidate):
        raise DomainValidationError(
            "IP addresses are not accepted. Enter the domain name you are authorised "
            "to assess."
        )
    if ":" in candidate:
        raise DomainValidationError("Ports are not accepted; enter a domain name only.")

    candidate = candidate.lower()
    if candidate.endswith("."):
        candidate = candidate[:-1]

    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError("Invalid domain name format.") from exc

    if len(ascii_name) > 253:
        raise DomainValidationError("Domain name exceeds 253 characters.")

    for suffix in BLOCKED_SUFFIXES:
        if ascii_name == suffix or ascii_name.endswith("." + suffix):
            raise DomainValidationError(
                f"'{ascii_name}' is a local, internal or reserved name and cannot be "
                "assessed."
            )

    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise DomainValidationError(
            "Enter a fully qualified domain name including its TLD (e.g. example.com)."
        )
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise DomainValidationError("Invalid domain name format.")
    if not _TLD_RE.fullmatch(labels[-1]):
        raise DomainValidationError("Invalid top-level domain.")

    return ascii_name


def is_public_ip(value: str) -> bool:
    """Return True only for globally routable unicast addresses.

    Beyond :pyattr:`ipaddress.IPv4Address.is_global`, this also unwraps IPv6
    transition formats that embed an IPv4 address (IPv4-mapped, 6to4, NAT64),
    which Python 3.11 reports as global even when they embed 127.0.0.1 or
    RFC 1918 space.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id:
            return False
        if address.ipv4_mapped is not None:
            return is_public_ip(str(address.ipv4_mapped))
        if address.sixtofour is not None:
            return is_public_ip(str(address.sixtofour))
        if address.teredo is not None:
            return False
        if address in _NAT64_PREFIX:
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
            return is_public_ip(str(embedded))
        if address in _NAT64_LOCAL_PREFIX:
            return False

    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
    )
