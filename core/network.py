"""Target resolution and safe outbound connections (SSRF guard).

Design:
1. The domain is resolved exactly once (A + AAAA through dnspython).
2. Every resolved address must be globally routable; otherwise the whole
   assessment is refused before any TCP connection is opened.
3. TLS and HTTP modules connect to these *pinned* addresses only, with SNI and
   the Host header set to the domain. No connection performs its own DNS
   resolution, which removes the DNS-rebinding window between validation and
   use.
4. Only ports 80 and 443 can be reached, with explicit timeouts.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

from core import config
from core.dns_client import NXDOMAIN, DnsAnswer, lookup
from utils.validators import is_public_ip, validate_domain


class TargetError(Exception):
    """Base class for target resolution problems (message is user-facing)."""


class TargetResolutionError(TargetError):
    """The domain could not be resolved to any address."""


class NoAddressError(TargetResolutionError):
    """The domain exists but publishes no A/AAAA record."""


class UnsafeTargetError(TargetError):
    """The domain resolves to at least one non-public address."""


@dataclass(frozen=True)
class Resolution:
    """A and AAAA answers for a domain, obtained once per assessment."""

    domain: str
    ipv4: DnsAnswer
    ipv6: DnsAnswer

    @property
    def nxdomain(self) -> bool:
        return NXDOMAIN in (self.ipv4.status, self.ipv6.status)

    @property
    def addresses(self) -> list[str]:
        seen: list[str] = []
        for answer in (self.ipv4, self.ipv6):
            if answer.ok:
                for address in answer.records:
                    if address not in seen:
                        seen.append(address)
        return seen


@dataclass(frozen=True)
class Target:
    """A validated domain and the public addresses connections are pinned to."""

    domain: str
    addresses: tuple[str, ...]


def resolve(domain: str) -> Resolution:
    """Resolve A and AAAA records for an already validated domain."""
    return Resolution(domain, lookup(domain, "A"), lookup(domain, "AAAA"))


def build_target(resolution: Resolution) -> Target:
    """Turn a :class:`Resolution` into a pinned :class:`Target`.

    Raises:
        UnsafeTargetError: any address is private, loopback, link-local, etc.
        NoAddressError: the domain has no A/AAAA record.
        TargetResolutionError: NXDOMAIN or DNS failure.
    """
    domain = resolution.domain
    if resolution.nxdomain:
        raise TargetResolutionError(f"The domain {domain} does not exist (NXDOMAIN).")

    addresses = resolution.addresses
    if not addresses:
        failures = [a.error or a.status for a in (resolution.ipv4, resolution.ipv6) if a.failed]
        if failures:
            raise TargetResolutionError(
                f"DNS resolution of {domain} failed: {'; '.join(failures)}"
            )
        raise NoAddressError(f"{domain} publishes no A or AAAA record.")

    blocked = [address for address in addresses if not is_public_ip(address)]
    if blocked:
        raise UnsafeTargetError(
            f"{domain} resolves to non-public address(es) {', '.join(blocked)}. "
            "The assessment was blocked to prevent access to private, loopback or "
            "reserved networks."
        )
    return Target(domain, tuple(addresses[: config.MAX_TARGET_ADDRESSES]))


def resolve_target(domain: str) -> Target:
    """Validate, resolve and pin ``domain`` in one call."""
    return build_target(resolve(validate_domain(domain)))


def open_connection(target: Target, port: int) -> tuple[socket.socket, str]:
    """Open a TCP connection to one of the target's pinned addresses.

    Returns:
        The connected socket and the IP address actually used.

    Raises:
        ValueError: the port is not allowed.
        UnsafeTargetError: a pinned address is not public (defence in depth).
        OSError: connection failure (refused, timeout, unreachable...).
    """
    if port not in config.ALLOWED_PORTS:
        raise ValueError(f"Port {port} is not allowed.")
    if not target.addresses:
        raise OSError("No address available for connection.")

    last_error: OSError | None = None
    for address in target.addresses[: config.MAX_CONNECT_ATTEMPTS]:
        if not is_public_ip(address):
            raise UnsafeTargetError(f"Refusing to connect to non-public address {address}.")
        try:
            # A literal IP is passed, so no DNS resolution happens here.
            sock = socket.create_connection(
                (address, port), timeout=config.CONNECT_TIMEOUT_SECONDS
            )
        except OSError as exc:
            last_error = exc
            continue
        sock.settimeout(config.READ_TIMEOUT_SECONDS)
        return sock, address
    assert last_error is not None
    raise last_error
