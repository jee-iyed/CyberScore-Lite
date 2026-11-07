"""Thin wrapper around dnspython that never raises and labels every outcome.

Distinguishing "the record does not exist" from "the lookup failed" is what
prevents a DNS timeout from being reported as a missing SPF record (and vice
versa).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.name
import dns.resolver

from core.config import DNS_LIFETIME_SECONDS, DNS_TIMEOUT_SECONDS

# Outcome labels
OK = "ok"
NXDOMAIN = "nxdomain"
NO_ANSWER = "no_answer"
TIMEOUT = "timeout"
SERVFAIL = "servfail"
ERROR = "error"

#: Outcomes meaning "the data is authoritatively absent".
ABSENT = frozenset({NXDOMAIN, NO_ANSWER})
#: Outcomes meaning "we could not find out".
FAILED = frozenset({TIMEOUT, SERVFAIL, ERROR})


@dataclass(frozen=True)
class DnsAnswer:
    """Result of one DNS query."""

    name: str
    rtype: str
    status: str
    records: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK

    @property
    def absent(self) -> bool:
        return self.status in ABSENT

    @property
    def failed(self) -> bool:
        return self.status in FAILED

    def to_evidence(self) -> dict[str, Any]:
        data: dict[str, Any] = {"query": f"{self.name} {self.rtype}", "outcome": self.status}
        if self.records:
            data["records"] = list(self.records)
        if self.error:
            data["error"] = self.error
        return data


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_LIFETIME_SECONDS
    return resolver


def _rdata_to_text(rtype: str, rdata: Any) -> str:
    if rtype == "TXT":
        # TXT records may be split into several <=255-byte strings that must
        # be concatenated without separator (RFC 7208 section 3.3).
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rtype in ("A", "AAAA"):
        return str(rdata.address)
    if rtype == "MX":
        exchange = "." if rdata.exchange == dns.name.root else rdata.exchange.to_text(True)
        return f"{rdata.preference} {exchange}"
    if rtype == "CAA":
        tag = rdata.tag.decode("ascii", errors="replace")
        value = rdata.value.decode("utf-8", errors="replace")
        return f'{rdata.flags} {tag} "{value}"'
    return rdata.to_text()


def lookup(name: str, rtype: str, resolver: dns.resolver.Resolver | None = None) -> DnsAnswer:
    """Resolve ``name``/``rtype`` and return a labelled :class:`DnsAnswer`."""
    try:
        active = resolver or _make_resolver()
        answer = active.resolve(name, rtype, search=False)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer(name, rtype, NXDOMAIN)
    except dns.resolver.NoAnswer:
        return DnsAnswer(name, rtype, NO_ANSWER)
    except dns.exception.Timeout:
        return DnsAnswer(name, rtype, TIMEOUT, error="DNS query timed out.")
    except dns.resolver.NoNameservers:
        return DnsAnswer(
            name, rtype, SERVFAIL, error="All nameservers failed (SERVFAIL/REFUSED)."
        )
    except dns.exception.DNSException as exc:
        return DnsAnswer(name, rtype, ERROR, error=f"{type(exc).__name__}: {exc}")

    records = [_rdata_to_text(rtype, rdata) for rdata in answer]
    return DnsAnswer(name, rtype, OK, records=records)
