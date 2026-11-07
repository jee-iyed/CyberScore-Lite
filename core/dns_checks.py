"""DNS & email security checks: resolution, MX, SPF, DMARC and CAA."""

from __future__ import annotations

import ipaddress
from typing import Any

from core import dns_client
from core.catalog import make_result
from core.config import DNS_MAX_TREE_WALK, SPF_MAX_DNS_LOOKUPS
from core.dns_client import DnsAnswer
from core.models import CheckResult, Status
from core.network import Resolution, resolve
from utils.validators import validate_domain


def lookup(name: str, rtype: str) -> DnsAnswer:
    """Indirection point so tests can mock every DNS query of this module."""
    return dns_client.lookup(name, rtype)


def _parent_domains(domain: str, limit: int = DNS_MAX_TREE_WALK) -> list[str]:
    """Return ``domain`` and its parents, stopping before the TLD."""
    labels = domain.split(".")
    names = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    return names[: limit + 1]


# --------------------------------------------------------------------- A/AAAA
def check_dns_resolution(resolution: Resolution) -> CheckResult:
    """Informational control listing the published A/AAAA addresses."""
    evidence = {
        "ipv4": resolution.ipv4.records,
        "ipv6": resolution.ipv6.records,
        "ipv4_outcome": resolution.ipv4.status,
        "ipv6_outcome": resolution.ipv6.status,
    }
    if resolution.addresses:
        return make_result(
            "dns_resolution",
            Status.PASS,
            f"Resolves to {len(resolution.addresses)} address(es).",
            evidence,
        )
    if resolution.ipv4.failed or resolution.ipv6.failed:
        return make_result(
            "dns_resolution", Status.ERROR, "A/AAAA lookup failed.", evidence
        )
    return make_result(
        "dns_resolution",
        Status.NOT_APPLICABLE,
        "No A/AAAA record: the domain does not host a web service at its apex.",
        evidence,
    )


# ------------------------------------------------------------------------- MX
def check_mx(domain: str) -> CheckResult:
    """Informational: does the domain receive email?"""
    answer = lookup(domain, "MX")
    evidence = answer.to_evidence()
    if answer.failed:
        return make_result("dns_mx", Status.ERROR, "MX lookup failed.", evidence)
    if answer.absent:
        return make_result(
            "dns_mx",
            Status.NOT_APPLICABLE,
            "No MX record: the domain does not appear to receive email. SPF and DMARC "
            "are still evaluated because the domain can be spoofed as a sender.",
            evidence,
        )
    if answer.records == ["0 ."]:
        return make_result(
            "dns_mx",
            Status.PASS,
            "Null MX (RFC 7505): the domain explicitly accepts no email.",
            evidence,
        )
    return make_result(
        "dns_mx", Status.PASS, f"{len(answer.records)} MX record(s) published.", evidence
    )


# ------------------------------------------------------------------------ SPF
_SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
_SPF_LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def is_spf_record(text: str) -> bool:
    """True if a TXT string is an SPF version 1 record (RFC 7208 section 4.5)."""
    lowered = text.strip().lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def parse_spf(record: str) -> dict[str, Any]:
    """Parse an SPF record into its relevant properties.

    Returns a dict with ``all_qualifier`` (``+ - ~ ?`` or None), ``redirect``,
    ``lookup_terms`` (top-level DNS-querying terms), ``uses_ptr`` and a list
    of syntax ``errors``.
    """
    terms = record.split()[1:]
    errors: list[str] = []
    all_qualifier: str | None = None
    redirect: str | None = None
    lookup_terms = 0
    uses_ptr = False
    modifiers_seen: set[str] = set()

    for term in terms:
        lowered = term.lower()
        name, sep, value = lowered.partition("=")
        if sep and ":" not in name and "/" not in name and name not in _SPF_MECHANISMS:
            # Modifier: name=value
            if name in ("redirect", "exp"):
                if name in modifiers_seen:
                    errors.append(f"duplicate '{name}' modifier")
                modifiers_seen.add(name)
                if not value:
                    errors.append(f"'{name}' modifier without domain")
                if name == "redirect":
                    redirect = value
                    lookup_terms += 1
            continue

        qualifier = "+"
        if lowered[:1] in "+-~?":
            qualifier, lowered = lowered[0], lowered[1:]
        mechanism, _, argument = lowered.partition(":")
        mechanism = mechanism.split("/")[0]
        if mechanism not in _SPF_MECHANISMS:
            errors.append(f"unknown mechanism '{term}'")
            continue
        if mechanism in _SPF_LOOKUP_TERMS:
            lookup_terms += 1
        if mechanism == "ptr":
            uses_ptr = True
        if mechanism == "all":
            all_qualifier = qualifier
        elif mechanism in ("include", "exists") and not argument:
            errors.append(f"'{mechanism}' requires a domain argument")
        elif mechanism in ("ip4", "ip6"):
            try:
                network = ipaddress.ip_network(argument, strict=False)
            except ValueError:
                errors.append(f"invalid network in '{term}'")
            else:
                if (mechanism == "ip4") != (network.version == 4):
                    errors.append(f"address family mismatch in '{term}'")

    return {
        "all_qualifier": all_qualifier,
        "redirect": redirect if all_qualifier is None else None,
        "lookup_terms": lookup_terms,
        "uses_ptr": uses_ptr,
        "errors": errors,
    }


def check_spf(domain: str) -> CheckResult:
    """Evaluate the domain's SPF policy (single record, syntax, ``all``)."""
    answer = lookup(domain, "TXT")
    if answer.failed:
        return make_result(
            "dns_spf", Status.ERROR, "TXT lookup failed; SPF could not be assessed.",
            answer.to_evidence(),
        )

    records = [txt for txt in answer.records if is_spf_record(txt)]
    evidence: dict[str, Any] = {"records": records}

    if not records:
        return make_result("dns_spf", Status.FAIL, "No SPF record is published.", evidence)
    if len(records) > 1:
        return make_result(
            "dns_spf",
            Status.FAIL,
            f"{len(records)} SPF records found; RFC 7208 treats this as a permanent "
            "error, so SPF is ignored by receivers.",
            evidence,
            "Merge all SPF records into a single 'v=spf1 ... -all' TXT record.",
        )

    parsed = parse_spf(records[0])
    all_qualifier = parsed["all_qualifier"]
    notes: list[str] = []

    if all_qualifier is None and parsed["redirect"]:
        redirect = parsed["redirect"]
        target = lookup(redirect, "TXT")
        targets = [t for t in target.records if is_spf_record(t)] if target.ok else []
        evidence["redirect"] = {"domain": redirect, "records": targets}
        if len(targets) == 1:
            all_qualifier = parse_spf(targets[0])["all_qualifier"]
            notes.append(f"policy inherited from redirect={redirect}")
        else:
            notes.append(f"redirect target {redirect} could not be evaluated")

    evidence.update(
        {
            "all_qualifier": all_qualifier,
            "top_level_dns_lookup_terms": parsed["lookup_terms"],
            "syntax_errors": parsed["errors"],
        }
    )

    if parsed["errors"]:
        return make_result(
            "dns_spf",
            Status.FAIL,
            "SPF record has syntax errors: " + "; ".join(parsed["errors"]) + ".",
            evidence,
        )
    if parsed["lookup_terms"] > SPF_MAX_DNS_LOOKUPS:
        return make_result(
            "dns_spf",
            Status.FAIL,
            f"SPF requires at least {parsed['lookup_terms']} DNS lookups (limit "
            f"{SPF_MAX_DNS_LOOKUPS}); receivers return a permanent error.",
            evidence,
            "Flatten or reduce include/a/mx/ptr/exists terms to stay within 10 lookups.",
        )
    if all_qualifier == "+":
        return make_result(
            "dns_spf",
            Status.FAIL,
            "SPF ends with '+all', which authorises every host on the Internet.",
            evidence,
            "Replace '+all' with '-all' (or '~all') after listing legitimate senders.",
        )
    if all_qualifier in ("?", None):
        reason = "'?all' (neutral)" if all_qualifier == "?" else "no 'all' mechanism"
        return make_result(
            "dns_spf",
            Status.WARNING,
            f"SPF has {reason}: unlisted senders are not rejected.",
            evidence,
            "End the SPF record with '-all' (or '~all') so unlisted senders fail.",
        )
    if parsed["uses_ptr"]:
        notes.append("uses the deprecated 'ptr' mechanism")
        evidence["notes"] = notes
        return make_result(
            "dns_spf",
            Status.WARNING,
            "SPF is restrictive but uses the deprecated 'ptr' mechanism.",
            evidence,
            "Replace 'ptr' with explicit ip4/ip6/include mechanisms.",
        )

    label = "hard fail (-all)" if all_qualifier == "-" else "soft fail (~all)"
    if notes:
        evidence["notes"] = notes
    return make_result(
        "dns_spf", Status.PASS, f"Single valid SPF record with {label}.", evidence
    )


# ---------------------------------------------------------------------- DMARC
def is_dmarc_record(text: str) -> bool:
    """True if a TXT string starts with the DMARC version tag."""
    return text.strip().replace(" ", "").lower().startswith("v=dmarc1")


def parse_dmarc(record: str) -> dict[str, str]:
    """Parse a DMARC record into a ``{tag: value}`` dict (lower-case tags)."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key and key not in tags:
            tags[key] = value.strip()
    return tags


def check_dmarc(domain: str) -> CheckResult:
    """Evaluate the DMARC policy that applies to ``domain``.

    Discovery climbs towards the organisational domain (DNS tree walk, as in
    DMARCbis) so that a subdomain inherits its parent's ``sp``/``p`` policy.
    """
    queried: list[str] = []
    found_at: str | None = None
    records: list[str] = []

    for name in _parent_domains(domain):
        answer = lookup(f"_dmarc.{name}", "TXT")
        queried.append(f"_dmarc.{name}")
        if answer.failed:
            return make_result(
                "dns_dmarc",
                Status.ERROR,
                f"DMARC lookup for _dmarc.{name} failed.",
                answer.to_evidence(),
            )
        records = [txt for txt in answer.records if is_dmarc_record(txt)]
        if records:
            found_at = name
            break

    evidence: dict[str, Any] = {"queried": queried, "records": records}
    if not records:
        return make_result("dns_dmarc", Status.FAIL, "No DMARC record is published.", evidence)
    if len(records) > 1:
        return make_result(
            "dns_dmarc",
            Status.FAIL,
            f"{len(records)} DMARC records found at _dmarc.{found_at}; receivers "
            "ignore DMARC when several records exist.",
            evidence,
            "Keep exactly one 'v=DMARC1' TXT record.",
        )

    tags = parse_dmarc(records[0])
    inherited = found_at != domain
    policy_tag = "sp" if inherited and "sp" in tags else "p"
    policy = tags.get(policy_tag, "").lower()

    pct_raw = tags.get("pct", "100")
    try:
        pct = int(pct_raw)
        if not 0 <= pct <= 100:
            raise ValueError
    except ValueError:
        pct = 100
        evidence["notes"] = [f"invalid pct value '{pct_raw}' treated as 100"]

    evidence.update(
        {
            "found_at": f"_dmarc.{found_at}",
            "inherited_from_parent": inherited,
            "policy_tag": policy_tag,
            "policy": policy or None,
            "pct": pct,
            "rua_present": "rua" in tags,
        }
    )

    if policy not in ("none", "quarantine", "reject"):
        return make_result(
            "dns_dmarc",
            Status.FAIL,
            "DMARC record has a missing or invalid policy (p=) tag.",
            evidence,
            "Set a valid policy: p=none (monitoring), p=quarantine or p=reject.",
        )
    if policy == "none":
        return make_result(
            "dns_dmarc",
            Status.WARNING,
            "DMARC policy is p=none (monitoring only): spoofed mail is not blocked.",
            evidence,
            "Review DMARC aggregate reports, align legitimate senders, then move to "
            "p=quarantine and finally p=reject.",
        )
    if pct < 100:
        return make_result(
            "dns_dmarc",
            Status.WARNING,
            f"DMARC policy {policy} applies to only {pct}% of failing mail.",
            evidence,
            "Raise pct to 100 (or remove the pct tag) once enforcement is validated.",
        )
    summary = f"DMARC enforces p={policy}"
    if inherited:
        summary += f" (inherited from {found_at})"
    if "rua" not in tags:
        summary += "; no aggregate reporting (rua) configured"
    return make_result("dns_dmarc", Status.PASS, summary + ".", evidence)


# ------------------------------------------------------------------------ CAA
def check_caa(domain: str) -> CheckResult:
    """Evaluate CAA records, climbing the tree as CAs do (RFC 8659)."""
    queried: list[str] = []
    for name in _parent_domains(domain):
        answer = lookup(name, "CAA")
        queried.append(name)
        if answer.failed:
            return make_result(
                "dns_caa", Status.ERROR, f"CAA lookup for {name} failed.",
                answer.to_evidence(),
            )
        if answer.ok and answer.records:
            evidence = {"found_at": name, "records": answer.records, "queried": queried}
            tags = {record.split()[1].lower() for record in answer.records if record.count(" ") >= 2}
            if tags & {"issue", "issuewild"}:
                return make_result(
                    "dns_caa",
                    Status.PASS,
                    f"CAA restricts certificate issuance (published at {name}).",
                    evidence,
                )
            return make_result(
                "dns_caa",
                Status.WARNING,
                "CAA records exist but contain no 'issue'/'issuewild' restriction.",
                evidence,
            )
    return make_result(
        "dns_caa",
        Status.WARNING,
        "No CAA record: any public certificate authority may issue certificates.",
        {"queried": queried},
    )


# ---------------------------------------------------------------- orchestration
def run_dns_checks(domain: str, resolution: Resolution | None = None) -> list[CheckResult]:
    """Run every DNS check for ``domain``."""
    domain = validate_domain(domain)
    resolution = resolution or resolve(domain)
    return [
        check_dns_resolution(resolution),
        check_mx(domain),
        check_spf(domain),
        check_dmarc(domain),
        check_caa(domain),
    ]
