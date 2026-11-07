from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from core import dns_client
from core.dns_checks import (
    check_caa,
    check_dmarc,
    check_dns_resolution,
    check_mx,
    check_spf,
    parse_spf,
    run_dns_checks,
)
from core.models import Status
from core.network import resolve

DOMAIN = "example.com"


# ------------------------------------------------------------- dns client
class FakeResolver:
    def __init__(self, result=None, exc=None):
        self.result, self.exc = result, exc

    def resolve(self, name, rtype, search=False):
        if self.exc:
            raise self.exc
        return self.result


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "no_answer"),
        (dns.exception.Timeout(), "timeout"),
        (dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]), "timeout"),
        (dns.resolver.NoNameservers(), "servfail"),
        (dns.resolver.YXDOMAIN(), "error"),
    ],
)
def test_lookup_classifies_outcomes(exc, status):
    result = dns_client.lookup(DOMAIN, "TXT", resolver=FakeResolver(exc=exc))
    assert result.status == status
    assert result.records == []


def test_lookup_joins_split_txt_strings():
    """Long TXT records are split into 255-byte chunks that must be concatenated."""
    rdata = SimpleNamespace(strings=[b"v=spf1 include:_spf.example.net ", b"ip4:192.0.2.0/24 -all"])
    result = dns_client.lookup(DOMAIN, "TXT", resolver=FakeResolver(result=[rdata]))
    assert result.ok
    assert result.records == ["v=spf1 include:_spf.example.net ip4:192.0.2.0/24 -all"]


# -------------------------------------------------------------------- SPF
@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=spf1 -all", Status.PASS),
        ("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all", Status.PASS),
        ("v=spf1 mx ?all", Status.WARNING),
        ("v=spf1 mx", Status.WARNING),
        ("v=spf1 +all", Status.FAIL),
        ("v=spf1 all", Status.FAIL),
        ("v=spf1 ip4:999.1.1.1 -all", Status.FAIL),
        ("v=spf1 foo:bar -all", Status.FAIL),
        ("v=spf1 ip6:192.0.2.1 -all", Status.FAIL),
        ("v=spf1 ptr -all", Status.WARNING),
        ("v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all", Status.FAIL),
    ],
)
def test_spf_evaluation(fake_dns, record, status):
    fake_dns.set(DOMAIN, "TXT", ["google-site-verification=abc", record])
    assert check_spf(DOMAIN).status == status


def test_spf_missing(fake_dns):
    fake_dns.set(DOMAIN, "TXT", ["some-other=value"])
    result = check_spf(DOMAIN)
    assert result.status == Status.FAIL
    assert "No SPF" in result.summary


def test_spf_no_txt_at_all(fake_dns):
    assert check_spf(DOMAIN).status == Status.FAIL


def test_multiple_spf_records_fail(fake_dns):
    fake_dns.set(DOMAIN, "TXT", ["v=spf1 -all", "v=spf1 mx -all"])
    result = check_spf(DOMAIN)
    assert result.status == Status.FAIL
    assert "2 SPF records" in result.summary


def test_spf_prefix_must_be_exact(fake_dns):
    fake_dns.set(DOMAIN, "TXT", ["v=spf10 -all"])
    assert check_spf(DOMAIN).status == Status.FAIL  # not an SPF record


def test_spf_dns_timeout_is_error_not_missing(fake_dns):
    fake_dns.set(DOMAIN, "TXT", status="timeout")
    result = check_spf(DOMAIN)
    assert result.status == Status.ERROR


def test_spf_redirect_is_followed_once(fake_dns):
    fake_dns.set(DOMAIN, "TXT", ["v=spf1 redirect=_spf.example.net"])
    fake_dns.set("_spf.example.net", "TXT", ["v=spf1 ip4:192.0.2.1 -all"])
    result = check_spf(DOMAIN)
    assert result.status == Status.PASS
    assert result.evidence["redirect"]["domain"] == "_spf.example.net"


def test_parse_spf_counts_lookups():
    parsed = parse_spf("v=spf1 a mx include:x.example ip4:192.0.2.1 exists:%{i}.x.example -all")
    assert parsed["lookup_terms"] == 4
    assert parsed["all_qualifier"] == "-"
    assert parsed["errors"] == []


# ------------------------------------------------------------------ DMARC
@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=DMARC1; p=reject; rua=mailto:d@example.com", Status.PASS),
        ("v=DMARC1; p=quarantine", Status.PASS),
        ("v=DMARC1;p=REJECT", Status.PASS),
        ("v=DMARC1; p=none; rua=mailto:d@example.com", Status.WARNING),
        ("v=DMARC1; p=none; sp=reject", Status.WARNING),  # regression: 'sp=reject' != p
        ("v=DMARC1; p=reject; pct=50", Status.WARNING),
        ("v=DMARC1; p=quarantine; pct=100", Status.PASS),
        ("v=DMARC1; p=block", Status.FAIL),
        ("v=DMARC1; rua=mailto:d@example.com", Status.FAIL),
    ],
)
def test_dmarc_evaluation(fake_dns, record, status):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", [record])
    assert check_dmarc(DOMAIN).status == status


def test_dmarc_reject_evidence(fake_dns):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=reject"])
    result = check_dmarc(DOMAIN)
    assert result.evidence["policy"] == "reject"
    assert result.evidence["pct"] == 100
    assert result.evidence["rua_present"] is False


def test_dmarc_missing(fake_dns):
    result = check_dmarc(DOMAIN)
    assert result.status == Status.FAIL


def test_dmarc_multiple_records_fail(fake_dns):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert check_dmarc(DOMAIN).status == Status.FAIL


def test_dmarc_timeout_is_error(fake_dns):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", status="servfail")
    assert check_dmarc(DOMAIN).status == Status.ERROR


def test_dmarc_subdomain_inherits_sp(fake_dns):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=reject; sp=none"])
    result = check_dmarc(f"shop.{DOMAIN}")
    assert result.status == Status.WARNING
    assert result.evidence["inherited_from_parent"] is True
    assert result.evidence["policy_tag"] == "sp"


def test_dmarc_subdomain_inherits_p(fake_dns):
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=reject"])
    assert check_dmarc(f"shop.{DOMAIN}").status == Status.PASS


# --------------------------------------------------------------------- MX
def test_mx_absent_is_not_applicable(fake_dns):
    assert check_mx(DOMAIN).status == Status.NOT_APPLICABLE


def test_mx_present(fake_dns):
    fake_dns.set(DOMAIN, "MX", ["10 mx1.example.com", "20 mx2.example.com"])
    assert check_mx(DOMAIN).status == Status.PASS


def test_null_mx(fake_dns):
    fake_dns.set(DOMAIN, "MX", ["0 ."])
    result = check_mx(DOMAIN)
    assert result.status == Status.PASS
    assert "Null MX" in result.summary


def test_mx_timeout_is_error(fake_dns):
    fake_dns.set(DOMAIN, "MX", status="timeout")
    assert check_mx(DOMAIN).status == Status.ERROR


def test_mx_has_no_weight():
    from core.catalog import CHECKS

    assert CHECKS["dns_mx"].weight == 0


# -------------------------------------------------------------------- CAA
def test_caa_present(fake_dns):
    fake_dns.set(DOMAIN, "CAA", ['0 issue "letsencrypt.org"'])
    assert check_caa(DOMAIN).status == Status.PASS


def test_caa_inherited_from_parent(fake_dns):
    fake_dns.set(DOMAIN, "CAA", ['0 issue "digicert.com"'])
    result = check_caa(f"www.{DOMAIN}")
    assert result.status == Status.PASS
    assert result.evidence["found_at"] == DOMAIN


def test_caa_iodef_only(fake_dns):
    fake_dns.set(DOMAIN, "CAA", ['0 iodef "mailto:sec@example.com"'])
    assert check_caa(DOMAIN).status == Status.WARNING


def test_caa_absent(fake_dns):
    assert check_caa(DOMAIN).status == Status.WARNING


def test_caa_error(fake_dns):
    fake_dns.set(DOMAIN, "CAA", status="timeout")
    assert check_caa(DOMAIN).status == Status.ERROR


# ------------------------------------------------------------- resolution
def test_resolution_check(fake_dns):
    fake_dns.set(DOMAIN, "A", ["93.184.215.14"])
    assert check_dns_resolution(resolve(DOMAIN)).status == Status.PASS


def test_resolution_absent_is_not_applicable(fake_dns):
    assert check_dns_resolution(resolve(DOMAIN)).status == Status.NOT_APPLICABLE


def test_resolution_timeout_is_error(fake_dns):
    fake_dns.set(DOMAIN, "A", status="timeout")
    fake_dns.set(DOMAIN, "AAAA", status="timeout")
    assert check_dns_resolution(resolve(DOMAIN)).status == Status.ERROR


def test_run_dns_checks_returns_all_controls(fake_dns):
    ids = [r.id for r in run_dns_checks(DOMAIN)]
    assert ids == ["dns_resolution", "dns_mx", "dns_spf", "dns_dmarc", "dns_caa"]


def test_all_dns_results_have_full_metadata(fake_dns):
    for result in run_dns_checks(DOMAIN):
        data = result.to_dict()
        for key in ("id", "category", "status", "severity", "weight", "evidence",
                    "description", "risk_explanation", "recommendation"):
            assert key in data
        assert data["description"] and data["recommendation"]
