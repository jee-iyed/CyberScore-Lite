"""Integration tests of the orchestration (network layer mocked)."""

import json

import pytest

from core import assessment
from core.assessment import AssessmentError, run_assessment
from core.catalog import CHECKS, make_result
from core.http_checks import HTTP_IDS
from core.models import Status
from core.report import report_to_json
from core.tls_checks import TLS_IDS
from utils.validators import DomainValidationError

DOMAIN = "example.com"


@pytest.fixture
def scanners(monkeypatch):
    calls = {"tls": 0, "http": 0}

    def fake_tls(target):
        calls["tls"] += 1
        calls["tls_target"] = target
        return [make_result(cid, Status.PASS, "ok") for cid in TLS_IDS]

    def fake_http(target):
        calls["http"] += 1
        return [make_result(cid, Status.WARNING, "meh") for cid in HTTP_IDS]

    monkeypatch.setattr(assessment.tls_checks, "run_tls_checks", fake_tls)
    monkeypatch.setattr(assessment.http_checks, "run_http_checks", fake_http)
    return calls


def test_full_assessment(fake_dns, scanners):
    fake_dns.set(DOMAIN, "A", ["93.184.215.14"])
    fake_dns.set(DOMAIN, "TXT", ["v=spf1 -all"])
    fake_dns.set(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=reject"])
    fake_dns.set(DOMAIN, "CAA", ['0 issue "letsencrypt.org"'])
    steps = []

    result = run_assessment("  Example.COM ", progress=lambda m, f: steps.append(f))

    assert result.domain == DOMAIN
    assert result.addresses == ["93.184.215.14"]
    assert scanners["tls_target"].addresses == ("93.184.215.14",)
    assert {r.id for r in result.results} == set(CHECKS)
    # DNS 25 PASS + TLS 40 PASS + HTTP 35 WARNING -> 82.5
    assert result.score["score"] == 82.5
    assert result.score["coverage_percent"] == 100.0
    assert steps == sorted(steps) and steps[-1] == 1.0
    json.loads(report_to_json(result.report))


def test_dns_resolved_only_once(fake_dns, scanners):
    fake_dns.set(DOMAIN, "A", ["93.184.215.14"])
    run_assessment(DOMAIN)
    assert fake_dns.queries.count((DOMAIN, "A")) == 1


def test_private_target_is_refused_before_any_connection(fake_dns, scanners):
    fake_dns.set(DOMAIN, "A", ["10.1.2.3"])
    with pytest.raises(AssessmentError, match="non-public"):
        run_assessment(DOMAIN)
    assert scanners["tls"] == 0 and scanners["http"] == 0


def test_nxdomain_is_refused(fake_dns, scanners):
    fake_dns.set(DOMAIN, "A", status="nxdomain")
    fake_dns.set(DOMAIN, "AAAA", status="nxdomain")
    with pytest.raises(AssessmentError, match="does not exist"):
        run_assessment(DOMAIN)


def test_invalid_domain_refused_without_dns(fake_dns, scanners):
    with pytest.raises(DomainValidationError):
        run_assessment("http://127.0.0.1/admin")
    assert fake_dns.queries == []


def test_domain_without_web_service(fake_dns, scanners):
    fake_dns.set(DOMAIN, "TXT", ["v=spf1 -all"])
    result = run_assessment(DOMAIN)
    web = [r for r in result.results if r.category.value in ("tls", "http")]
    assert {r.status for r in web} == {Status.NOT_APPLICABLE}
    assert scanners["tls"] == 0
    assert result.notices


def test_dns_failure_marks_web_checks_as_error(fake_dns, scanners):
    fake_dns.set(DOMAIN, "A", status="timeout")
    fake_dns.set(DOMAIN, "AAAA", status="timeout")
    result = run_assessment(DOMAIN)
    web = [r for r in result.results if r.category.value in ("tls", "http")]
    assert {r.status for r in web} == {Status.ERROR}
    assert result.score["reliable"] is False
