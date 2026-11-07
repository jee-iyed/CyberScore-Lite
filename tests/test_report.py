import json
from datetime import UTC, datetime

from core.catalog import CHECKS, make_result
from core.config import VERSION
from core.models import Status
from core.report import build_report, prioritized_recommendations, report_to_json
from core.sample import build_sample_assessment
from core.scoring import compute_score


def sample_results():
    statuses = {
        "tls_certificate_trust": Status.FAIL,  # critical -> P1
        "http_referrer_policy": Status.WARNING,  # low -> P3
        "http_hsts": Status.WARNING,  # high -> P2
        "http_csp": Status.FAIL,  # medium -> P2
        "dns_caa": Status.ERROR,
        "dns_mx": Status.FAIL,  # informational, weight 0
    }
    return [make_result(cid, statuses.get(cid, Status.PASS), f"summary {cid}", {"k": cid}) for cid in CHECKS]


def test_report_is_valid_json_and_complete():
    results = sample_results()
    fixed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    report = build_report("example.com", results, compute_score(results),
                          addresses=["93.184.215.14"], generated_at=fixed)
    parsed = json.loads(report_to_json(report))

    assert parsed["tool"] == {"name": "CyberScore Lite", "version": VERSION}
    assert parsed["assessment"]["domain"] == "example.com"
    assert parsed["assessment"]["generated_at_utc"] == "2026-01-02T03:04:05+00:00"
    assert parsed["assessment"]["sample_data"] is False
    assert parsed["summary"]["score"] is not None
    assert set(parsed["summary"]["categories"]) == {"dns", "tls", "http"}
    assert len(parsed["checks"]) == len(CHECKS)
    assert parsed["limitations"]
    for check in parsed["checks"]:
        for key in ("id", "category", "status", "severity", "weight", "evidence",
                    "description", "risk_explanation", "recommendation"):
            assert key in check


def test_evidence_is_passed_through_unchanged():
    results = sample_results()
    report = build_report("example.com", results, compute_score(results))
    assert all(c["evidence"] == {"k": c["id"]} for c in report["checks"])


def test_recommendations_prioritised():
    recs = prioritized_recommendations(sample_results())
    ids = [r["check_id"] for r in recs]
    assert ids == ["tls_certificate_trust", "http_csp", "http_hsts", "http_referrer_policy"]
    assert [r["priority"] for r in recs] == ["P1", "P2", "P2", "P3"]
    assert "dns_mx" not in ids  # weight-0 informational checks are not remediation items
    assert all(r["risk"] and r["recommendation"] for r in recs)


def test_errors_listed_as_not_assessed():
    results = sample_results()
    report = build_report("example.com", results, compute_score(results))
    assert [item["check_id"] for item in report["not_assessed"]] == ["dns_caa"]


def test_non_native_evidence_is_serialisable():
    result = make_result("http_hsts", Status.PASS, "ok",
                         {"tuple": (1, 2), "when": datetime(2026, 1, 1, tzinfo=UTC),
                          "raw": b"\x01", "status": Status.PASS, "obj": object()})
    report = build_report("example.com", [result], compute_score([result]))
    parsed = json.loads(report_to_json(report))
    evidence = parsed["checks"][0]["evidence"]
    assert evidence["tuple"] == [1, 2]
    assert evidence["status"] == "PASS"
    assert evidence["raw"] == "01"


def test_null_score_serialises():
    result = make_result("http_hsts", Status.ERROR, "unreachable")
    parsed = json.loads(report_to_json(build_report("example.com", [result], compute_score([result]))))
    assert parsed["summary"]["score"] is None


def test_sample_report_is_flagged():
    sample = build_sample_assessment()
    assert sample.sample_data is True
    assert sample.report["assessment"]["sample_data"] is True
    assert sample.domain.endswith(".example")  # reserved documentation TLD
    json.loads(report_to_json(sample.report))
