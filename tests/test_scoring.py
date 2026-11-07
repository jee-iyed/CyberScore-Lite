import pytest

from core.catalog import CATEGORY_WEIGHTS, CHECKS, make_result, validate_catalog
from core.models import Category, Status
from core.scoring import compute_score, grade_for

SCORED_IDS = [check_id for check_id, d in CHECKS.items() if d.weight > 0]


def results_with(default: Status = Status.PASS, **overrides: Status):
    return [
        make_result(check_id, overrides.get(check_id, default), "test")
        for check_id in CHECKS
    ]


def test_category_weights_total_100():
    assert sum(CATEGORY_WEIGHTS.values()) == 100
    assert CATEGORY_WEIGHTS == {Category.DNS: 25, Category.TLS: 40, Category.HTTP: 35}
    validate_catalog()


def test_catalog_matches_scanner_ids():
    """The scoring catalog must cover exactly the ids the scanners emit."""
    from core.http_checks import HTTP_IDS
    from core.tls_checks import TLS_IDS

    dns_ids = {"dns_resolution", "dns_mx", "dns_spf", "dns_dmarc", "dns_caa"}
    assert set(CHECKS) == dns_ids | set(TLS_IDS) | set(HTTP_IDS)


def test_all_pass_scores_100():
    score = compute_score(results_with(Status.PASS))
    assert score["score"] == 100.0
    assert score["coverage_percent"] == 100.0
    assert score["grade"] == "A"
    assert score["reliable"] is True


def test_all_fail_scores_0():
    score = compute_score(results_with(Status.FAIL))
    assert score["score"] == 0.0
    assert score["grade"] == "F"


def test_warning_is_half():
    score = compute_score(results_with(Status.WARNING))
    assert score["score"] == 50.0


def test_mixed_statuses():
    # TLS trust (15) FAIL, HSTS (10) WARNING, everything else PASS
    score = compute_score(results_with(tls_certificate_trust=Status.FAIL, http_hsts=Status.WARNING))
    assert score["score"] == pytest.approx(80.0)
    assert score["categories"]["tls"]["score"] == pytest.approx(62.5)
    assert score["categories"]["http"]["score"] == pytest.approx(100 * 30 / 35, abs=0.1)
    assert score["categories"]["dns"]["score"] == 100.0
    assert score["failed"] == 1 and score["warnings"] == 1


def test_error_excluded_and_lowers_coverage():
    score = compute_score(results_with(tls_certificate_trust=Status.ERROR, http_csp=Status.FAIL))
    # evaluated = 100 - 15 ; earned = 85 - 8
    assert score["score"] == pytest.approx(round(100 * 77 / 85, 1))
    assert score["coverage_percent"] == 85.0
    assert score["errors"] == 1


def test_not_applicable_excluded_without_lowering_coverage():
    score = compute_score(results_with(http_https_redirect=Status.NOT_APPLICABLE))
    assert score["score"] == 100.0
    assert score["coverage_percent"] == 100.0
    assert score["applicable_points"] == 95.0
    assert score["not_applicable"] == 1


def test_partial_coverage_has_no_grade():
    errors = {check_id: Status.ERROR for check_id in SCORED_IDS if not check_id.startswith("dns_")}
    score = compute_score(results_with(Status.PASS, **errors))
    assert score["score"] == 100.0  # only DNS evaluated, all passing...
    assert score["coverage_percent"] == 25.0
    assert score["reliable"] is False  # ...but it is explicitly flagged
    assert score["grade"] is None
    assert score["categories"]["tls"]["score"] is None


def test_nothing_evaluable_returns_null_score():
    score = compute_score(results_with(Status.ERROR))
    assert score["score"] is None
    assert score["grade"] is None
    assert score["coverage_percent"] == 0.0


def test_empty_results():
    score = compute_score([])
    assert score["score"] is None
    assert score["coverage_percent"] == 0.0


def test_informational_checks_do_not_affect_score():
    score = compute_score(results_with(Status.PASS, dns_mx=Status.FAIL, dns_resolution=Status.ERROR))
    assert score["score"] == 100.0
    assert score["coverage_percent"] == 100.0


def test_accepts_serialised_results():
    as_dicts = [r.to_dict() for r in results_with(http_hsts=Status.FAIL)]
    assert compute_score(as_dicts)["score"] == 90.0


def test_counts():
    score = compute_score(
        results_with(dns_spf=Status.FAIL, dns_dmarc=Status.WARNING, dns_caa=Status.ERROR,
                     http_https_redirect=Status.NOT_APPLICABLE)
    )
    assert score["counts"] == {"PASS": 10, "WARNING": 1, "FAIL": 1, "ERROR": 1, "NOT_APPLICABLE": 1}


@pytest.mark.parametrize(("value", "grade"), [(95, "A"), (90, "A"), (85, "B"), (72, "C"), (60, "D"), (10, "F"), (None, None)])
def test_grades(value, grade):
    assert grade_for(value) == grade
