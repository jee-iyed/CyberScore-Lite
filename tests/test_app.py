"""UI tests using Streamlit's headless AppTest runner (no browser, no network)."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from core import assessment
from core.catalog import make_result
from core.models import Status
from core.sample import build_sample_assessment
from utils.formatting import controls_rows, evidence_preview, format_score, report_filename, status_label

APP = str(Path(__file__).resolve().parents[1] / "app.py")


@pytest.fixture
def engine_calls(monkeypatch):
    calls = []

    def fake_run(domain, progress=None):
        calls.append(domain)
        if progress:
            progress("step", 1.0)
        return build_sample_assessment()

    monkeypatch.setattr(assessment, "run_assessment", fake_run)
    return calls


def submit(at: AppTest, domain: str, authorized: bool) -> AppTest:
    at.text_input[0].input(domain)
    at.checkbox[0].check() if authorized else at.checkbox[0].uncheck()
    at.button(key="FormSubmitter:assessment_form-Run Assessment").click()
    return at.run()


def test_app_loads_without_running_assessment(engine_calls):
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert at.title[0].value.endswith("CyberScore Lite")
    assert engine_calls == []
    assert len(at.metric) == 0


def test_authorization_required(engine_calls):
    at = submit(AppTest.from_file(APP, default_timeout=30).run(), "example.com", authorized=False)
    assert any("authorised" in e.value for e in at.error)
    assert engine_calls == []


def test_invalid_domain_rejected(engine_calls):
    at = submit(AppTest.from_file(APP, default_timeout=30).run(), "localhost", authorized=True)
    assert at.error
    assert engine_calls == []


def test_successful_run_renders_dashboard(engine_calls):
    at = submit(AppTest.from_file(APP, default_timeout=30).run(), "Example.com", authorized=True)
    assert not at.exception
    assert engine_calls == ["example.com"]
    labels = [m.label for m in at.metric]
    assert "Overall score" in labels and "Coverage" in labels
    assert any(label.startswith("TLS/HTTPS") for label in labels)


def test_cooldown_blocks_rapid_reruns(engine_calls):
    at = submit(AppTest.from_file(APP, default_timeout=30).run(), "example.com", authorized=True)
    at = submit(at, "example.com", authorized=True)
    assert engine_calls == ["example.com"]
    assert any("wait" in w.value for w in at.warning)


def test_engine_refusal_is_displayed(monkeypatch):
    def refuse(domain, progress=None):
        raise assessment.AssessmentError("resolves to non-public address(es) 10.0.0.1")

    monkeypatch.setattr(assessment, "run_assessment", refuse)
    at = submit(AppTest.from_file(APP, default_timeout=30).run(), "example.com", authorized=True)
    assert any("non-public" in e.value for e in at.error)
    assert len(at.metric) == 0


def test_sample_button(engine_calls):
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.sidebar.button[0].click()
    at = at.run()
    assert not at.exception
    assert any("Sample data" in i.value for i in at.info)
    assert engine_calls == []


# ------------------------------------------------------------- formatting
def test_formatting_helpers():
    assert status_label(Status.FAIL) == "❌ FAIL"
    assert format_score(None) == "N/A"
    assert format_score(82.5) == "82.5"
    assert format_score(80.0) == "80"
    assert evidence_preview({}) == "—"
    assert len(evidence_preview({"x": "a" * 500})) <= 140
    assert report_filename("example.com", "2026-01-02T03:04:05+00:00") == "cyberscore-example.com-20260102T030405.json"


def test_controls_rows_hide_recommendation_for_pass():
    rows = controls_rows([make_result("http_hsts", Status.PASS, "ok"),
                          make_result("http_csp", Status.FAIL, "missing")])
    assert rows[0]["Recommendation"] == "—"
    assert rows[1]["Recommendation"] != "—"
    assert rows[1]["Category"] == "HTTP Security Headers"


def test_demo_query_param_loads_sample_without_network(engine_calls):
    at = AppTest.from_file(APP, default_timeout=30)
    at.query_params["demo"] = "sample"
    at = at.run()
    assert not at.exception
    assert any("Sample data" in i.value for i in at.info)
    assert engine_calls == []
