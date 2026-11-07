"""CyberScore Lite - Streamlit dashboard.

No network activity happens until the user submits an authorised domain.
"""

from __future__ import annotations

import time

import streamlit as st

from core import assessment as engine
from core.catalog import CATEGORY_WEIGHTS, CHECKS
from core.config import APP_NAME, ASSESSMENT_COOLDOWN_SECONDS, VERSION
from core.models import Category, Status
from core.report import report_to_json
from core.sample import build_sample_assessment
from utils.formatting import (
    PRIORITY_LABELS,
    controls_rows,
    format_score,
    report_filename,
    status_label,
)
from utils.validators import DomainValidationError, validate_domain

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

STATE_KEY = "assessment"
LAST_RUN_KEY = "last_run_at"
SHORT_LABELS = {Category.DNS: "DNS & Email", Category.TLS: "TLS/HTTPS", Category.HTTP: "HTTP Headers"}


# ----------------------------------------------------------------- sidebar
def render_sidebar() -> None:
    with st.sidebar:
        st.header("About")
        st.write(
            "CyberScore Lite performs a **non-intrusive** review of a domain's external "
            "configuration: DNS/email, TLS/HTTPS and HTTP security headers."
        )
        st.subheader("Scoring weights")
        st.dataframe(
            [
                {"Category": c.label, "Points": int(w)}
                for c, w in CATEGORY_WEIGHTS.items()
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption("PASS = 100 %, WARNING = 50 %, FAIL = 0 %. ERROR and N/A are excluded.")
        st.divider()
        st.subheader("Offline demo")
        if st.button("Load sample report", help="Illustrative data, no network access."):
            st.session_state[STATE_KEY] = build_sample_assessment()
        st.divider()
        st.caption(f"{APP_NAME} v{VERSION} · educational tool, not an official rating.")


# ------------------------------------------------------------------- input
def render_header() -> None:
    st.title("🛡️ CyberScore Lite")
    st.markdown(
        "**External Cyber Exposure & Security Posture Scoring** — an explainable score "
        "out of 100 based on DNS & email security, TLS/HTTPS and HTTP security headers."
    )
    with st.expander("Scope & authorised use"):
        st.markdown(
            "- Only assess domains you own or are **explicitly authorised** to assess.\n"
            "- Footprint: a few DNS queries, up to 3 TLS handshakes and at most 8 HTTP "
            "HEAD/GET requests to `/` on ports 80/443.\n"
            "- No port scanning, brute force, fuzzing or exploitation.\n"
            "- Domains resolving to private, loopback, link-local or reserved "
            "addresses are refused."
        )


def run_from_form() -> None:
    with st.form("assessment_form"):
        domain_input = st.text_input("Domain to assess", placeholder="example.com")
        authorized = st.checkbox(
            "I confirm that I own this domain or am explicitly authorised to assess it."
        )
        submitted = st.form_submit_button("Run Assessment", type="primary")

    if not submitted:
        return
    try:
        domain = validate_domain(domain_input)
    except DomainValidationError as exc:
        st.error(str(exc))
        return
    if not authorized:
        st.error("Please confirm that you are authorised to assess this domain.")
        return

    elapsed = time.monotonic() - st.session_state.get(LAST_RUN_KEY, float("-inf"))
    if elapsed < ASSESSMENT_COOLDOWN_SECONDS:
        st.warning(
            f"Please wait {ASSESSMENT_COOLDOWN_SECONDS - elapsed:.0f}s before running "
            "another assessment."
        )
        return
    st.session_state[LAST_RUN_KEY] = time.monotonic()

    with st.status(f"Assessing {domain}…", expanded=True) as status:
        bar = st.progress(0.0)

        def progress(message: str, fraction: float) -> None:
            status.write(message)
            bar.progress(min(max(fraction, 0.0), 1.0))

        try:
            result = engine.run_assessment(domain, progress=progress)
        except (engine.AssessmentError, DomainValidationError) as exc:
            status.update(label="Assessment refused", state="error")
            st.error(str(exc))
            return
        except Exception:  # noqa: BLE001 - never show a stack trace to users
            status.update(label="Assessment failed", state="error")
            st.error("An unexpected error occurred. No results were produced.")
            return
        status.update(label=f"Assessment of {domain} complete", state="complete", expanded=False)
    st.session_state[STATE_KEY] = result


# --------------------------------------------------------------- dashboard
def render_dashboard(result: engine.AssessmentResult) -> None:
    score = result.score
    report = result.report

    st.divider()
    st.subheader(f"Results for `{result.domain}`")
    if result.sample_data:
        st.info("**Sample data** — illustrative only, no host was contacted.", icon="🧪")
    for notice in result.notices:
        if not result.sample_data:
            st.warning(notice)
    if score["score"] is not None and not score["reliable"]:
        st.warning(
            f"Coverage is only {score['coverage_percent']:.0f} %: the score is based on a "
            "subset of controls and must be interpreted with caution (no grade given)."
        )
    st.caption(
        f"Generated {report['assessment']['generated_at_utc']} UTC · "
        f"addresses: {', '.join(result.addresses) or '—'}"
    )

    cols = st.columns(6)
    cols[0].metric("Overall score", f"{format_score(score['score'])}/100")
    cols[1].metric(
        "Grade",
        score["grade"] or "—",
        help="A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60. Only given when coverage ≥ 80 %.",
    )
    cols[2].metric("Coverage", f"{score['coverage_percent']:.0f} %",
                   help="Evaluated points / applicable points. ERROR lowers coverage.")
    for col, category in zip(cols[3:], (Category.DNS, Category.TLS, Category.HTTP), strict=True):
        data = score["categories"][category.value]
        col.metric(
            SHORT_LABELS[category],
            f"{format_score(data['score'])}/100",
            help=(
                f"{category.label} — weight {int(data['max_points'])} pts. "
                f"{data['earned_points']:g} / {data['evaluated_points']:g} evaluated points, "
                f"coverage {data['coverage_percent']:.0f} %."
            ),
        )

    counts = st.columns(5)
    counts[0].metric("✅ PASS", score["passed"])
    counts[1].metric("⚠️ WARNING", score["warnings"])
    counts[2].metric("❌ FAIL", score["failed"])
    counts[3].metric("⛔ ERROR", score["errors"])
    counts[4].metric("➖ N/A", score["not_applicable"])

    tab_controls, tab_fix, tab_evidence, tab_method = st.tabs(
        ["Controls", "Remediation", "Evidence", "Methodology & limits"]
    )

    with tab_controls:
        options = [s.value for s in Status]
        selected = st.multiselect("Filter by status", options, default=options)
        rows = [r for r in result.results if r.status.value in selected]
        st.dataframe(
            controls_rows(rows),
            hide_index=True,
            width="stretch",
            column_config={
                "Weight": st.column_config.NumberColumn(format="%g"),
                "Finding": st.column_config.TextColumn(width="large"),
                "Recommendation": st.column_config.TextColumn(width="large"),
            },
        )

    with tab_fix:
        recommendations = report["recommendations"]
        if not recommendations:
            st.success("No scored control failed or raised a warning.")
        for item in recommendations:
            with st.container(border=True):
                st.markdown(
                    f"**{PRIORITY_LABELS[item['priority']]} — {item['name']}** "
                    f"· {status_label(item['status'])} · severity {item['severity']} "
                    f"· {item['weight']:g} pts"
                )
                st.markdown(f"**Finding:** {item['finding']}")
                st.markdown(f"**Risk:** {item['risk']}")
                st.markdown(f"**Action:** {item['recommendation']}")
        if report["not_assessed"]:
            st.markdown("##### Not assessed (ERROR)")
            for item in report["not_assessed"]:
                st.markdown(f"- **{item['name']}** — {item['reason']}")

    with tab_evidence:
        for check in result.results:
            with st.expander(f"{status_label(check.status)} · {check.name}"):
                st.write(check.summary)
                st.json(check.evidence, expanded=False)

    with tab_method:
        st.markdown(
            "**Score** = 100 × earned points / evaluated points, where PASS earns the "
            "full weight, WARNING half and FAIL nothing. ERROR and NOT_APPLICABLE "
            "controls are excluded. **Coverage** = evaluated points / applicable "
            "points; a grade is only shown when coverage ≥ 80 %."
        )
        st.dataframe(
            [
                {
                    "Control": d.name,
                    "Category": d.category.label,
                    "Weight": d.weight,
                    "Severity": d.severity.value,
                    "What is checked": d.description,
                }
                for d in CHECKS.values()
            ],
            hide_index=True,
            width="stretch",
        )
        st.markdown("**Limitations**")
        for limitation in report["limitations"]:
            st.markdown(f"- {limitation}")

    st.download_button(
        "⬇️ Download JSON Report",
        data=report_to_json(report),
        file_name=report_filename(result.domain, report["assessment"]["generated_at_utc"]),
        mime="application/json",
        type="primary",
    )


def main() -> None:
    # "?demo=sample" opens the offline sample (never triggers a network scan).
    if st.query_params.get("demo") == "sample" and STATE_KEY not in st.session_state:
        st.session_state[STATE_KEY] = build_sample_assessment()
    render_sidebar()
    render_header()
    run_from_form()
    result = st.session_state.get(STATE_KEY)
    if result is not None:
        render_dashboard(result)


main()
