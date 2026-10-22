"""
CyberRakshak
Intelligent Cyber Threat Detection & Defense Validation Platform

Dashboard built with Streamlit.
"""

import json

import pandas as pd
import plotly.express as px
import streamlit as st

from engine.url_analyzer import analyze_url
from engine.threat_intelligence import check_threat_intelligence
from security.auth_security import (
    LoginRateLimiter,
    create_otp,
    hash_password,
    verify_otp,
    verify_password,
)
from security.defense_validator import run_all_validations
from simulation.phishing_simulator import (
    SCENARIOS,
    run_simulation,
)
from reports.report_generator import (
    generate_report,
    export_report_json,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberRakshak | Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# STYLING
# ============================================================

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background-color: #111827;
    }

    .hero {
        padding: 1.5rem;
        border-radius: 16px;
        background: linear-gradient(120deg, #111827, #172554);
        border: 1px solid #334155;
        margin-bottom: 1.2rem;
    }

    .hero h1 {
        margin-bottom: 0.3rem;
        color: #f8fafc;
    }

    .hero p {
        color: #cbd5e1;
    }

    .section-note {
        color: #94a3b8;
        font-size: 0.9rem;
    }

    div[data-testid="stMetric"] {
        background: #111827;
        border: 1px solid #334155;
        padding: 1rem;
        border-radius: 12px;
    }

    div.stButton > button {
        border-radius: 8px;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "last_url_result" not in st.session_state:
    st.session_state.last_url_result = None

if "last_simulation_result" not in st.session_state:
    st.session_state.last_simulation_result = None

if "last_defense_result" not in st.session_state:
    st.session_state.last_defense_result = None

if "last_report" not in st.session_state:
    st.session_state.last_report = None


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown("# 🛡️ CyberRakshak")
st.sidebar.caption("Cyber Threat Detection & Defense Validation")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "🏠 Home",
        "🔍 URL Investigation",
        "🌐 Threat Intelligence",
        "🎭 Simulation Lab",
        "🔐 Authentication Lab",
        "🛡️ Defense Validation",
        "📄 Reports",
    ],
)

st.sidebar.divider()

st.sidebar.markdown("### Project Status")
st.sidebar.success("Backend modules loaded")

st.sidebar.caption(
    "Educational security platform. "
    "Risk scores are heuristic indicators, not proof of malicious activity."
)


# ============================================================
# REUSABLE DISPLAY FUNCTIONS
# ============================================================

def show_url_result(result: dict) -> None:
    """Display URL analysis results and verification details."""

    if not result["valid"]:
        st.error("The URL could not be analyzed.")

        for indicator in result["indicators"]:
            st.write(f"• {indicator}")

        return

    score = result["risk_score"]

    # Main results
    col1, col2, col3 = st.columns(3)

    col1.metric("Risk Score", f"{score}/100")
    col2.metric("Risk Level", result["risk_level"])
    col3.metric("Hostname", result["hostname"])

    st.caption(
        "The risk score is based on local heuristic rules. "
        "It is not a probability of fraud and does not prove "
        "that a website is malicious or safe."
    )

    # Risk-level message
    if result["risk_level"] == "High":
        st.error(
            "High heuristic risk: avoid interacting with the URL "
            "until it has been investigated further."
        )
    elif result["risk_level"] == "Medium":
        st.warning(
            "Medium heuristic risk: inspect the URL carefully "
            "before interacting with it."
        )
    else:
        st.info(
            "Low heuristic risk: suspicious indicators were limited, "
            "but the URL has not been verified as safe."
        )

    # Analysis and verification status
    st.markdown("#### Analysis Details")

    detail_col1, detail_col2 = st.columns(2)

    detail_col1.markdown("**Analysis Method**")
    detail_col1.info(
        result.get("analysis_method", "local_heuristics")
    )

    detail_col2.markdown("**Verification Status**")
    detail_col2.warning(
        result.get("verification_status", "not_checked")
    )

    st.caption(
        "No external threat-intelligence provider or live website "
        "verification is used by this URL analyzer."
    )

    # Indicators
    st.markdown("#### Suspicious Indicators")

    indicators = result.get("indicators", [])

    if indicators:
        for indicator in indicators:
            st.write(f"• {indicator}")
    else:
        st.success(
            "No suspicious indicators were detected by the current rules."
        )

    # Clear warning for shortened URLs
    shortened_url_warning = any(
        "shortened URL" in indicator.lower()
        or "shortener" in indicator.lower()
        for indicator in indicators
    )

    if shortened_url_warning:
        st.warning(
            "**Shortened URL warning:** The final destination has not "
            "been checked. Do not assume that the destination is safe."
        )

    # Recommendation
    st.markdown("#### Recommendation")
    st.write(result["recommendation"])


def show_defense_results(report: dict) -> None:
    """Display the actual defense validation results."""

    summary = report["summary"]

    col1, col2, col3 = st.columns(3)

    col1.metric("Checks", summary["total"])
    col2.metric("Passed", summary["passed"])
    col3.metric("Failed", summary["failed"])

    if summary["overall_status"] == "PASS":
        st.success("All registered validation checks passed.")
    else:
        st.error("One or more validation checks failed.")

    for result in report["results"]:
        with st.expander(
            f"{result['status']} — {result['test']}"
        ):
            st.write(result["details"])
            st.json(result["checks"])


# ============================================================
# HOME
# ============================================================

if page == "🏠 Home":

    st.markdown(
        """
        <div class="hero">
            <h1>🛡️ CyberRakshak</h1>
            <p>
                Detect the Threat. Understand the Attack.
                Strengthen the Defense.
            </p>
            <p>
                Investigate suspicious URLs, explore safe phishing
                simulations, and validate security controls.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Platform Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Detection Engine", "Available")
    col2.metric("Simulation Lab", "Available")
    col3.metric("Defense Validation", "Available")

    st.markdown("### What would you like to do?")

    col1, col2 = st.columns(2)

    with col1:
        st.info(
            "**Investigate a URL**\n\n"
            "Review hostname structure and suspicious indicators."
        )

        st.info(
            "**Explore a Simulation**\n\n"
            "Learn to recognize deceptive messages safely."
        )

    with col2:
        st.info(
            "**Validate Security**\n\n"
            "Run automated checks against authentication controls."
        )

        st.info(
            "**Generate a Report**\n\n"
            "Combine investigation results into a downloadable JSON report."
        )

    st.markdown(
        '<p class="section-note">'
        "This platform is an educational prototype. "
        "It does not certify URLs or systems as safe."
        "</p>",
        unsafe_allow_html=True,
    )


# ============================================================
# URL INVESTIGATION
# ============================================================

elif page == "🔍 URL Investigation":

    st.title("🔍 URL Investigation")
    st.write(
        "Analyze URL structure and identify potentially suspicious indicators."
    )

    url = st.text_input(
        "Enter a URL",
        placeholder="https://example.com/login",
    )

    if st.button("Analyze URL", type="primary"):

        if not url.strip():
            st.warning("Enter a URL before starting the analysis.")
        else:
            result = analyze_url(url)
            st.session_state.last_url_result = result
            st.session_state.last_report = None

    result = st.session_state.last_url_result

    if result is not None:
        st.divider()
        show_url_result(result)


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

elif page == "🌐 Threat Intelligence":

    st.title("🌐 Threat Intelligence")
    st.write(
        "Check whether an external threat intelligence provider is configured."
    )

    st.warning(
        "The current implementation is an interface only. "
        "It does not query a real threat intelligence feed."
    )

    url = st.text_input(
        "URL to check",
        key="threat_url",
        placeholder="https://example.com",
    )

    if st.button("Check Provider Status"):

        result = check_threat_intelligence(url)

        if result["status"] == "invalid_input":
            st.error(result["message"])
        else:
            st.info(result["message"])

        st.json(result)


# ============================================================
# SIMULATION LAB
# ============================================================

elif page == "🎭 Simulation Lab":

    st.title("🎭 Controlled Phishing Simulation")

    st.write(
        "Explore fictional phishing-awareness scenarios without "
        "contacting real targets or collecting credentials."
    )

    scenario_id = st.selectbox(
        "Choose a scenario",
        options=list(SCENARIOS.keys()),
        format_func=lambda item: SCENARIOS[item]["title"],
    )

    selected_scenario = SCENARIOS[scenario_id]

    st.info(selected_scenario["message"])

    if st.button("Run Simulation", type="primary"):

        result = run_simulation(scenario_id)
        st.session_state.last_simulation_result = result
        st.session_state.last_report = None

    result = st.session_state.last_simulation_result

    if result is not None:

        st.subheader(result["title"])
        st.write(result["message"])

        st.markdown("#### Warning Signs")

        for sign in result["warning_signs"]:
            st.write(f"• {sign}")

        st.markdown("#### URL Analysis")

        show_url_result(result["url_analysis"])

        st.markdown("#### Safe Action")
        st.success(result["safe_action"])

        st.caption(
            "This simulation makes no network requests and collects "
            "no credentials."
        )


# ============================================================
# AUTHENTICATION LAB
# ============================================================

elif page == "🔐 Authentication Lab":

    st.title("🔐 Authentication Security Lab")

    st.write(
        "Demonstrate password hashing, OTP expiration, and login rate limiting "
        "using fictional data."
    )

    tab1, tab2, tab3 = st.tabs(
        [
            "Password Hashing",
            "OTP Demonstration",
            "Rate Limiting",
        ]
    )

    with tab1:

        st.subheader("Password Hashing")

        password = st.text_input(
            "Demo password",
            type="password",
            key="demo_password",
        )

        if st.button("Hash Demo Password"):

            if not password:
                st.warning("Enter a fictional demo password.")
            else:
                stored = hash_password(password)
                st.session_state.demo_hash = stored

                st.success("Password hash generated.")

        stored = st.session_state.get("demo_hash")

        if stored:
            st.json(
                {
                    "algorithm": "PBKDF2-HMAC-SHA256",
                    "iterations": stored["iterations"],
                    "salt": stored["salt"],
                    "password_hash": stored["password_hash"],
                }
            )

            check_password = st.text_input(
                "Password to verify",
                type="password",
                key="verify_demo_password",
            )

            if st.button("Verify Password"):

                if verify_password(check_password, stored):
                    st.success("Password verification succeeded.")
                else:
                    st.error("Password verification failed.")

        st.caption(
            "Use fictional passwords only. Never enter a real account password."
        )

    with tab2:

        st.subheader("Simulated OTP")

        st.write(
            "Generate a demonstration OTP, then test its expiration "
            "and one-time-use behavior."
        )

        if st.button("Generate Demo OTP"):

            st.session_state.demo_otp = create_otp(ttl_seconds=120)
            st.session_state.demo_otp_displayed = True

        challenge = st.session_state.get("demo_otp")

        if challenge:

            st.code(challenge.code)
            st.caption(
                "Educational simulation: this code is displayed locally. "
                "It is not delivered to a real phone or account."
            )

            submitted_code = st.text_input(
                "Enter the demo OTP",
                key="submitted_demo_otp",
            )

            if st.button("Verify Demo OTP"):

                if verify_otp(challenge, submitted_code):
                    st.success(
                        "OTP accepted. Reuse will be rejected."
                    )
                else:
                    st.error(
                        "OTP rejected, expired, already used, "
                        "or the attempt limit was reached."
                    )

    with tab3:

        st.subheader("Login Rate Limiting")

        st.write(
            "Simulate failed login attempts against a fictional account."
        )

        if "demo_limiter" not in st.session_state:
            st.session_state.demo_limiter = LoginRateLimiter(
                max_attempts=3,
                window_seconds=60,
            )

        limiter = st.session_state.demo_limiter

        if st.button("Record Failed Login"):

            account = "fictional-demo-account"

            if limiter.is_allowed(account):

                limiter.record_failure(account)

                st.warning("A failed login attempt was recorded.")

            else:
                st.error("Rate limit reached. Further attempts are blocked.")

        if st.button("Check Login Availability"):

            if limiter.is_allowed("fictional-demo-account"):
                st.success("Another attempt is currently allowed.")
            else:
                st.error("Login attempts are currently rate-limited.")

        if st.button("Reset Demo Limiter"):
            st.session_state.demo_limiter = LoginRateLimiter(
                max_attempts=3,
                window_seconds=60,
            )
            st.success("Demo limiter reset.")


# ============================================================
# DEFENSE VALIDATION
# ============================================================

elif page == "🛡️ Defense Validation":

    st.title("🛡️ Defense Validation Engine")

    st.write(
        "Run automated checks against the authentication controls "
        "implemented in this project."
    )

    if st.button("Run All Validations", type="primary"):

        report = run_all_validations()

        st.session_state.last_defense_result = report
        st.session_state.last_report = None

    report = st.session_state.last_defense_result

    if report is not None:

        show_defense_results(report)

        with st.expander("Full Validation Report"):
            st.json(report)


# ============================================================
# REPORTS
# ============================================================

elif page == "📄 Reports":

    st.title("📄 Investigation Reports")

    st.write(
        "Create a downloadable JSON report from the results currently "
        "available in this session."
    )

    st.caption(
        "The report includes only results you have generated in this session. "
        "It does not automatically retrieve previous sessions."
    )

    url_result = st.session_state.last_url_result
    simulation_result = st.session_state.last_simulation_result
    defense_result = st.session_state.last_defense_result

    st.markdown("### Available Results")

    st.write(
        f"URL analysis: {'Available' if url_result else 'Not run'}"
    )

    st.write(
        f"Simulation: {'Available' if simulation_result else 'Not run'}"
    )

    st.write(
        f"Defense validation: {'Available' if defense_result else 'Not run'}"
    )

    if st.button("Generate JSON Report", type="primary"):

        if not any(
            [url_result, simulation_result, defense_result]
        ):
            st.warning(
                "Run at least one investigation or validation first."
            )
        else:

            report = generate_report(
                url_analysis=url_result,
                simulation_result=simulation_result,
                defense_report=defense_result,
            )

            st.session_state.last_report = report

    report = st.session_state.last_report

    if report is not None:

        st.success("Report generated successfully.")

        st.download_button(
            label="Download JSON Report",
            data=json.dumps(report, indent=4),
            file_name="cyberrakshak_report.json",
            mime="application/json",
        )

        with st.expander("Preview Report"):
            st.json(report)

        st.caption(
            "PDF export is not implemented yet."
        )