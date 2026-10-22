
"""
CyberRakshak
Intelligent Cyber Threat Detection & Defense Validation Platform

Tagline:
Detect the Threat. Understand the Attack. Strengthen the Defense.

Educational cybersecurity platform built with Streamlit.
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

from reports.report_generator import generate_report


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
# CUSTOM STYLING
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

SESSION_DEFAULTS = {
    "last_url_result": None,
    "last_simulation_result": None,
    "last_defense_result": None,
    "last_report": None,
    "demo_hash": None,
    "demo_otp": None,
    "demo_limiter": None,
}

for key, default_value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default_value


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

st.sidebar.markdown("# 🛡️ CyberRakshak")

st.sidebar.caption(
    "Cyber Threat Detection & Defense Validation"
)

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
    "Educational security platform. Risk scores are based on "
    "heuristics and do not prove that a website is malicious or safe."
)


# ============================================================
# REUSABLE URL RESULT DISPLAY
# ============================================================

def show_url_result(result: dict) -> None:
    """Display URL analysis results and suspicious indicators."""

    if not isinstance(result, dict):
        st.error("The URL analyzer returned an unexpected result.")
        return

    if not result.get("valid", False):
        st.error("The URL could not be analyzed.")

        for indicator in result.get("indicators", []):
            st.write(f"• {indicator}")

        return

    score = result.get("risk_score", 0)
    hostname = result.get("hostname", "Unknown")
    risk_level = result.get("risk_level", "Unknown")
    indicators = result.get("indicators", [])

    # --------------------------------------------------------
    # MAIN METRICS
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Risk Score",
        f"{score}/100",
    )

    col2.metric(
        "Risk Level",
        risk_level,
    )

    col3.metric(
        "Hostname",
        hostname,
    )

    st.caption(
        "The risk score is calculated using local heuristic rules. "
        "It is not a probability of fraud and does not prove that "
        "a website is malicious or safe."
    )

    # --------------------------------------------------------
    # RISK LEVEL MESSAGE
    # --------------------------------------------------------

    if risk_level == "High":
        st.error(
            "High heuristic risk: avoid interacting with this URL "
            "until it has been investigated further."
        )

    elif risk_level == "Medium":
        st.warning(
            "Medium heuristic risk: inspect the URL carefully "
            "before interacting with it."
        )

    else:
        st.info(
            "Low heuristic risk: the analyzer found limited "
            "suspicious indicators. This does not mean the URL "
            "has been verified as safe."
        )

    # --------------------------------------------------------
    # BRAND IMPERSONATION WARNING
    # --------------------------------------------------------

    lookalike_indicators = [
        indicator
        for indicator in indicators
        if any(
            term in indicator.lower()
            for term in [
                "character-substitution",
                "character substitution",
                "lookalike",
                "look-alike",
                "appears in a subdomain",
            ]
        )
    ]

    if lookalike_indicators:
        st.error(
            "🚨 Possible Brand Impersonation Detected"
        )

        st.warning(
            "This URL contains a possible brand-impersonation "
            "indicator. A domain may imitate a familiar company "
            "using substituted characters or by placing a brand "
            "name inside an unrelated domain. Do not enter "
            "passwords, payment information, or OTPs."
        )

        for indicator in lookalike_indicators:
            st.write(f"• {indicator}")

    # --------------------------------------------------------
    # ANALYSIS DETAILS
    # --------------------------------------------------------

    st.markdown("#### Analysis Details")

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    detail_col1.markdown("**Analysis Method**")
    detail_col1.info(
        result.get(
            "analysis_method",
            "local_heuristics",
        )
    )

    detail_col2.markdown("**Verification Status**")
    detail_col2.warning(
        result.get(
            "verification_status",
            "not_checked",
        )
    )

    destination_status = result.get(
        "destination_status",
        "not_checked",
    )

    detail_col3.markdown("**Destination Status**")

    if destination_status == "unknown":
        detail_col3.warning(
            "Unknown — shortened URL"
        )

    elif destination_status == "checked":
        detail_col3.success("Checked")

    else:
        detail_col3.info("Not checked")

    st.caption(
        "The local analyzer does not visit websites, follow redirects, "
        "resolve DNS, or query an external threat-intelligence feed."
    )

    # --------------------------------------------------------
    # SUSPICIOUS INDICATORS
    # --------------------------------------------------------

    st.markdown("#### Suspicious Indicators")

    if indicators:
        for indicator in indicators:
            st.write(f"• {indicator}")
    else:
        st.success(
            "No suspicious indicators were detected by the "
            "current analysis rules."
        )

    # --------------------------------------------------------
    # SHORTENED URL WARNING
    # --------------------------------------------------------

    shortened_url_warning = (
        destination_status == "unknown"
        or any(
            "shortened url" in str(indicator).lower()
            or "shortener" in str(indicator).lower()
            for indicator in indicators
        )
    )

    if shortened_url_warning:
        st.warning(
            "**Shortened URL warning:** The final destination "
            "has not been checked. Do not assume that the "
            "destination is safe."
        )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    st.markdown("#### Recommendation")

    st.write(
        result.get(
            "recommendation",
            "Exercise caution and verify the destination independently.",
        )
    )


# ============================================================
# REUSABLE DEFENSE VALIDATION DISPLAY
# ============================================================

def show_defense_results(report: dict) -> None:
    """Display defense validation results."""

    if not isinstance(report, dict):
        st.error("The validation module returned an unexpected result.")
        st.json(report)
        return

    summary = report.get("summary", {})

    if not isinstance(summary, dict):
        st.error("The validation summary is unavailable.")
        st.json(report)
        return

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Checks",
        summary.get("total", 0),
    )

    col2.metric(
        "Passed",
        summary.get("passed", 0),
    )

    col3.metric(
        "Failed",
        summary.get("failed", 0),
    )

    overall_status = summary.get(
        "overall_status",
        "UNKNOWN",
    )

    if overall_status == "PASS":
        st.success(
            "All registered validation checks passed."
        )
    else:
        st.error(
            "One or more validation checks failed, "
            "or the overall status is not PASS."
        )

    results = report.get("results", [])

    if not results:
        st.info("No individual validation results were returned.")

    for item in results:
        if not isinstance(item, dict):
            st.write(item)
            continue

        status = item.get("status", "UNKNOWN")
        test_name = item.get("test", "Unnamed test")

        with st.expander(
            f"{status} — {test_name}"
        ):
            st.write(
                item.get(
                    "details",
                    "No additional details were provided.",
                )
            )

            checks = item.get("checks")

            if checks is not None:
                st.json(checks)


# ============================================================
# HOME DASHBOARD
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

    col1.metric(
        "Detection Engine",
        "Available",
    )

    col2.metric(
        "Simulation Lab",
        "Available",
    )

    col3.metric(
        "Defense Validation",
        "Available",
    )

    st.markdown("### Platform Modules")

    col1, col2 = st.columns(2)

    with col1:
        st.info(
            "**🔍 URL Investigation**\n\n"
            "Analyze URL structure, hostname patterns, "
            "and suspicious indicators."
        )

        st.info(
            "**🎭 Simulation Lab**\n\n"
            "Learn to identify phishing warning signs "
            "through fictional scenarios."
        )

        st.info(
            "**🔐 Authentication Lab**\n\n"
            "Demonstrate password hashing, OTP verification, "
            "and login rate limiting."
        )

    with col2:
        st.info(
            "**🌐 Threat Intelligence**\n\n"
            "Inspect the status of the project's "
            "threat-intelligence integration."
        )

        st.info(
            "**🛡️ Defense Validation**\n\n"
            "Run automated checks against implemented "
            "security controls."
        )

        st.info(
            "**📄 Reports**\n\n"
            "Generate and download JSON reports from "
            "results collected in this session."
        )

    st.divider()

    st.markdown("### Current Session")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "URL Investigations",
        int(st.session_state.last_url_result is not None),
    )

    col2.metric(
        "Simulations Run",
        int(st.session_state.last_simulation_result is not None),
    )

    col3.metric(
        "Validation Reports",
        int(st.session_state.last_defense_result is not None),
    )

    st.markdown(
        """
        <p class="section-note">
        CyberRakshak is an educational prototype. Heuristic results
        are indicators, not proof of malicious activity or safety.
        </p>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# URL INVESTIGATION
# ============================================================

elif page == "🔍 URL Investigation":

    st.title("🔍 URL Investigation")

    st.write(
        "Analyze a URL's structure and identify potentially "
        "suspicious indicators using local heuristic rules."
    )

    st.info(
        "This investigation uses local analysis. It does not "
        "open the submitted website."
    )

    with st.form("url_investigation_form"):

        url = st.text_input(
            "Enter a URL",
            placeholder="https://example.com/login",
        )

        submitted = st.form_submit_button(
            "Analyze URL",
            type="primary",
        )

    if submitted:

        if not url.strip():
            st.warning(
                "Enter a URL before starting the analysis."
            )

        else:
            try:
                result = analyze_url(url.strip())

                st.session_state.last_url_result = result
                st.session_state.last_report = None

            except Exception as exc:
                st.error(
                    "The URL analysis could not be completed."
                )

                st.exception(exc)

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
        "Inspect the threat-intelligence integration available "
        "in the current project."
    )

    st.warning(
        "The current provider module is a placeholder unless an "
        "external provider has been configured. A provider status "
        "response is not proof that a URL is safe or malicious."
    )

    with st.form("threat_intelligence_form"):

        threat_url = st.text_input(
            "URL to check",
            key="threat_url",
            placeholder="https://example.com",
        )

        check_provider = st.form_submit_button(
            "Check Threat Intelligence",
            type="primary",
        )

    if check_provider:

        if not threat_url.strip():
            st.warning("Enter a URL first.")

        else:
            try:
                result = check_threat_intelligence(
                    threat_url.strip()
                )

                if isinstance(result, dict):

                    status = result.get(
                        "status",
                        "unknown",
                    )

                    message = result.get(
                        "message",
                        "No message was returned by the provider.",
                    )

                    if status == "invalid_input":
                        st.error(message)

                    elif status in {
                        "not_configured",
                        "provider_not_configured",
                    }:
                        st.warning(message)

                    else:
                        st.info(message)

                    st.markdown("#### Provider Response")
                    st.json(result)

                else:
                    st.write(result)

            except Exception as exc:
                st.error(
                    "The threat-intelligence check failed."
                )

                st.exception(exc)

    st.divider()

    st.markdown("### What Threat Intelligence Adds")

    st.write(
        "A real integration could compare indicators against "
        "reputable threat feeds. Until such a provider is configured, "
        "this module must not be treated as a live reputation check."
    )


# ============================================================
# PHISHING SIMULATION LAB
# ============================================================

elif page == "🎭 Simulation Lab":

    st.title("🎭 Phishing Simulation Lab")

    st.write(
        "Explore fictional phishing-awareness scenarios and learn "
        "to recognize deceptive messages safely."
    )

    st.info(
        "The simulations are for education. Do not use real accounts, "
        "real passwords, OTPs, or real targets."
    )

    if not isinstance(SCENARIOS, dict) or not SCENARIOS:

        st.error(
            "No simulation scenarios are configured in "
            "simulation/phishing_simulator.py."
        )

    else:

        scenario_ids = list(SCENARIOS.keys())

        def scenario_label(scenario_id):
            scenario = SCENARIOS[scenario_id]

            if isinstance(scenario, dict):
                return scenario.get("title", str(scenario_id))

            return str(scenario_id)

        selected_scenario_id = st.selectbox(
            "Choose a scenario",
            options=scenario_ids,
            format_func=scenario_label,
        )

        selected_scenario = SCENARIOS[selected_scenario_id]

        if isinstance(selected_scenario, dict):

            message = selected_scenario.get(
                "message",
                "Review the selected fictional scenario.",
            )

            st.markdown("### Scenario Preview")
            st.info(message)

        if st.button(
            "Run Simulation",
            type="primary",
        ):

            try:
                simulation_result = run_simulation(
                    selected_scenario_id
                )

                st.session_state.last_simulation_result = (
                    simulation_result
                )

                st.session_state.last_report = None

            except Exception as exc:
                st.error(
                    "The simulation could not be completed."
                )

                st.exception(exc)

        result = st.session_state.last_simulation_result

        if result is not None:

            st.divider()

            if not isinstance(result, dict):
                st.write(result)

            else:

                st.subheader(
                    result.get(
                        "title",
                        "Simulation Results",
                    )
                )

                if result.get("message"):
                    st.write(result["message"])

                warning_signs = result.get(
                    "warning_signs",
                    [],
                )

                if warning_signs:
                    st.markdown("#### Warning Signs")

                    for sign in warning_signs:
                        st.write(f"• {sign}")

                url_analysis = result.get("url_analysis")

                if isinstance(url_analysis, dict):
                    st.markdown("#### Related URL Analysis")
                    show_url_result(url_analysis)

                safe_action = result.get("safe_action")

                if safe_action:
                    st.markdown("#### Recommended Safe Action")
                    st.success(safe_action)

                st.caption(
                    "Use the lessons from the simulation to verify "
                    "senders independently, avoid suspicious links, "
                    "and never disclose passwords or OTPs."
                )


# ============================================================
# AUTHENTICATION SECURITY LAB
# ============================================================

elif page == "🔐 Authentication Lab":

    st.title("🔐 Authentication Security Lab")

    st.write(
        "Demonstrate password hashing, OTP verification, "
        "and login rate limiting with fictional data."
    )

    st.warning(
        "Use fictional demo values only. Never enter a real "
        "account password or real OTP."
    )

    tab1, tab2, tab3 = st.tabs(
        [
            "Password Hashing",
            "OTP Demonstration",
            "Login Rate Limiting",
        ]
    )

    # --------------------------------------------------------
    # TAB 1: PASSWORD HASHING
    # --------------------------------------------------------

    with tab1:

        st.subheader("Password Hashing")

        password = st.text_input(
            "Fictional demo password",
            type="password",
            key="demo_password",
        )

        if st.button(
            "Hash Demo Password",
            key="hash_demo_password_button",
        ):

            if not password:
                st.warning(
                    "Enter a fictional demo password first."
                )

            else:
                try:
                    stored_hash = hash_password(password)

                    st.session_state.demo_hash = stored_hash

                    st.success(
                        "Password hash generated successfully."
                    )

                except Exception as exc:
                    st.error(
                        "Password hashing failed."
                    )

                    st.exception(exc)

        stored = st.session_state.demo_hash

        if stored is not None:

            st.markdown("#### Stored Password Hash")

            if isinstance(stored, dict):
                st.json(stored)
            else:
                st.code(str(stored))

            check_password = st.text_input(
                "Password to verify",
                type="password",
                key="verify_demo_password",
            )

            if st.button(
                "Verify Password",
                key="verify_demo_password_button",
            ):

                if not check_password:
                    st.warning(
                        "Enter the demo password to verify."
                    )

                else:
                    try:
                        verified = verify_password(
                            check_password,
                            stored,
                        )

                        if verified:
                            st.success(
                                "Password verification succeeded."
                            )
                        else:
                            st.error(
                                "Password verification failed."
                            )

                    except Exception as exc:
                        st.error(
                            "Password verification could not be completed."
                        )

                        st.exception(exc)

        st.caption(
            "Password hashing stores a derived hash instead of "
            "the original password. Do not use real account passwords "
            "in this demonstration."
        )

    # --------------------------------------------------------
    # TAB 2: OTP DEMONSTRATION
    # --------------------------------------------------------

    with tab2:

        st.subheader("One-Time Password Demonstration")

        st.write(
            "Generate a temporary demo OTP and verify it using "
            "the project's authentication module."
        )

        if st.button(
            "Generate Demo OTP",
            key="generate_demo_otp_button",
        ):

            try:
                challenge = create_otp(
                    ttl_seconds=120
                )

                st.session_state.demo_otp = challenge

                st.success(
                    "Demo OTP generated."
                )

            except Exception as exc:
                st.session_state.demo_otp = None

                st.error(
                    "Could not generate the demo OTP."
                )

                st.exception(exc)

        challenge = st.session_state.demo_otp

        if challenge is not None:

            # Display only the locally generated demonstration code.
            if isinstance(challenge, dict):
                displayed_code = challenge.get("code")

            else:
                displayed_code = getattr(
                    challenge,
                    "code",
                    None,
                )

            if displayed_code is not None:
                st.markdown("#### Demo OTP")
                st.code(str(displayed_code))

            st.caption(
                "This code is displayed locally for demonstration. "
                "It is not sent to a phone or real account."
            )

            submitted_otp = st.text_input(
                "Enter the demo OTP",
                key="submitted_demo_otp",
            )

            if st.button(
                "Verify Demo OTP",
                key="verify_demo_otp_button",
            ):

                if not submitted_otp.strip():
                    st.warning(
                        "Enter the demo OTP first."
                    )

                else:
                    try:
                        verified = verify_otp(
                            challenge,
                            submitted_otp.strip(),
                        )

                        if verified:
                            st.success(
                                "OTP accepted by the verification module."
                            )
                        else:
                            st.error(
                                "OTP rejected. It may be incorrect, "
                                "expired, previously used, or blocked "
                                "by the attempt limit."
                            )

                    except Exception as exc:
                        st.error(
                            "OTP verification could not be completed."
                        )

                        st.exception(exc)

    # --------------------------------------------------------
    # TAB 3: LOGIN RATE LIMITING
    # --------------------------------------------------------

    with tab3:

        st.subheader("Login Rate Limiting")

        st.write(
            "Simulate failed login attempts against a fictional "
            "account to demonstrate rate limiting."
        )

        if st.session_state.demo_limiter is None:

            st.session_state.demo_limiter = LoginRateLimiter(
                max_attempts=3,
                window_seconds=60,
            )

        limiter = st.session_state.demo_limiter
        demo_account = "fictional-demo-account"

        col1, col2 = st.columns(2)

        with col1:

            if st.button(
                "Record Failed Login",
                key="record_failed_login_button",
            ):

                try:
                    if limiter.is_allowed(demo_account):

                        limiter.record_failure(demo_account)

                        st.warning(
                            "A failed login attempt was recorded."
                        )

                    else:
                        st.error(
                            "Rate limit reached. Further attempts "
                            "are currently blocked."
                        )

                except Exception as exc:
                    st.error(
                        "Could not record the demonstration attempt."
                    )

                    st.exception(exc)

        with col2:

            if st.button(
                "Check Login Availability",
                key="check_login_availability_button",
            ):

                try:
                    if limiter.is_allowed(demo_account):
                        st.success(
                            "Another attempt is currently allowed."
                        )
                    else:
                        st.error(
                            "Login attempts are currently rate-limited."
                        )

                except Exception as exc:
                    st.error(
                        "Could not check rate-limit status."
                    )

                    st.exception(exc)

        if st.button(
            "Reset Demo Limiter",
            key="reset_demo_limiter_button",
        ):

            st.session_state.demo_limiter = LoginRateLimiter(
                max_attempts=3,
                window_seconds=60,
            )

            st.success(
                "The demonstration rate limiter has been reset."
            )

        st.caption(
            "This is a local demonstration, not a production login system."
        )


# ============================================================
# DEFENSE VALIDATION
# ============================================================

elif page == "🛡️ Defense Validation":

    st.title("🛡️ Defense Validation Engine")

    st.write(
        "Run automated checks against security controls "
        "implemented in the CyberRakshak project."
    )

    st.info(
        "Validation results describe the checks implemented in "
        "this project. They do not certify the security of an "
        "entire computer or network."
    )

    if st.button(
        "Run All Validations",
        type="primary",
    ):

        try:
            defense_report = run_all_validations()

            st.session_state.last_defense_result = defense_report
            st.session_state.last_report = None

        except Exception as exc:
            st.error(
                "Defense validation could not be completed."
            )

            st.exception(exc)

    report = st.session_state.last_defense_result

    if report is not None:

        st.divider()

        show_defense_results(report)

        with st.expander("View Full Validation Report"):
            st.json(report)


# ============================================================
# REPORT GENERATION
# ============================================================

elif page == "📄 Reports":

    st.title("📄 Investigation Reports")

    st.write(
        "Generate a downloadable JSON report using results "
        "collected during the current session."
    )

    st.caption(
        "Only results generated in this session are included. "
        "Results are not automatically restored from previous sessions."
    )

    url_result = st.session_state.last_url_result
    simulation_result = st.session_state.last_simulation_result
    defense_result = st.session_state.last_defense_result

    # --------------------------------------------------------
    # AVAILABLE RESULTS
    # --------------------------------------------------------

    st.markdown("### Available Results")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "URL Analysis",
        "Available" if url_result is not None else "Not Run",
    )

    col2.metric(
        "Simulation",
        "Available" if simulation_result is not None else "Not Run",
    )

    col3.metric(
        "Defense Validation",
        "Available" if defense_result is not None else "Not Run",
    )

    st.divider()

    # --------------------------------------------------------
    # GENERATE REPORT
    # --------------------------------------------------------

    if st.button(
        "Generate JSON Report",
        type="primary",
    ):

        if not any(
            item is not None
            for item in [
                url_result,
                simulation_result,
                defense_result,
            ]
        ):

            st.warning(
                "Run at least one URL investigation, simulation, "
                "or defense validation before generating a report."
            )

        else:

            try:
                report = generate_report(
                    url_analysis=url_result,
                    simulation_result=simulation_result,
                    defense_report=defense_result,
                )

                st.session_state.last_report = report

                st.success(
                    "JSON report generated successfully."
                )

            except Exception as exc:
                st.error(
                    "Report generation failed."
                )

                st.exception(exc)

    report = st.session_state.last_report

    # --------------------------------------------------------
    # REPORT PREVIEW AND DOWNLOAD
    # --------------------------------------------------------

    if report is not None:

        st.markdown("### Report Preview")

        st.json(report)

        report_json = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
            default=str,
        )

        st.download_button(
            label="⬇️ Download JSON Report",
            data=report_json,
            file_name="cyberrakshak_report.json",
            mime="application/json",
            type="primary",
        )

        st.success(
            "Your report is ready to download."
        )

    st.caption(
        "The current report export is JSON. PDF export is not "
        "implemented in this dashboard."
    )


# ============================================================
# END OF CYBERRAKSHAK DASHBOARD
# ============================================================

