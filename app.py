"""
CyberRakshak — Cyber Fraud Detection, Phishing Investigation and
Defense Validation Platform.
Tagline: Detect the Threat. Understand the Attack. Protect the User.
"""

import json
import streamlit as st
import plotly.graph_objects as go

from engine.url_analyzer import analyze_url
from engine.threat_intelligence import check_threat_intelligence
from security.auth_security import (
    LoginRateLimiter, create_otp, hash_password, verify_otp, verify_password
)
from security.defense_validator import run_all_validations
from simulation.phishing_simulator import SCENARIOS, run_simulation
from reports.report_generator import generate_report

st.set_page_config(
    page_title="CyberRakshak | Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Professional dark cybersecurity design ----------
st.markdown("""
<style>
:root {--bg:#070b14;--panel:#0c111d;--border:#263142;--text:#e8edf6;
--muted:#8995a8;--teal:#12d6b0;--red:#ff4058;--amber:#f5b82e;--green:#19d17c;}
.stApp,[data-testid="stAppViewContainer"]{background:#070b14;color:#e8edf6}
[data-testid="stHeader"]{background:rgba(7,11,20,.96);border-bottom:1px solid #263142}
[data-testid="stSidebar"]{background:#0d1422;border-right:1px solid #263142}
[data-testid="stSidebar"] *{color:#c8d1df}
.brand{font-size:1.4rem;font-weight:800;letter-spacing:-.5px;color:#f4f7fb}
.brand span{color:#12d6b0}
.eyebrow{color:#12d6b0;text-transform:uppercase;letter-spacing:1.5px;font-size:.74rem;font-weight:800}
.hero{background:linear-gradient(125deg,#101b2b,#0c1421 55%,#102a2b);border:1px solid #263849;border-radius:18px;padding:1.7rem;margin:.2rem 0 1.2rem}
.hero h1{font-size:2.6rem;line-height:1.1;letter-spacing:-1px;color:#f7fafc;margin:.4rem 0}
.hero p{color:#aebbd0;max-width:760px}
.panel{background:#0c111d;border:1px solid #263142;border-radius:14px;padding:1rem 1.1rem;margin-bottom:.8rem}
.panel-title{font-weight:750;color:#e8edf6;margin-bottom:.25rem}
.muted{color:#8995a8;font-size:.86rem}
.alert-danger{background:linear-gradient(100deg,#2a0b16,#150d18);border:1px solid #812438;border-radius:14px;padding:1rem 1.2rem;margin:.7rem 0 1rem}
.alert-danger h3{color:#ff6879;font-size:1.12rem;margin:0 0 .4rem}
.alert-danger p{color:#e5cbd1;margin:0}
.metric-card{background:#0c111d;border:1px solid #273244;border-radius:13px;padding:1rem;min-height:95px}
.metric-label{color:#8793a6;font-size:.8rem;margin-bottom:.4rem}
.metric-value{color:#f2f6fc;font-size:1.3rem;font-weight:800;overflow-wrap:anywhere}
.metric-sub{color:#8492a7;font-size:.75rem;margin-top:.25rem}
div[data-testid="stMetric"]{background:#0c111d;border:1px solid #273244;padding:.8rem 1rem;border-radius:12px}
div.stButton>button,div.stDownloadButton>button{border-radius:9px;border:1px solid #334155;font-weight:700;min-height:2.5rem}
div.stButton>button[kind="primary"]{background:#12d6b0;color:#04120f;border-color:#12d6b0}
div.stTabs button[aria-selected="true"]{color:#12d6b0;border-bottom-color:#12d6b0}
input,textarea,[data-baseweb="select"]>div{background:#0d1420!important;border-color:#2b3749!important}
.footer-note{color:#718096;font-size:.77rem}
</style>
""", unsafe_allow_html=True)

# ---------- Session state ----------
DEFAULTS = {
    "last_url_result": None, "last_url_input": "",
    "last_simulation_result": None, "last_defense_result": None,
    "last_report": None, "demo_hash": None, "demo_otp": None,
    "demo_limiter": None,
}
for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ---------- Shared UI helpers ----------
def metric_card(label, value, sub=""):
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{label}</div>'
        f'<div class="metric-value">{value}</div><div class="metric-sub">{sub}</div></div>',
        unsafe_allow_html=True,
    )


def risk_color(level):
    return {"high": "#ff4058", "medium": "#f5b82e"}.get(str(level).lower(), "#19d17c")


def show_risk_gauge(score, level):
    try:
        score = max(0, min(100, float(score)))
    except (TypeError, ValueError):
        score = 0
    color = risk_color(level)
    fig = go.Figure(go.Pie(
        values=[score, 100-score], hole=.78, sort=False,
        direction="clockwise", rotation=270,
        marker=dict(colors=[color, "#202a39"]),
        textinfo="none", hoverinfo="skip", showlegend=False,
    ))
    fig.update_layout(
        height=205, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        annotations=[dict(
            text=f"<b>{score:.0f}</b><br><span style='font-size:12px;color:#8793a6'>/ 100</span>",
            x=.5, y=.5, font=dict(size=30, color="#f2f6fc"), showarrow=False,
        )],
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.markdown(
        f"<div style='text-align:center;margin-top:-1rem;color:{color};font-weight:800'>{str(level).upper()} RISK</div>",
        unsafe_allow_html=True,
    )


def show_url_result(result):
    """Show only facts returned by the local URL analyzer."""
    if not isinstance(result, dict):
        st.error("The URL analyzer returned an unexpected result.")
        st.write(result)
        return
    if not result.get("valid", False):
        st.markdown(
            '<div class="alert-danger"><h3>URL Could Not Be Analyzed</h3>'
            '<p>Check the URL format and try again.</p></div>',
            unsafe_allow_html=True,
        )
        for item in result.get("indicators", []):
            st.write("• " + str(item))
        return

    score = result.get("risk_score", 0)
    level = result.get("risk_level", "Unknown")
    hostname = result.get("hostname", "Unknown")
    indicators = result.get("indicators") or []
    destination = result.get("destination_status", "not_checked")
    brand_signals = [
        str(x) for x in indicators
        if any(t in str(x).lower() for t in (
            "character-substitution", "character substitution", "lookalike",
            "look-alike", "appears in a subdomain"
        ))
    ]

    if brand_signals:
        st.markdown(
            '<div class="alert-danger"><h3>🚨 Possible Brand Impersonation Detected</h3>'
            '<p>This hostname contains a pattern that may imitate a familiar brand. '
            'Verify the domain independently. Never enter passwords, payment details, or OTPs.</p></div>',
            unsafe_allow_html=True,
        )
    elif str(level).lower() == "high":
        st.markdown(
            '<div class="alert-danger"><h3>⚠️ High-Risk Indicators Detected</h3>'
            '<p>Review the indicators before interacting with this URL.</p></div>',
            unsafe_allow_html=True,
        )
    elif str(level).lower() == "medium":
        st.warning("Medium heuristic risk: review the URL before interacting.")
    else:
        st.info("Initial heuristic scan complete. Low risk does not mean verified safe.")

    overview, ssl_tab, dns_tab, whois_tab, web_tab, html_tab = st.tabs(
        ["Overview", "SSL Certificate", "DNS Records", "WHOIS", "Web Analysis", "HTML"]
    )
    with overview:
        left, right = st.columns([1, 3], vertical_alignment="center")
        with left:
            show_risk_gauge(score, level)
        with right:
            a, b = st.columns(2)
            with a:
                metric_card("Target hostname", hostname)
                metric_card("Analysis method", result.get("analysis_method", "local_heuristics"))
            with b:
                metric_card("Verification status", result.get("verification_status", "not_checked"))
                metric_card("Destination status", destination)
            st.markdown("#### Suspicious Indicators")
            if indicators:
                for indicator in indicators:
                    st.write("• " + str(indicator))
            else:
                st.success("No suspicious indicators detected by the current rules.")
        st.markdown("#### Recommendation")
        st.info(result.get("recommendation", "Verify the domain independently before interacting."))
        if destination == "unknown" or any(
            "shortener" in str(x).lower() or "shortened url" in str(x).lower()
            for x in indicators
        ):
            st.warning("The URL may be shortened; its final destination has not been checked.")
        st.caption(
            "Risk score is a heuristic indicator, not a probability of fraud. "
            "The current local analyzer does not visit websites, follow redirects, "
            "resolve DNS, or query external threat feeds."
        )
    with ssl_tab:
        st.subheader("SSL Certificate")
        st.info("Live certificate inspection is not implemented in the current backend. No certificate result is being invented.")
        st.write("Status: Not checked")
    with dns_tab:
        st.subheader("DNS Records")
        st.info("Live DNS resolution and record inspection are not implemented in the current backend.")
        st.write("Status: Not checked")
    with whois_tab:
        st.subheader("WHOIS / Domain Registration")
        st.info("WHOIS/RDAP lookup is not implemented in the current backend.")
        st.write("Status: Not checked")
    with web_tab:
        st.subheader("Local Web/URL Analysis")
        st.write("Hostname:", hostname)
        st.write("Analysis method:", result.get("analysis_method", "local_heuristics"))
        st.write("Verification:", result.get("verification_status", "not_checked"))
        st.write("Destination:", destination)
        if indicators:
            for indicator in indicators:
                st.write("• " + str(indicator))
        else:
            st.write("No indicators returned.")
    with html_tab:
        st.subheader("HTML Inspection")
        st.info("The current analyzer does not fetch or parse page HTML.")
        st.write("Status: Not checked")


def show_defense_results(report):
    if not isinstance(report, dict):
        st.error("Unexpected validation result.")
        st.json(report)
        return
    summary = report.get("summary", {})
    a, b, c = st.columns(3)
    a.metric("Checks", summary.get("total", 0))
    b.metric("Passed", summary.get("passed", 0))
    c.metric("Failed", summary.get("failed", 0))
    if summary.get("overall_status") == "PASS":
        st.success("All registered validation checks passed.")
    else:
        st.warning("One or more checks failed, or the overall status is not PASS.")
    for item in report.get("results", []):
        if not isinstance(item, dict):
            st.write(item)
            continue
        with st.expander(f"{item.get('status', 'UNKNOWN')} — {item.get('test', 'Validation check')}"):
            st.write(item.get("details", "No additional details."))
            if "checks" in item:
                st.json(item["checks"])


# ---------- Sidebar ----------
with st.sidebar:
    st.markdown('<div class="brand"><span>◈</span> CyberRakshak</div>', unsafe_allow_html=True)
    st.caption("Cyber Threat Detection & Defense Validation")
    st.divider()
    page = st.radio("WORKSPACE", [
        "🏠 Home", "🔍 URL Investigation", "🌐 Threat Intelligence",
        "🎭 Simulation Lab", "🔐 Authentication Lab",
        "🛡️ Defense Validation", "📄 Reports",
    ])
    st.divider()
    st.markdown("**SYSTEM STATUS**")
    st.success("Local engine ready")
    st.markdown(
        '<p class="footer-note">Educational prototype. Heuristic scores are not proof '
        'that a URL is malicious or safe.</p>', unsafe_allow_html=True
    )


# ============================================================
# 1. HOME
# ============================================================
if page == "🏠 Home":
    st.markdown(
        '<div class="hero"><div class="eyebrow">Cyber threat investigation workspace</div>'
        '<h1>Detect the Threat.<br>Understand the Attack.</h1>'
        '<p>Investigate suspicious URLs, learn to recognize phishing, and validate '
        'security controls — in one educational cybersecurity platform.</p></div>',
        unsafe_allow_html=True,
    )
    st.markdown("### Security overview")
    a, b, c, d = st.columns(4)
    with a: metric_card("URL engine", "READY", "Local heuristic analysis")
    with b: metric_card("Simulation lab", "READY", "Fictional scenarios")
    with c: metric_card("Defense checks", "READY", "Authentication controls")
    with d: metric_card("Reports", "JSON", "Downloadable session report")
    st.markdown("### Platform modules")
    left, right = st.columns(2)
    with left:
        st.markdown('<div class="panel"><div class="panel-title">🔍 URL Investigation</div><div class="muted">Score suspicious URLs and inspect indicators.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🎭 Simulation Lab</div><div class="muted">Practice spotting phishing warning signs safely.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🔐 Authentication Lab</div><div class="muted">Explore password hashing, OTPs, and rate limiting.</div></div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="panel"><div class="panel-title">🌐 Threat Intelligence</div><div class="muted">Inspect the configured provider status.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🛡️ Defense Validation</div><div class="muted">Run registered security checks.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">📄 Reports</div><div class="muted">Export current-session results.</div></div>', unsafe_allow_html=True)
    st.markdown("### Current session activity")
    a, b, c = st.columns(3)
    a.metric("URL analysis", "Completed" if st.session_state.last_url_result is not None else "Not run")
    b.metric("Simulation", "Completed" if st.session_state.last_simulation_result is not None else "Not run")
    c.metric("Defense validation", "Completed" if st.session_state.last_defense_result is not None else "Not run")


# ============================================================
# 2. URL INVESTIGATION
# ============================================================
elif page == "🔍 URL Investigation":
    st.markdown('<div class="eyebrow">Investigation workspace</div>', unsafe_allow_html=True)
    st.title("URL Investigation")
    st.write("Inspect a URL using CyberRakshak's local heuristic detection engine.")
    with st.form("url_scan_form"):
        url = st.text_input("Enter URL or domain to scan", value=st.session_state.last_url_input, placeholder="e.g., https://example.com/login")
        submitted = st.form_submit_button("🔎 Scan URL", type="primary")
    if submitted:
        if not url.strip():
            st.warning("Enter a URL or domain first.")
        else:
            try:
                with st.spinner("Analyzing URL structure..."):
                    result = analyze_url(url.strip())
                st.session_state.last_url_result = result
                st.session_state.last_url_input = url.strip()
                st.session_state.last_report = None
            except Exception as exc:
                st.error("URL analysis could not be completed.")
                st.exception(exc)
    if st.session_state.last_url_result is not None:
        st.divider()
        show_url_result(st.session_state.last_url_result)
    else:
        st.markdown('<div class="panel"><div class="panel-title">Ready to investigate</div><div class="muted">Enter a URL above to see its risk score, indicators, and recommendation.</div></div>', unsafe_allow_html=True)


# ============================================================
# 3. THREAT INTELLIGENCE
# ============================================================
elif page == "🌐 Threat Intelligence":
    st.markdown('<div class="eyebrow">Reputation integration</div>', unsafe_allow_html=True)
    st.title("Threat Intelligence")
    st.write("Check the status returned by the project's threat-intelligence module.")
    st.warning("The current module is a placeholder unless a provider has been configured. This is not a live reputation verdict.")
    with st.form("ti_form"):
        url = st.text_input("URL to check", placeholder="https://example.com")
        submit = st.form_submit_button("Check provider status", type="primary")
    if submit:
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            try:
                result = check_threat_intelligence(url.strip())
                if isinstance(result, dict):
                    status = result.get("status", "unknown")
                    message = result.get("message", "No provider message returned.")
                    if status == "invalid_input": st.error(message)
                    elif "not_configured" in str(status): st.warning(message)
                    else: st.info(message)
                    st.markdown("#### Provider response")
                    st.json(result)
                else:
                    st.write(result)
            except Exception as exc:
                st.error("Threat-intelligence check failed.")
                st.exception(exc)


# ============================================================
# 4. SIMULATION LAB
# ============================================================
elif page == "🎭 Simulation Lab":
    st.markdown('<div class="eyebrow">Security awareness</div>', unsafe_allow_html=True)
    st.title("Phishing Simulation Lab")
    st.write("Explore fictional scenarios without contacting real targets or collecting credentials.")
    if not isinstance(SCENARIOS, dict) or not SCENARIOS:
        st.error("No scenarios are configured in simulation/phishing_simulator.py.")
    else:
        ids = list(SCENARIOS.keys())
        def title_for(sid):
            item = SCENARIOS[sid]
            return item.get("title", str(sid)) if isinstance(item, dict) else str(sid)
        sid = st.selectbox("Choose a scenario", ids, format_func=title_for)
        selected = SCENARIOS[sid]
        if isinstance(selected, dict):
            st.markdown("#### Scenario preview")
            st.info(selected.get("message", "Review this fictional scenario."))
        if st.button("Run simulation", type="primary"):
            try:
                st.session_state.last_simulation_result = run_simulation(sid)
                st.session_state.last_report = None
            except Exception as exc:
                st.error("Simulation could not be completed.")
                st.exception(exc)
        result = st.session_state.last_simulation_result
        if result is not None:
            st.divider()
            if not isinstance(result, dict):
                st.write(result)
            else:
                st.subheader(result.get("title", "Simulation results"))
                if result.get("message"): st.write(result["message"])
                signs = result.get("warning_signs", [])
                if signs:
                    st.markdown("#### Warning signs")
                    for sign in signs: st.write("• " + str(sign))
                analysis = result.get("url_analysis")
                if isinstance(analysis, dict):
                    st.markdown("#### Related URL analysis")
                    show_url_result(analysis)
                if result.get("safe_action"):
                    st.markdown("#### Safe action")
                    st.success(result["safe_action"])
                st.caption("Fictional educational simulation; no real credentials are collected.")


# ============================================================
# 5. AUTHENTICATION LAB
# ============================================================
elif page == "🔐 Authentication Lab":
    st.markdown('<div class="eyebrow">Authentication defense</div>', unsafe_allow_html=True)
    st.title("Authentication Security Lab")
    st.write("Demonstrate security controls with fictional test data only.")
    tab1, tab2, tab3 = st.tabs(["Password hashing", "OTP demonstration", "Rate limiting"])
    with tab1:
        st.subheader("Password hashing")
        password = st.text_input("Fictional demo password", type="password", key="demo_password")
        if st.button("Generate password hash", key="make_hash"):
            if not password:
                st.warning("Enter a fictional demo password.")
            else:
                try:
                    st.session_state.demo_hash = hash_password(password)
                    st.success("Hash generated.")
                except Exception as exc:
                    st.error("Password hashing failed.")
                    st.exception(exc)
        stored = st.session_state.demo_hash
        if stored is not None:
            st.markdown("#### Stored hash representation")
            if isinstance(stored, dict): st.json(stored)
            else: st.code(str(stored))
            check = st.text_input("Password to verify", type="password", key="verify_password_input")
            if st.button("Verify password", key="check_hash"):
                try:
                    if verify_password(check, stored): st.success("Password verification succeeded.")
                    else: st.error("Password verification failed.")
                except Exception as exc:
                    st.error("Password verification failed to run.")
                    st.exception(exc)
        st.caption("Never enter a real account password in this demonstration.")
    with tab2:
        st.subheader("One-time password")
        if st.button("Generate demo OTP", key="make_otp"):
            try:
                st.session_state.demo_otp = create_otp(ttl_seconds=120)
                st.success("Demo OTP generated locally.")
            except Exception as exc:
                st.session_state.demo_otp = None
                st.error("OTP generation failed.")
                st.exception(exc)
        challenge = st.session_state.demo_otp
        if challenge is not None:
            code = challenge.get("code") if isinstance(challenge, dict) else getattr(challenge, "code", None)
            if code is not None:
                st.markdown("#### Local demo code")
                st.code(str(code))
            submitted = st.text_input("Enter demo OTP", key="otp_entry")
            if st.button("Verify demo OTP", key="check_otp"):
                if not submitted.strip():
                    st.warning("Enter the demo OTP.")
                else:
                    try:
                        if verify_otp(challenge, submitted.strip()): st.success("OTP accepted.")
                        else: st.error("OTP rejected, expired, already used, or blocked.")
                    except Exception as exc:
                        st.error("OTP verification failed to run.")
                        st.exception(exc)
        st.caption("This OTP is not delivered to a real phone or account.")
    with tab3:
        st.subheader("Login rate limiting")
        if st.session_state.demo_limiter is None:
            st.session_state.demo_limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        limiter = st.session_state.demo_limiter
        account = "fictional-demo-account"
        left, right = st.columns(2)
        with left:
            if st.button("Record failed login", key="record_failure"):
                try:
                    if limiter.is_allowed(account):
                        limiter.record_failure(account)
                        st.warning("A failed login attempt was recorded.")
                    else: st.error("Rate limit reached; further attempts are blocked.")
                except Exception as exc:
                    st.error("Could not record attempt.")
                    st.exception(exc)
        with right:
            if st.button("Check availability", key="check_limiter"):
                try:
                    if limiter.is_allowed(account): st.success("Another attempt is currently allowed.")
                    else: st.error("Attempts are currently rate-limited.")
                except Exception as exc:
                    st.error("Could not check rate limit.")
                    st.exception(exc)
        if st.button("Reset demo limiter", key="reset_limiter"):
            st.session_state.demo_limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
            st.success("Demo limiter reset.")
        st.caption("Local demonstration only; not a production authentication service.")


# ============================================================
# 6. DEFENSE VALIDATION
# ============================================================
elif page == "🛡️ Defense Validation":
    st.markdown('<div class="eyebrow">Control verification</div>', unsafe_allow_html=True)
    st.title("Defense Validation")
    st.write("Run the automated security checks registered in this project.")
    st.info("These checks evaluate implemented controls; they do not certify an entire system.")
    if st.button("Run all validations", type="primary"):
        try:
            st.session_state.last_defense_result = run_all_validations()
            st.session_state.last_report = None
        except Exception as exc:
            st.error("Defense validation failed to run.")
            st.exception(exc)
    if st.session_state.last_defense_result is not None:
        st.divider()
        show_defense_results(st.session_state.last_defense_result)
        with st.expander("Full validation report"):
            st.json(st.session_state.last_defense_result)


# ============================================================
# 7. REPORTS
# ============================================================
elif page == "📄 Reports":
    st.markdown('<div class="eyebrow">Evidence and export</div>', unsafe_allow_html=True)
    st.title("Investigation Reports")
    st.write("Generate a JSON report from results collected during this session.")
    url_result = st.session_state.last_url_result
    sim_result = st.session_state.last_simulation_result
    defense_result = st.session_state.last_defense_result
    a, b, c = st.columns(3)
    a.metric("URL analysis", "Available" if url_result is not None else "Not run")
    b.metric("Simulation", "Available" if sim_result is not None else "Not run")
    c.metric("Defense validation", "Available" if defense_result is not None else "Not run")
    if st.button("Generate JSON report", type="primary"):
        if all(x is None for x in (url_result, sim_result, defense_result)):
            st.warning("Run at least one investigation or validation first.")
        else:
            try:
                st.session_state.last_report = generate_report(
                    url_analysis=url_result,
                    simulation_result=sim_result,
                    defense_report=defense_result,
                )
                st.success("Report generated.")
            except Exception as exc:
                st.error("Report generation failed.")
                st.exception(exc)
    report = st.session_state.last_report
    if report is not None:
        report_text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        with st.expander("Preview JSON report", expanded=True):
            st.code(report_text, language="json")
        st.download_button(
            "⬇ Download JSON report", data=report_text,
            file_name="cyberrakshak_report.json", mime="application/json",
            type="primary",
        )
    st.caption("Reports include current-session results only. PDF export is not implemented.")


st.divider()
st.markdown(
    '<div class="footer-note">CyberRakshak · Detect the Threat. Understand the Attack. Protect the User. '
    'Use only for authorized, educational security investigation.</div>',
    unsafe_allow_html=True,
)