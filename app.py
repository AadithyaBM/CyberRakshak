"""
CyberRakshak — Cyber Fraud Detection, Phishing Investigation and
Defense Validation Platform.
Tagline: Detect the Threat. Understand the Attack. Protect the User.
"""

import json
import sqlite3
from io import BytesIO
from datetime import datetime
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from engine.url_analyzer import analyze_url
from engine.site_inspector import (
    inspect_ssl,
    inspect_dns,
    inspect_whois,
    inspect_web,
    inspect_html,
)
from engine.threat_intelligence import check_threat_intelligence
from security.auth_security import (
    LoginRateLimiter, create_otp, hash_password, verify_otp, verify_password
)
from security.defense_validator import run_all_validations
from simulation.phishing_simulator import SCENARIOS, run_simulation
from reports.report_generator import (
    generate_report,
    generate_report_pdf,
)

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

/* ---------- Full-site roaming CyberRakshak ghosts ---------- */
.cyber-ghost-field {
    position: fixed;
    inset: 0;
    z-index: 20;
    overflow: hidden;
    pointer-events: none;
    contain: layout paint;
}
.cyber-roaming-ghost {
    position: absolute;
    display: block;
    left: var(--start-x, 5vw);
    top: var(--start-y, 15vh);
    font-size: clamp(28px, 3.1vw, 44px);
    line-height: 1;
    opacity: .78;
    filter: drop-shadow(0 0 8px var(--ghost-glow, #12d6b0)) drop-shadow(0 0 16px var(--ghost-glow, #12d6b0));
    will-change: transform;
    animation: ghost-drift var(--travel-time, 13s) ease-in-out infinite alternate,
               ghost-bob var(--bob-time, 2.3s) ease-in-out infinite;
}
.cyber-roaming-ghost.g1 { --start-x: 2vw; --start-y: 13vh; --travel-time: 14s; --bob-time: 2.1s; }
.cyber-roaming-ghost.g2 { --start-x: 82vw; --start-y: 18vh; --travel-time: 17s; --bob-time: 2.8s; animation-delay: -4s, -.8s; }
.cyber-roaming-ghost.g3 { --start-x: 10vw; --start-y: 72vh; --travel-time: 16s; --bob-time: 2.4s; animation-delay: -7s, -.4s; }
.cyber-roaming-ghost.g4 { --start-x: 86vw; --start-y: 78vh; --travel-time: 19s; --bob-time: 3s; animation-delay: -9s, -1.1s; }
.cyber-roaming-ghost.g5 { --start-x: 46vw; --start-y: 8vh; --travel-time: 15s; --bob-time: 2.6s; animation-delay: -5s, -.6s; font-size: clamp(25px, 2.6vw, 38px); }
.cyber-roaming-ghost.g6 { --start-x: 58vw; --start-y: 84vh; --travel-time: 18s; --bob-time: 2.2s; animation-delay: -11s, -1.3s; }
.cyber-roaming-ghost.g7 { --start-x: 32vw; --start-y: 48vh; --travel-time: 21s; --bob-time: 2.9s; animation-delay: -8s, -.2s; font-size: clamp(24px, 2.5vw, 36px); opacity: .58; }
.cyber-roaming-ghost.g8 { --start-x: 72vw; --start-y: 55vh; --travel-time: 16s; --bob-time: 2.5s; animation-delay: -3s, -.9s; font-size: clamp(24px, 2.5vw, 36px); opacity: .62; }
.ghost-low { --ghost-glow: #12d6b0; }
.ghost-medium { --ghost-glow: #f5b82e; }
.ghost-high { --ghost-glow: #ff4058; }
.ghost-invalid { --ghost-glow: #b89cff; }
@keyframes ghost-drift {
    0%   { transform: translate3d(0, 0, 0) rotate(-9deg) scale(.96); }
    25%  { transform: translate3d(5vw, 5vh, 0) rotate(8deg) scale(1.04); }
    50%  { transform: translate3d(10vw, -3vh, 0) rotate(-5deg) scale(1); }
    75%  { transform: translate3d(-3vw, 6vh, 0) rotate(10deg) scale(1.06); }
    100% { transform: translate3d(2vw, -4vh, 0) rotate(-8deg) scale(.98); }
}
@keyframes ghost-bob {
    0%,100% { margin-top: 0; }
    50% { margin-top: -15px; }
}
.ghost-high .cyber-roaming-ghost { filter: drop-shadow(0 0 10px #ff4058) drop-shadow(0 0 20px #ff4058); }
.ghost-medium .cyber-roaming-ghost { filter: drop-shadow(0 0 10px #f5b82e) drop-shadow(0 0 18px #f5b82e); }
.ghost-invalid .cyber-roaming-ghost { filter: drop-shadow(0 0 10px #b89cff) drop-shadow(0 0 18px #b89cff); }
@media (prefers-reduced-motion: reduce) {
    .cyber-roaming-ghost { animation: none !important; }
}
@media (max-width: 640px) {
    .cyber-roaming-ghost.g7, .cyber-roaming-ghost.g8 { display: none; }
    .cyber-roaming-ghost { opacity: .42; font-size: 27px; }
}

/* ---------- Fixed reactive ghost alert card (bottom-right) ---------- */
.ghost-alert-card {
    position: fixed;
    right: 24px;
    bottom: 22px;
    z-index: 9999;
    width: min(425px, calc(100vw - 36px));
    min-height: 94px;
    display: flex;
    align-items: center;
    gap: 17px;
    box-sizing: border-box;
    padding: 16px 20px;
    border: 1.5px solid var(--alert-color, #12d6b0);
    border-radius: 23px;
    background: linear-gradient(110deg, rgba(13,17,29,.98), rgba(7,11,20,.98));
    box-shadow: 0 0 16px color-mix(in srgb, var(--alert-color, #12d6b0) 30%, transparent),
                inset 0 0 20px rgba(255,255,255,.015);
    color: #e8edf6;
    pointer-events: none;
    animation: ghost-card-in .55s ease-out both, ghost-card-glow 3s ease-in-out infinite;
}
.ghost-alert-card .alert-face {
    flex: 0 0 68px;
    width: 68px;
    text-align: center;
    font-size: 47px;
    line-height: 1;
    filter: drop-shadow(0 0 10px var(--alert-color, #12d6b0));
    animation: ghost-bob 2.3s ease-in-out infinite;
}
.ghost-alert-card .alert-title {
    color: var(--alert-color, #12d6b0);
    font-weight: 900;
    font-size: 15px;
    letter-spacing: 2px;
    line-height: 1.25;
    margin-bottom: 7px;
}
.ghost-alert-card .alert-message {
    color: #d3d9e5;
    font-size: 13px;
    font-weight: 600;
    line-height: 1.4;
}
@keyframes ghost-card-in {
    from { opacity: 0; transform: translateY(18px) scale(.97); }
    to { opacity: 1; transform: translateY(0) scale(1); }
}
@keyframes ghost-card-glow {
    0%,100% { box-shadow: 0 0 12px color-mix(in srgb, var(--alert-color, #12d6b0) 24%, transparent); }
    50% { box-shadow: 0 0 23px color-mix(in srgb, var(--alert-color, #12d6b0) 43%, transparent); }
}
.ghost-alert-low { --alert-color: #12d6b0; }
.ghost-alert-medium { --alert-color: #f5b82e; }
.ghost-alert-high { --alert-color: #ff4058; }
.ghost-alert-invalid { --alert-color: #b89cff; }
@media (max-width: 640px) {
    .ghost-alert-card { right: 10px; bottom: 10px; width: calc(100vw - 20px); padding: 12px 14px; gap: 10px; border-radius: 17px; }
    .ghost-alert-card .alert-face { flex-basis: 48px; width: 48px; font-size: 36px; }
    .ghost-alert-card .alert-title { font-size: 12px; letter-spacing: 1.3px; }
    .ghost-alert-card .alert-message { font-size: 12px; }
}


/* ---------- CYBERRAKSHAK HYBRID NEON THEME OVERRIDES ---------- */
:root {
  --bg:#070914; --panel:#0d1222; --border:#293550; --text:#eef3ff;
  --muted:#96a3bc; --teal:#35f2b5; --red:#ff4d7d; --amber:#ffc857;
  --green:#35f2b5; --neon-blue:#38bdf8; --neon-purple:#b78aff;
}
.stApp,[data-testid="stAppViewContainer"] {
  background: radial-gradient(ellipse at 12% 0%,rgba(56,189,248,.10),transparent 34%),
              radial-gradient(ellipse at 90% 12%,rgba(183,138,255,.10),transparent 32%),
              linear-gradient(145deg,#070914 0%,#080d1a 52%,#090817 100%);
  color:var(--text);
}
[data-testid="stHeader"]{background:rgba(7,9,20,.88);border-bottom:1px solid rgba(56,189,248,.20)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0b1020 0%,#101027 58%,#0a1421 100%);border-right:1px solid rgba(56,189,248,.28)}
[data-testid="stSidebar"]>div:first-child{background:transparent}
.brand{font-size:1.48rem;font-weight:900;letter-spacing:-.6px;color:#f5f7ff;text-shadow:0 0 18px rgba(56,189,248,.16)}
.brand span{color:var(--neon-blue);text-shadow:0 0 12px rgba(56,189,248,.7),0 0 22px rgba(183,138,255,.35)}
.eyebrow{color:var(--neon-blue);text-transform:uppercase;letter-spacing:2px;font-size:.74rem;font-weight:850}
.hero{position:relative;overflow:hidden;background:radial-gradient(ellipse at 88% 10%,rgba(183,138,255,.20),transparent 38%),linear-gradient(125deg,rgba(15,27,48,.98),rgba(11,17,34,.97) 54%,rgba(8,35,42,.96));border:1px solid rgba(56,189,248,.38);border-radius:20px;padding:1.85rem;margin:.2rem 0 1.2rem;box-shadow:0 0 0 1px rgba(183,138,255,.05),0 12px 40px rgba(0,0,0,.20)}
.hero:after{content:"";position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,#35f2b5,#38bdf8,#b78aff);opacity:.95}
.hero h1{font-size:clamp(2rem,4vw,2.8rem);line-height:1.08;letter-spacing:-1.2px;color:#f7f9ff;margin:.5rem 0;text-shadow:0 0 25px rgba(56,189,248,.09)}
.hero p{color:#b6c4dc;max-width:760px}
.panel,.metric-card,div[data-testid="stMetric"]{background:linear-gradient(145deg,rgba(15,21,39,.96),rgba(10,15,29,.98));border:1px solid #293550;border-radius:15px;box-shadow:0 7px 24px rgba(0,0,0,.14);transition:border-color .2s ease,transform .2s ease,box-shadow .2s ease}
.panel{padding:1.05rem 1.15rem}
.panel:hover,.metric-card:hover{border-color:rgba(56,189,248,.55);box-shadow:0 0 20px rgba(56,189,248,.07),0 10px 28px rgba(0,0,0,.18);transform:translateY(-2px)}
.panel-title{font-weight:800;color:#eef3ff}
.muted,.metric-label,.metric-sub{color:#9ba9c2}
.metric-card{padding:1rem;min-height:95px}
.metric-value{color:#f4f7ff;font-size:1.35rem;font-weight:850;overflow-wrap:anywhere;text-shadow:0 0 14px rgba(56,189,248,.08)}
div[data-testid="stMetric"]{padding:.8rem 1rem}
div[data-testid="stMetricLabel"]{color:#a9b7d0}
div[data-testid="stMetricValue"]{color:#f4f7ff}
div.stButton>button,div.stDownloadButton>button{border-radius:10px;border:1px solid #354563;background:linear-gradient(120deg,#131d32,#17152d);color:#edf4ff;font-weight:750;min-height:2.55rem;transition:all .2s ease}
div.stButton>button:hover,div.stDownloadButton>button:hover{border-color:var(--neon-blue);color:white;box-shadow:0 0 16px rgba(56,189,248,.15),0 0 18px rgba(183,138,255,.08);transform:translateY(-1px)}
div.stButton>button[kind="primary"],div.stDownloadButton>button[kind="primary"]{background:linear-gradient(105deg,#35f2b5 0%,#38bdf8 55%,#b78aff 100%);color:#07101a;border:0;font-weight:900;box-shadow:0 4px 18px rgba(56,189,248,.13)}
div.stTabs [data-baseweb="tab-list"]{gap:.3rem;border-bottom:1px solid #293550}
div.stTabs button{color:#aebbd3}
div.stTabs button[aria-selected="true"]{color:#62d7ff;border-bottom-color:#62d7ff}
input,textarea,[data-baseweb="select"]>div{background:#0b1120!important;border-color:#34425e!important;color:#edf4ff!important}
[data-testid="stDataFrame"]{border:1px solid #293550;border-radius:12px;overflow:hidden}
[data-testid="stAlert"]{border-radius:12px;border:1px solid rgba(56,189,248,.20)}
hr{border-color:rgba(56,189,248,.18)}
.footer-note{color:#8190aa;font-size:.77rem}
.ghost-alert-card{backdrop-filter:blur(12px);background:linear-gradient(115deg,rgba(12,17,33,.97),rgba(12,10,29,.97));border-radius:20px}
.ghost-alert-low,.ghost-low{--alert-color:#35f2b5;--ghost-glow:#35f2b5}
.ghost-alert-medium,.ghost-medium{--alert-color:#ffc857;--ghost-glow:#ffc857}
.ghost-alert-high,.ghost-high{--alert-color:#ff4d7d;--ghost-glow:#ff4d7d}
.ghost-alert-invalid,.ghost-invalid{--alert-color:#b78aff;--ghost-glow:#b78aff}
@media(max-width:640px){.hero{padding:1.25rem;border-radius:15px}}


/* ---------- SIDEBAR NEON NAVIGATION POLISH ---------- */
[data-testid="stSidebar"] {
  background:
    radial-gradient(ellipse at 5% 0%, rgba(56,189,248,.13), transparent 38%),
    radial-gradient(ellipse at 100% 55%, rgba(183,138,255,.12), transparent 42%),
    linear-gradient(180deg, #080e1c 0%, #101027 58%, #091522 100%) !important;
  border-right: 1px solid rgba(56,189,248,.42) !important;
  box-shadow: 5px 0 28px rgba(56,189,248,.04);
}
[data-testid="stSidebar"] .brand {
  padding: .35rem 0 .25rem;
  font-size: 1.55rem;
  background: linear-gradient(90deg, #f5fbff 0%, #62d7ff 48%, #a9f9d8 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 10px rgba(56,189,248,.24));
}
[data-testid="stSidebar"] .brand span {
  -webkit-text-fill-color: #38bdf8;
  filter: drop-shadow(0 0 7px rgba(56,189,248,.9));
}
[data-testid="stSidebar"] [data-testid="stRadio"] > label {
  color: #8ea2bf !important;
  font-size: .72rem !important;
  font-weight: 850 !important;
  letter-spacing: 1.6px !important;
  text-transform: uppercase;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] {
  gap: .32rem;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] > label {
  border: 1px solid transparent;
  border-radius: 10px;
  padding: .48rem .55rem;
  transition: background .18s ease, border-color .18s ease, box-shadow .18s ease;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] > label:hover {
  background: rgba(56,189,248,.08);
  border-color: rgba(56,189,248,.22);
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] > label:has(input:checked) {
  background: linear-gradient(100deg, rgba(53,242,181,.14), rgba(56,189,248,.17), rgba(183,138,255,.13));
  border-color: rgba(56,189,248,.65);
  box-shadow: inset 0 0 16px rgba(56,189,248,.06), 0 0 15px rgba(56,189,248,.08);
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] > label:has(input:checked) p {
  color: #f0fbff !important;
  font-weight: 800 !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] > label p {
  color: #aebdd3;
  font-size: .88rem;
}
[data-testid="stSidebar"] [data-testid="stDivider"] {
  border-color: rgba(56,189,248,.18);
}

</style>
""", unsafe_allow_html=True)

# ---------- Session state ----------
DEFAULTS = {
    "last_url_result": None, "last_url_input": "",
    "last_simulation_result": None, "last_defense_result": None,
    "last_report": None, "demo_hash": None, "demo_otp": None,
    "demo_limiter": None, "site_inspection_results": {},
    "scan_history": [],
}
for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ---------- Persistent scan history (SQLite) ----------
DB_PATH = "cyberrakshak_history.db"

def init_history_db():
    """Create the local history database if it does not exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                hostname TEXT,
                risk_score REAL,
                risk_level TEXT,
                valid INTEGER,
                indicators TEXT,
                recommendation TEXT
            )
        """)
        conn.commit()

def save_scan_to_db(entry):
    """Persist one explicit Scan URL action to disk."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO scan_history
            (timestamp, url, hostname, risk_score, risk_level, valid, indicators, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(entry.get("timestamp", "")),
            str(entry.get("url", "")),
            str(entry.get("hostname", "—")),
            float(entry.get("risk_score", 0) or 0),
            str(entry.get("risk_level", "Invalid")),
            1 if entry.get("valid", False) else 0,
            str(entry.get("indicators", "")),
            str(entry.get("recommendation", "")),
        ))
        conn.commit()

def load_scan_history(limit=5000):
    """Return persistent scan history, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT timestamp, url, hostname, risk_score, risk_level, valid, indicators, recommendation
            FROM scan_history ORDER BY id DESC LIMIT ?
        """, (int(limit),)).fetchall()
    return [dict(row) | {"valid": bool(row["valid"])} for row in rows]

def clear_scan_history_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()

def make_history_pdf(rows):
    """Create a readable PDF report for filtered scan-history records."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        rightMargin=12*mm, leftMargin=12*mm,
        topMargin=12*mm, bottomMargin=12*mm
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#123047")))
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9, wordWrap="CJK"))
    story = [
        Paragraph("CyberRakshak — Scan History Report", styles["ReportTitle"]),
        Paragraph("Generated: " + datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"), styles["Normal"]),
        Spacer(1, 5*mm),
        Paragraph(f"Records included: {len(rows)}", styles["Heading2"]),
        Spacer(1, 2*mm),
    ]
    counts = {}
    for row in rows:
        level = str(row.get("risk_level", "Unknown")).title()
        counts[level] = counts.get(level, 0) + 1
    summary_data = [["Risk level", "Count"]] + [[k, str(v)] for k, v in sorted(counts.items())]
    summary = Table(summary_data, colWidths=[38*mm, 22*mm])
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#123047")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), .4, colors.HexColor("#B8C4CE")),
        ("PADDING", (0,0), (-1,-1), 5),
    ]))
    story.extend([summary, Spacer(1, 5*mm)])
    data = [[
        "Time", "Hostname", "Risk", "Score", "URL", "Indicators", "Recommendation"
    ]]
    for row in rows:
        data.append([
            Paragraph(str(row.get("timestamp", "")), styles["SmallCell"]),
            Paragraph(str(row.get("hostname", "—")), styles["SmallCell"]),
            Paragraph(str(row.get("risk_level", "Unknown")), styles["SmallCell"]),
            Paragraph(str(row.get("risk_score", 0)), styles["SmallCell"]),
            Paragraph(str(row.get("url", "")), styles["SmallCell"]),
            Paragraph(str(row.get("indicators", "")), styles["SmallCell"]),
            Paragraph(str(row.get("recommendation", "")), styles["SmallCell"]),
        ])
    table = Table(data, repeatRows=1, colWidths=[29*mm, 28*mm, 18*mm, 14*mm, 48*mm, 54*mm, 48*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#123047")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#B8C4CE")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("PADDING", (0,0), (-1,-1), 4),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F1F5F8")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "Note: Risk scores are heuristic indicators and do not prove that a URL is malicious or safe. "
        "This report contains only scans recorded by this local CyberRakshak instance.",
        styles["SmallCell"]
    ))
    doc.build(story)
    return buffer.getvalue()

init_history_db()


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
        ti_result = result.get("threat_intelligence", {})
        if isinstance(ti_result, dict) and ti_result.get("status") != "not_requested":
            st.markdown("#### Google Safe Browsing result")
            ti_status = ti_result.get("status", "unknown")
            ti_message = ti_result.get("message", "No provider message returned.")
            if ti_status == "match":
                st.error("Known threat match reported by Google Safe Browsing. " + ti_message)
            elif ti_status == "no_match":
                st.info("No known threat match returned. This does not guarantee safety. " + ti_message)
            elif ti_status in {"unavailable", "not_configured"}:
                st.warning(ti_message)
            else:
                st.info(ti_message)
            with st.expander("Threat-intelligence response details"):
                st.json(ti_result)
        st.caption(
            "Risk scores are heuristic indicators, not probabilities. Google Safe Browsing checks are only made when selected. "
            "This reputation check does not open the destination or follow redirects."
        )
    target_url = result.get("normalized_url") or ("https://" + hostname)
    if "site_inspection_results" not in st.session_state:
        st.session_state.site_inspection_results = {}
    cache_key = target_url
    def run_inspection(label, function):
        if st.button(f"Run {label}", key=f"inspect_{label.lower().replace(' ', '_')}", type="primary"):
            try:
                with st.spinner(f"Running {label.lower()}…"):
                    st.session_state.site_inspection_results[(cache_key, label)] = function(target_url)
            except Exception as exc:
                st.session_state.site_inspection_results[(cache_key, label)] = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        data = st.session_state.site_inspection_results.get((cache_key, label))
        if data is None:
            st.info(f"Click Run {label} to perform this read-only check.")
        else:
            status = data.get("status", "UNKNOWN")
            if status in {"OK", "PASS"}:
                st.success(f"Status: {status}")
            elif status == "ERROR":
                st.error(f"Status: {status}")
            else:
                st.warning(f"Status: {status}")
            st.json(data)

    with ssl_tab:
        st.subheader("SSL Certificate")
        st.caption("Checks a public HTTPS certificate using the system trust store. Network errors are reported, not treated as maliciousness.")
        run_inspection("SSL Certificate", inspect_ssl)
    with dns_tab:
        st.subheader("DNS Records")
        st.caption("Queries public DNS records for the analyzed hostname.")
        run_inspection("DNS Records", inspect_dns)
    with whois_tab:
        st.subheader("WHOIS / Domain Registration")
        st.caption("Uses RDAP over HTTPS; some registration fields may be private or unavailable.")
        run_inspection("WHOIS", inspect_whois)
    with web_tab:
        st.subheader("Web Analysis")
        st.caption("Fetches a public page without submitting forms; redirects are checked manually and limited.")
        run_inspection("Web Analysis", inspect_web)
    with html_tab:
        st.subheader("HTML Inspection")
        st.caption("Parses static HTML only; does not execute JavaScript or submit forms. Output is capped at 500 KB.")
        run_inspection("HTML Inspection", inspect_html)



def show_reactive_ghost(result=None):
    """Render roaming ghosts and a floating card based on the latest URL scan only."""
    if not isinstance(result, dict):
        state = "idle"
        title = "CYBER GHOSTS"
        message = "Ready to scan a URL."
        card_face = "👻"
    elif not result.get("valid", False):
        state = "invalid"
        title = "URL NEEDS A CHECK"
        message = "Unable to analyze this URL. Check its format."
        card_face = "👻"
    else:
        # The card reflects analyze_url()'s actual risk_level. SSL, DNS,
        # WHOIS, web, and HTML inspection results do not control this card.
        level = str(result.get("risk_level", "unknown")).strip().lower()
        if level == "high":
            state = "high"
            title = "THREAT ALERT"
            message = "Strong warning signs detected. Verify independently."
            card_face = "👾"
        elif level == "medium":
            state = "medium"
            title = "STAY ALERT"
            message = "Review this URL before interacting."
            card_face = "👻"
        elif level == "low":
            state = "low"
            title = "GUARDIAN GHOST"
            message = "Few warning signs detected. Not a safety guarantee."
            card_face = "👻"
        else:
            state = "invalid"
            title = "URL NEEDS A CHECK"
            message = "The scan returned an unrecognized result."
            card_face = "👻"

    ghosts = "".join(
        f'<span class="cyber-roaming-ghost g{i}" aria-hidden="true">👻</span>'
        for i in range(1, 9)
    )
    st.markdown(
        f"""
        <div class="cyber-ghost-field ghost-{state}" aria-hidden="true">
          {ghosts}
        </div>
        <div class="ghost-alert-card ghost-alert-{state}" role="status" aria-live="polite">
          <div class="alert-face" aria-hidden="true">{card_face}</div>
          <div class="alert-copy">
            <div class="alert-title">{title}</div>
            <div class="alert-message">{message}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

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
        "🛡️ Defense Validation", "🕘 Scan History", "📄 Reports",
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
# Global ghost card is rendered at the end, after all page actions.

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
    with d: metric_card("Reports", "PDF", "Downloadable security report")
    st.markdown("### Platform modules")
    left, right = st.columns(2)
    with left:
        st.markdown('<div class="panel"><div class="panel-title">🔍 URL Investigation</div><div class="muted">Score suspicious URLs and inspect indicators.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🎭 Simulation Lab</div><div class="muted">Practice spotting phishing warning signs safely.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🔐 Authentication Lab</div><div class="muted">Explore password hashing, OTPs, and rate limiting.</div></div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="panel"><div class="panel-title">🌐 Threat Intelligence</div><div class="muted">Inspect the configured provider status.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🛡️ Defense Validation</div><div class="muted">Run registered security checks.</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">🕘 Scan History</div><div class="muted">Review and export previous URL scans.</div></div><div class="panel"><div class="panel-title">📄 Reports</div><div class="muted">Export current-session results.</div></div>', unsafe_allow_html=True)
    st.markdown("### Security dashboard")
    dashboard_history = load_scan_history()
    total = len(dashboard_history)
    counts = {
        "Low": sum(str(x.get("risk_level", "")).lower() == "low" for x in dashboard_history),
        "Medium": sum(str(x.get("risk_level", "")).lower() == "medium" for x in dashboard_history),
        "High": sum(str(x.get("risk_level", "")).lower() == "high" for x in dashboard_history),
        "Invalid": sum(not x.get("valid", False) for x in dashboard_history),
    }
    d1, d2, d3, d4, d5 = st.columns(5)
    d1.metric("Total scans", total)
    d2.metric("Low risk", counts["Low"])
    d3.metric("Medium risk", counts["Medium"])
    d4.metric("High risk", counts["High"])
    d5.metric("Invalid", counts["Invalid"])
    if dashboard_history:
        chart_left, chart_right = st.columns(2)
        with chart_left:
            st.markdown("#### Scan distribution")
            distribution = [{"Risk level": key, "Scans": value} for key, value in counts.items() if value]
            if distribution:
                fig = px.pie(distribution, names="Risk level", values="Scans", hole=0.55)
                fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10),
                                  paper_bgcolor="rgba(0,0,0,0)", font_color="#e8edf6")
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        with chart_right:
            st.markdown("#### Recent scan scores")
            recent = list(reversed(dashboard_history[:10]))
            score_data = [{"Scan": i + 1, "Score": float(x.get("risk_score", 0) or 0),
                           "Hostname": x.get("hostname", "—")} for i, x in enumerate(recent)]
            fig = px.bar(score_data, x="Scan", y="Score", hover_data=["Hostname"], range_y=[0, 100])
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#e8edf6")
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("Your dashboard charts will appear after you scan your first URL.")

    st.markdown("### Current session activity")
    a, b, c, d = st.columns(4)
    a.metric("URL analysis", "Completed" if st.session_state.last_url_result is not None else "Not run")
    b.metric("Saved scans", total)
    c.metric("Simulation", "Completed" if st.session_state.last_simulation_result is not None else "Not run")
    d.metric("Defense validation", "Completed" if st.session_state.last_defense_result is not None else "Not run")


# ============================================================
# 2. URL INVESTIGATION
# ============================================================
elif page == "🔍 URL Investigation":
    st.markdown('<div class="eyebrow">Investigation workspace</div>', unsafe_allow_html=True)
    st.title("URL Investigation")
    st.write("Inspect a URL using local heuristics, with an optional Google Safe Browsing reputation check.")
    with st.form("url_scan_form"):
        url = st.text_input("Enter URL or domain to scan", value=st.session_state.last_url_input, placeholder="e.g., https://example.com/login")
        check_online = st.checkbox(
            "Check Google Safe Browsing (online)",
            value=False,
            help="When enabled, the submitted URL is sent to the configured Google Safe Browsing API. The website itself is not opened by this check."
        )
        submitted = st.form_submit_button("🔎 Scan URL", type="primary")
    if submitted:
        if not url.strip():
            st.warning("Enter a URL or domain first.")
        else:
            try:
                with st.spinner("Analyzing URL and checking selected threat-intelligence sources..."):
                    result = analyze_url(url.strip(), check_online=check_online)
                st.session_state.last_url_result = result
                st.session_state.last_url_input = url.strip()
                st.session_state.last_report = None

                # Keep a timestamped record of each explicit Scan URL action.
                history_entry = {
                    "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "url": url.strip(),
                    "hostname": result.get("hostname") or "—",
                    "risk_score": result.get("risk_score", 0),
                    "risk_level": result.get("risk_level", "Invalid"),
                    "valid": bool(result.get("valid", False)),
                    "indicators": " | ".join(str(x) for x in result.get("indicators", [])),
                    "recommendation": result.get("recommendation", ""),
                }
                st.session_state.scan_history.insert(0, history_entry)
                # Save to SQLite so records remain after restarting Streamlit.
                save_scan_to_db(history_entry)
                # Keep a convenient in-session copy for the current interface.
                st.session_state.scan_history = st.session_state.scan_history[:500]
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
    st.write("Check a URL against the configured Google Safe Browsing provider.")
    st.caption("The submitted URL is sent to Google Safe Browsing when an API key is configured. A no-match result is not a guarantee that a URL is safe.")
    with st.form("ti_form"):
        url = st.text_input("URL to check", placeholder="https://example.com")
        submit = st.form_submit_button("Check URL reputation", type="primary")
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
                    elif status == "match": st.error("Known threat match reported. " + message)
                    elif status in {"not_configured", "unavailable"}: st.warning(message)
                    elif status == "no_match": st.info("No known threat match returned; this does not guarantee safety. " + message)
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
# 7. SCAN HISTORY
# ============================================================
elif page == "🕘 Scan History":
    st.markdown('<div class="eyebrow">Investigation timeline</div>', unsafe_allow_html=True)
    st.title("Scan History")
    st.write("Review scans saved in the local SQLite database. Records remain available after restarting the app.")

    history = load_scan_history()
    if not history:
        st.info("No URL scans recorded yet. Open URL Investigation and click Scan URL to create your first history entry.")
    else:
        total = len(history)
        high_count = sum(str(item.get("risk_level", "")).lower() == "high" for item in history)
        medium_count = sum(str(item.get("risk_level", "")).lower() == "medium" for item in history)
        low_count = sum(str(item.get("risk_level", "")).lower() == "low" for item in history)
        invalid_count = sum(not item.get("valid", False) for item in history)

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total scans", total)
        m2.metric("High risk", high_count)
        m3.metric("Medium risk", medium_count)
        m4.metric("Low risk", low_count)
        m5.metric("Invalid", invalid_count)

        levels = ["All", "High", "Medium", "Low", "Invalid"]
        selected_level = st.selectbox("Filter by result", levels, key="history_filter")
        if selected_level == "All":
            filtered = history
        elif selected_level == "Invalid":
            filtered = [item for item in history if not item.get("valid", False)]
        else:
            filtered = [item for item in history if str(item.get("risk_level", "")).lower() == selected_level.lower()]

        st.caption(f"Showing {len(filtered)} of {total} saved scans. Newest scans appear first.")
        display_rows = [{
            "Time": item.get("timestamp", ""),
            "Hostname": item.get("hostname", "—"),
            "Risk": item.get("risk_level", "Unknown"),
            "Score": item.get("risk_score", 0),
            "URL": item.get("url", ""),
            "Valid input": "Yes" if item.get("valid", False) else "No",
        } for item in filtered]
        st.dataframe(display_rows, use_container_width=True, hide_index=True)

        with st.expander("View scan details"):
            options = [
                f'{idx + 1}. {item.get("timestamp", "")} — {item.get("hostname", "—")} — {item.get("risk_level", "Invalid")}'
                for idx, item in enumerate(filtered)
            ]
            if options:
                selected = st.selectbox("Choose a scan", options, key="history_detail_choice")
                st.json(filtered[options.index(selected)])

        try:
            pdf_bytes = make_history_pdf(filtered)
            st.download_button(
                "📄 Download filtered history as PDF",
                data=pdf_bytes,
                file_name="CyberRakshak_Scan_History.pdf",
                mime="application/pdf",
                type="primary",
                key="download_scan_history_pdf",
            )
        except Exception as exc:
            st.error("Could not generate the scan-history PDF.")
            st.caption("Check that reportlab is installed in your Python environment.")
            st.exception(exc)

        if st.button("Clear all saved scan history", type="secondary"):
            clear_scan_history_db()
            st.session_state.scan_history = []
            st.rerun()


# 8. REPORTS
# ============================================================
elif page == "📄 Reports":
    st.markdown(
        '<div class="eyebrow">Evidence and export</div>',
        unsafe_allow_html=True,
    )

    st.title("Investigation Reports")

    st.write(
        "Generate and download a professional PDF report for reading, sharing, and printing."
    )

    url_result = st.session_state.last_url_result
    sim_result = st.session_state.last_simulation_result
    defense_result = st.session_state.last_defense_result

    a, b, c = st.columns(3)

    a.metric(
        "URL analysis",
        "Available" if url_result is not None else "Not run",
    )

    b.metric(
        "Simulation",
        "Available" if sim_result is not None else "Not run",
    )

    c.metric(
        "Defense validation",
        "Available" if defense_result is not None else "Not run",
    )

    # --------------------------------------------------------
    # GENERATE REPORT
    # --------------------------------------------------------

    if st.button("Generate Investigation Report", type="primary"):
        if all(
            item is None
            for item in (url_result, sim_result, defense_result)
        ):
            st.warning(
                "Run at least one investigation, simulation, "
                "or validation before generating a report."
            )
        else:
            try:
                st.session_state.last_report = generate_report(
                    url_analysis=url_result,
                    simulation_result=sim_result,
                    defense_report=defense_result,
                )

                st.success("Investigation report generated.")

            except Exception as exc:
                st.error("Report generation failed.")
                st.exception(exc)

    # --------------------------------------------------------
    # PREVIEW AND DOWNLOAD
    # --------------------------------------------------------

    report = st.session_state.last_report

    if report is not None:
        report_text = json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        with st.expander("Preview report data"):
            st.code(report_text, language="json")

        # PDF generation
        try:
            pdf_bytes = generate_report_pdf(report)

            st.download_button(
                label="📄 Download Professional PDF Report",
                data=pdf_bytes,
                file_name="CyberRakshak_Security_Report.pdf",
                mime="application/pdf",
                key="download_cyberrakshak_pdf",
                type="primary",
            )

            st.caption(
                "The PDF contains a readable summary, investigation "
                "findings, risk information, recommendations, and limitations."
            )

        except Exception as exc:
            st.error("PDF generation failed.")
            st.exception(exc)

    else:
        st.info(
            "Generate a report after completing a URL investigation, "
            "phishing simulation, or defense validation."
        )

    st.caption(
        "Reports include current-session results only. "
        "Heuristic findings do not guarantee that a URL or system is safe."
    )

st.divider()
st.markdown(
    '<div class="footer-note">CyberRakshak · Detect the Threat. Understand the Attack. Protect the User. '
    'Use only for authorized, educational security investigation.</div>',
    unsafe_allow_html=True,
)

# Render after page handlers so clicking Scan URL updates the card on the same run.
show_reactive_ghost(st.session_state.get("last_url_result"))
