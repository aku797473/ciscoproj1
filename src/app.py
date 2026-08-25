"""
NetSage AI: Automated Network Diagnostic Platform
Interactive Operations & Human-in-the-Loop (HITL) Dashboard (app.py)
"""

import sys
import html as _html
from pathlib import Path

def h(text):
    """Safely escape any string for HTML insertion."""
    return _html.escape(str(text)) if text else ""

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import pandas as pd
import streamlit as st
import altair as alt

st.set_page_config(
    page_title="NetSage AI | Network Diagnostic Platform",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# GLOBAL STYLES — Clean White / Light Theme + Responsive
# =============================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
}
[data-testid="stAppViewContainer"], .stApp, .main, body {
    background: #f0f4f8 !important;
    color: #1e293b !important;
}
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 2rem !important;
    max-width: 100% !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #ffffff !important;
    border-right: 1px solid #e2e8f0 !important;
    box-shadow: 2px 0 12px rgba(0,0,0,0.05) !important;
}

/* Hero Header */
.brand-container {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    padding: 1.4rem 2rem;
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 20px;
    margin-bottom: 1.5rem;
    box-shadow: 0 4px 24px rgba(0,0,0,0.07);
    position: relative;
    overflow: hidden;
}
.brand-container::before {
    content: "";
    position: absolute;
    top: 0; right: 0;
    width: 300px; height: 100%;
    background: linear-gradient(135deg, transparent 40%, rgba(99,102,241,0.05) 100%);
    pointer-events: none;
}
.brand-title {
    font-size: clamp(1.4rem, 3vw, 2rem);
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(90deg, #6366f1 0%, #8b5cf6 60%, #06b6d4 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    line-height: 1.15;
}
.brand-sub {
    font-size: 0.82rem;
    color: #94a3b8;
    font-weight: 500;
    margin-top: 4px;
}
.brand-badges {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
}

/* Badges */
.badge-pill {
    display: inline-block;
    padding: 0.28rem 0.8rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    white-space: nowrap;
}
.badge-indigo  { background:#eef2ff; color:#6366f1; border:1px solid #c7d2fe; }
.badge-violet  { background:#f5f3ff; color:#8b5cf6; border:1px solid #ddd6fe; }
.badge-cyan    { background:#ecfeff; color:#0891b2; border:1px solid #a5f3fc; }
.badge-emerald { background:#ecfdf5; color:#059669; border:1px solid #a7f3d0; }
.badge-amber   { background:#fffbeb; color:#d97706; border:1px solid #fde68a; }
.badge-rose    { background:#fff1f2; color:#e11d48; border:1px solid #fecdd3; }
.badge-purple  { background:#faf5ff; color:#7c3aed; border:1px solid #ddd6fe; }
.badge-online {
    background:#ecfdf5; color:#059669; border:1px solid #6ee7b7;
    animation: pulse-g 2.2s ease-in-out infinite;
}
@keyframes pulse-g {
    0%,100% { box-shadow: 0 0 0 0 rgba(5,150,105,0.25); }
    50%      { box-shadow: 0 0 0 6px rgba(5,150,105,0); }
}

/* Cards */
.glass-card {
    background: #ffffff !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 16px;
    padding: 1.4rem 1.6rem;
    margin-bottom: 1.2rem;
    color: #1e293b !important;
    box-shadow: 0 2px 12px rgba(0,0,0,0.06);
    transition: border-color .22s, box-shadow .22s, transform .18s;
}
.glass-card:hover {
    border-color: #c7d2fe !important;
    box-shadow: 0 6px 28px rgba(99,102,241,0.12) !important;
    transform: translateY(-2px);
}

/* Terminal */
.terminal-box {
    position: relative;
    font-family: 'JetBrains Mono', monospace;
    background: #f8fafc !important;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 2.6rem 1.4rem 1.3rem;
    color: #0f766e;
    font-size: 0.8rem;
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre-wrap;
    max-height: 400px;
    overflow-y: auto;
    box-shadow: inset 0 2px 6px rgba(0,0,0,0.04);
}
.terminal-box::before {
    content: "●  ●  ●    Cisco IOS CLI Telemetry";
    position: absolute;
    top:0; left:0; right:0;
    height: 2.2rem;
    background: #f1f5f9;
    color: #94a3b8;
    font-size: 0.7rem;
    font-family: 'Outfit', sans-serif;
    font-weight: 600;
    padding-left: 1rem;
    display: flex;
    align-items: center;
    border-bottom: 1px solid #e2e8f0;
    border-radius: 13px 13px 0 0;
    letter-spacing: 0.4px;
}

/* Metric cards */
.metric-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 1.4rem 1rem;
    text-align: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    transition: transform .2s, box-shadow .2s;
}
.metric-box:hover { transform: translateY(-3px); box-shadow: 0 8px 24px rgba(99,102,241,0.12); }
.metric-value { font-size: 2.2rem; font-weight:800; color:#6366f1; margin:0; line-height:1; }
.metric-label { font-size:0.72rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.6px; margin-top:7px; font-weight:600; }

/* Confidence bar */
.conf-bar-wrap { background:#f1f5f9; border-radius:999px; height:8px; margin-top:6px; overflow:hidden; }
.conf-bar-fill  { height:100%; border-radius:999px; transition: width .7s cubic-bezier(.22,1,.36,1); }

/* Sidebar status dot */
.status-dot {
    display:inline-block; width:8px; height:8px; border-radius:50%;
    background:#10b981; margin-right:6px; animation:blink 2s infinite; flex-shrink:0;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.35} }

/* Tab bar */
div[data-testid="stTabBar"] {
    background:#ffffff !important;
    border:1px solid #e2e8f0 !important;
    border-radius:14px !important;
    padding:0.4rem 0.6rem !important;
    margin-bottom:1.5rem !important;
    box-shadow:0 2px 10px rgba(0,0,0,0.05) !important;
}
div[data-testid="stTabBar"] button {
    color:#94a3b8 !important; font-weight:600 !important;
    font-size:clamp(0.72rem,1.5vw,0.88rem) !important;
    border-radius:10px !important; padding:0.4rem 0.8rem !important;
    transition:all .2s !important;
}
div[data-testid="stTabBar"] button:hover { color:#6366f1 !important; background:#eef2ff !important; }
div[data-testid="stTabBar"] button[aria-selected="true"] {
    color:#6366f1 !important; background:#eef2ff !important;
    border-bottom:2px solid #6366f1 !important; font-weight:700 !important;
}

/* Inputs */
div[data-baseweb="textarea"], div[data-baseweb="input"], div[data-baseweb="select"] {
    background-color:#ffffff !important; border:1px solid #cbd5e1 !important;
    border-radius:10px !important; transition:border-color .2s, box-shadow .2s !important;
}
div[data-baseweb="textarea"]:focus-within,
div[data-baseweb="input"]:focus-within,
div[data-baseweb="select"]:focus-within {
    border-color:#6366f1 !important;
    box-shadow:0 0 0 3px rgba(99,102,241,0.12) !important;
}
textarea, input { color:#1e293b !important; }

/* Buttons */
div.stButton > button:first-child {
    border-radius:10px; font-weight:600; transition:all .2s;
    border:1px solid #e2e8f0; background:#ffffff; color:#475569;
}
div.stButton > button:first-child:hover {
    border-color:#6366f1; color:#6366f1; background:#eef2ff;
    box-shadow:0 4px 14px rgba(99,102,241,0.2); transform:translateY(-1px);
}
button[kind="primary"] {
    background:linear-gradient(135deg,#6366f1,#8b5cf6) !important;
    border:none !important; color:#fff !important;
    box-shadow:0 4px 14px rgba(99,102,241,0.35) !important; font-weight:700 !important;
}
button[kind="primary"]:hover {
    box-shadow:0 6px 22px rgba(99,102,241,0.5) !important; transform:translateY(-2px) !important;
}

/* DataFrames */
div[data-testid="stDataFrame"], div[data-testid="stDataFrame"] > div {
    background-color:#ffffff !important; border:1px solid #e2e8f0 !important; border-radius:14px !important;
}

/* Expanders */
div[data-testid="stExpander"] {
    background-color:#ffffff !important; border:1px solid #e2e8f0 !important; border-radius:12px !important;
}

/* Dropdown */
div[role="listbox"] {
    background-color:#ffffff !important; color:#1e293b !important;
    border:1px solid #e2e8f0 !important; box-shadow:0 8px 24px rgba(0,0,0,0.1) !important;
}

h1, h2, h3, h4 { color:#1e293b !important; font-family:'Outfit',sans-serif !important; font-weight:700 !important; }

/* Download buttons */
div[data-testid="stDownloadButton"] > button {
    border:1px solid #e2e8f0; background:#ffffff; color:#6366f1;
    font-weight:600; border-radius:10px; transition:all .2s;
}
div[data-testid="stDownloadButton"] > button:hover {
    border-color:#6366f1; background:#eef2ff;
    box-shadow:0 4px 14px rgba(99,102,241,0.18); transform:translateY(-1px);
}

.section-divider {
    height:1px; background:linear-gradient(90deg,transparent,#e2e8f0,transparent);
    margin:1.5rem 0; border:none;
}

.app-footer {
    margin-top:3rem; padding:1.2rem 2rem;
    border-top:1px solid #e2e8f0; background:#ffffff; border-radius:16px;
    display:flex; justify-content:space-between; align-items:center;
    flex-wrap:wrap; gap:8px; font-size:0.75rem; color:#94a3b8;
}

::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background:#f1f5f9; }
::-webkit-scrollbar-thumb { background:#cbd5e1; border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:#6366f1; }

@media (max-width: 768px) {
    .brand-container { padding:1rem 1.2rem; }
    .brand-title { font-size:1.3rem; }
    .glass-card { padding:1rem 1.1rem; border-radius:12px; }
    .metric-value { font-size:1.7rem; }
    .app-footer { flex-direction:column; text-align:center; }
}
</style>
""", unsafe_allow_html=True)

from src.engine import DiagnosticEngine

@st.cache_resource
def get_engine():
    return DiagnosticEngine()

@st.cache_data
def load_cases():
    base_dir = Path(__file__).resolve().parent.parent
    csv_path = base_dir / "data" / "cases.csv"
    if csv_path.exists():
        return pd.read_csv(csv_path)
    return pd.DataFrame()

engine   = get_engine()
df_cases = load_cases()

# =============================================================================
# SIDEBAR
# =============================================================================
with st.sidebar:
    st.markdown("""
    <div style="padding: 0.6rem 0 0.4rem;">
        <div style="font-size:1.2rem; font-weight:800; color:#1e293b; letter-spacing:-0.3px; line-height:1.2;">
            <span style="color:#6366f1;">NetSage</span> AI
        </div>
        <div style="font-size:0.66rem; color:#64748b; font-weight:600; text-transform:uppercase; letter-spacing:0.6px; margin-top:3px;">
            Cisco Diagnostic Platform
        </div>
    </div>
    <hr style="border:none; border-top:1px solid #e2e8f0; margin:0.6rem 0;">
    """, unsafe_allow_html=True)

    stats_sb   = engine.get_audit_statistics()
    n_cases    = len(df_cases) if not df_cases.empty else 0
    n_concepts = df_cases["concept_tag"].nunique() if not df_cases.empty else 0

    # System status
    st.markdown("""<div style="font-size:0.68rem;color:#94a3b8;font-weight:700;text-transform:uppercase;
        letter-spacing:0.8px;margin-bottom:0.7rem;margin-top:0.4rem;">System Status</div>""",
        unsafe_allow_html=True)
    for label, status in [("Diagnostic Engine","ONLINE"),("HITL Gate","ARMED"),("Audit Logger","ACTIVE")]:
        st.markdown(f"""
        <div style="display:flex;align-items:center;margin-bottom:6px;font-size:0.82rem;color:#475569;
            background:#f8fafc;padding:6px 10px;border-radius:8px;border:1px solid #f1f5f9;">
            <span class="status-dot"></span>
            <span style="flex:1;">{label}</span>
            <span style="color:#059669;font-weight:700;font-size:0.75rem;">{status}</span>
        </div>""", unsafe_allow_html=True)

    st.markdown("<hr style='border:none;border-top:1px solid #e2e8f0;margin:0.8rem 0;'>",
        unsafe_allow_html=True)

    # Dataset KPIs
    st.markdown("""<div style="font-size:0.68rem;color:#94a3b8;font-weight:700;text-transform:uppercase;
        letter-spacing:0.8px;margin-bottom:0.7rem;">Dataset Overview</div>""",
        unsafe_allow_html=True)
    for lbl, val, col in [
        ("Scenarios Loaded",   n_cases,                          "#6366f1"),
        ("Concept Tags",       n_concepts,                       "#8b5cf6"),
        ("Operator Decisions", stats_sb['total_records'],        "#d97706"),
        ("Agreement Rate",     f"{stats_sb['agreement_rate']}%", "#059669"),
    ]:
        st.markdown(f"""
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;
            font-size:0.82rem;color:#475569;background:#f8fafc;padding:6px 10px;
            border-radius:8px;border:1px solid #f1f5f9;">
            <span>{lbl}</span><span style="font-weight:700;color:{col};">{val}</span>
        </div>""", unsafe_allow_html=True)

    st.markdown("<hr style='border:none;border-top:1px solid #e2e8f0;margin:0.8rem 0;'>",
        unsafe_allow_html=True)

    # Severity legend
    st.markdown("""<div style="font-size:0.68rem;color:#94a3b8;font-weight:700;text-transform:uppercase;
        letter-spacing:0.8px;margin-bottom:0.7rem;">Severity Legend</div>""",
        unsafe_allow_html=True)
    for color, label in [("#e11d48","Critical / High"),("#d97706","Medium"),("#059669","Low")]:
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;
            font-size:0.82rem;color:#475569;">
            <span style="width:10px;height:10px;border-radius:50%;background:{color};
                display:inline-block;flex-shrink:0;"></span>{label}
        </div>""", unsafe_allow_html=True)

    st.markdown("""
    <hr style="border:none;border-top:1px solid #e2e8f0;margin:0.8rem 0;">
    <div style="font-size:0.68rem;color:#cbd5e1;text-align:center;padding-top:0.3rem;line-height:1.6;">
        Cisco AICTE VIP Program 2026<br>
        <span style="color:#6366f1;font-weight:600;">v1.0.0</span>
    </div>""", unsafe_allow_html=True)

# =============================================================================
# HERO HEADER
# =============================================================================
st.markdown("""
<div class="brand-container">
    <div>
        <div class="brand-title">NetSage AI</div>
        <div class="brand-sub">Automated Network Diagnostic Engine &nbsp;·&nbsp; Human-in-the-Loop (HITL) Control Gate</div>
    </div>
    <div class="brand-badges">
        <span class="badge-pill badge-online">● SYSTEM ONLINE</span>
        <span class="badge-pill badge-indigo">Cisco IOS / Packet Tracer</span>
        <span class="badge-pill badge-violet">v1.0.0</span>
        <span class="badge-pill badge-amber">HITL ARMED</span>
    </div>
</div>
""", unsafe_allow_html=True)

# =============================================================================
# TABS
# =============================================================================
tab_diag, tab_custom, tab_audit, tab_catalog, tab_arch = st.tabs([
    "🚨 Active Diagnostics",
    "🔬 Custom Lab",
    "📊 Audit & Analytics",
    "📚 Cases Catalog",
    "🏛️ Architecture"
])

# ── Helpers ──────────────────────────────────────────────────────────────────

def conf_bar(pct: int) -> str:
    color = "#059669" if pct >= 90 else ("#d97706" if pct >= 70 else "#e11d48")
    return (
        f'<div style="margin-bottom:14px;">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:5px;">'
        f'<span style="font-size:0.7rem;color:#94a3b8;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Confidence Score</span>'
        f'<span style="font-size:0.88rem;font-weight:800;color:{color};">{pct}%</span>'
        f'</div>'
        f'<div style="background:#f1f5f9;border-radius:999px;height:8px;overflow:hidden;">'
        f'<div style="height:100%;width:{pct}%;background:{color};border-radius:999px;"></div>'
        f'</div></div>'
    )


def diag_card(res: dict, sev_color: str = "#6366f1") -> str:
    pct = int(res['confidence'] * 100)
    src_badge = (
        '<span style="display:inline-block;padding:0.28rem 0.8rem;border-radius:9999px;font-size:0.72rem;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;background:#ecfdf5;color:#059669;border:1px solid #a7f3d0;">⚙️ DETERMINISTIC RULE</span>'
        if res["source"] == "deterministic_rule" else
        '<span style="display:inline-block;padding:0.28rem 0.8rem;border-radius:9999px;font-size:0.72rem;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;background:#f5f3ff;color:#8b5cf6;border:1px solid #ddd6fe;">🔍 SEMANTIC INFERENCE</span>'
    )
    osi_badge = f'<span style="display:inline-block;padding:0.28rem 0.8rem;border-radius:9999px;font-size:0.72rem;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;background:#eef2ff;color:#6366f1;border:1px solid #c7d2fe;">{h(res["osi_layer"])}</span>'
    ev_html = "".join([
        f'<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:6px;font-family:JetBrains Mono,monospace;font-size:0.78rem;color:#be123c;background:#fff1f2;padding:7px 10px;border-radius:8px;border:1px solid #fecdd3;line-height:1.5;">'
        f'<span style="color:#e11d48;font-weight:bold;flex-shrink:0;">[!]</span>'
        f'<span>{h(ev)}</span></div>'
        for ev in res['evidence']
    ]) or '<div style="color:#94a3b8;font-size:0.82rem;font-style:italic;padding:4px 0;">No anomaly signatures detected.</div>'

    fix_cmds_str = "\n".join(res.get("fix_steps", [])) if res.get("fix_steps") else "No action required"

    return (
        f'<div style="background:#ffffff;border:1px solid #e2e8f0;border-left:4px solid {sev_color};border-radius:16px;padding:1.4rem 1.6rem;margin-bottom:1.2rem;box-shadow:0 2px 12px rgba(0,0,0,0.06);">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:6px;">'
        f'<div>{src_badge}</div>{osi_badge}</div>'
        f'{conf_bar(pct)}'
        f'<div style="font-size:0.7rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">&#128204; ROOT CAUSE</div>'
        f'<div style="color:#1e293b;font-size:0.9rem;background:#f8fafc;padding:12px 14px;border-radius:10px;border-left:3px solid {sev_color};margin-bottom:14px;line-height:1.6;">{h(res["root_cause"])}</div>'
        f'<div style="font-size:0.7rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">&#128270; EVIDENCE TRACE</div>'
        f'<div style="margin-bottom:14px;">{ev_html}</div>'
        f'<div style="font-size:0.7rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">&#128161; RECOMMENDED ACTION</div>'
        f'<div style="background:#f8fafc;border:1px solid #e2e8f0;padding:12px 14px;border-radius:10px;margin-bottom:14px;font-family:JetBrains Mono,monospace;font-size:0.85rem;color:#4338ca;white-space:pre-wrap;">{h(fix_cmds_str)}</div>'
        f'<div style="font-size:0.7rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">&#128269; NEXT DIAGNOSTIC COMMAND</div>'
        f'<div style="background:#f8fafc;border:1px solid #e2e8f0;padding:10px 14px;border-radius:10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">'
        f'<div><code style="color:#6366f1;font-family:JetBrains Mono,monospace;font-size:0.88rem;font-weight:800;">{h(res["next_command"])}</code></div>'
        f'<span style="font-size:1.2rem;opacity:0.4;">&#128269;</span></div>'
        f'</div>'
    )


def hitl_buttons(case_id: str, res: dict, commands: str, pfx: str):
    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button("🟢 Approve & Deploy", key=f"{pfx}_appr"):
            engine.log_operator_action(case_id=case_id, action="APPROVED",
                source_engine=res["source"], osi_layer=res["osi_layer"],
                confidence=res["confidence"], root_cause=res["root_cause"],
                deployed_commands=commands.splitlines(), notes="Approved as proposed")
            st.success(f"✅ **{case_id}** approved and logged.")
            st.balloons()
    with b2:
        if st.button("🟡 Deploy with Override", key=f"{pfx}_edit"):
            engine.log_operator_action(case_id=case_id, action="EDITED",
                source_engine=res["source"], osi_layer=res["osi_layer"],
                confidence=res["confidence"], root_cause=res["root_cause"],
                deployed_commands=commands.splitlines(), notes="Operator modified CLI")
            st.warning(f"⚠️ Override for **{case_id}** logged.")
    with b3:
        if st.button("🔴 Reject / False Positive", key=f"{pfx}_rej"):
            engine.log_operator_action(case_id=case_id, action="REJECTED",
                source_engine=res["source"], osi_layer=res["osi_layer"],
                confidence=res["confidence"], root_cause=res["root_cause"],
                deployed_commands=[], notes="Rejected — false positive")
            st.error(f"❌ **{case_id}** flagged as false positive.")



# =============================================================================
# TAB 1 — ACTIVE CASE DIAGNOSTICS
# =============================================================================
with tab_diag:
    if df_cases.empty:
        st.error("❌ No test cases found in `data/cases.csv`")
    else:
        col_f1, col_f2, col_f3 = st.columns([2, 1, 1])
        with col_f2:
            concepts = ["All Concepts"] + sorted(df_cases["concept_tag"].dropna().unique().tolist())
            sel_concept = st.selectbox("🏷️ Filter Concept", concepts, key="f_concept")
        with col_f3:
            severities = ["All Severities"] + sorted(df_cases["severity"].dropna().unique().tolist())
            sel_sev = st.selectbox("⚠️ Filter Severity", severities, key="f_sev")

        fdf = df_cases.copy()
        if sel_concept != "All Concepts":
            fdf = fdf[fdf["concept_tag"] == sel_concept]
        if sel_sev != "All Severities":
            fdf = fdf[fdf["severity"] == sel_sev]

        with col_f1:
            opts = [f"{r['case_id']} — {r['symptom'][:55]}…" for _, r in fdf.iterrows()]
            if opts:
                sel = st.selectbox("📋 Select Scenario", opts, index=0, key="sel_case")
                cid = sel.split(" — ")[0]
                row = fdf[fdf["case_id"] == cid].iloc[0]
            else:
                st.warning("No cases match filters.")
                row = None

        if row is not None:
            sev = row.get("severity", "Medium")
            sev_border = {"Critical":"#e11d48","High":"#f97316","Medium":"#d97706","Low":"#059669"}.get(sev,"#6366f1")
            sev_cls    = {"Critical":"badge-rose","High":"badge-amber","Medium":"badge-amber","Low":"badge-emerald"}.get(sev,"badge-indigo")

            st.markdown(f"""
            <div class="glass-card" style="border-left:4px solid {sev_border};">
                <div style="display:flex;justify-content:space-between;align-items:center;
                    flex-wrap:wrap;gap:8px;margin-bottom:10px;">
                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <span style="font-size:1rem;font-weight:800;color:#6366f1;
                            font-family:'JetBrains Mono',monospace;">{row['case_id']}</span>
                        <span class="badge-pill {sev_cls}">{sev}</span>
                        <span class="badge-pill badge-violet">{row.get('concept_tag','Network')}</span>
                    </div>
                    <span style="font-size:0.72rem;color:#94a3b8;font-weight:600;
                        text-transform:uppercase;letter-spacing:0.4px;">Packet Tracer Lab</span>
                </div>
                <div style="font-size:0.95rem;font-weight:600;color:#1e293b;margin-bottom:6px;">
                    🎯 {h(row['symptom'])}</div>
                <div style="font-size:0.84rem;color:#64748b;">
                    🌐 <b>Topology:</b> {h(str(row.get('topology_note','N/A')))}</div>
            </div>""", unsafe_allow_html=True)

            c_cli, c_diag = st.columns([1, 1], gap="medium")
            with c_cli:
                st.markdown("#### 🖥️ Cisco CLI Telemetry", unsafe_allow_html=True)
                st.markdown(f'<div class="terminal-box">{h(row["show_outputs"])}</div>',
                            unsafe_allow_html=True)
                with st.expander("🔎 Ground Truth Reference", expanded=False):
                    st.info(row.get("expected_fault", "N/A"))

            with c_diag:
                st.markdown("#### 🔍 Diagnostic Report", unsafe_allow_html=True)
                dr = engine.diagnose(
                    case_id=row["case_id"], symptom=row["symptom"],
                    topology_note=row.get("topology_note",""),
                    show_outputs=row["show_outputs"],
                    concept_tag=row.get("concept_tag",""),
                    severity=sev
                )
                st.markdown(diag_card(dr, sev_border), unsafe_allow_html=True)

                st.markdown("#### 🛡️ HITL Remediation Gate", unsafe_allow_html=True)
                st.caption("Review and optionally edit CLI commands before deploying.")
                cmds = st.text_area("Proposed IOS Remediation Commands",
                    value="\n".join(dr["fix_steps"]), height=120,
                    key=f"cli_{row['case_id']}")
                hitl_buttons(row["case_id"], dr, cmds, "t1")

# =============================================================================
# TAB 2 — CUSTOM DIAGNOSTIC LAB
# =============================================================================
with tab_custom:
    st.markdown("#### 🔬 Real-Time Cisco IOS Diagnostic Sandbox", unsafe_allow_html=True)
    st.caption("Paste raw `show` command outputs from Packet Tracer or a live IOS device.")

    cc1, cc2 = st.columns([1, 1], gap="medium")
    with cc1:
        sym  = st.text_input("🚨 Symptom / Issue",
            value="Users cannot access the internet. Gateway ping shows packet loss.", key="c_symp")
        topo = st.text_input("🌐 Topology Notes",
            value="Access Switch → Core Router → ISP. Multiple VLANs.", key="c_topo")
        conc = st.selectbox("📌 Concept Tag",
            ["","DHCP","OSPF","EIGRP","VLAN/Trunking","Inter-VLAN Routing",
             "ACL","NAT/PAT","STP","Port Security","Static Routing",
             "BGP","SSH/Management","Physical/Data Link","NTP/System"], key="c_concept")
        default_cli = """Router# show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0    192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/1    10.0.0.1        YES NVRAM  administratively down down

Router# show ip route
Gateway of last resort is not set
C    192.168.1.0/24 is directly connected, GigabitEthernet0/0

Router# show ip dhcp binding
(No bindings found — pool may be exhausted or misconfigured)"""
        cli  = st.text_area("🖥️ Paste CLI Show Outputs", value=default_cli, height=250, key="c_cli")
        run  = st.button("🔍 Run Diagnostic Analysis", type="primary", key="run_custom")

    with cc2:
        if run or "c_res" in st.session_state:
            if run:
                res = engine.diagnose(case_id="CUSTOM", symptom=sym, topology_note=topo,
                                      show_outputs=cli, concept_tag=conc)
                st.session_state["c_res"] = res
            else:
                res = st.session_state["c_res"]

            sc = "#6366f1"
            if "Layer 1" in res['osi_layer'] or "Physical" in res['osi_layer']: sc = "#e11d48"
            elif "Layer 2" in res['osi_layer'] or "Data Link" in res['osi_layer']: sc = "#d97706"
            elif "Layer 3" in res['osi_layer'] or "Network" in res['osi_layer']: sc = "#8b5cf6"

            st.markdown("#### 🔍 Diagnostic Report", unsafe_allow_html=True)
            st.markdown(diag_card(res, sc), unsafe_allow_html=True)
            st.markdown("#### 🛡️ HITL Remediation Gate", unsafe_allow_html=True)
            ec = st.text_area("Proposed IOS Remediation Commands",
                value="\n".join(res["fix_steps"]), height=150, key="c_cmds")
            hitl_buttons("CUSTOM", res, ec, "t2")
        else:
            st.markdown("""
            <div class="glass-card" style="text-align:center;padding:3rem 2rem;">
                <div style="font-size:2.6rem;margin-bottom:0.8rem;color:#94a3b8;">🖥️</div>
                <div style="font-size:1rem;font-weight:700;color:#1e293b;margin-bottom:0.6rem;">Diagnostic Sandbox Ready</div>
                <div style="font-size:0.84rem;color:#64748b;line-height:1.8;">
                    Paste CLI <code style="color:#6366f1;background:#eef2ff;padding:1px 6px;border-radius:4px;">show</code>
                    outputs on the left and click <b>Run Diagnostic Analysis</b>.
                </div>
            </div>""", unsafe_allow_html=True)

# =============================================================================
# TAB 3 — AUDIT & ANALYTICS
# =============================================================================
with tab_audit:
    st.markdown("#### 📊 Model Audit & Agreement Analytics", unsafe_allow_html=True)
    stats = engine.get_audit_statistics()

    m1, m2, m3, m4, m5 = st.columns(5)
    for col, val, lbl, color in [
        (m1, stats['total_records'],          "Total Decisions",     "#6366f1"),
        (m2, stats['approvals'],              "Approved & Deployed", "#059669"),
        (m3, stats['edits'],                  "CLI Overrides",       "#d97706"),
        (m4, stats['rejections'],             "False Positives",     "#e11d48"),
        (m5, f"{stats['agreement_rate']}%",   "Agreement Rate",      "#8b5cf6"),
    ]:
        with col:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value" style="color:{color};">{val}</div>
                <div class="metric-label">{lbl}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    ar = stats['agreement_rate']
    st.markdown(f"""
    <div class="glass-card" style="padding:1.2rem 1.6rem;">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:0.8rem;">
            <span style="color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:0.4px;">
                Agreement Rate vs Benchmark (76.6%)</span>
            <span style="color:#8b5cf6;font-weight:800;">{ar}%</span>
        </div>
        <div style="background:#f1f5f9;border-radius:999px;height:10px;position:relative;margin-bottom:6px;">
            <div style="height:100%;width:{min(ar,100)}%;background:linear-gradient(90deg,#6366f1,#8b5cf6);
                border-radius:999px;box-shadow:0 0 8px rgba(99,102,241,0.35);"></div>
            <div style="position:absolute;top:-5px;left:76.6%;width:2px;height:20px;
                background:#d97706;border-radius:1px;"></div>
        </div>
        <div style="font-size:0.72rem;color:#94a3b8;">
            ▲ Benchmark 76.6% &nbsp;|&nbsp; Delta:
            <span style="color:#059669;font-weight:700;">+{max(ar-76.6,0):.1f}%</span>
        </div>
    </div>""", unsafe_allow_html=True)

    ch_col, ex_col = st.columns([2, 1])
    with ch_col:
        st.markdown("#### Decision Distribution", unsafe_allow_html=True)
        if stats['total_records'] > 0:
            cdf = pd.DataFrame([
                {"Decision":"Approved",    "Count":stats['approvals'],  "color":"#059669"},
                {"Decision":"CLI Override","Count":stats['edits'],      "color":"#d97706"},
                {"Decision":"Rejected",    "Count":stats['rejections'], "color":"#e11d48"},
            ])
            chart = (alt.Chart(cdf)
                .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
                .encode(
                    x=alt.X("Decision:N", axis=alt.Axis(labelColor="#94a3b8",
                        titleColor="#94a3b8", labelFontSize=12, title=None)),
                    y=alt.Y("Count:Q", axis=alt.Axis(labelColor="#94a3b8",
                        grid=True, gridColor="#f1f5f9", title="Count")),
                    color=alt.Color("color:N", scale=None, legend=None),
                    tooltip=["Decision","Count"]
                ).properties(height=220, background="transparent")
                .configure_view(strokeWidth=0)
                .configure_axis(domainColor="#e2e8f0", tickColor="#e2e8f0"))
            st.altair_chart(chart, width='stretch')
        else:
            st.markdown("""<div class="glass-card" style="text-align:center;color:#94a3b8;padding:2rem;">
                No decisions yet. Use Active Diagnostics tab to log actions.</div>""",
                unsafe_allow_html=True)

    with ex_col:
        st.markdown("#### Export", unsafe_allow_html=True)
        if stats['records']:
            adf = pd.DataFrame(stats['records'])
            st.download_button("📥 Download Audit Log (CSV)",
                data=adf.to_csv(index=False),
                file_name="netsage_audit_log.csv", mime="text/csv")
        else:
            st.button("📥 Download Audit Log", disabled=True)

    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("#### 📜 Live Audit Log", unsafe_allow_html=True)
    if stats['records']:
        st.dataframe(pd.DataFrame(stats['records']), width='stretch')
    else:
        st.markdown("""<div class="glass-card" style="text-align:center;color:#94a3b8;">
            No entries yet. HITL actions appear here in real-time.</div>""",
            unsafe_allow_html=True)

# =============================================================================
# TAB 4 — CASES CATALOG
# =============================================================================
with tab_catalog:
    st.markdown("#### 📚 Cisco Packet Tracer Scenarios Catalog", unsafe_allow_html=True)
    st.caption("Multi-layer network failure scenarios spanning OSI Layers 1–7.")

    if not df_cases.empty:
        s_col, n_col = st.columns([3, 1])
        with s_col:
            kw = st.text_input("🔍 Search by keyword, concept, or case ID", "")
        with n_col:
            st.markdown(f"""<div class="metric-box" style="padding:0.8rem;margin-top:2px;">
                <div class="metric-value" style="font-size:1.7rem;">{len(df_cases)}</div>
                <div class="metric-label">Total Scenarios</div>
            </div>""", unsafe_allow_html=True)

        cdf = df_cases.copy()
        if kw:
            cdf = cdf[
                cdf["case_id"].str.contains(kw,case=False,na=False) |
                cdf["symptom"].str.contains(kw,case=False,na=False) |
                cdf["concept_tag"].str.contains(kw,case=False,na=False) |
                cdf["expected_fault"].str.contains(kw,case=False,na=False)
            ]
            st.caption(f"Showing **{len(cdf)}** result(s) for _{kw}_")

        st.dataframe(
            cdf[["case_id","concept_tag","severity","symptom","expected_fault","topology_note"]],
            width='stretch',
            column_config={
                "case_id":        st.column_config.TextColumn("Case ID",       width="small"),
                "concept_tag":    st.column_config.TextColumn("Concept Tag",   width="medium"),
                "severity":       st.column_config.TextColumn("Severity",      width="small"),
                "symptom":        st.column_config.TextColumn("Symptom",       width="large"),
                "expected_fault": st.column_config.TextColumn("Exp. Fault",    width="large"),
                "topology_note":  st.column_config.TextColumn("Topology",      width="medium"),
            })

# =============================================================================
# TAB 5 — ARCHITECTURE
# =============================================================================
with tab_arch:
    st.markdown("#### 🏛️ NetSage AI — 4-Tier System Architecture", unsafe_allow_html=True)

    a1, a2 = st.columns(2, gap="medium")
    tiers = [
        ("#6366f1","Tier 1","Data Layer",[
            ("cases.csv","30 Cisco PT scenarios across OSI Layers 1–7"),
            ("system_config.json","Diagnostic thresholds & confidence parameters")]),
        ("#8b5cf6","Tier 2","Diagnostic Core Engine",[
            ("checker.py","High-precision deterministic regex & rule verification"),
            ("engine.py","Hybrid: deterministic rules + semantic prompt inference"),
            ("diagnose_prompt.md","OSI layer mapping & strict JSON schema")]),
        ("#d97706","Tier 3","HITL Gate",[
            ("app.py","Streamlit interactive NOC dashboard"),
            ("Approve & Deploy","One-click remediation confirmation"),
            ("Edit CLI","Editable IOS command override"),
            ("Reject / Flag","False positive reporting & feedback loop")]),
        ("#059669","Tier 4","Audit & Compliance",[
            ("model_audit_log.md","Agreement metrics tracking (76.6% benchmark)"),
            ("audit_log.csv","Persistent audit trail: timestamps, confidence, notes")]),
    ]
    for i,(color,tier,title,items) in enumerate(tiers):
        col = a1 if i%2==0 else a2
        rows = "".join([
            f"<div style='display:flex;gap:8px;margin-bottom:7px;font-size:0.84rem;color:#475569;'>"
            f"<span style='color:{color};font-weight:700;flex-shrink:0;'>▸</span>"
            f"<span><b style='color:#1e293b;'>{k}</b> — {v}</span></div>"
            for k,v in items])
        with col:
            st.markdown(f"""
            <div class="glass-card" style="border-left:4px solid {color};">
                <div style="font-size:0.68rem;color:{color};font-weight:700;text-transform:uppercase;
                    letter-spacing:0.8px;margin-bottom:4px;">{tier}</div>
                <h4 style="color:#1e293b;margin:0 0 12px;font-size:0.98rem;">{title}</h4>
                {rows}
            </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("#### 🔄 Diagnostic Flow")
    steps = [("#6366f1","📡 CLI Telemetry"),("#8b5cf6","🔍 Deterministic Rules"),
             ("#7c3aed","🧠 Semantic Inference"),("#d97706","🛡️ HITL Gate"),("#059669","📋 Audit Log")]
    html = " ".join([
        f"<div style='background:{c}15;border:1px solid {c}44;border-radius:10px;"
        f"padding:8px 14px;color:{c};font-weight:700;font-size:0.8rem;"
        f"font-family:\"JetBrains Mono\",monospace;white-space:nowrap;'>{lbl}</div>"
        + (f"<div style='color:#cbd5e1;font-size:1.1rem;'>→</div>" if i<len(steps)-1 else "")
        for i,(c,lbl) in enumerate(steps)])
    st.markdown(f"""
    <div class="glass-card" style="padding:1.4rem 1.8rem;">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:center;">
            {html}
        </div>
    </div>""", unsafe_allow_html=True)

# =============================================================================
# FOOTER
# =============================================================================
st.markdown("""
<div class="app-footer">
    <div>
        <span style="color:#6366f1;font-weight:700;">⚡ NetSage AI</span>
        &nbsp;·&nbsp; Cisco AICTE VIP Program 2026
        &nbsp;·&nbsp; Automated Network Diagnostic Platform v1.0.0
    </div>
    <div>
        Amit Kumar Mishra &amp; Aditya Tiwari &nbsp;·&nbsp; Networking Track
        &nbsp;·&nbsp; Guides: Dr. Praveen Sharma &amp; Mr. Madhav Sahu
    </div>
</div>
""", unsafe_allow_html=True)
