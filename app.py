import socket
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from reports.generator import export_findings_csv
from reports.pdf_report import generate_pdf_report
from scanners.nmap_scan import run_nmap_scan
from analysis.parser import analyze_nmap_file
from analysis.triage import triage_all
from scanners.shodan_scan import lookup_host, enrich_findings_with_shodan, create_shodan_findings
from scanners.openvas_parse import parse_openvas_xml, merge_openvas_with_nmap
from scanners.vulners_parse import parse_vulners_from_nmap_xml, merge_vulners_with_nmap
from scanners.zap_scan import parse_zap_xml, merge_zap_with_nmap
from analysis.parsers.excel_assets import parse_asset_excel, apply_sensitivity_to_findings


st.set_page_config(
    page_title="RedFlag",
    page_icon="🚩",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Global styles ──────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* ══════════════════════════════════════════════════════════════
   REDFLAG  —  Design System v2
   Fonts  : Fira Code (mono/technical) + Fira Sans (body)
   Palette: Deep navy · Severity red / orange / yellow / green
══════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap');

/* ── Base ── */
[data-testid="stAppViewContainer"] { background: #07090f; }
[data-testid="stHeader"]           { background: transparent; }
[data-testid="stMainBlockContainer"] { padding-top: 0 !important; }
html, body, [class*="css"],
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
.stCheckbox label, .stSlider label, .stMultiSelect label,
.stCaption, .stAlert p, button { font-family: 'Fira Sans', -apple-system, sans-serif !important; }

/* ── METRIC CARDS ── */
.rf-metric {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-radius: 10px;
    padding: 16px 18px 20px;
    text-align: center;
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.2s ease;
    cursor: default;
    position: relative;
}
.rf-metric:hover { transform: translateY(-3px); }
.rf-metric .label {
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.13em;
    text-transform: uppercase;
    color: #364060;
    margin-bottom: 10px;
    font-family: 'Fira Code', monospace;
}
.rf-metric .value {
    font-size: 2.7rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'Fira Code', monospace;
}
.rf-metric.red    { border-top: 3px solid #ef4444; }
.rf-metric.red    .value { color: #ef4444; }
.rf-metric.red:hover    { border-color: rgba(239,68,68,0.5); box-shadow: 0 8px 32px rgba(239,68,68,0.2); }
.rf-metric.orange { border-top: 3px solid #f97316; }
.rf-metric.orange .value { color: #f97316; }
.rf-metric.orange:hover { border-color: rgba(249,115,22,0.5); box-shadow: 0 8px 32px rgba(249,115,22,0.2); }
.rf-metric.yellow { border-top: 3px solid #eab308; }
.rf-metric.yellow .value { color: #eab308; }
.rf-metric.yellow:hover { border-color: rgba(234,179,8,0.5); box-shadow: 0 8px 32px rgba(234,179,8,0.18); }
.rf-metric.green  { border-top: 3px solid #22c55e; }
.rf-metric.green  .value { color: #22c55e; }
.rf-metric.green:hover  { border-color: rgba(34,197,94,0.5); box-shadow: 0 8px 32px rgba(34,197,94,0.2); }
.rf-metric.blue   { border-top: 3px solid #3b82f6; }
.rf-metric.blue   .value { color: #c7d8f5; }
.rf-metric.blue:hover   { border-color: rgba(59,130,246,0.5); box-shadow: 0 8px 32px rgba(59,130,246,0.2); }

/* ── SECTION LABEL ── */
.rf-section-label {
    font-family: 'Fira Code', monospace;
    font-size: 0.61rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #364060;
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
    margin-top: 4px;
}
.rf-section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, #17203a 0%, transparent 100%);
}

/* ── BADGES ── */
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    font-family: 'Fira Code', monospace;
}
.badge-dk   { background: rgba(239,68,68,0.14);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
.badge-crit { background: rgba(249,115,22,0.14); color: #fb923c; border: 1px solid rgba(249,115,22,0.35); }
.badge-mod  { background: rgba(234,179,8,0.12);  color: #facc15; border: 1px solid rgba(234,179,8,0.35); }
.badge-man  { background: rgba(34,197,94,0.12);  color: #4ade80; border: 1px solid rgba(34,197,94,0.35); }
.badge-unk  { background: rgba(107,114,128,0.1); color: #6b7280; border: 1px solid rgba(107,114,128,0.25); }
.badge-inet { background: rgba(96,165,250,0.12); color: #60a5fa; border: 1px solid rgba(59,130,246,0.35); }
.badge-part { background: rgba(167,139,250,0.12);color: #a78bfa; border: 1px solid rgba(124,58,237,0.35); }
.badge-int  { background: rgba(74,222,128,0.10); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
.badge-ukn  { background: rgba(107,114,128,0.1); color: #6b7280; border: 1px solid rgba(55,65,81,0.3); }

/* ── FINDING CARDS ── */
.finding-card {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-left: 3px solid #17203a;
    border-radius: 10px;
    padding: 18px 22px 18px 20px;
    margin-bottom: 8px;
    transition: background 0.18s ease, border-color 0.18s ease, box-shadow 0.2s ease;
}
.finding-card:hover { background: #0f1422; box-shadow: 0 4px 36px rgba(0,0,0,0.65); }
.finding-card.dk   { border-left-color: #ef4444; }
.finding-card.crit { border-left-color: #f97316; }
.finding-card.mod  { border-left-color: #eab308; }
.finding-card.man  { border-left-color: #22c55e; }
.finding-card.dk:hover   { border-color: rgba(239,68,68,0.35); box-shadow: 0 4px 36px rgba(239,68,68,0.12); }
.finding-card.crit:hover { border-color: rgba(249,115,22,0.35); box-shadow: 0 4px 36px rgba(249,115,22,0.12); }
.finding-card.mod:hover  { border-color: rgba(234,179,8,0.35); }
.finding-card.man:hover  { border-color: rgba(34,197,94,0.35); }
.finding-card h4 {
    color: #dde4f0;
    font-size: 0.97rem;
    font-weight: 600;
    margin: 0 0 8px 0;
    font-family: 'Fira Sans', sans-serif;
    line-height: 1.4;
}
.finding-card .meta {
    color: #4b6080;
    font-size: 0.79rem;
    margin-bottom: 12px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}
.finding-card .fc-divider { border: none; border-top: 1px solid #17203a; margin: 12px 0; }
.finding-card .field-label {
    color: #364060;
    font-size: 0.61rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.11em;
    margin-bottom: 3px;
    font-family: 'Fira Code', monospace;
}
.finding-card .field-value { color: #7a93b8; font-size: 0.85rem; margin-bottom: 12px; line-height: 1.6; }
.finding-card .score-pill {
    background: #07090f;
    border: 1px solid #17203a;
    border-radius: 8px;
    padding: 12px 14px;
    text-align: center;
    min-width: 72px;
}
.finding-card .score-pill .s-label {
    color: #364060;
    font-size: 0.59rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.11em;
    font-family: 'Fira Code', monospace;
    display: block;
    margin-bottom: 4px;
}
.finding-card .score-pill .s-value {
    font-size: 1.8rem;
    font-weight: 700;
    font-family: 'Fira Code', monospace;
    line-height: 1;
}

/* ── STATUS DOTS ── */
.rf-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    margin-top: 1px;
}
.rf-dot.ok   { background: #22c55e; box-shadow: 0 0 7px rgba(34,197,94,0.8); }
.rf-dot.warn { background: #eab308; box-shadow: 0 0 7px rgba(234,179,8,0.8); }
.rf-dot.err  { background: #ef4444; box-shadow: 0 0 7px rgba(239,68,68,0.8); }
.rf-dot.off  { background: #1c2a45; }

/* ── SCANNER PIPELINE ── */
.rf-pipeline {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 10px;
}
.rf-pipeline-header {
    padding: 9px 16px;
    border-bottom: 1px solid #17203a;
    font-family: 'Fira Code', monospace;
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #364060;
    background: #07090f;
}
.rf-pipeline-grid { display: grid; grid-template-columns: 1fr 1fr; }
.rf-pipeline-item {
    display: flex;
    align-items: flex-start;
    gap: 9px;
    padding: 10px 14px;
    border-bottom: 1px solid #0d1120;
    transition: background 0.15s ease;
}
.rf-pipeline-item:nth-child(odd)  { border-right: 1px solid #0d1120; }
.rf-pipeline-item:hover           { background: #0f1422; }
.rf-pi-name {
    font-family: 'Fira Code', monospace;
    font-size: 0.77rem;
    color: #7a93b8;
    min-width: 78px;
    font-weight: 500;
}
.rf-pi-status { font-size: 0.77rem; color: #364060; font-family: 'Fira Sans', sans-serif; }
.rf-pi-status.ok     { color: #4ade80; }
.rf-pi-status.active { color: #60a5fa; }
.rf-pi-status.warn   { color: #facc15; }

/* ── TARGET PANEL ── */
.rf-target-panel {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-radius: 10px;
    padding: 14px 16px 6px;
    margin-bottom: 10px;
}
.rf-tp-row {
    display: grid;
    grid-template-columns: 80px 1fr;
    align-items: baseline;
    margin-bottom: 8px;
    gap: 8px;
}
.rf-tp-label {
    font-family: 'Fira Code', monospace;
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #364060;
}
.rf-tp-value {
    font-size: 0.84rem;
    color: #dde4f0;
    font-family: 'Fira Code', monospace;
    word-break: break-all;
}

/* ── SHODAN SNAPSHOT ── */
.rf-shodan {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-left: 3px solid #1d4ed8;
    border-radius: 10px;
    padding: 14px 16px 6px;
}
.rf-shodan-row {
    display: grid;
    grid-template-columns: 90px 1fr;
    align-items: baseline;
    margin-bottom: 8px;
    gap: 8px;
}
.rf-shodan-label {
    font-family: 'Fira Code', monospace;
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #364060;
}
.rf-shodan-value { font-size: 0.84rem; color: #7a93b8; font-family: 'Fira Sans', sans-serif; }

/* ── INFO PANEL (legacy compat) ── */
.info-panel {
    background: #0c0f1a;
    border: 1px solid #17203a;
    border-radius: 10px;
    padding: 14px 16px;
}
.info-panel .ip-label {
    color: #364060;
    font-size: 0.61rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 2px;
    font-family: 'Fira Code', monospace;
}
.info-panel .ip-value { color: #dde4f0; font-size: 0.86rem; margin-bottom: 10px; }

/* ── DIVIDERS ── */
.rf-divider { border: none; border-top: 1px solid #17203a; margin: 14px 0; }

/* ── SCAN BAR ── */
[data-testid="stTextInput"] input {
    background: #0c0f1a !important;
    border: 1px solid #17203a !important;
    border-radius: 8px !important;
    color: #dde4f0 !important;
    font-size: 0.9rem !important;
    font-family: 'Fira Code', monospace !important;
    letter-spacing: 0.025em !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #ef4444 !important;
    box-shadow: 0 0 0 2px rgba(239,68,68,0.12), 0 0 24px rgba(239,68,68,0.05) !important;
}
[data-testid="stTextInput"] input::placeholder { color: #1c2a45 !important; }
[data-testid="stTextInput"] label {
    color: #364060 !important;
    font-size: 0.6rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
    font-family: 'Fira Code', monospace !important;
}

/* ── PRIMARY BUTTON ── */
[data-testid="stButton"] > button[kind="primary"],
[data-testid="stBaseButton-primary"] {
    background: linear-gradient(160deg, #ef4444 0%, #b91c1c 100%) !important;
    border: 1px solid rgba(239,68,68,0.35) !important;
    border-radius: 8px !important;
    font-family: 'Fira Sans', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 0.05em !important;
    box-shadow: 0 2px 20px rgba(239,68,68,0.3), inset 0 1px 0 rgba(255,255,255,0.07) !important;
    transition: box-shadow 0.15s ease, transform 0.1s ease !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover {
    box-shadow: 0 4px 28px rgba(239,68,68,0.55), inset 0 1px 0 rgba(255,255,255,0.1) !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] > button[kind="primary"]:active,
[data-testid="stBaseButton-primary"]:active { transform: translateY(0) !important; }

/* ── DOWNLOAD BUTTONS ── */
[data-testid="stDownloadButton"] > button {
    background: #0c0f1a !important;
    border: 1px solid #17203a !important;
    border-radius: 8px !important;
    color: #7a93b8 !important;
    font-family: 'Fira Sans', sans-serif !important;
    font-weight: 500 !important;
    transition: border-color 0.15s ease, color 0.15s ease, box-shadow 0.15s ease !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #2563eb !important;
    color: #60a5fa !important;
    box-shadow: 0 2px 18px rgba(37,99,235,0.22) !important;
}

/* ── TABS ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid #17203a !important;
    gap: 0 !important;
    background: transparent !important;
}
[data-testid="stTabs"] button[role="tab"] {
    font-family: 'Fira Sans', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.84rem !important;
    color: #364060 !important;
    letter-spacing: 0.05em !important;
    padding: 10px 26px !important;
    border-bottom: 2px solid transparent !important;
    transition: color 0.15s ease !important;
    background: transparent !important;
    border-radius: 0 !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    color: #dde4f0 !important;
    border-bottom-color: #ef4444 !important;
}
[data-testid="stTabs"] button[role="tab"]:hover { color: #7a93b8 !important; }

/* ── EXPANDERS ── */
[data-testid="stExpander"] details {
    background: #0c0f1a !important;
    border: 1px solid #17203a !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] summary {
    font-family: 'Fira Sans', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.84rem !important;
    color: #7a93b8 !important;
    padding: 11px 16px !important;
}
[data-testid="stExpander"] summary:hover { color: #dde4f0 !important; }
[data-testid="stExpander"] details > div { padding: 4px 16px 14px !important; }

/* ── MULTISELECT ── */
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
    background: #0c0f1a !important;
    border-color: #17203a !important;
    border-radius: 8px !important;
}

/* ── CHECKBOX ── */
[data-testid="stCheckbox"] label {
    font-size: 0.86rem !important;
    color: #7a93b8 !important;
    font-family: 'Fira Sans', sans-serif !important;
}

/* ── CAPTION ── */
[data-testid="stCaptionContainer"] p {
    font-family: 'Fira Code', monospace !important;
    font-size: 0.74rem !important;
    color: #364060 !important;
    letter-spacing: 0.02em !important;
}

/* ── ALERTS ── */
[data-testid="stAlertContainer"] { border-radius: 8px !important; }

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #07090f; }
::-webkit-scrollbar-thumb { background: #17203a; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #1f2d4a; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

TIER_COLOR = {
    "deal_killer": "#ef4444",
    "critical":    "#f97316",
    "moderate":    "#eab308",
    "manageable":  "#22c55e",
    "unscored":    "#6b7280",
}

def tier_badge_html(tier):
    cls = {"deal_killer": "badge-dk", "critical": "badge-crit",
           "moderate": "badge-mod", "manageable": "badge-man"}.get(str(tier), "badge-unk")
    label = str(tier).replace("_", " ").upper()
    return f'<span class="badge {cls}">{label}</span>'

def exposure_badge_html(exposure):
    cls = {"internet_facing": "badge-inet", "partner": "badge-part",
           "internal": "badge-int"}.get(str(exposure), "badge-ukn")
    label = str(exposure).replace("_", " ").upper()
    return f'<span class="badge {cls}">{label}</span>'

def metric_card(label, value, color_class):
    return f"""
    <div class="rf-metric {color_class}">
        <div class="label">{label}</div>
        <div class="value">{value}</div>
    </div>"""

def score_color(score):
    if score >= 75: return "#ef4444"
    if score >= 50: return "#f97316"
    if score >= 25: return "#eab308"
    return "#22c55e"

def format_label(value):
    if value is None: return "—"
    return str(value).replace("_", " ").title()


# ── Header ────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="display:flex; align-items:center; justify-content:space-between;
            padding: 18px 0 14px; border-bottom: 1px solid #17203a; margin-bottom:20px;">
  <div style="display:flex; align-items:center; gap:14px;">
    <div style="width:40px; height:40px; background:linear-gradient(135deg,#ef4444,#9b1c1c);
                border-radius:9px; display:flex; align-items:center; justify-content:center;
                font-size:1.25rem; flex-shrink:0; box-shadow:0 4px 18px rgba(239,68,68,0.4);">🚩</div>
    <div>
      <div style="font-size:1.55rem; font-weight:800; color:#dde4f0; letter-spacing:-0.03em;
                  font-family:'Fira Sans',sans-serif; line-height:1.1;">RedFlag</div>
      <div style="font-size:0.59rem; font-weight:600; letter-spacing:0.16em;
                  text-transform:uppercase; color:#364060; font-family:'Fira Code',monospace;
                  margin-top:2px;">Cybersecurity Due Diligence &nbsp;·&nbsp; M&amp;A Risk Intelligence</div>
    </div>
  </div>
  <div style="display:flex; gap:20px; align-items:center;">
    <div style="text-align:right;">
      <div style="font-size:0.59rem; font-weight:600; letter-spacing:0.14em; text-transform:uppercase;
                  color:#364060; font-family:'Fira Code',monospace; margin-bottom:3px;">Platform</div>
      <div style="font-size:0.78rem; color:#7a93b8; font-family:'Fira Code',monospace;">
        Nmap · Shodan · Vulners · OpenVAS · ZAP
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Scan controls ─────────────────────────────────────────────────────────────

scan_col1, scan_col2, scan_col3 = st.columns([5, 1, 1])
with scan_col1:
    target = st.text_input(
        ">_ Scan Target",
        value="scanme.nmap.org",
        placeholder="IP address, hostname, or subnet  —  e.g.  192.168.1.0/24  ·  scanme.nmap.org",
    )
with scan_col2:
    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
    run_scan = st.button("Run Scan", use_container_width=True, type="primary")
with scan_col3:
    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
    fast_mode = st.checkbox("Fast Scan", value=False,
                            help="Top 200 ports · version-intensity 3 · ~2x faster. May miss uncommon ports.")

st.markdown('<div class="rf-section-label" style="margin-top:4px;">Optional Intelligence Sources</div>',
            unsafe_allow_html=True)
upload_col1, upload_col2, upload_col3 = st.columns(3)

with upload_col1:
    with st.expander("OpenVAS XML"):
        st.caption("Upload OpenVAS / Greenbone XML to merge verified CVE findings with CONFIRMED evidence strength.")
        openvas_file = st.file_uploader("OpenVAS XML", type=["xml"], label_visibility="collapsed", key="ov_upload")

with upload_col2:
    with st.expander("OWASP ZAP XML"):
        st.caption("Upload OWASP ZAP XML to merge web application layer findings into the risk model.")
        zap_file = st.file_uploader("ZAP XML", type=["xml"], label_visibility="collapsed", key="zap_upload")

with upload_col3:
    with st.expander("Asset Inventory Excel"):
        st.caption("Map host IPs to sensitivity tiers (Crown Jewel / Regulated / Sensitive). Unlocks the most impactful deal-killer rules.")
        st.markdown(
            "<span style='color:#364060;font-size:0.75rem;font-family:Fira Code,monospace;'>"
            "Required columns: IP &nbsp;·&nbsp; Sensitivity</span>",
            unsafe_allow_html=True,
        )
        asset_file = st.file_uploader("Asset Inventory Excel", type=["xlsx", "xls"], label_visibility="collapsed", key="asset_upload")

# ── Scan execution ────────────────────────────────────────────────────────────

if run_scan:
    if not target.strip():
        st.error("Please enter a valid target.")
    else:
        try:
            with st.spinner("Scanning target · Vulners CVE lookup · Shodan enrichment · NVD CVSS · CISA KEV — this may take 30–60s..."):
                clean_target      = target.strip()
                xml_file          = run_nmap_scan(clean_target, fast_mode=fast_mode)
                nmap_findings     = analyze_nmap_file(xml_file)

                # Vulners NSE: parse CVEs from same XML, merge back into Nmap findings
                vulners_raw       = parse_vulners_from_nmap_xml(xml_file)
                if vulners_raw:
                    nmap_findings = merge_vulners_with_nmap(nmap_findings, vulners_raw)
                st.session_state["vulners_count"] = len(vulners_raw)

                resolved_ip       = socket.gethostbyname(clean_target)
                shodan_result     = lookup_host(resolved_ip)
                findings          = enrich_findings_with_shodan(nmap_findings, shodan_result)
                shodan_standalone = create_shodan_findings(shodan_result, resolved_ip)
                all_findings      = findings + shodan_standalone

                import tempfile, os

                # ── OpenVAS ──────────────────────────────────────────────────
                openvas_findings = []
                if openvas_file is not None:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
                        tmp.write(openvas_file.read())
                        tmp_path = tmp.name
                    try:
                        openvas_findings = parse_openvas_xml(tmp_path)
                    except ValueError as e:
                        st.warning(f"OpenVAS parse error: {e}")
                    finally:
                        os.unlink(tmp_path)

                if openvas_findings:
                    merged_nmap = merge_openvas_with_nmap(findings, openvas_findings)
                    all_findings = merged_nmap + shodan_standalone
                    openvas_matched = len(findings) + len(openvas_findings) - len(merged_nmap)
                    st.session_state["openvas_matched"] = openvas_matched
                    findings = merged_nmap  # keep reference for ZAP merge below
                else:
                    st.session_state["openvas_matched"] = 0

                # ── ZAP ──────────────────────────────────────────────────────
                zap_findings = []
                if zap_file is not None:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
                        tmp.write(zap_file.read())
                        tmp_path = tmp.name
                    try:
                        zap_findings = parse_zap_xml(tmp_path)
                    except ValueError as e:
                        st.warning(f"ZAP parse error: {e}")
                    finally:
                        os.unlink(tmp_path)

                if zap_findings:
                    merged_nmap = merge_zap_with_nmap(findings, zap_findings)
                    all_findings = merged_nmap + shodan_standalone
                st.session_state["zap_count"] = len(zap_findings)

                # ── Asset inventory / data_sensitivity ───────────────────────
                asset_map = {}
                if asset_file is not None:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
                        tmp.write(asset_file.read())
                        tmp_path = tmp.name
                    try:
                        asset_map = parse_asset_excel(tmp_path)
                        all_findings = apply_sensitivity_to_findings(all_findings, asset_map)
                    except ValueError as e:
                        st.warning(f"Asset inventory error: {e}")
                    finally:
                        os.unlink(tmp_path)
                st.session_state["asset_hosts"] = len(asset_map)

                findings = triage_all(all_findings)

            st.session_state["findings"]         = findings
            st.session_state["shodan_result"]    = shodan_result
            st.session_state["resolved_ip"]      = resolved_ip
            st.session_state["clean_target"]     = clean_target
            st.session_state["openvas_count"]    = len(openvas_findings)
            st.session_state["zap_count"]        = len(zap_findings)
            st.session_state["asset_hosts"]      = len(asset_map)

            deal_killers = sum(1 for f in findings if str(getattr(f.deal_tier, "value", f.deal_tier)) == "deal_killer")
            if deal_killers:
                st.error(f"⚠️  Scan complete — **{deal_killers} deal-killer finding{'s' if deal_killers > 1 else ''}** detected across {len(findings)} total findings.")
            else:
                st.success(f"✅  Scan complete — {len(findings)} findings for **{clean_target}**.")

        except Exception as e:
            st.error(f"Scan failed: {e}")

# ── Guard ─────────────────────────────────────────────────────────────────────

if "findings" not in st.session_state:
    st.stop()

findings      = st.session_state["findings"]
shodan_result = st.session_state["shodan_result"]
resolved_ip   = st.session_state["resolved_ip"]
clean_target  = st.session_state["clean_target"]

# Pre-compute counts
tier_counts = {}
for f in findings:
    t = str(getattr(f.deal_tier, "value", f.deal_tier))
    tier_counts[t] = tier_counts.get(t, 0) + 1

n_total = len(findings)
n_dk    = tier_counts.get("deal_killer", 0)
n_crit  = tier_counts.get("critical", 0)
n_mod   = tier_counts.get("moderate", 0)
n_man   = tier_counts.get("manageable", 0)

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_findings, tab_export = st.tabs(["  Overview  ", "  Findings  ", "  Export  "])

# ══════════════════════════════════════════════════════════════════════════════
# Tab: Overview
# ══════════════════════════════════════════════════════════════════════════════

with tab_overview:

    # Metric cards
    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
    mc1.markdown(metric_card("Total Findings", n_total, "blue"),   unsafe_allow_html=True)
    mc2.markdown(metric_card("Deal Killers",   n_dk,    "red"),    unsafe_allow_html=True)
    mc3.markdown(metric_card("Critical",       n_crit,  "orange"), unsafe_allow_html=True)
    mc4.markdown(metric_card("Moderate",       n_mod,   "yellow"), unsafe_allow_html=True)
    mc5.markdown(metric_card("Manageable",     n_man,   "green"),  unsafe_allow_html=True)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    _asset_hosts_loaded = st.session_state.get("asset_hosts", 0)
    if _asset_hosts_loaded:
        st.markdown(f"""
        <div style="background:rgba(34,197,94,0.06); border:1px solid rgba(34,197,94,0.25);
                    border-left:3px solid #22c55e; border-radius:8px; padding:11px 16px;
                    font-size:0.82rem; color:#4ade80; font-family:'Fira Sans',sans-serif;
                    margin-bottom:16px;">
            <strong>Asset Inventory Active</strong> &nbsp;—&nbsp;
            {_asset_hosts_loaded} hosts classified. Data sensitivity is factored into all scores.
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(234,179,8,0.05); border:1px solid rgba(234,179,8,0.2);
                    border-left:3px solid #eab308; border-radius:8px; padding:11px 16px;
                    font-size:0.82rem; color:#facc15; font-family:'Fira Sans',sans-serif;
                    margin-bottom:16px;">
            <strong>Data Sensitivity Unclassified</strong> &nbsp;—&nbsp;
            All findings default to <code style="font-family:'Fira Code',monospace;font-size:0.78rem;">UNKNOWN</code>
            (25% of the risk model). Upload an asset inventory to unlock the most impactful deal-killer rules.
        </div>""", unsafe_allow_html=True)

    # Charts + Intel panel
    chart_col, shodan_col = st.columns([11, 9])

    with chart_col:
        st.markdown('<div class="rf-section-label">Risk Breakdown</div>', unsafe_allow_html=True)

        # Donut — tier breakdown
        labels, values, colors = [], [], []
        for tier, count in [("Deal Killer", n_dk), ("Critical", n_crit),
                             ("Moderate", n_mod), ("Manageable", n_man)]:
            if count:
                labels.append(tier); values.append(count)
                colors.append(TIER_COLOR[tier.lower().replace(" ", "_")])

        if values:
            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.68,
                marker=dict(colors=colors, line=dict(color="#07090f", width=3)),
                textinfo="label+percent",
                textfont=dict(size=11, color="#7a93b8", family="Fira Code"),
                hovertemplate="<b>%{label}</b><br>%{value} findings (%{percent})<extra></extra>",
            ))
            fig.update_layout(
                showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=8, b=8, l=8, r=8), height=230,
                annotations=[dict(
                    text=f"<b>{n_total}</b><br><span style='font-size:10px;color:#364060'>total</span>",
                    x=0.5, y=0.5, font_size=24, font_color="#dde4f0",
                    font=dict(family="Fira Code"), showarrow=False,
                )],
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        # Horizontal bar — top findings by score
        top_n = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:8]
        if top_n:
            bar_labels = [f.title[:38] + "…" if len(f.title) > 38 else f.title for f in top_n]
            bar_values = [f.risk_score for f in top_n]
            bar_colors = [score_color(s) for s in bar_values]

            fig2 = go.Figure(go.Bar(
                x=bar_values, y=bar_labels, orientation="h",
                marker=dict(color=bar_colors, line=dict(width=0),
                            opacity=0.85),
                hovertemplate="<b>%{y}</b><br>Risk Score: %{x:.1f}<extra></extra>",
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(range=[0, 100], gridcolor="#17203a", zeroline=False,
                           tickfont=dict(color="#364060", size=10, family="Fira Code"), title=""),
                yaxis=dict(autorange="reversed",
                           tickfont=dict(color="#7a93b8", size=10, family="Fira Sans"), title=""),
                margin=dict(t=0, b=4, l=4, r=4), height=250,
            )
            st.markdown('<div class="rf-section-label">Top Findings by Risk Score</div>',
                        unsafe_allow_html=True)
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    with shodan_col:
        # ── Target intelligence ───────────────────────────────────────
        st.markdown('<div class="rf-section-label">Target Intelligence</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="rf-target-panel">
          <div class="rf-tp-row">
            <span class="rf-tp-label">Target</span>
            <span class="rf-tp-value">{clean_target}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Resolved IP</span>
            <span class="rf-tp-value">{resolved_ip}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Scanner pipeline ──────────────────────────────────────────
        vulners_count   = st.session_state.get("vulners_count", 0)
        openvas_count   = st.session_state.get("openvas_count", 0)
        openvas_matched = st.session_state.get("openvas_matched", 0)
        zap_count       = st.session_state.get("zap_count", 0)
        asset_hosts     = st.session_state.get("asset_hosts", 0)
        shodan_ok       = shodan_result.get("success", False)

        def _pi(dot_cls, name, status, status_cls=""):
            return (f'<div class="rf-pipeline-item">'
                    f'<span class="rf-dot {dot_cls}"></span>'
                    f'<div><div class="rf-pi-name">{name}</div>'
                    f'<div class="rf-pi-status {status_cls}">{status}</div></div></div>')

        nmap_pi    = _pi("ok",  "Nmap",          "Completed", "ok")
        vulners_pi = _pi("ok" if vulners_count else "off", "Vulners NSE",
                         f"{vulners_count} CVEs" if vulners_count else "Not detected", "ok" if vulners_count else "")
        shodan_pi  = _pi("ok" if shodan_ok else "err", "Shodan",
                         "Connected" if shodan_ok else "Unavailable", "ok" if shodan_ok else "")
        ov_pi      = _pi("ok" if openvas_count else "off", "OpenVAS",
                         f"{openvas_count} findings" if openvas_count else "Not uploaded", "ok" if openvas_count else "")
        zap_pi     = _pi("ok" if zap_count else "off", "ZAP",
                         f"{zap_count} findings" if zap_count else "Not uploaded", "ok" if zap_count else "")
        asset_pi   = _pi("ok" if asset_hosts else "warn", "Asset Inv.",
                         f"{asset_hosts} hosts" if asset_hosts else "Not uploaded", "ok" if asset_hosts else "warn")

        st.markdown(f"""
        <div class="rf-pipeline">
          <div class="rf-pipeline-header">Scanner Pipeline</div>
          <div class="rf-pipeline-grid">
            {nmap_pi}{vulners_pi}{shodan_pi}{ov_pi}{zap_pi}{asset_pi}
          </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Shodan snapshot ───────────────────────────────────────────
        if shodan_result.get("success"):
            ports_str  = ", ".join(map(str, shodan_result.get("ports", []))) or "—"
            vuln_count = len(shodan_result.get("vulns", []))
            org        = shodan_result.get("organization") or "Unknown"
            isp        = shodan_result.get("isp") or "Unknown"
            country    = shodan_result.get("country") or "Unknown"
            city       = shodan_result.get("city") or "Unknown"
            cve_color  = "#f87171" if vuln_count else "#4ade80"

            st.markdown(f"""
            <div class="rf-shodan">
              <div class="rf-section-label" style="margin-bottom:10px;">Shodan Snapshot</div>
              <div class="rf-shodan-row">
                <span class="rf-shodan-label">Org</span>
                <span class="rf-shodan-value">{org}</span>
              </div>
              <div class="rf-shodan-row">
                <span class="rf-shodan-label">ISP</span>
                <span class="rf-shodan-value">{isp}</span>
              </div>
              <div class="rf-shodan-row">
                <span class="rf-shodan-label">Location</span>
                <span class="rf-shodan-value">{city}, {country}</span>
              </div>
              <div class="rf-shodan-row">
                <span class="rf-shodan-label">Open Ports</span>
                <span class="rf-shodan-value" style="font-family:'Fira Code',monospace;font-size:0.78rem;">{ports_str}</span>
              </div>
              <div class="rf-shodan-row">
                <span class="rf-shodan-label">CVEs</span>
                <span class="rf-shodan-value" style="color:{cve_color};font-weight:700;font-family:'Fira Code',monospace;">{vuln_count}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

            if shodan_result["vulns"]:
                with st.expander(f"Associated CVEs  ({len(shodan_result['vulns'])})"):
                    top_cves = shodan_result["vulns"][:12]
                    rest     = shodan_result["vulns"][12:]
                    st.markdown(
                        "<div style='display:flex;flex-wrap:wrap;gap:6px;padding:4px 0;'>"
                        + "".join(f'<span class="badge badge-dk">{c}</span>' for c in top_cves)
                        + "</div>", unsafe_allow_html=True)
                    if rest:
                        st.caption(f"+ {len(rest)} more CVEs not shown")
        else:
            st.warning(shodan_result.get("error", "Shodan enrichment unavailable."))

# ══════════════════════════════════════════════════════════════════════════════
# Tab: Findings
# ══════════════════════════════════════════════════════════════════════════════

with tab_findings:
    if not findings:
        st.info("No findings were detected.")
    else:
        rows = []
        for f in findings:
            rows.append({
                "Title":       f.title,
                "Host":        f.host or "—",
                "Port":        f.port,
                "Service":     f.service or "—",
                "Scanner":     str(getattr(f.scanner_source, "value", f.scanner_source)).upper(),
                "Risk Score":  f.risk_score,
                "Deal Tier":   str(getattr(f.deal_tier, "value", f.deal_tier)),
                "Exposure":    str(getattr(f.exposure, "value", f.exposure)),
                "Evidence":    str(getattr(f.evidence_strength, "value", f.evidence_strength)),
                "Description": f.description,
                "Remediation": f.remediation,
            })

        df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False).reset_index(drop=True)

        # Filters
        st.markdown('<div class="rf-section-label">Filter Findings</div>', unsafe_allow_html=True)
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            selected_tiers = st.multiselect(
                "Deal Tier",
                options=sorted(df["Deal Tier"].dropna().unique()),
                default=sorted(df["Deal Tier"].dropna().unique()),
            )
        with fc2:
            selected_exposure = st.multiselect(
                "Exposure",
                options=sorted(df["Exposure"].dropna().unique()),
                default=sorted(df["Exposure"].dropna().unique()),
            )
        with fc3:
            min_score = st.slider("Min Risk Score", 0, 100, 0)

        filtered_df = df[
            df["Deal Tier"].isin(selected_tiers) &
            df["Exposure"].isin(selected_exposure) &
            (df["Risk Score"] >= min_score)
        ].copy()

        st.caption(f"Showing {len(filtered_df)} of {len(df)} findings")

        # Table
        table_df = filtered_df[["Title", "Host", "Port", "Service", "Scanner", "Risk Score", "Deal Tier", "Exposure", "Evidence"]].copy()
        table_df["Deal Tier"] = table_df["Deal Tier"].apply(lambda x: x.replace("_", " ").title())
        table_df["Exposure"]  = table_df["Exposure"].apply(lambda x: x.replace("_", " ").title())
        table_df["Evidence"]  = table_df["Evidence"].apply(lambda x: x.replace("_", " ").title())

        st.dataframe(
            table_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Title":    st.column_config.TextColumn("Title", width="large"),
                "Host":     st.column_config.TextColumn("Host", width="medium"),
                "Port":     st.column_config.NumberColumn("Port", format="%d"),
                "Service":  st.column_config.TextColumn("Service", width="small"),
                "Scanner":  st.column_config.TextColumn("Scanner", width="small"),
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=100, format="%.1f"
                ),
                "Deal Tier": st.column_config.TextColumn("Deal Tier", width="medium"),
                "Exposure":  st.column_config.TextColumn("Exposure", width="medium"),
                "Evidence":  st.column_config.TextColumn("Evidence", width="medium"),
            }
        )

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Detail cards
        st.markdown('<div class="rf-section-label" style="margin-top:12px;">Detailed Findings</div>',
                    unsafe_allow_html=True)
        show_details = st.checkbox("Expand finding cards", value=False)

        TIER_CSS = {"deal killer": "dk", "critical": "crit", "moderate": "mod", "manageable": "man"}

        if not filtered_df.empty and show_details:
            for _, row in filtered_df.iterrows():
                tier_val     = str(row["Deal Tier"]).lower().replace(" ", "_")
                tier_display = str(row["Deal Tier"]).lower()
                sev_cls      = TIER_CSS.get(tier_display, "")
                sc           = score_color(row["Risk Score"])
                tier_html    = tier_badge_html(tier_val)
                exp_html     = exposure_badge_html(str(row["Exposure"]).lower().replace(" ", "_"))
                evid_label   = format_label(row["Evidence"])
                port_svc     = f'{row["Port"]} / {row["Service"]}' if row["Port"] else row["Service"]

                st.markdown(f"""
                <div class="finding-card {sev_cls}">
                  <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px;">
                    <div style="flex:1; min-width:0;">
                      <h4>{row['Title']}</h4>
                      <div class="meta">
                        {tier_html}&nbsp;{exp_html}
                        &nbsp;<span style="font-family:'Fira Code',monospace;font-size:0.72rem;
                                          color:#364060;">{row['Host']} &nbsp;·&nbsp; :{port_svc} &nbsp;·&nbsp; {row['Scanner']}</span>
                      </div>
                      <hr class="fc-divider">
                      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0 28px;">
                        <div>
                          <div class="field-label">Description</div>
                          <div class="field-value">{row['Description']}</div>
                        </div>
                        <div>
                          <div class="field-label">Remediation</div>
                          <div class="field-value">{row['Remediation']}</div>
                        </div>
                      </div>
                      <div style="display:flex; gap:24px; margin-top:4px;">
                        <div>
                          <span class="field-label">Evidence</span>&nbsp;
                          <span style="font-family:'Fira Code',monospace;font-size:0.78rem;
                                       color:#7a93b8;">{evid_label}</span>
                        </div>
                      </div>
                    </div>
                    <div class="score-pill">
                      <span class="s-label">Risk</span>
                      <div class="s-value" style="color:{sc}">{row['Risk Score']:.1f}</div>
                    </div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# Tab: Export
# ══════════════════════════════════════════════════════════════════════════════

with tab_export:

    exp_col, _ = st.columns([2, 3])
    with exp_col:
        st.markdown('<div class="rf-section-label">Report Summary</div>', unsafe_allow_html=True)

        dk_color  = "#f87171" if n_dk   else "#4ade80"
        crt_color = "#fb923c" if n_crit else "#364060"

        st.markdown(f"""
        <div class="rf-target-panel" style="margin-bottom:16px;">
          <div class="rf-tp-row">
            <span class="rf-tp-label">Target</span>
            <span class="rf-tp-value">{clean_target}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">IP</span>
            <span class="rf-tp-value">{resolved_ip}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Findings</span>
            <span class="rf-tp-value" style="color:#c7d8f5;">{n_total}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Deal Killers</span>
            <span class="rf-tp-value" style="color:{dk_color};font-weight:700;">{n_dk}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Critical</span>
            <span class="rf-tp-value" style="color:{crt_color};font-weight:600;">{n_crit}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Moderate</span>
            <span class="rf-tp-value" style="color:#364060;">{n_mod}</span>
          </div>
          <div class="rf-tp-row">
            <span class="rf-tp-label">Manageable</span>
            <span class="rf-tp-value" style="color:#364060;">{n_man}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="rf-section-label">Download Reports</div>', unsafe_allow_html=True)

        csv_file = export_findings_csv(findings)
        with open(csv_file, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f,
                file_name=csv_file.split("\\")[-1].split("/")[-1],
                mime="text/csv",
                use_container_width=True,
            )

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        pdf_file = generate_pdf_report(findings, clean_target, resolved_ip)
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name=pdf_file.split("\\")[-1].split("/")[-1],
                mime="application/pdf",
                use_container_width=True,
            )
