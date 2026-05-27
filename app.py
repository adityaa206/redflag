import socket
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from reports.generator import export_findings_csv
from reports.pdf_report import generate_pdf_report
from scanners.nmap_scan import run_nmap_scan, vulners_nse_available
from analysis.parser import analyze_nmap_file
from analysis.triage import triage_all
from scanners.shodan_scan import lookup_host, enrich_findings_with_shodan, create_shodan_findings, parse_shodan_json
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
   REDFLAG  —  Design System v3
   Fonts  : JetBrains Mono (data/mono) + Inter (body)
   Palette: Deep void · Signal red · Threat amber · Safe emerald
══════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* ── Base ── */
[data-testid="stAppViewContainer"] { background: #030508 !important; }
[data-testid="stHeader"]           { background: transparent !important; }
[data-testid="stMainBlockContainer"] { padding-top: 0 !important; }
html, body, [class*="css"],
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
.stCheckbox label, .stSlider label, .stMultiSelect label,
.stCaption, .stAlert p, button { font-family: 'Inter', -apple-system, sans-serif !important; }

/* ── METRIC CARDS ── */
.rf-metric {
    background: linear-gradient(160deg, #080d1c 0%, #060a16 100%);
    border: 1px solid #0e1828;
    border-radius: 14px;
    padding: 20px 16px 22px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s ease, box-shadow 0.25s ease;
    cursor: default;
}
.rf-metric::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    border-radius: 14px 14px 0 0;
}
.rf-metric:hover { transform: translateY(-4px); }
.rf-metric .label {
    font-size: 0.58rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #263550;
    margin-bottom: 12px;
    font-family: 'JetBrains Mono', monospace;
}
.rf-metric .value {
    font-size: 2.9rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: -0.03em;
}
.rf-metric.red::before    { background: linear-gradient(90deg, #f43f5e, #9f1239); }
.rf-metric.red .value     { color: #f43f5e; }
.rf-metric.red:hover      { box-shadow: 0 12px 44px rgba(244,63,94,0.25), 0 0 0 1px rgba(244,63,94,0.12); border-color: rgba(244,63,94,0.2); }
.rf-metric.orange::before { background: linear-gradient(90deg, #fb923c, #c2410c); }
.rf-metric.orange .value  { color: #fb923c; }
.rf-metric.orange:hover   { box-shadow: 0 12px 44px rgba(251,146,60,0.22), 0 0 0 1px rgba(251,146,60,0.12); border-color: rgba(251,146,60,0.2); }
.rf-metric.yellow::before { background: linear-gradient(90deg, #fbbf24, #b45309); }
.rf-metric.yellow .value  { color: #fbbf24; }
.rf-metric.yellow:hover   { box-shadow: 0 12px 44px rgba(251,191,36,0.18), 0 0 0 1px rgba(251,191,36,0.1); border-color: rgba(251,191,36,0.18); }
.rf-metric.green::before  { background: linear-gradient(90deg, #34d399, #065f46); }
.rf-metric.green .value   { color: #34d399; }
.rf-metric.green:hover    { box-shadow: 0 12px 44px rgba(52,211,153,0.2), 0 0 0 1px rgba(52,211,153,0.1); border-color: rgba(52,211,153,0.18); }
.rf-metric.blue::before   { background: linear-gradient(90deg, #60a5fa, #1d4ed8); }
.rf-metric.blue .value    { color: #93b8f8; }
.rf-metric.blue:hover     { box-shadow: 0 12px 44px rgba(96,165,250,0.2), 0 0 0 1px rgba(96,165,250,0.12); border-color: rgba(96,165,250,0.18); }

/* ── SECTION LABEL ── */
.rf-section-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.57rem;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #243048;
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
    background: linear-gradient(90deg, #0d1a30 0%, transparent 100%);
}

/* ── BADGES ── */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 0.59rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
}
.badge-dk   { background: rgba(244,63,94,0.12);  color: #f87171; border: 1px solid rgba(244,63,94,0.3); }
.badge-crit { background: rgba(251,146,60,0.12); color: #fb923c; border: 1px solid rgba(251,146,60,0.3); }
.badge-mod  { background: rgba(251,191,36,0.1);  color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.badge-man  { background: rgba(52,211,153,0.1);  color: #34d399; border: 1px solid rgba(52,211,153,0.25); }
.badge-unk  { background: rgba(107,114,128,0.08);color: #6b7280; border: 1px solid rgba(107,114,128,0.2); }
.badge-inet { background: rgba(96,165,250,0.1);  color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }
.badge-part { background: rgba(167,139,250,0.1); color: #a78bfa; border: 1px solid rgba(124,58,237,0.3); }
.badge-int  { background: rgba(52,211,153,0.08); color: #34d399; border: 1px solid rgba(52,211,153,0.22); }
.badge-ukn  { background: rgba(107,114,128,0.08);color: #6b7280; border: 1px solid rgba(55,65,81,0.22); }

/* ── FINDING CARDS ── */
@keyframes pulse-dk {
    0%,100% { box-shadow: 0 0 0 0 rgba(244,63,94,0.3), 0 4px 28px rgba(244,63,94,0.08); }
    50%      { box-shadow: 0 0 0 5px rgba(244,63,94,0), 0 4px 28px rgba(244,63,94,0.18); }
}
.finding-card {
    background: linear-gradient(145deg, #080d1c 0%, #060a16 100%);
    border: 1px solid #0e1828;
    border-left: 3px solid #0e1828;
    border-radius: 12px;
    padding: 18px 22px;
    margin-bottom: 8px;
    transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    position: relative;
}
.finding-card:hover { background: linear-gradient(145deg, #0c1220 0%, #09101c 100%); }
.finding-card.dk   { border-left-color: #f43f5e; animation: pulse-dk 3s ease-in-out infinite; }
.finding-card.crit { border-left-color: #fb923c; }
.finding-card.mod  { border-left-color: #fbbf24; }
.finding-card.man  { border-left-color: #34d399; }
.finding-card.dk:hover   { border-color: rgba(244,63,94,0.28);  box-shadow: 0 6px 40px rgba(244,63,94,0.14); }
.finding-card.crit:hover { border-color: rgba(251,146,60,0.28); box-shadow: 0 6px 40px rgba(251,146,60,0.12); }
.finding-card.mod:hover  { border-color: rgba(251,191,36,0.25); box-shadow: 0 4px 28px rgba(251,191,36,0.08); }
.finding-card.man:hover  { border-color: rgba(52,211,153,0.22); box-shadow: 0 4px 28px rgba(52,211,153,0.08); }
.finding-card h4 {
    color: #dce8ff;
    font-size: 0.96rem;
    font-weight: 600;
    margin: 0 0 8px 0;
    font-family: 'Inter', sans-serif;
    line-height: 1.45;
    letter-spacing: -0.01em;
}
.finding-card .meta {
    color: #374e6e;
    font-size: 0.78rem;
    margin-bottom: 14px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}
.finding-card .fc-divider { border: none; border-top: 1px solid #0e1828; margin: 12px 0; }
.finding-card .field-label {
    color: #243048;
    font-size: 0.57rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-bottom: 4px;
    font-family: 'JetBrains Mono', monospace;
}
.finding-card .field-value { color: #5f7ca0; font-size: 0.84rem; margin-bottom: 12px; line-height: 1.65; }
.finding-card .score-pill {
    background: #050810;
    border: 1px solid #0e1828;
    border-radius: 10px;
    padding: 14px 16px;
    text-align: center;
    min-width: 76px;
    flex-shrink: 0;
}
.finding-card .score-pill .s-label {
    color: #243048;
    font-size: 0.56rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    font-family: 'JetBrains Mono', monospace;
    display: block;
    margin-bottom: 5px;
}
.finding-card .score-pill .s-value {
    font-size: 1.9rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
    letter-spacing: -0.03em;
}

/* ── STATUS DOTS ── */
.rf-dot {
    display: inline-block;
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    margin-top: 2px;
}
@keyframes warn-blink { 0%,100%{opacity:1} 50%{opacity:0.25} }
.rf-dot.ok   { background: #34d399; box-shadow: 0 0 8px rgba(52,211,153,0.9); }
.rf-dot.warn { background: #fbbf24; box-shadow: 0 0 8px rgba(251,191,36,0.9); animation: warn-blink 2s infinite; }
.rf-dot.err  { background: #f43f5e; box-shadow: 0 0 8px rgba(244,63,94,0.9); }
.rf-dot.off  { background: #182236; }

/* ── SCANNER PIPELINE (horizontal flow) ── */
.rf-pipeline-h {
    background: linear-gradient(145deg, #080d1c 0%, #060a16 100%);
    border: 1px solid #0e1828;
    border-radius: 12px;
    padding: 14px 16px 12px;
    margin-bottom: 10px;
}
.rf-pipeline-header {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.56rem;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #243048;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #0e1828;
}
.rf-pipeline-flow {
    display: flex;
    align-items: flex-start;
    gap: 0;
    flex-wrap: wrap;
    row-gap: 8px;
}
.rf-pipeline-step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: 8px 12px;
    border-radius: 8px;
    transition: background 0.15s ease;
    min-width: 64px;
    cursor: default;
}
.rf-pipeline-step:hover { background: rgba(255,255,255,0.025); }
.rf-pipeline-step .step-dot { margin-bottom: 2px; }
.rf-pipeline-step .step-name {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.67rem;
    font-weight: 600;
    color: #5f7ca0;
    white-space: nowrap;
}
.rf-pipeline-step .step-status {
    font-size: 0.62rem;
    color: #243048;
    font-family: 'Inter', sans-serif;
    white-space: nowrap;
    text-align: center;
}
.rf-pipeline-step .step-status.ok   { color: #34d399; }
.rf-pipeline-step .step-status.warn { color: #fbbf24; }
.rf-pipeline-arrow {
    color: #182236;
    font-size: 0.85rem;
    margin: 0 1px;
    padding-top: 16px;
    flex-shrink: 0;
}

/* ── TARGET PANEL ── */
.rf-target-panel {
    background: linear-gradient(145deg, #080d1c 0%, #060a16 100%);
    border: 1px solid #0e1828;
    border-radius: 12px;
    padding: 14px 16px 8px;
    margin-bottom: 10px;
}
.rf-tp-row {
    display: grid;
    grid-template-columns: 86px 1fr;
    align-items: baseline;
    margin-bottom: 9px;
    gap: 8px;
}
.rf-tp-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.57rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #243048;
}
.rf-tp-value {
    font-size: 0.83rem;
    color: #dce8ff;
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all;
}

/* ── SHODAN SNAPSHOT ── */
.rf-shodan {
    background: linear-gradient(145deg, #080d1c 0%, #060a16 100%);
    border: 1px solid #0e1828;
    border-left: 3px solid #2563eb;
    border-radius: 12px;
    padding: 14px 16px 8px;
}
.rf-shodan-row {
    display: grid;
    grid-template-columns: 90px 1fr;
    align-items: baseline;
    margin-bottom: 9px;
    gap: 8px;
}
.rf-shodan-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.57rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #243048;
}
.rf-shodan-value { font-size: 0.83rem; color: #5f7ca0; font-family: 'Inter', sans-serif; }

/* ── DEAL-KILLER ALERT BANNER ── */
.dk-alert {
    background: linear-gradient(135deg, rgba(244,63,94,0.07) 0%, rgba(159,18,57,0.04) 100%);
    border: 1px solid rgba(244,63,94,0.22);
    border-left: 4px solid #f43f5e;
    border-radius: 10px;
    padding: 13px 18px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.dk-alert-body { flex: 1; }
.dk-alert-title { font-size: 0.84rem; font-weight: 700; color: #f43f5e; font-family: 'Inter', sans-serif; margin-bottom: 2px; }
.dk-alert-sub   { font-size: 0.77rem; color: rgba(244,63,94,0.65); font-family: 'Inter', sans-serif; }
.dk-alert-count { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; color: #f43f5e; line-height: 1; flex-shrink: 0; }

/* ── ASSET INVENTORY NOTICE ── */
.inv-notice {
    border-radius: 10px; padding: 11px 16px; margin-bottom: 16px;
    font-size: 0.82rem; font-family: 'Inter', sans-serif;
    display: flex; align-items: center; gap: 10px;
}
.inv-notice.active { background: rgba(52,211,153,0.05); border: 1px solid rgba(52,211,153,0.2); border-left: 3px solid #34d399; color: #34d399; }
.inv-notice.warn   { background: rgba(251,191,36,0.04);  border: 1px solid rgba(251,191,36,0.18); border-left: 3px solid #fbbf24; color: #fbbf24; }

/* ── DIVIDERS ── */
.rf-divider { border: none; border-top: 1px solid #0e1828; margin: 14px 0; }

/* ── SCAN INPUT ── */
[data-testid="stTextInput"] input {
    background: #070b16 !important;
    border: 1px solid #0f1d35 !important;
    border-radius: 10px !important;
    color: #dce8ff !important;
    font-size: 0.92rem !important;
    font-family: 'JetBrains Mono', monospace !important;
    letter-spacing: 0.02em !important;
    padding: 10px 14px !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #f43f5e !important;
    box-shadow: 0 0 0 3px rgba(244,63,94,0.1), 0 0 30px rgba(244,63,94,0.06) !important;
}
[data-testid="stTextInput"] input::placeholder { color: #182236 !important; }
[data-testid="stTextInput"] label {
    color: #243048 !important;
    font-size: 0.57rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.18em !important;
    text-transform: uppercase !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── PRIMARY BUTTON ── */
[data-testid="stButton"] > button[kind="primary"],
[data-testid="stBaseButton-primary"] {
    background: linear-gradient(160deg, #f43f5e 0%, #9f1239 100%) !important;
    border: 1px solid rgba(244,63,94,0.4) !important;
    border-radius: 10px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 0.06em !important;
    font-size: 0.86rem !important;
    box-shadow: 0 4px 24px rgba(244,63,94,0.38), inset 0 1px 0 rgba(255,255,255,0.08) !important;
    transition: box-shadow 0.15s ease, transform 0.12s ease !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover {
    box-shadow: 0 6px 36px rgba(244,63,94,0.6), inset 0 1px 0 rgba(255,255,255,0.1) !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] > button[kind="primary"]:active,
[data-testid="stBaseButton-primary"]:active { transform: translateY(0) !important; }

/* ── DOWNLOAD BUTTONS ── */
[data-testid="stDownloadButton"] > button {
    background: #070b16 !important;
    border: 1px solid #0f1d35 !important;
    border-radius: 10px !important;
    color: #5f7ca0 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    transition: all 0.15s ease !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #2563eb !important;
    color: #60a5fa !important;
    box-shadow: 0 2px 22px rgba(37,99,235,0.22) !important;
}

/* ── TABS ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid #0e1828 !important;
    gap: 0 !important;
    background: transparent !important;
}
[data-testid="stTabs"] button[role="tab"] {
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.83rem !important;
    color: #243048 !important;
    letter-spacing: 0.04em !important;
    padding: 11px 28px !important;
    border-bottom: 2px solid transparent !important;
    transition: color 0.15s ease !important;
    background: transparent !important;
    border-radius: 0 !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    color: #dce8ff !important;
    border-bottom-color: #f43f5e !important;
}
[data-testid="stTabs"] button[role="tab"]:hover { color: #5f7ca0 !important; }

/* ── EXPANDERS ── */
[data-testid="stExpander"] details {
    background: #070b16 !important;
    border: 1px solid #0e1828 !important;
    border-radius: 10px !important;
}
[data-testid="stExpander"] summary {
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.83rem !important;
    color: #5f7ca0 !important;
    padding: 12px 16px !important;
}
[data-testid="stExpander"] summary:hover { color: #dce8ff !important; }
[data-testid="stExpander"] details > div { padding: 4px 16px 14px !important; }

/* ── MULTISELECT ── */
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
    background: #070b16 !important;
    border-color: #0e1828 !important;
    border-radius: 8px !important;
}

/* ── CHECKBOX ── */
[data-testid="stCheckbox"] label {
    font-size: 0.85rem !important;
    color: #5f7ca0 !important;
    font-family: 'Inter', sans-serif !important;
}

/* ── CAPTION ── */
[data-testid="stCaptionContainer"] p {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.71rem !important;
    color: #243048 !important;
    letter-spacing: 0.02em !important;
}

/* ── ALERTS ── */
[data-testid="stAlertContainer"] { border-radius: 10px !important; }

/* ── METRIC CARD — clickable view buttons ──
   Target secondary buttons inside ANY 5-column horizontal block.
   The metric row is the only 5-col layout in the app, so this is specific enough.
   Uses CSS :has() — supported in all modern browsers (Chrome 105+, FF 121+, Safari 15.4+).
── */
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button,
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondaryFormSubmit"] button {
    background:     transparent !important;
    border:         none        !important;
    box-shadow:     none        !important;
    color:          #1e2d48     !important;
    font-size:      0.53rem     !important;
    font-family:    'JetBrains Mono', monospace !important;
    font-weight:    700         !important;
    letter-spacing: 0.16em      !important;
    text-transform: uppercase   !important;
    padding:        3px 0 2px   !important;
    margin-top:     -4px        !important;
    width:          100%        !important;
    transition:     color 0.15s ease, transform 0.1s ease !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button:hover {
    color:      #5f7ca0     !important;
    background: transparent !important;
    box-shadow: none        !important;
    transform:  none        !important;
}
/* Accent the first column (mc1 = Total Findings) — not clickable, no button */
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    > div:first-child [data-testid="stBaseButton-secondary"] { display: none; }

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #030508; }
::-webkit-scrollbar-thumb { background: #0e1828; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #182236; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

TIER_COLOR = {
    "deal_killer": "#f43f5e",
    "critical":    "#fb923c",
    "moderate":    "#fbbf24",
    "manageable":  "#34d399",
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
    return f"""<div class="rf-metric {color_class}">
        <div class="label">{label}</div>
        <div class="value">{value}</div>
    </div>"""

def score_color(score):
    if score >= 75: return "#f43f5e"
    if score >= 50: return "#fb923c"
    if score >= 25: return "#fbbf24"
    return "#34d399"

def format_label(value):
    if value is None: return "—"
    return str(value).replace("_", " ").title()


# ── Header ────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="display:flex; align-items:center; justify-content:space-between;
            padding:22px 0 16px; border-bottom:1px solid #0e1828; margin-bottom:22px;">

  <!-- Left: logo + wordmark -->
  <div style="display:flex; align-items:center; gap:16px;">
    <div style="width:46px; height:46px; flex-shrink:0;
                background:linear-gradient(140deg,#f43f5e 0%,#9f1239 100%);
                border-radius:13px; display:flex; align-items:center; justify-content:center;
                font-size:1.4rem;
                box-shadow:0 4px 28px rgba(244,63,94,0.5), 0 0 0 1px rgba(244,63,94,0.25);">🚩</div>
    <div>
      <div style="font-size:1.65rem; font-weight:800; color:#dce8ff; letter-spacing:-0.04em;
                  font-family:'Inter',sans-serif; line-height:1.05;">RedFlag</div>
      <div style="font-size:0.57rem; font-weight:700; letter-spacing:0.18em; text-transform:uppercase;
                  color:#243048; font-family:'JetBrains Mono',monospace; margin-top:3px;">
        M&amp;A Cybersecurity Intelligence Platform
      </div>
    </div>
  </div>

  <!-- Right: engine chips -->
  <div style="display:flex; gap:6px; align-items:center; flex-wrap:wrap; justify-content:flex-end;">
    <span style="background:#080d1c; border:1px solid #0e1828; border-radius:6px;
                 padding:5px 11px; font-size:0.59rem; font-weight:700; letter-spacing:0.12em;
                 color:#243048; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">Nmap</span>
    <span style="background:#080d1c; border:1px solid #0e1828; border-radius:6px;
                 padding:5px 11px; font-size:0.59rem; font-weight:700; letter-spacing:0.12em;
                 color:#243048; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">Vulners</span>
    <span style="background:#080d1c; border:1px solid #0e1828; border-radius:6px;
                 padding:5px 11px; font-size:0.59rem; font-weight:700; letter-spacing:0.12em;
                 color:#243048; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">Shodan</span>
    <span style="background:#080d1c; border:1px solid #0e1828; border-radius:6px;
                 padding:5px 11px; font-size:0.59rem; font-weight:700; letter-spacing:0.12em;
                 color:#243048; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">OpenVAS</span>
    <span style="background:#080d1c; border:1px solid #0e1828; border-radius:6px;
                 padding:5px 11px; font-size:0.59rem; font-weight:700; letter-spacing:0.12em;
                 color:#243048; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">ZAP</span>
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
upload_col1, upload_col2, upload_col3, upload_col4 = st.columns(4)

with upload_col1:
    with st.expander("Shodan JSON (Target-provided)"):
        st.caption(
            "Upload a Shodan host JSON exported by the target company instead of running a live API scan. "
            "If uploaded, this replaces the automatic Shodan lookup — no API credit is consumed."
        )
        st.markdown(
            "<span style='color:#364060;font-size:0.75rem;font-family:Fira Code,monospace;'>"
            "Export via: <code style='font-family:Fira Code,monospace'>shodan host &lt;ip&gt; --save</code>"
            " or Shodan web UI → Download JSON</span>",
            unsafe_allow_html=True,
        )
        shodan_json_file = st.file_uploader(
            "Shodan JSON", type=["json"], label_visibility="collapsed", key="shodan_json_upload"
        )

with upload_col2:
    with st.expander("OpenVAS XML"):
        st.caption("Upload OpenVAS / Greenbone XML to merge verified CVE findings with CONFIRMED evidence strength.")
        openvas_file = st.file_uploader("OpenVAS XML", type=["xml"], label_visibility="collapsed", key="ov_upload")

with upload_col3:
    with st.expander("OWASP ZAP XML"):
        st.caption("Upload OWASP ZAP XML to merge web application layer findings into the risk model.")
        zap_file = st.file_uploader("ZAP XML", type=["xml"], label_visibility="collapsed", key="zap_upload")

with upload_col4:
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
                st.session_state["vulners_count"]  = len(vulners_raw)
                st.session_state["vulners_active"] = vulners_nse_available()

                resolved_ip = socket.gethostbyname(clean_target)

                # ── Shodan source: uploaded JSON takes priority over live API ─
                if shodan_json_file is not None:
                    import json as _json
                    try:
                        raw_shodan_data = _json.loads(shodan_json_file.read())
                        shodan_result   = parse_shodan_json(raw_shodan_data)
                        st.session_state["shodan_source"] = "external_json"
                    except (ValueError, _json.JSONDecodeError) as _e:
                        st.warning(f"Shodan JSON parse error: {_e}  —  falling back to live API scan.")
                        shodan_result = lookup_host(resolved_ip)
                        st.session_state["shodan_source"] = "api"
                else:
                    shodan_result = lookup_host(resolved_ip)
                    st.session_state["shodan_source"] = "api"

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

# ── Main results (only rendered after a scan) ───────────────────────────────

if "findings" in st.session_state:


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

    tab_overview, tab_findings, tab_export = st.tabs(
        ["  Overview  ", "  Findings  ", "  Export  "]
    )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Overview
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_overview:

        # Metric cards — mc2–mc5 are clickable; clicking navigates to a pre-filtered Findings tab
        mc1, mc2, mc3, mc4, mc5 = st.columns(5)
        with mc1:
            st.markdown(metric_card("Total Findings", n_total, "blue"), unsafe_allow_html=True)
        with mc2:
            st.markdown(metric_card("Deal Killers", n_dk, "red"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_dk", use_container_width=True):
                st.session_state["tier_preset"]         = "deal_killer"
                st.session_state["_switch_to_findings"] = True
        with mc3:
            st.markdown(metric_card("Critical", n_crit, "orange"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_crit", use_container_width=True):
                st.session_state["tier_preset"]         = "critical"
                st.session_state["_switch_to_findings"] = True
        with mc4:
            st.markdown(metric_card("Moderate", n_mod, "yellow"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_mod", use_container_width=True):
                st.session_state["tier_preset"]         = "moderate"
                st.session_state["_switch_to_findings"] = True
        with mc5:
            st.markdown(metric_card("Manageable", n_man, "green"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_man", use_container_width=True):
                st.session_state["tier_preset"]         = "manageable"
                st.session_state["_switch_to_findings"] = True

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        # Deal-killer alert banner
        if n_dk:
            st.markdown(f"""
            <div class="dk-alert">
              <div style="font-size:1.5rem; flex-shrink:0;">⚠️</div>
              <div class="dk-alert-body">
                <div class="dk-alert-title">Deal-Killer Findings Detected</div>
                <div class="dk-alert-sub">Immediate escalation required — these findings block deal close</div>
              </div>
              <div class="dk-alert-count">{n_dk}</div>
            </div>""", unsafe_allow_html=True)

        _asset_hosts_loaded = st.session_state.get("asset_hosts", 0)
        if _asset_hosts_loaded:
            st.markdown(f"""
            <div class="inv-notice active">
                <span>✓</span>
                <span><strong>Asset Inventory Active</strong> &nbsp;—&nbsp;
                {_asset_hosts_loaded} hosts classified · Data sensitivity factored into all scores</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="inv-notice warn">
                <span>⚠</span>
                <span><strong>Data Sensitivity Unclassified</strong> &nbsp;—&nbsp;
                All findings default to <code style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">UNKNOWN</code>.
                Upload an asset inventory to unlock the most impactful deal-killer rules.</span>
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
                    labels=labels, values=values, hole=0.70,
                    marker=dict(colors=colors, line=dict(color="#030508", width=4)),
                    textinfo="label+percent",
                    textfont=dict(size=11, color="#5f7ca0", family="JetBrains Mono"),
                    hovertemplate="<b>%{label}</b><br>%{value} findings (%{percent})<extra></extra>",
                ))
                fig.update_layout(
                    showlegend=False,
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=8, b=8, l=8, r=8), height=240,
                    annotations=[dict(
                        text=f"<b>{n_total}</b><br><span style='font-size:10px;color:#243048'>total</span>",
                        x=0.5, y=0.5, font_size=26, font_color="#dce8ff",
                        font=dict(family="JetBrains Mono"), showarrow=False,
                    )],
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

            # Horizontal bar — top findings by score
            top_n = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:8]
            if top_n:
                bar_labels = [f.title[:40] + "…" if len(f.title) > 40 else f.title for f in top_n]
                bar_values = [f.risk_score for f in top_n]
                bar_colors = [score_color(s) for s in bar_values]

                fig2 = go.Figure(go.Bar(
                    x=bar_values, y=bar_labels, orientation="h",
                    marker=dict(color=bar_colors, line=dict(width=0), opacity=0.82),
                    hovertemplate="<b>%{y}</b><br>Risk Score: %{x:.1f}<extra></extra>",
                ))
                fig2.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    xaxis=dict(range=[0, 100], gridcolor="#0e1828", zeroline=False,
                               tickfont=dict(color="#243048", size=10, family="JetBrains Mono"), title=""),
                    yaxis=dict(autorange="reversed",
                               tickfont=dict(color="#5f7ca0", size=10, family="Inter"), title=""),
                    margin=dict(t=0, b=4, l=4, r=4), height=260,
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
            vulners_active  = st.session_state.get("vulners_active", False)
            openvas_count   = st.session_state.get("openvas_count", 0)
            openvas_matched = st.session_state.get("openvas_matched", 0)
            zap_count       = st.session_state.get("zap_count", 0)
            asset_hosts     = st.session_state.get("asset_hosts", 0)
            shodan_ok     = shodan_result.get("success", False)
            shodan_source = st.session_state.get("shodan_source", "api")

            def _ps(dot_cls, name, status, status_cls=""):
                return (f'<div class="rf-pipeline-step">'
                        f'<span class="rf-dot {dot_cls} step-dot"></span>'
                        f'<div class="step-name">{name}</div>'
                        f'<div class="step-status {status_cls}">{status}</div>'
                        f'</div>')

            arrow = '<span class="rf-pipeline-arrow">›</span>'

            nmap_ps = _ps("ok", "Nmap", "done", "ok")
            if vulners_count:
                vuln_ps = _ps("ok",   "Vulners",  f"{vulners_count} CVEs",       "ok")
            elif vulners_active:
                vuln_ps = _ps("warn", "Vulners",  "0 CVEs",                       "warn")
            else:
                vuln_ps = _ps("off",  "Vulners",  "not installed",                "")

            if shodan_ok:
                _sd_lbl = "ext JSON" if shodan_source == "external_json" else "live API"
                shod_ps = _ps("ok",  "Shodan", _sd_lbl, "ok")
            else:
                shod_ps = _ps("err", "Shodan", "unavailable", "")

            ov_ps   = _ps("ok"   if openvas_count else "off",
                          "OpenVAS",
                          f"{openvas_count} findings" if openvas_count else "not uploaded",
                          "ok" if openvas_count else "")
            zap_ps  = _ps("ok"   if zap_count else "off",
                          "ZAP",
                          f"{zap_count} findings" if zap_count else "not uploaded",
                          "ok" if zap_count else "")
            asset_ps = _ps("ok"  if asset_hosts else "warn",
                           "Assets",
                           f"{asset_hosts} hosts" if asset_hosts else "not uploaded",
                           "ok" if asset_hosts else "warn")

            st.markdown(f"""
            <div class="rf-pipeline-h">
              <div class="rf-pipeline-header">Scanner Pipeline</div>
              <div class="rf-pipeline-flow">
                {nmap_ps}{arrow}{vuln_ps}{arrow}{shod_ps}{arrow}{ov_ps}{arrow}{zap_ps}{arrow}{asset_ps}
              </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Shodan snapshot ───────────────────────────────────────────
            if shodan_result.get("success"):
                ports_str    = ", ".join(map(str, shodan_result.get("ports", []))) or "—"
                vuln_count   = len(shodan_result.get("vulns", []))
                org          = shodan_result.get("organization") or "Unknown"
                isp          = shodan_result.get("isp") or "Unknown"
                country      = shodan_result.get("country") or "Unknown"
                city         = shodan_result.get("city") or "Unknown"
                cve_color    = "#f87171" if vuln_count else "#4ade80"
                source_label = (
                    '<span style="font-size:0.58rem;font-family:\'JetBrains Mono\',monospace;'
                    'color:#a78bfa;margin-left:8px;font-weight:700;letter-spacing:0.1em;">TARGET-PROVIDED</span>'
                    if shodan_source == "external_json" else
                    '<span style="font-size:0.58rem;font-family:\'JetBrains Mono\',monospace;'
                    'color:#34d399;margin-left:8px;font-weight:700;letter-spacing:0.1em;">LIVE API</span>'
                )

                st.markdown(f"""
                <div class="rf-shodan">
                  <div class="rf-section-label" style="margin-bottom:10px;">Shodan Snapshot {source_label}</div>
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
                    <span class="rf-shodan-value" style="font-family:'JetBrains Mono',monospace;font-size:0.77rem;">{ports_str}</span>
                  </div>
                  <div class="rf-shodan-row">
                    <span class="rf-shodan-label">CVEs</span>
                    <span class="rf-shodan-value" style="color:{cve_color};font-weight:700;font-family:'JetBrains Mono',monospace;">{vuln_count}</span>
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

            # Apply preset tier filter from metric card click (Overview → Findings navigation)
            if "tier_preset" in st.session_state:
                _preset = st.session_state.pop("tier_preset")
                if _preset in df["Deal Tier"].values:
                    st.session_state["tier_filter_ms"] = [_preset]

            # Filters
            st.markdown('<div class="rf-section-label">Filter Findings</div>', unsafe_allow_html=True)
            fc1, fc2, fc3 = st.columns(3)
            with fc1:
                selected_tiers = st.multiselect(
                    "Deal Tier",
                    options=sorted(df["Deal Tier"].dropna().unique()),
                    default=sorted(df["Deal Tier"].dropna().unique()),
                    key="tier_filter_ms",
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
                            &nbsp;<span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;
                                              color:#243048;">{row['Host']} &nbsp;·&nbsp; :{port_svc} &nbsp;·&nbsp; {row['Scanner']}</span>
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
                              <span style="font-family:'JetBrains Mono',monospace;font-size:0.76rem;
                                           color:#5f7ca0;">{evid_label}</span>
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

            dk_color  = "#f87171" if n_dk   else "#34d399"
            crt_color = "#fb923c" if n_crit else "#243048"

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

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Privacy Policy
    # ══════════════════════════════════════════════════════════════════════════════

    # ── Metric-card → Findings tab navigation ────────────────────────────────────
    # When a "View all ›" button on a metric card is clicked, _switch_to_findings is
    # set to True. We inject a tiny JS snippet (in an invisible iframe) that clicks
    # the Findings tab button inside the parent document. Streamlit renders all tab
    # contents eagerly, so the pre-filtered multiselect is already in the DOM.

    if st.session_state.get("_switch_to_findings"):
        st.session_state["_switch_to_findings"] = False
        import streamlit.components.v1 as _components
        _components.html(
            """<script>
            (function () {
                var parent = window.parent;
                // Findings is the second tab (index 1)
                var tabs = parent.document.querySelectorAll(
                    '[data-testid="stTabs"] button[role="tab"]'
                );
                if (tabs && tabs.length > 1) {
                    tabs[1].click();
                }
            })();
            </script>""",
            height=0,
            scrolling=False,
        )

# ══════════════════════════════════════════════════════════════════════════════
# Footer — Privacy Policy & Contact  (always visible, even before scanning)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown(
    "<hr style='border:none;border-top:1px solid #0d1828;margin:48px 0 0;'>",
    unsafe_allow_html=True,
)

_fp_col, _fc_col, _copy_col = st.columns([4, 4, 4])

with _fp_col:
    with st.expander("\U0001f4c4  Privacy Policy"):
        st.markdown(
            """<div style="padding:6px 0 4px;">
  <div style="font-size:1rem;font-weight:800;color:#dce8ff;
              font-family:'Inter',sans-serif;margin-bottom:3px;">Privacy Policy</div>
  <div style="font-size:0.65rem;color:#243048;font-family:'JetBrains Mono',monospace;
              margin-bottom:16px;">Effective: May 2026 &middot; RedFlag v3</div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#f43f5e;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">01 &middot; Data We Process</div>
    <div style="font-size:0.82rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.75;">
      RedFlag processes only data you explicitly provide: scan targets, uploaded files (OpenVAS, ZAP,
      Shodan JSON, Asset Excel), and scan outputs stored locally in
      <code style="font-family:'JetBrains Mono',monospace;color:#60a5fa;">data/results/</code>.
      <strong style="color:#7a93b8;">No personal data</strong> is collected.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#f43f5e;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">02 &middot; How Data Is Processed</div>
    <div style="font-size:0.82rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.75;">
      All processing is <strong style="color:#7a93b8;">local</strong>. Outbound API calls enrich
      findings only &mdash; <strong style="color:#7a93b8;">Shodan</strong> (1 credit/scan),
      <strong style="color:#7a93b8;">NVD/NIST</strong> (public CVSS),
      <strong style="color:#7a93b8;">CISA KEV</strong> (public feed),
      <strong style="color:#7a93b8;">Vulners</strong> (NSE exploit metadata).
      Each request contains only the IP or CVE ID queried.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#f43f5e;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">03 &middot; Data Retention</div>
    <div style="font-size:0.82rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.75;">
      No data is retained on remote servers. Scan files live only in your local
      <code style="font-family:'JetBrains Mono',monospace;color:#60a5fa;">data/results/</code> folder.
      In-session state clears on restart.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#f43f5e;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">04 &middot; Responsible Use</div>
    <div style="font-size:0.82rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.75;">
      Use RedFlag only against systems you own or have
      <strong style="color:#7a93b8;">explicit written authorisation</strong> to assess.
      The developers accept no liability for misuse.
    </div>
  </div>

  <div>
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#f43f5e;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">05 &middot; Changes &amp; Contact</div>
    <div style="font-size:0.82rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.75;">
      Material changes will be reflected in an updated effective date above.
      Questions? Use the Contact panel.
    </div>
  </div>
</div>""",
            unsafe_allow_html=True,
        )

with _fc_col:
    with st.expander("✉️  Contact"):
        st.markdown(
            """<div style="padding:6px 0 4px;">
  <div style="font-size:1rem;font-weight:800;color:#dce8ff;
              font-family:'Inter',sans-serif;margin-bottom:3px;">Get in Touch</div>
  <div style="font-size:0.65rem;color:#243048;font-family:'JetBrains Mono',monospace;
              margin-bottom:14px;">RedFlag &middot; M&amp;A Cybersecurity Intelligence</div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:16px;">
    <div style="background:linear-gradient(145deg,#080d1c,#060a16);
                border:1px solid #0e1828;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128737;&#65039;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#dce8ff;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Security Questions</div>
      <div style="font-size:0.75rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.55;">
        Methodology, scoring, M&amp;A interpretation.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#080d1c,#060a16);
                border:1px solid #0e1828;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#129309;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#dce8ff;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Partnerships</div>
      <div style="font-size:0.75rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.55;">
        Enterprise, white-label, advisory.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#080d1c,#060a16);
                border:1px solid #0e1828;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128027;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#dce8ff;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Bug Reports</div>
      <div style="font-size:0.75rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.55;">
        Unexpected behaviour or feature ideas.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#080d1c,#060a16);
                border:1px solid #0e1828;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128203;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#dce8ff;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Privacy Enquiries</div>
      <div style="font-size:0.75rem;color:#5f7ca0;font-family:'Inter',sans-serif;line-height:1.55;">
        Questions about how RedFlag handles data.
      </div>
    </div>
  </div>

  <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#97;&#100;&#105;&#116;&#121;&#97;&#97;&#118;&#101;&#108;&#48;&#48;&#55;&#64;&#103;&#109;&#97;&#105;&#108;&#46;&#99;&#111;&#109;"
     style="display:block;text-align:center;
            background:linear-gradient(160deg,#f43f5e,#9f1239);
            color:#fff;text-decoration:none;font-family:'Inter',sans-serif;
            font-weight:700;font-size:0.83rem;letter-spacing:0.05em;
            padding:11px 20px;border-radius:10px;
            box-shadow:0 4px 22px rgba(244,63,94,0.4);margin-bottom:14px;">
    &#9993;&nbsp; Send Message
  </a>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
    <div style="font-size:0.76rem;color:#5f7ca0;font-family:'Inter',sans-serif;">
      <span style="color:#34d399;font-weight:700;">General enquiries</span><br>Within 2 business days
    </div>
    <div style="font-size:0.76rem;color:#5f7ca0;font-family:'Inter',sans-serif;">
      <span style="color:#fbbf24;font-weight:700;">Security / critical</span><br>Within 24 hours
    </div>
  </div>
</div>""",
            unsafe_allow_html=True,
        )

with _copy_col:
    st.markdown(
        "<div style='display:flex;align-items:center;justify-content:flex-end;"
        "padding-top:18px;'>"
        "<span style='font-size:0.6rem;font-family:\"JetBrains Mono\",monospace;"
        "color:#182236;letter-spacing:0.1em;'>"
        "&#169; 2026 RedFlag &nbsp;&middot;&nbsp; M&amp;A Cybersecurity Intelligence"
        "</span></div>",
        unsafe_allow_html=True,
    )
