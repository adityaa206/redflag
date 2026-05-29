import socket
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from reports.generator import export_findings_csv
from reports.pdf_report import generate_pdf_report, generate_cost_section
from scanners.nmap_scan import run_nmap_scan, vulners_nse_available
from analysis.parser import analyze_nmap_file
from analysis.triage import triage_all
from scanners.shodan_scan import lookup_host, enrich_findings_with_shodan, create_shodan_findings, parse_shodan_json
from scanners.openvas_parse import parse_openvas_xml, merge_openvas_with_nmap
from scanners.vulners_parse import parse_vulners_from_nmap_xml, merge_vulners_with_nmap
from scanners.zap_scan import parse_zap_xml, merge_zap_with_nmap
from analysis.parsers.excel_assets import parse_asset_excel, apply_sensitivity_to_findings
from analysis.maturity import run_assessment, get_all_domains, get_domain_questions, MaturityGapSeverity
from analysis.standards_compare import compare_to_standard
from cost.rollup import run_cost_pipeline
from cost.schema import ScenarioType, ReviewFlag
from narrative.engine import build_executive_summary, build_maturity_narrative, build_cost_narrative


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
   REDFLAG  —  Design System v4
   Fonts  : JetBrains Mono + Inter
   Palette: Deep navy · Signal red · Electric blue
══════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* ── Base ── */
[data-testid="stAppViewContainer"] { background: #080c14 !important; }
[data-testid="stHeader"]           { display: none !important; }
[data-testid="stMainBlockContainer"] { padding-top: 0 !important; max-width: 100% !important; }
[data-testid="stAppViewBlockContainer"] { padding: 0 2rem !important; }
html, body, [class*="css"],
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
.stCheckbox label, .stSlider label, .stMultiSelect label,
.stCaption, .stAlert p, button { font-family: 'Inter', -apple-system, sans-serif !important; }

/* ── TOP NAVBAR ── */
.rf-topnav {
    display: flex; align-items: center; padding: 0 24px;
    height: 56px; background: #0a0f1c;
    border-bottom: 1px solid #141d2e;
    margin: 0 -2rem 20px; gap: 0;
    position: sticky; top: 0; z-index: 999;
}
.rf-brand {
    display: flex; align-items: center; gap: 10px; margin-right: 36px; text-decoration: none;
}
.rf-brand-icon {
    width: 30px; height: 30px; background: linear-gradient(135deg, #e6394a 0%, #9f1239 100%);
    border-radius: 7px; display: flex; align-items: center; justify-content: center;
    font-size: 0.7rem; color: white; font-weight: 900;
    box-shadow: 0 2px 14px rgba(230,57,74,0.45);
}
.rf-brand-name {
    font-size: 1.2rem; font-weight: 800; color: #e8f0ff;
    letter-spacing: -0.03em; font-family: 'Inter', sans-serif; line-height: 1;
}
.rf-nav { display: flex; align-items: center; gap: 2px; flex: 1; }
.rf-nav-link {
    padding: 7px 15px; border-radius: 8px; font-size: 0.84rem; font-weight: 500;
    color: #3a5070; cursor: default; transition: color 0.15s ease;
    display: inline-flex; align-items: center; gap: 5px;
    font-family: 'Inter', sans-serif; border: none; background: none;
}
.rf-nav-link:hover { color: #6a87a8; }
.rf-nav-link.active {
    color: #c8daf5; position: relative;
}
.rf-nav-link.active::after {
    content: ''; position: absolute; bottom: -1px; left: 15px; right: 15px;
    height: 2px; background: #3d7fff; border-radius: 1px;
}
.rf-nav-right { display: flex; align-items: center; gap: 10px; }

/* ── METRIC CARDS ── */
.rf-metric {
    background: #0f1623;
    border: 1px solid #1a2640;
    border-radius: 14px;
    padding: 18px 16px 20px;
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
.rf-metric:hover { transform: translateY(-3px); }
.rf-metric .label {
    font-size: 0.58rem; font-weight: 700; letter-spacing: 0.18em;
    text-transform: uppercase; color: #2d4060; margin-bottom: 10px;
    font-family: 'JetBrains Mono', monospace;
}
.rf-metric .value {
    font-size: 2.6rem; font-weight: 700; line-height: 1;
    font-family: 'JetBrains Mono', monospace; letter-spacing: -0.03em;
}
.rf-metric.red::before    { background: linear-gradient(90deg, #e6394a, #9f1239); }
.rf-metric.red .value     { color: #e6394a; }
.rf-metric.red:hover      { box-shadow: 0 8px 32px rgba(230,57,74,0.2); border-color: rgba(230,57,74,0.2); }
.rf-metric.orange::before { background: linear-gradient(90deg, #f97316, #c2410c); }
.rf-metric.orange .value  { color: #f97316; }
.rf-metric.orange:hover   { box-shadow: 0 8px 32px rgba(249,115,22,0.18); border-color: rgba(249,115,22,0.2); }
.rf-metric.yellow::before { background: linear-gradient(90deg, #f59e0b, #b45309); }
.rf-metric.yellow .value  { color: #f59e0b; }
.rf-metric.yellow:hover   { box-shadow: 0 8px 32px rgba(245,158,11,0.15); border-color: rgba(245,158,11,0.18); }
.rf-metric.green::before  { background: linear-gradient(90deg, #10b981, #065f46); }
.rf-metric.green .value   { color: #10b981; }
.rf-metric.green:hover    { box-shadow: 0 8px 32px rgba(16,185,129,0.16); border-color: rgba(16,185,129,0.18); }
.rf-metric.blue::before   { background: linear-gradient(90deg, #3d7fff, #1d4ed8); }
.rf-metric.blue .value    { color: #6fa3ff; }
.rf-metric.blue:hover     { box-shadow: 0 8px 32px rgba(61,127,255,0.18); border-color: rgba(61,127,255,0.18); }

/* ── SECTION LABEL ── */
.rf-section-label {
    font-family: 'JetBrains Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.2em; text-transform: uppercase; color: #2d4060;
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 12px; margin-top: 4px;
}
.rf-section-label::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, #141d2e 0%, transparent 100%);
}

/* ── BADGES ── */
.badge {
    display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 5px;
    font-size: 0.59rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
}
.badge-dk   { background: rgba(230,57,74,0.12);  color: #f87171; border: 1px solid rgba(230,57,74,0.3); }
.badge-crit { background: rgba(249,115,22,0.12); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }
.badge-mod  { background: rgba(245,158,11,0.1);  color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }
.badge-man  { background: rgba(16,185,129,0.1);  color: #10b981; border: 1px solid rgba(16,185,129,0.25); }
.badge-unk  { background: rgba(107,114,128,0.08);color: #6b7280; border: 1px solid rgba(107,114,128,0.2); }
.badge-inet { background: rgba(61,127,255,0.1);  color: #6fa3ff; border: 1px solid rgba(61,127,255,0.3); }
.badge-part { background: rgba(167,139,250,0.1); color: #a78bfa; border: 1px solid rgba(124,58,237,0.3); }
.badge-int  { background: rgba(16,185,129,0.08); color: #10b981; border: 1px solid rgba(16,185,129,0.22); }
.badge-ukn  { background: rgba(107,114,128,0.08);color: #6b7280; border: 1px solid rgba(55,65,81,0.22); }

/* ── FINDING CARDS ── */
@keyframes pulse-dk {
    0%,100% { box-shadow: 0 0 0 0 rgba(230,57,74,0.25); }
    50%      { box-shadow: 0 0 0 4px rgba(230,57,74,0); }
}
.finding-card {
    background: #0f1623;
    border: 1px solid #1a2640;
    border-left: 3px solid #1a2640;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 8px;
    transition: background 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
}
.finding-card:hover { background: #131a27; }
.finding-card.dk   { border-left-color: #e6394a; animation: pulse-dk 3s ease-in-out infinite; }
.finding-card.crit { border-left-color: #f97316; }
.finding-card.mod  { border-left-color: #f59e0b; }
.finding-card.man  { border-left-color: #10b981; }
.finding-card.dk:hover   { border-color: rgba(230,57,74,0.25);  box-shadow: 0 4px 24px rgba(230,57,74,0.12); }
.finding-card.crit:hover { border-color: rgba(249,115,22,0.25); box-shadow: 0 4px 24px rgba(249,115,22,0.10); }
.finding-card.mod:hover  { border-color: rgba(245,158,11,0.22); box-shadow: 0 4px 20px rgba(245,158,11,0.07); }
.finding-card.man:hover  { border-color: rgba(16,185,129,0.2);  box-shadow: 0 4px 20px rgba(16,185,129,0.07); }
.finding-card h4 {
    color: #c8daf5; font-size: 0.94rem; font-weight: 600;
    margin: 0 0 7px; font-family: 'Inter', sans-serif;
    line-height: 1.45; letter-spacing: -0.01em;
}
.finding-card .meta {
    color: #3a5070; font-size: 0.76rem; margin-bottom: 12px;
    display: flex; gap: 8px; flex-wrap: wrap; align-items: center;
}
.finding-card .fc-divider { border: none; border-top: 1px solid #141d2e; margin: 11px 0; }
.finding-card .field-label {
    color: #2d4060; font-size: 0.57rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.15em;
    margin-bottom: 4px; font-family: 'JetBrains Mono', monospace;
}
.finding-card .field-value { color: #4a6080; font-size: 0.83rem; margin-bottom: 10px; line-height: 1.65; }
.finding-card .score-pill {
    background: #0a0f1c; border: 1px solid #1a2640; border-radius: 10px;
    padding: 12px 14px; text-align: center; min-width: 70px; flex-shrink: 0;
}
.finding-card .score-pill .s-label {
    color: #2d4060; font-size: 0.55rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.15em; font-family: 'JetBrains Mono', monospace;
    display: block; margin-bottom: 4px;
}
.finding-card .score-pill .s-value {
    font-size: 1.75rem; font-weight: 700; font-family: 'JetBrains Mono', monospace;
    line-height: 1; letter-spacing: -0.03em;
}

/* ── MINI FINDING CARDS (Overview right panel) ── */
.fmc {
    background: #0f1623; border: 1px solid #1a2640; border-left: 3px solid #1a2640;
    border-radius: 10px; padding: 12px 16px; margin-bottom: 6px;
    display: flex; align-items: flex-start; gap: 12px;
    transition: background 0.15s ease;
}
.fmc:hover { background: #131a27; }
.fmc.dk   { border-left-color: #e6394a; }
.fmc.crit { border-left-color: #f97316; }
.fmc.mod  { border-left-color: #f59e0b; }
.fmc.man  { border-left-color: #10b981; }
.fmc-icon {
    width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.8rem; background: #141d2e;
}
.fmc-icon.dk   { background: rgba(230,57,74,0.1); }
.fmc-icon.crit { background: rgba(249,115,22,0.1); }
.fmc-icon.mod  { background: rgba(245,158,11,0.08); }
.fmc-icon.man  { background: rgba(16,185,129,0.08); }
.fmc-body { flex: 1; min-width: 0; }
.fmc-title {
    font-size: 0.83rem; font-weight: 600; color: #c8daf5;
    font-family: 'Inter', sans-serif; margin-bottom: 4px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.fmc-desc {
    font-size: 0.74rem; color: #3a5070; font-family: 'Inter', sans-serif;
    line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 1;
    -webkit-box-orient: vertical; overflow: hidden;
}
.fmc-meta {
    display: flex; align-items: center; gap: 6px; margin-top: 4px;
}
.fmc-port {
    font-family: 'JetBrains Mono', monospace; font-size: 0.66rem; color: #2d4060;
}
.fmc-score {
    font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; font-weight: 700;
    margin-left: auto;
}

/* ── STATUS DOTS ── */
.rf-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; flex-shrink: 0;
}
@keyframes warn-blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.rf-dot.ok   { background: #10b981; box-shadow: 0 0 7px rgba(16,185,129,0.9); }
.rf-dot.warn { background: #f59e0b; box-shadow: 0 0 7px rgba(245,158,11,0.9); animation: warn-blink 2s infinite; }
.rf-dot.err  { background: #e6394a; box-shadow: 0 0 7px rgba(230,57,74,0.9); }
.rf-dot.off  { background: #1e2d45; }

/* ── SCANNER PIPELINE ── */
.rf-pipeline-h {
    background: #0f1623; border: 1px solid #1a2640;
    border-radius: 14px; padding: 16px 20px 14px; margin-bottom: 12px;
}
.rf-pipeline-header {
    font-family: 'JetBrains Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.2em; text-transform: uppercase; color: #2d4060;
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #141d2e;
    display: flex; align-items: center; gap: 8px;
}
.rf-pipeline-flow {
    display: flex; align-items: center; justify-content: space-between;
    position: relative; gap: 0;
}
.rf-pipeline-flow::before {
    content: ''; position: absolute; top: 11px; left: 28px; right: 28px;
    height: 1px; background: linear-gradient(90deg, #1e2d45, #2a3f60 50%, #1e2d45);
    z-index: 0;
}
.rf-pipeline-step {
    display: flex; flex-direction: column; align-items: center; gap: 6px;
    padding: 0 8px; z-index: 1; background: #0f1623; min-width: 60px;
    cursor: default;
}
.rf-pipeline-step .step-dot { margin-bottom: 0; }
.rf-pipeline-step .step-name {
    font-family: 'JetBrains Mono', monospace; font-size: 0.67rem; font-weight: 600;
    color: #4a6080; white-space: nowrap;
}
.rf-pipeline-step .step-status {
    font-size: 0.6rem; color: #2d4060; font-family: 'Inter', sans-serif;
    white-space: nowrap; text-align: center;
}
.rf-pipeline-step .step-status.ok   { color: #10b981; }
.rf-pipeline-step .step-status.warn { color: #f59e0b; }
.rf-pipeline-arrow {
    color: #1e2d45; font-size: 0.8rem; padding-top: 14px; flex-shrink: 0;
}

/* ── TARGET / INFO PANEL ── */
.rf-target-panel {
    background: #0f1623; border: 1px solid #1a2640;
    border-radius: 12px; padding: 14px 16px 8px; margin-bottom: 10px;
}
.rf-tp-row {
    display: grid; grid-template-columns: 86px 1fr;
    align-items: baseline; margin-bottom: 9px; gap: 8px;
}
.rf-tp-label {
    font-family: 'JetBrains Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.15em; text-transform: uppercase; color: #2d4060;
}
.rf-tp-value {
    font-size: 0.83rem; color: #c8daf5;
    font-family: 'JetBrains Mono', monospace; word-break: break-all;
}

/* ── SHODAN SNAPSHOT ── */
.rf-shodan {
    background: #0c1422; border: 1px solid #1e3050;
    border-left: 3px solid #3d7fff; border-radius: 12px; padding: 14px 16px 8px;
}
.rf-shodan-row {
    display: grid; grid-template-columns: 90px 1fr;
    align-items: baseline; margin-bottom: 9px; gap: 8px;
}
.rf-shodan-label {
    font-family: 'JetBrains Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.15em; text-transform: uppercase; color: #2d4060;
}
.rf-shodan-value { font-size: 0.83rem; color: #7a91b3; font-family: 'Inter', sans-serif; }

/* ── DEAL-KILLER ALERT BANNER ── */
.dk-alert {
    background: linear-gradient(135deg, rgba(230,57,74,0.07), rgba(159,18,57,0.04));
    border: 1px solid rgba(230,57,74,0.2);
    border-left: 4px solid #e6394a;
    border-radius: 12px; padding: 14px 18px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 14px;
}
.dk-alert-body { flex: 1; }
.dk-alert-title { font-size: 0.84rem; font-weight: 700; color: #e6394a; font-family: 'Inter', sans-serif; margin-bottom: 2px; }
.dk-alert-sub   { font-size: 0.77rem; color: rgba(230,57,74,0.6); font-family: 'Inter', sans-serif; }
.dk-alert-count { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; color: #e6394a; line-height: 1; flex-shrink: 0; }

/* ── ASSET INVENTORY NOTICE ── */
.inv-notice {
    border-radius: 10px; padding: 11px 16px; margin-bottom: 16px;
    font-size: 0.82rem; font-family: 'Inter', sans-serif;
    display: flex; align-items: center; gap: 10px;
}
.inv-notice.active { background: rgba(16,185,129,0.05); border: 1px solid rgba(16,185,129,0.2); border-left: 3px solid #10b981; color: #10b981; }
.inv-notice.warn   { background: rgba(245,158,11,0.04);  border: 1px solid rgba(245,158,11,0.18); border-left: 3px solid #f59e0b; color: #f59e0b; }

/* ── DIVIDERS ── */
.rf-divider { border: none; border-top: 1px solid #141d2e; margin: 14px 0; }

/* ── SCAN INPUT ── */
[data-testid="stTextInput"] input {
    background: #0f1623 !important; border: 1px solid #1e2d45 !important;
    border-radius: 12px !important; color: #e8f0ff !important;
    font-size: 0.93rem !important; font-family: 'Inter', sans-serif !important;
    padding: 13px 18px !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #3d7fff !important;
    box-shadow: 0 0 0 3px rgba(61,127,255,0.15) !important;
}
[data-testid="stTextInput"] input::placeholder { color: #2d4060 !important; }
[data-testid="stTextInput"] label {
    color: #2d4060 !important; font-size: 0.57rem !important; font-weight: 700 !important;
    letter-spacing: 0.18em !important; text-transform: uppercase !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── PRIMARY BUTTON ── */
[data-testid="stButton"] > button[kind="primary"],
[data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #3d7fff 0%, #1d4ed8 100%) !important;
    border: 1px solid rgba(61,127,255,0.4) !important;
    border-radius: 10px !important; font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important; font-size: 0.86rem !important; color: white !important;
    box-shadow: 0 4px 20px rgba(61,127,255,0.35) !important;
    transition: box-shadow 0.15s ease, transform 0.12s ease !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover {
    box-shadow: 0 6px 28px rgba(61,127,255,0.55) !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] > button[kind="primary"]:active,
[data-testid="stBaseButton-primary"]:active { transform: translateY(0) !important; }

/* ── DOWNLOAD BUTTONS ── */
[data-testid="stDownloadButton"] > button {
    background: #0f1623 !important; border: 1px solid #1e2d45 !important;
    border-radius: 10px !important; color: #4a6080 !important;
    font-family: 'Inter', sans-serif !important; font-weight: 500 !important;
    transition: all 0.15s ease !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #3d7fff !important; color: #6fa3ff !important;
    box-shadow: 0 2px 18px rgba(61,127,255,0.2) !important;
}

/* ── TABS ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid #141d2e !important;
    gap: 0 !important; background: transparent !important;
}
[data-testid="stTabs"] button[role="tab"] {
    font-family: 'Inter', sans-serif !important; font-weight: 500 !important;
    font-size: 0.84rem !important; color: #3a5070 !important;
    letter-spacing: 0.02em !important; padding: 12px 24px !important;
    border-bottom: 2px solid transparent !important;
    transition: color 0.15s ease !important;
    background: transparent !important; border-radius: 0 !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    color: #e8f0ff !important; border-bottom-color: #3d7fff !important;
}
[data-testid="stTabs"] button[role="tab"]:hover { color: #7a91b3 !important; }

/* ── EXPANDERS ── */
[data-testid="stExpander"] details {
    background: #0f1623 !important; border: 1px solid #1e2d45 !important;
    border-radius: 12px !important; transition: border-color 0.15s ease !important;
}
[data-testid="stExpander"] details:hover {
    border-color: #2a3f60 !important;
}
[data-testid="stExpander"] details[open] {
    border-color: #3d7fff44 !important;
}
[data-testid="stExpander"] summary {
    font-family: 'Inter', sans-serif !important; font-weight: 600 !important;
    font-size: 0.84rem !important; color: #7a91b3 !important; padding: 14px 18px !important;
}
[data-testid="stExpander"] summary:hover { color: #c8daf5 !important; }
[data-testid="stExpander"] details > div { padding: 2px 18px 16px !important; }
[data-testid="stExpander"] [data-testid="stCaptionContainer"] p {
    color: #2d4060 !important; font-family: 'Inter', sans-serif !important;
    font-size: 0.75rem !important; letter-spacing: 0 !important;
}

/* ── FILE UPLOADER ── */
[data-testid="stFileUploader"] section {
    background: #080c14 !important; border: 1px dashed #1e2d45 !important;
    border-radius: 10px !important;
}
[data-testid="stFileUploader"] section:hover {
    border-color: #3d7fff !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] {
    color: #2d4060 !important; font-family: 'Inter', sans-serif !important;
    font-size: 0.78rem !important;
}

/* ── SCAN HERO INPUT (override for the borderless look) ── */
.scan-hero [data-testid="stTextInput"] input {
    background: #080c14 !important;
    border: 1px solid #253555 !important;
    border-radius: 10px !important;
    font-size: 1rem !important;
    padding: 14px 20px !important;
    height: 50px !important;
}
.scan-hero [data-testid="stTextInput"] input:focus {
    border-color: #3d7fff !important;
    box-shadow: 0 0 0 3px rgba(61,127,255,0.12) !important;
}

/* ── MULTISELECT ── */
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
    background: #0f1623 !important; border-color: #1e2d45 !important;
    border-radius: 10px !important;
}

/* ── CHECKBOX ── */
[data-testid="stCheckbox"] label {
    font-size: 0.85rem !important; color: #4a6080 !important;
    font-family: 'Inter', sans-serif !important;
}

/* ── CAPTION ── */
[data-testid="stCaptionContainer"] p {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.71rem !important; color: #2d4060 !important; letter-spacing: 0.02em !important;
}

/* ── ALERTS ── */
[data-testid="stAlertContainer"] { border-radius: 10px !important; }

/* ── METRIC CARD — clickable view buttons ── */
/* ghost "View all ›" links under each metric card (5-col row) */
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button,
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondaryFormSubmit"] button {
    background:     transparent !important;
    border:         none !important;
    box-shadow:     none !important;
    color:          #253555 !important;
    font-size:      0.6rem !important;
    font-family:    'JetBrains Mono', monospace !important;
    font-weight:    700 !important;
    letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
    padding:        6px 0 4px !important;
    margin-top:     0 !important;
    width:          100% !important;
    min-height:     0 !important;
    height:         auto !important;
    transition:     color 0.15s ease !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button:hover {
    color: #6fa3ff !important; background: transparent !important;
    box-shadow: none !important; transform: none !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    > div:first-child [data-testid="stBaseButton-secondary"] { display: none; }

/* ── ENGINE PILLS (navbar right) ── */
.rf-engine-pills {
    display: flex; gap: 4px; align-items: center; margin-right: 16px;
}
.rf-epill {
    font-family: 'JetBrains Mono', monospace; font-size: 0.58rem; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    color: #2d4060; background: #0f1623; border: 1px solid #1a2640;
    border-radius: 5px; padding: 4px 9px;
    transition: color 0.15s ease, border-color 0.15s ease;
}
.rf-epill:hover { color: #4a6080; border-color: #253555; }
.rf-status-dot-wrap {
    display: flex; align-items: center; gap: 6px;
    padding: 5px 12px; background: rgba(16,185,129,0.06);
    border: 1px solid rgba(16,185,129,0.15); border-radius: 20px;
}

/* ── SCAN HERO ── */
.rf-scan-hero {
    position: relative; overflow: hidden;
    background: linear-gradient(135deg, #0c1526 0%, #090e1c 60%, #080c14 100%);
    border: 1px solid #1a2640; border-radius: 18px;
    padding: 24px 28px 12px; margin-bottom: 18px;
}
.rf-hero-svg {
    position: absolute; right: 0; top: 0; bottom: 0;
    height: 100%; width: 42%; opacity: 0.9;
    pointer-events: none;
}
.rf-hero-glow {
    position: absolute; border-radius: 50%;
    pointer-events: none; filter: blur(60px);
}
.rf-hero-glow-blue {
    width: 280px; height: 180px;
    background: radial-gradient(circle, rgba(61,127,255,0.12) 0%, transparent 70%);
    right: 10%; top: -30px;
}
.rf-hero-glow-red {
    width: 200px; height: 160px;
    background: radial-gradient(circle, rgba(230,57,74,0.08) 0%, transparent 70%);
    right: 30%; bottom: -20px;
}
.rf-hero-content {
    position: relative; z-index: 2;
    max-width: 62%;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #080c14; }
::-webkit-scrollbar-thumb { background: #1a2640; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #253555; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

TIER_COLOR = {
    "deal_killer": "#e6394a",
    "critical":    "#f97316",
    "moderate":    "#f59e0b",
    "manageable":  "#10b981",
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
    if score >= 75: return "#e6394a"
    if score >= 50: return "#f97316"
    if score >= 25: return "#f59e0b"
    return "#10b981"

def format_label(value):
    if value is None: return "—"
    return str(value).replace("_", " ").title()


# ── Header ────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="rf-topnav">
  <!-- Brand -->
  <div class="rf-brand">
    <div class="rf-brand-icon">▶</div>
    <span class="rf-brand-name">RedFlag</span>
  </div>

  <!-- Nav links -->
  <nav class="rf-nav">
    <span class="rf-nav-link active">&#9679; Scan</span>
    <span class="rf-nav-link">&#128196; Reports</span>
    <span class="rf-nav-link">&#128193; Inventories</span>
    <span class="rf-nav-link">&#9881; Settings</span>
  </nav>

  <!-- Right: engine status pills -->
  <div class="rf-nav-right">
    <div class="rf-engine-pills">
      <span class="rf-epill">Nmap</span>
      <span class="rf-epill">Vulners</span>
      <span class="rf-epill">Shodan</span>
      <span class="rf-epill">OpenVAS</span>
      <span class="rf-epill">ZAP</span>
    </div>
    <div class="rf-status-dot-wrap">
      <span class="rf-dot ok" style="width:7px;height:7px;"></span>
      <span style="font-size:0.62rem;font-family:'JetBrains Mono',monospace;color:#10b981;
                   font-weight:600;letter-spacing:0.06em;">All systems operational</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Scan controls ─────────────────────────────────────────────────────────────

# Scan hero area — network SVG background
st.markdown("""
<div class="rf-scan-hero">

  <!-- Decorative SVG network graph (right side) -->
  <svg class="rf-hero-svg" viewBox="0 0 480 160" xmlns="http://www.w3.org/2000/svg"
       fill="none" aria-hidden="true">
    <!-- Connection lines -->
    <line x1="60"  y1="40"  x2="160" y2="80"  stroke="#1e3050" stroke-width="1"/>
    <line x1="60"  y1="40"  x2="200" y2="20"  stroke="#1e3050" stroke-width="1"/>
    <line x1="160" y1="80"  x2="280" y2="50"  stroke="#1e3050" stroke-width="1"/>
    <line x1="160" y1="80"  x2="240" y2="130" stroke="#1e3050" stroke-width="1"/>
    <line x1="200" y1="20"  x2="280" y2="50"  stroke="#1e3050" stroke-width="1"/>
    <line x1="280" y1="50"  x2="380" y2="30"  stroke="#1e3050" stroke-width="1"/>
    <line x1="280" y1="50"  x2="360" y2="100" stroke="#1e3050" stroke-width="1"/>
    <line x1="240" y1="130" x2="360" y2="100" stroke="#1e3050" stroke-width="1"/>
    <line x1="380" y1="30"  x2="450" y2="70"  stroke="#1e3050" stroke-width="1"/>
    <line x1="360" y1="100" x2="450" y2="70"  stroke="#1e3050" stroke-width="1"/>
    <line x1="160" y1="80"  x2="200" y2="20"  stroke="#253555" stroke-width="0.5"/>
    <line x1="60"  y1="40"  x2="100" y2="120" stroke="#1a2640" stroke-width="1"/>
    <line x1="100" y1="120" x2="240" y2="130" stroke="#1a2640" stroke-width="1"/>
    <!-- Highlighted path (blue) -->
    <line x1="60"  y1="40"  x2="160" y2="80"  stroke="#3d7fff" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.4"/>
    <line x1="160" y1="80"  x2="280" y2="50"  stroke="#3d7fff" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.4"/>
    <line x1="280" y1="50"  x2="380" y2="30"  stroke="#3d7fff" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.4"/>
    <!-- Red threat path -->
    <line x1="240" y1="130" x2="360" y2="100" stroke="#e6394a" stroke-width="1" opacity="0.35"/>
    <!-- Nodes — outer ring -->
    <circle cx="60"  cy="40"  r="5"   fill="#0f1623" stroke="#2a3f60" stroke-width="1.5"/>
    <circle cx="200" cy="20"  r="4"   fill="#0f1623" stroke="#1e3050" stroke-width="1"/>
    <circle cx="100" cy="120" r="3.5" fill="#0f1623" stroke="#1e3050" stroke-width="1"/>
    <circle cx="380" cy="30"  r="4"   fill="#0f1623" stroke="#1e3050" stroke-width="1"/>
    <circle cx="450" cy="70"  r="5"   fill="#0f1623" stroke="#2a3f60" stroke-width="1.5"/>
    <!-- Nodes — inner -->
    <circle cx="160" cy="80"  r="7"   fill="#0f1623" stroke="#3d7fff" stroke-width="1.5"/>
    <circle cx="280" cy="50"  r="7"   fill="#0f1623" stroke="#3d7fff" stroke-width="1.5"/>
    <!-- Threat node (red) -->
    <circle cx="240" cy="130" r="6"   fill="#120a0e"  stroke="#e6394a" stroke-width="1.5"/>
    <circle cx="360" cy="100" r="5"   fill="#120a0e"  stroke="#e6394a" stroke-width="1"/>
    <!-- Glow on primary nodes -->
    <circle cx="160" cy="80"  r="14"  fill="#3d7fff" opacity="0.05"/>
    <circle cx="280" cy="50"  r="14"  fill="#3d7fff" opacity="0.05"/>
    <circle cx="240" cy="130" r="12"  fill="#e6394a" opacity="0.07"/>
    <!-- Node dots (inner fill) -->
    <circle cx="60"  cy="40"  r="2"   fill="#3d7fff" opacity="0.7"/>
    <circle cx="160" cy="80"  r="3"   fill="#3d7fff"/>
    <circle cx="280" cy="50"  r="3"   fill="#3d7fff"/>
    <circle cx="450" cy="70"  r="2"   fill="#4a6080"/>
    <circle cx="200" cy="20"  r="1.5" fill="#4a6080"/>
    <circle cx="380" cy="30"  r="1.5" fill="#4a6080"/>
    <circle cx="100" cy="120" r="1.5" fill="#4a6080"/>
    <circle cx="240" cy="130" r="2.5" fill="#e6394a"/>
    <circle cx="360" cy="100" r="2"   fill="#e6394a" opacity="0.8"/>
  </svg>

  <!-- Glow blobs -->
  <div class="rf-hero-glow rf-hero-glow-blue"></div>
  <div class="rf-hero-glow rf-hero-glow-red"></div>

  <!-- Content -->
  <div class="rf-hero-content">
    <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.22em;text-transform:uppercase;
                color:#2d4060;font-family:'JetBrains Mono',monospace;margin-bottom:12px;">
      M&amp;A Cybersecurity Intelligence &nbsp;·&nbsp; Scan Target
    </div>
""", unsafe_allow_html=True)

scan_col1, scan_col2, scan_col3 = st.columns([6, 2, 1])
with scan_col1:
    target = st.text_input(
        "TARGET_LABEL",
        value="scanme.nmap.org",
        placeholder="Target Domain or IP... (e.g., scanme.nmap.org)",
        label_visibility="collapsed",
    )
with scan_col2:
    run_scan = st.button("Run Comprehensive Scan", use_container_width=True, type="primary")
with scan_col3:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    fast_mode = st.checkbox("Fast Scan Mode", value=False,
                            help="Top 200 ports · version-intensity 3 · ~2x faster. May miss uncommon ports.")

st.markdown("</div></div>", unsafe_allow_html=True)

# Upload section — styled cards instead of plain expanders
st.markdown("""
<div style="font-size:0.56rem;font-weight:700;letter-spacing:0.2em;text-transform:uppercase;
            color:#2d4060;font-family:'JetBrains Mono',monospace;margin:16px 0 10px;
            display:flex;align-items:center;gap:10px;">
  Optional Intelligence Sources
  <div style="flex:1;height:1px;background:linear-gradient(90deg,#141d2e,transparent);"></div>
</div>
""", unsafe_allow_html=True)
upload_col1, upload_col2, upload_col3, upload_col4 = st.columns(4)

with upload_col1:
    with st.expander("🔍  Shodan JSON"):
        st.caption("Target-provided Shodan export — replaces live API, 0 credits consumed.")
        shodan_json_file = st.file_uploader(
            "Shodan JSON", type=["json"], label_visibility="collapsed", key="shodan_json_upload"
        )

with upload_col2:
    with st.expander("🛡  OpenVAS XML"):
        st.caption("Merge verified CVE findings with CONFIRMED evidence strength.")
        openvas_file = st.file_uploader("OpenVAS XML", type=["xml"], label_visibility="collapsed", key="ov_upload")

with upload_col3:
    with st.expander("🕷  OWASP ZAP XML"):
        st.caption("Merge web application layer findings into the risk model.")
        zap_file = st.file_uploader("ZAP XML", type=["xml"], label_visibility="collapsed", key="zap_upload")

with upload_col4:
    with st.expander("📋  Asset Inventory"):
        st.caption("Map host IPs to Crown Jewel / Regulated / Sensitive tiers. Unlocks deal-killer rules.")
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

    tab_overview, tab_findings, tab_maturity, tab_cost, tab_export = st.tabs(
        ["  Overview  ", "  Findings  ", "  Maturity Assessment  ", "  Cost & Budget  ", "  Export  "]
    )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Overview
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_overview:

        # ── Metric cards row (5 cols) ─────────────────────────────────────────
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

        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

        # ── Deal-killer alert banner ──────────────────────────────────────────
        if n_dk:
            st.markdown(f"""
            <div class="dk-alert">
              <div style="font-size:1.4rem;flex-shrink:0;">⚠️</div>
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
                All findings default to <code style="font-family:'JetBrains Mono',monospace;font-size:0.77rem;">UNKNOWN</code>.
                Upload an asset inventory to unlock the most impactful deal-killer rules.</span>
            </div>""", unsafe_allow_html=True)

        # ── Two-panel layout: left (chart+summaries) / right (scanner+findings) ──
        left_col, right_col = st.columns([5, 7])

        with left_col:
            st.markdown('<div class="rf-section-label">Risk Breakdown</div>', unsafe_allow_html=True)

            # Donut chart
            labels, values, colors = [], [], []
            for tier, count in [("Deal Killer", n_dk), ("Critical", n_crit),
                                 ("Moderate", n_mod), ("Manageable", n_man)]:
                if count:
                    labels.append(tier); values.append(count)
                    colors.append(TIER_COLOR[tier.lower().replace(" ", "_")])

            if values:
                fig = go.Figure(go.Pie(
                    labels=labels, values=values, hole=0.72,
                    marker=dict(colors=colors, line=dict(color="#080c14", width=3)),
                    textinfo="label+percent",
                    textfont=dict(size=10, color="#4a6080", family="JetBrains Mono"),
                    hovertemplate="<b>%{label}</b><br>%{value} findings (%{percent})<extra></extra>",
                ))
                fig.update_layout(
                    showlegend=True,
                    legend=dict(
                        font=dict(color="#4a6080", size=11, family="Inter"),
                        bgcolor="rgba(0,0,0,0)", x=0.5, xanchor="center", y=-0.05,
                        orientation="h",
                    ),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=8, b=32, l=8, r=8), height=260,
                    annotations=[dict(
                        text=f"<b>{n_total}</b><br><span style='font-size:10px;color:#2d4060'>total</span>",
                        x=0.5, y=0.5, font_size=28, font_color="#c8daf5",
                        font=dict(family="JetBrains Mono"), showarrow=False,
                    )],
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

            # Risk Profile Summary (collapsible)
            avg_score = sum(f.risk_score for f in findings) / len(findings) if findings else 0
            top_exposure = max(
                set(str(getattr(f.exposure, "value", f.exposure)) for f in findings),
                key=lambda e: {"internet_facing": 3, "partner": 2, "internal": 1}.get(e, 0),
                default="unknown"
            )
            with st.expander("Risk Profile Summary", expanded=False):
                st.markdown(f"""
                <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;">
                    <div style="background:#080c14;border:1px solid #141d2e;border-radius:9px;padding:12px;">
                      <div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;
                                  color:#2d4060;font-family:'JetBrains Mono',monospace;margin-bottom:4px;">Avg Risk Score</div>
                      <div style="font-size:1.5rem;font-weight:700;color:{score_color(avg_score)};
                                  font-family:'JetBrains Mono',monospace;">{avg_score:.1f}</div>
                    </div>
                    <div style="background:#080c14;border:1px solid #141d2e;border-radius:9px;padding:12px;">
                      <div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;
                                  color:#2d4060;font-family:'JetBrains Mono',monospace;margin-bottom:4px;">Max Exposure</div>
                      <div style="font-size:0.82rem;font-weight:600;color:#c8daf5;
                                  font-family:'JetBrains Mono',monospace;margin-top:4px;">{top_exposure.replace("_"," ").upper()}</div>
                    </div>
                  </div>
                  <div style="color:#3a5070;font-size:0.79rem;line-height:1.7;">
                    {n_dk} deal-killer · {n_crit} critical · {n_mod} moderate · {n_man} manageable across {n_total} total findings.
                  </div>
                </div>""", unsafe_allow_html=True)

            # Deployment Status (collapsible)
            _ov_count  = st.session_state.get("openvas_count", 0)
            _zap_c     = st.session_state.get("zap_count", 0)
            _vul_c     = st.session_state.get("vulners_count", 0)
            _asset_c   = st.session_state.get("asset_hosts", 0)
            _scanners_active = sum([1, bool(_vul_c), bool(st.session_state.get("shodan_result", {}).get("success")),
                                    bool(_ov_count), bool(_zap_c)])
            _posture   = "High Risk" if n_dk else ("Elevated" if n_crit >= 3 else ("Moderate" if n_mod >= 3 else "Low Risk"))
            _posture_c = "#e6394a" if n_dk else ("#f97316" if n_crit >= 3 else ("#f59e0b" if n_mod >= 3 else "#10b981"))

            with st.expander("Deployment Status", expanded=False):
                st.markdown(f"""
                <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
                  <div style="display:flex;align-items:center;justify-content:space-between;
                              margin-bottom:10px;padding:10px 14px;
                              background:#080c14;border:1px solid #141d2e;border-radius:9px;">
                    <span style="font-size:0.78rem;color:#3a5070;font-family:'Inter',sans-serif;">Overall Posture</span>
                    <span style="font-size:0.86rem;font-weight:700;color:{_posture_c};
                                 font-family:'JetBrains Mono',monospace;">{_posture}</span>
                  </div>
                  <div style="color:#2d4060;font-size:0.76rem;line-height:1.8;">
                    <span style="color:#10b981;">●</span> {_scanners_active} of 5 scanners active &nbsp;·&nbsp;
                    <span style="color:{'#10b981' if _asset_c else '#f59e0b'};">●</span>
                    Asset inventory {'loaded' if _asset_c else 'not uploaded'}
                  </div>
                </div>""", unsafe_allow_html=True)

        with right_col:
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

            nmap_ps = _ps("ok", "Nmap", "done", "ok")
            if vulners_count:
                vuln_ps = _ps("ok",   "Vulners", f"{vulners_count} CVEs", "ok")
            elif vulners_active:
                vuln_ps = _ps("warn", "Vulners", "0 CVEs", "warn")
            else:
                vuln_ps = _ps("off",  "Vulners", "not installed", "")

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

            # Target intel + source chip
            source_chip = (
                '<span style="font-size:0.55rem;font-family:\'JetBrains Mono\',monospace;'
                'color:#a78bfa;background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.25);'
                'border-radius:4px;padding:2px 7px;font-weight:700;letter-spacing:0.1em;">TARGET-PROVIDED</span>'
                if shodan_source == "external_json" else
                '<span style="font-size:0.55rem;font-family:\'JetBrains Mono\',monospace;'
                'color:#10b981;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.25);'
                'border-radius:4px;padding:2px 7px;font-weight:700;letter-spacing:0.1em;">LIVE API</span>'
            )

            st.markdown(f"""
            <div class="rf-pipeline-h" style="margin-bottom:14px;">
              <div class="rf-pipeline-header">
                Scanner Status
                <span style="margin-left:auto;font-size:0.6rem;color:#2d4060;">
                  {clean_target} &nbsp;·&nbsp; {resolved_ip}
                </span>
              </div>
              <div class="rf-pipeline-flow">
                {nmap_ps}{vuln_ps}{shod_ps}{ov_ps}{zap_ps}
              </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Shodan snapshot (inline card) ─────────────────────────────
            if shodan_result.get("success"):
                ports_str  = ", ".join(map(str, shodan_result.get("ports", []))) or "—"
                vuln_count = len(shodan_result.get("vulns", []))
                org        = shodan_result.get("organization") or "Unknown"
                isp        = shodan_result.get("isp") or "Unknown"
                country    = shodan_result.get("country") or "Unknown"
                city       = shodan_result.get("city") or "Unknown"
                cve_color  = "#e6394a" if vuln_count else "#10b981"

                st.markdown(f"""
                <div class="rf-shodan" style="margin-bottom:14px;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;font-weight:700;
                              letter-spacing:0.18em;text-transform:uppercase;color:#3d7fff;
                              margin-bottom:12px;display:flex;align-items:center;gap:8px;">
                    SHODAN SNAPSHOT {source_chip}
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 0;">
                    <div class="rf-shodan-row" style="margin-bottom:6px;">
                      <span class="rf-shodan-label">Org</span>
                      <span class="rf-shodan-value">{org}</span>
                    </div>
                    <div class="rf-shodan-row" style="margin-bottom:6px;">
                      <span class="rf-shodan-label">ISP</span>
                      <span class="rf-shodan-value">{isp}</span>
                    </div>
                    <div class="rf-shodan-row" style="margin-bottom:6px;">
                      <span class="rf-shodan-label">Location</span>
                      <span class="rf-shodan-value">{city}, {country}</span>
                    </div>
                    <div class="rf-shodan-row" style="margin-bottom:6px;">
                      <span class="rf-shodan-label">Open Ports</span>
                      <span class="rf-shodan-value" style="font-family:'JetBrains Mono',monospace;font-size:0.74rem;color:#6fa3ff;">{ports_str}</span>
                    </div>
                    <div class="rf-shodan-row">
                      <span class="rf-shodan-label">CVEs</span>
                      <span class="rf-shodan-value" style="color:{cve_color};font-weight:700;font-family:'JetBrains Mono',monospace;">{vuln_count}</span>
                    </div>
                  </div>
                  {('<div style="margin-top:10px;border-top:1px solid #1e3050;padding-top:10px;">'
                    + '<div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;'
                    + 'color:#2d4060;font-family:\'JetBrains Mono\',monospace;margin-bottom:6px;">CVE Lists</div>'
                    + "<div style='display:flex;flex-wrap:wrap;gap:5px;'>"
                    + "".join(f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;color:#4a6080;'
                              f'background:#080c14;border:1px solid #1e2d45;border-radius:4px;padding:2px 8px;">{c}</span>'
                              for c in shodan_result["vulns"][:8])
                    + (f'<span style="font-size:0.62rem;color:#2d4060;padding:2px 8px;">+{len(shodan_result["vulns"])-8} more</span>'
                       if len(shodan_result["vulns"]) > 8 else "")
                    + "</div></div>") if shodan_result.get("vulns") else ""}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.warning(shodan_result.get("error", "Shodan enrichment unavailable."))

            # ── Mini findings list ────────────────────────────────────────
            st.markdown('<div class="rf-section-label">Top Findings</div>', unsafe_allow_html=True)

            TIER_CSS_MAP = {"deal_killer": "dk", "critical": "crit", "moderate": "mod", "manageable": "man"}
            TIER_ICONS   = {"deal_killer": "⚡", "critical": "🔴", "moderate": "🟡", "manageable": "🟢"}

            for f in findings[:6]:
                t_val  = str(getattr(f.deal_tier, "value", f.deal_tier))
                t_cls  = TIER_CSS_MAP.get(t_val, "")
                t_icon = TIER_ICONS.get(t_val, "●")
                sc     = score_color(f.risk_score)
                port_label = f":{f.port}" if f.port else ""
                svc_label  = f.service or ""
                desc_short = (f.description[:80] + "…") if len(f.description) > 80 else f.description

                st.markdown(f"""
                <div class="fmc {t_cls}">
                  <div class="fmc-icon {t_cls}">{t_icon}</div>
                  <div class="fmc-body">
                    <div class="fmc-title">{f.title}</div>
                    <div class="fmc-meta">
                      <span class="badge badge-{t_cls}">{t_val.replace('_',' ')}</span>
                      <span class="fmc-port">{port_label} {svc_label}</span>
                      <span class="fmc-score" style="color:{sc};">{f.risk_score:.0f}</span>
                    </div>
                    <div class="fmc-desc">{desc_short}</div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

            if len(findings) > 6:
                st.markdown(
                    f"<div style='text-align:center;padding:8px;font-size:0.72rem;"
                    f"color:#2d4060;font-family:\"JetBrains Mono\",monospace;'>"
                    f"+ {len(findings)-6} more findings — see Findings tab</div>",
                    unsafe_allow_html=True,
                )

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
                                              color:#2d4060;">{row['Host']} &nbsp;·&nbsp; :{port_svc} &nbsp;·&nbsp; {row['Scanner']}</span>
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
                                           color:#4a6080;">{evid_label}</span>
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
    # Tab: Maturity Assessment
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_maturity:

        st.markdown('<div class="rf-section-label">Inside-Out Maturity Assessment</div>', unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:0.82rem;color:#4a6080;font-family:\"Inter\",sans-serif;"
            "line-height:1.7;margin-bottom:20px;'>"
            "Complete the questionnaire below to assess the target's internal security programme maturity. "
            "Scores are compared against a corporate acquisition standard to identify gaps and deal-blockers. "
            "All fields are optional — unanswered domains are excluded from scoring.</div>",
            unsafe_allow_html=True,
        )

        # ── Questionnaire form ────────────────────────────────────────────────
        all_domains = get_all_domains()
        mat_answers: dict[str, int] = {}

        with st.form("maturity_form"):
            for domain_key, domain_label in all_domains:
                questions = get_domain_questions(domain_key)
                st.markdown(
                    f"<div style='font-size:0.7rem;font-weight:700;letter-spacing:0.15em;"
                    f"text-transform:uppercase;color:#e6394a;font-family:\"JetBrains Mono\",monospace;"
                    f"margin:18px 0 6px;'>{domain_label}</div>",
                    unsafe_allow_html=True,
                )
                for q in questions:
                    options = q.get("options", [])
                    if not options:
                        continue
                    # Build labelled options: "0 — <text>"
                    option_labels = [f"{i} — {opt}" for i, opt in enumerate(options)]
                    default_idx = st.session_state.get(f"mat_{q['id']}_idx", 0)
                    sel = st.selectbox(
                        label=q["text"],
                        options=option_labels,
                        index=default_idx,
                        key=f"mat_form_{q['id']}",
                    )
                    # Extract level from "N — ..." prefix
                    mat_answers[q["id"]] = int(sel.split(" — ")[0])

            submitted = st.form_submit_button(
                "Run Maturity Assessment",
                use_container_width=True,
            )

        if submitted:
            assessment = run_assessment(mat_answers, target=clean_target)
            gap_report = compare_to_standard(assessment)
            st.session_state["maturity_assessment"] = assessment
            st.session_state["gap_report"]          = gap_report

        # ── Results ───────────────────────────────────────────────────────────
        assessment = st.session_state.get("maturity_assessment")
        gap_report = st.session_state.get("gap_report")

        if assessment:
            # Overall score banner
            overall = assessment.overall_score
            ov_color = "#e6394a" if assessment.is_deal_blocker else ("#f59e0b" if assessment.has_gaps else "#10b981")
            ov_label = "DEAL-BLOCKER" if assessment.is_deal_blocker else ("GAPS PRESENT" if assessment.has_gaps else "ACCEPTABLE")

            st.markdown(f"""
            <div style="background:linear-gradient(160deg,#0f1623,#0a0f1c);border:1px solid {ov_color}33;
                        border-radius:14px;padding:20px 24px;margin-bottom:24px;
                        display:flex;align-items:center;gap:24px;">
              <div style="text-align:center;min-width:80px;">
                <div style="font-size:3rem;font-weight:700;color:{ov_color};
                            font-family:'JetBrains Mono',monospace;line-height:1;">{overall:.1f}<span style="font-size:1.2rem;color:#2d4060;">/5</span></div>
                <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;
                            color:{ov_color};font-family:'JetBrains Mono',monospace;margin-top:4px;">{ov_label}</div>
              </div>
              <div style="flex:1;">
                <div style="font-size:0.9rem;font-weight:700;color:#c8daf5;
                            font-family:'Inter',sans-serif;margin-bottom:6px;">Overall Maturity Score</div>
                <div style="font-size:0.78rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.6;">
                  {assessment.completion_pct:.0f}% of questions answered &nbsp;&middot;&nbsp;
                  {len(assessment.domain_scores)} domains assessed
                </div>
              </div>
            </div>""", unsafe_allow_html=True)

            # Domain score cards
            st.markdown('<div class="rf-section-label">Domain Scores</div>', unsafe_allow_html=True)

            _SEV_COLORS = {
                "deal_blocker": ("#e6394a", "DEAL-BLOCKER"),
                "below_min":    ("#f59e0b", "BELOW MIN"),
                "acceptable":   ("#6fa3ff", "ACCEPTABLE"),
                "at_target":    ("#10b981", "AT TARGET"),
            }

            domain_cols = st.columns(2)
            for di, ds in enumerate(assessment.domain_scores):
                sev_val   = str(ds.gap_severity.value if hasattr(ds.gap_severity, "value") else ds.gap_severity)
                sev_color, sev_label = _SEV_COLORS.get(sev_val, ("#4a6080", "N/A"))
                bar_pct = int(ds.score / 5 * 100)
                with domain_cols[di % 2]:
                    st.markdown(f"""
                    <div style="background:linear-gradient(160deg,#0f1623,#0a0f1c);
                                border:1px solid #1a2640;border-radius:12px;
                                padding:16px 18px;margin-bottom:12px;">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <div style="font-size:0.8rem;font-weight:700;color:#c7d8f5;
                                    font-family:'Inter',sans-serif;">{ds.label}</div>
                        <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                                    text-transform:uppercase;color:{sev_color};
                                    font-family:'JetBrains Mono',monospace;">{sev_label}</div>
                      </div>
                      <div style="display:flex;align-items:center;gap:12px;">
                        <div style="flex:1;height:6px;background:#0d1828;border-radius:3px;">
                          <div style="width:{bar_pct}%;height:6px;background:{sev_color};
                                      border-radius:3px;transition:width 0.3s;"></div>
                        </div>
                        <div style="font-size:1.1rem;font-weight:700;color:{sev_color};
                                    font-family:'JetBrains Mono',monospace;min-width:36px;
                                    text-align:right;">{ds.score:.1f}</div>
                      </div>
                      <div style="margin-top:8px;display:flex;gap:16px;">
                        <span style="font-size:0.7rem;color:#2d4060;font-family:'JetBrains Mono',monospace;">
                          Min acceptable: <span style="color:#4a6080;">{ds.acceptable_min}</span>
                        </span>
                        <span style="font-size:0.7rem;color:#2d4060;font-family:'JetBrains Mono',monospace;">
                          Target: <span style="color:#4a6080;">{ds.recommended}</span>
                        </span>
                        <span style="font-size:0.7rem;color:#2d4060;font-family:'JetBrains Mono',monospace;">
                          Answered: <span style="color:#4a6080;">{ds.answered}/{ds.total_questions}</span>
                        </span>
                      </div>
                    </div>""", unsafe_allow_html=True)

            # Gap narrative
            if gap_report and gap_report.has_any_gaps:
                st.markdown('<div class="rf-section-label">Gap Analysis</div>', unsafe_allow_html=True)
                mat_narrative = build_maturity_narrative(assessment)
                if mat_narrative:
                    st.markdown(
                        f"<div style='font-size:0.85rem;color:#c7d8f5;font-family:\"Inter\",sans-serif;"
                        f"line-height:1.75;padding:16px;background:#0a0f1c;border-radius:10px;"
                        f"border-left:3px solid #f59e0b;margin-bottom:16px;'>{mat_narrative}</div>",
                        unsafe_allow_html=True,
                    )

                for gap in gap_report.deal_blocker_gaps + gap_report.below_min_gaps:
                    st.markdown(f"""
                    <div style="background:#0a0f1c;border:1px solid #e6394a33;border-radius:10px;
                                border-left:3px solid #e6394a;padding:14px 18px;margin-bottom:10px;">
                      <div style="font-size:0.82rem;font-weight:700;color:#e6394a;
                                  font-family:'Inter',sans-serif;margin-bottom:4px;">
                        {gap.label} — Score {gap.current_score:.1f} (need {gap.acceptable_min})
                      </div>
                      <div style="font-size:0.78rem;color:#4a6080;font-family:'Inter',sans-serif;
                                  line-height:1.65;">{gap.rationale}</div>
                    </div>""", unsafe_allow_html=True)
        else:
            st.markdown(
                "<div style='padding:40px;text-align:center;color:#2d4060;"
                "font-family:\"JetBrains Mono\",monospace;font-size:0.78rem;'>"
                "Complete the questionnaire above and click Run Maturity Assessment to see results.</div>",
                unsafe_allow_html=True,
            )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Cost & Budget
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_cost:

        st.markdown('<div class="rf-section-label">Remediation Cost & Budget</div>', unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:0.82rem;color:#4a6080;font-family:\"Inter\",sans-serif;"
            "line-height:1.7;margin-bottom:20px;'>"
            "Cost estimates are generated from scanner findings and maturity gaps using industry benchmark "
            "pricing.  All figures are shown as low / base / high scenarios.  CapEx and OpEx are separated. "
            "Flagged items require human review before export.</div>",
            unsafe_allow_html=True,
        )

        # ── Generate cost estimate ─────────────────────────────────────────────
        gap_report_for_cost = st.session_state.get("gap_report")

        include_gaps = st.checkbox(
            "Include maturity gap remediation costs",
            value=bool(gap_report_for_cost),
            disabled=not bool(gap_report_for_cost),
            help="Requires a completed Maturity Assessment.",
        )

        if st.button("Generate Cost Estimate", use_container_width=False):
            with st.spinner("Building cost model…"):
                rollup = run_cost_pipeline(
                    findings=findings,
                    gap_report=gap_report_for_cost if include_gaps else None,
                    target=clean_target,
                    include_maturity_gaps=include_gaps,
                )
                st.session_state["cost_rollup"] = rollup

        rollup = st.session_state.get("cost_rollup")

        if rollup:
            # ── Cost narrative ─────────────────────────────────────────────────
            cost_narrative = build_cost_narrative(rollup)
            if cost_narrative:
                st.markdown(
                    f"<div style='font-size:0.85rem;color:#c7d8f5;font-family:\"Inter\",sans-serif;"
                    f"line-height:1.75;padding:16px;background:#0a0f1c;border-radius:10px;"
                    f"border-left:3px solid #6fa3ff;margin-bottom:20px;'>{cost_narrative}</div>",
                    unsafe_allow_html=True,
                )

            # ── Scenario summary cards ─────────────────────────────────────────
            st.markdown('<div class="rf-section-label">Cost Scenarios</div>', unsafe_allow_html=True)
            sc_low  = next((s for s in rollup.scenarios if str(s.scenario_type) == "low"),  None)
            sc_base = next((s for s in rollup.scenarios if str(s.scenario_type) == "base"), None)
            sc_high = next((s for s in rollup.scenarios if str(s.scenario_type) == "high"), None)

            sc_col1, sc_col2, sc_col3 = st.columns(3)
            for sc_col, sc, sc_label, sc_color in [
                (sc_col1, sc_low,  "Low Scenario",  "#10b981"),
                (sc_col2, sc_base, "Base Scenario", "#6fa3ff"),
                (sc_col3, sc_high, "High Scenario", "#e6394a"),
            ]:
                with sc_col:
                    if sc:
                        st.markdown(f"""
                        <div style="background:linear-gradient(160deg,#0f1623,#0a0f1c);
                                    border:1px solid #1a2640;border-radius:14px;padding:20px 16px;">
                          <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.18em;
                                      text-transform:uppercase;color:#2d4060;
                                      font-family:'JetBrains Mono',monospace;margin-bottom:10px;">{sc_label}</div>
                          <div style="font-size:2.2rem;font-weight:700;color:{sc_color};
                                      font-family:'JetBrains Mono',monospace;line-height:1;">
                            ${sc.total_usd:,.0f}
                          </div>
                          <div style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:6px;">
                            <div style="font-size:0.72rem;color:#4a6080;font-family:'Inter',sans-serif;">
                              <span style="color:#f59e0b;font-weight:700;">CapEx</span><br>
                              ${sc.capex_usd:,.0f}
                            </div>
                            <div style="font-size:0.72rem;color:#4a6080;font-family:'Inter',sans-serif;">
                              <span style="color:#10b981;font-weight:700;">OpEx</span><br>
                              ${sc.opex_usd:,.0f}
                            </div>
                          </div>
                        </div>""", unsafe_allow_html=True)

            st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

            # ── Review gate ────────────────────────────────────────────────────
            if rollup.has_flagged_items:
                flagged_items = [i for i in rollup.line_items if i.needs_review]
                st.markdown(f"""
                <div style="background:#0a0610;border:1px solid #e6394a44;border-radius:12px;
                            border-left:3px solid #e6394a;padding:16px 20px;margin-bottom:16px;">
                  <div style="font-size:0.82rem;font-weight:700;color:#e6394a;
                              font-family:'Inter',sans-serif;margin-bottom:6px;">
                    ⚠  {len(flagged_items)} Item(s) Require Human Review Before Export
                  </div>
                  <div style="font-size:0.78rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.65;">
                    The highlighted items below have high cost variance, zero estimates, or are linked to
                    deal-killer findings.  Review and acknowledge before downloading the cost report.
                  </div>
                </div>""", unsafe_allow_html=True)

                acknowledge = st.checkbox(
                    "I have reviewed all flagged items and acknowledge the estimates are reasonable.",
                    key="cost_review_ack",
                )
                if acknowledge:
                    rollup.review_acknowledged = True
                    st.session_state["cost_rollup"] = rollup

            # ── Line items table ───────────────────────────────────────────────
            st.markdown('<div class="rf-section-label">Remediation Line Items</div>', unsafe_allow_html=True)

            import pandas as _pd_cost
            cost_rows = []
            for item in rollup.line_items:
                cat  = str(getattr(item.category,   "value", item.category)).replace("_", " ").title()
                ce   = str(getattr(item.capex_opex, "value", item.capex_opex)).upper()
                conf = str(getattr(item.confidence, "value", item.confidence)).upper()
                flags = "; ".join(str(getattr(f, "value", f)) for f in item.review_flags) or "-"
                cost_rows.append({
                    "Title":       item.title,
                    "Category":    cat,
                    "CapEx/OpEx":  ce,
                    "Low ($)":     int(item.cost.low),
                    "Base ($)":    int(item.cost.base),
                    "High ($)":    int(item.cost.high),
                    "Confidence":  conf,
                    "Findings":    len(item.finding_ids),
                    "Flags":       flags,
                })

            cost_df = _pd_cost.DataFrame(cost_rows)
            st.dataframe(
                cost_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Low ($)":  st.column_config.NumberColumn(format="$%d"),
                    "Base ($)": st.column_config.NumberColumn(format="$%d"),
                    "High ($)": st.column_config.NumberColumn(format="$%d"),
                },
            )

            # ── Export cost report ─────────────────────────────────────────────
            st.markdown('<div class="rf-section-label" style="margin-top:20px;">Export Cost Report</div>', unsafe_allow_html=True)

            if rollup.export_blocked:
                st.warning("Acknowledge all flagged items above to unlock export.")
            else:
                from cost.exporters import export_rollup_csv, export_rollup_xlsx

                exp_c1, exp_c2 = st.columns(2)
                with exp_c1:
                    try:
                        csv_bytes = export_rollup_csv(rollup)
                        st.download_button(
                            label="Download Cost Report (CSV)",
                            data=csv_bytes,
                            file_name=f"redflag_cost_{clean_target.replace('.', '_')}.csv",
                            mime="text/csv",
                            use_container_width=True,
                        )
                    except Exception as e_csv:
                        st.error(f"CSV export failed: {e_csv}")

                with exp_c2:
                    try:
                        xlsx_bytes = export_rollup_xlsx(rollup)
                        st.download_button(
                            label="Download Cost Report (XLSX)",
                            data=xlsx_bytes,
                            file_name=f"redflag_cost_{clean_target.replace('.', '_')}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            use_container_width=True,
                        )
                    except ImportError:
                        st.info("Install openpyxl for XLSX export: `pip install openpyxl`")
                    except Exception as e_xlsx:
                        st.error(f"XLSX export failed: {e_xlsx}")

        else:
            st.markdown(
                "<div style='padding:40px;text-align:center;color:#2d4060;"
                "font-family:\"JetBrains Mono\",monospace;font-size:0.78rem;'>"
                "Click Generate Cost Estimate to build the remediation budget.</div>",
                unsafe_allow_html=True,
            )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Export
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_export:

        exp_col, _ = st.columns([2, 3])
        with exp_col:
            st.markdown('<div class="rf-section-label">Report Summary</div>', unsafe_allow_html=True)

            dk_color  = "#f87171" if n_dk   else "#10b981"
            crt_color = "#f97316" if n_crit else "#2d4060"

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
    "<hr style='border:none;border-top:1px solid #141d2e;margin:48px 0 0;'>",
    unsafe_allow_html=True,
)

_fp_col, _fc_col, _copy_col = st.columns([4, 4, 4])

with _fp_col:
    with st.expander("\U0001f4c4  Privacy Policy"):
        st.markdown(
            """<div style="padding:6px 0 4px;">
  <div style="font-size:1rem;font-weight:800;color:#c8daf5;
              font-family:'Inter',sans-serif;margin-bottom:3px;">Privacy Policy</div>
  <div style="font-size:0.65rem;color:#2d4060;font-family:'JetBrains Mono',monospace;
              margin-bottom:16px;">Effective: May 2026 &middot; RedFlag v3</div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#e6394a;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">01 &middot; Data We Process</div>
    <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
      RedFlag processes only data you explicitly provide: scan targets, uploaded files (OpenVAS, ZAP,
      Shodan JSON, Asset Excel), and scan outputs stored locally in
      <code style="font-family:'JetBrains Mono',monospace;color:#6fa3ff;">data/results/</code>.
      <strong style="color:#7a93b8;">No personal data</strong> is collected.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#e6394a;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">02 &middot; How Data Is Processed</div>
    <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
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
                color:#e6394a;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">03 &middot; Data Retention</div>
    <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
      No data is retained on remote servers. Scan files live only in your local
      <code style="font-family:'JetBrains Mono',monospace;color:#6fa3ff;">data/results/</code> folder.
      In-session state clears on restart.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#e6394a;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">04 &middot; Responsible Use</div>
    <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
      Use RedFlag only against systems you own or have
      <strong style="color:#7a93b8;">explicit written authorisation</strong> to assess.
      The developers accept no liability for misuse.
    </div>
  </div>

  <div>
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#e6394a;font-family:'JetBrains Mono',monospace;margin-bottom:5px;">05 &middot; Changes &amp; Contact</div>
    <div style="font-size:0.82rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.75;">
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
  <div style="font-size:1rem;font-weight:800;color:#c8daf5;
              font-family:'Inter',sans-serif;margin-bottom:3px;">Get in Touch</div>
  <div style="font-size:0.65rem;color:#2d4060;font-family:'JetBrains Mono',monospace;
              margin-bottom:14px;">RedFlag &middot; M&amp;A Cybersecurity Intelligence</div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:16px;">
    <div style="background:linear-gradient(145deg,#0f1623,#0a0f1c);
                border:1px solid #1a2640;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128737;&#65039;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#c8daf5;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Security Questions</div>
      <div style="font-size:0.75rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.55;">
        Methodology, scoring, M&amp;A interpretation.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#0f1623,#0a0f1c);
                border:1px solid #1a2640;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#129309;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#c8daf5;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Partnerships</div>
      <div style="font-size:0.75rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.55;">
        Enterprise, white-label, advisory.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#0f1623,#0a0f1c);
                border:1px solid #1a2640;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128027;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#c8daf5;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Bug Reports</div>
      <div style="font-size:0.75rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.55;">
        Unexpected behaviour or feature ideas.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#0f1623,#0a0f1c);
                border:1px solid #1a2640;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128203;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#c8daf5;
                  font-family:'Inter',sans-serif;margin-bottom:3px;">Privacy Enquiries</div>
      <div style="font-size:0.75rem;color:#4a6080;font-family:'Inter',sans-serif;line-height:1.55;">
        Questions about how RedFlag handles data.
      </div>
    </div>
  </div>

  <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#97;&#100;&#105;&#116;&#121;&#97;&#97;&#118;&#101;&#108;&#48;&#48;&#55;&#64;&#103;&#109;&#97;&#105;&#108;&#46;&#99;&#111;&#109;"
     style="display:block;text-align:center;
            background:linear-gradient(160deg,#e6394a,#9f1239);
            color:#fff;text-decoration:none;font-family:'Inter',sans-serif;
            font-weight:700;font-size:0.83rem;letter-spacing:0.05em;
            padding:11px 20px;border-radius:10px;
            box-shadow:0 4px 22px rgba(244,63,94,0.4);margin-bottom:14px;">
    &#9993;&nbsp; Send Message
  </a>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
    <div style="font-size:0.76rem;color:#4a6080;font-family:'Inter',sans-serif;">
      <span style="color:#10b981;font-weight:700;">General enquiries</span><br>Within 2 business days
    </div>
    <div style="font-size:0.76rem;color:#4a6080;font-family:'Inter',sans-serif;">
      <span style="color:#f59e0b;font-weight:700;">Security / critical</span><br>Within 24 hours
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
