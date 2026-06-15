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
from scanners.dns_scan import run_dns_scan
from scanners.tls_scan import run_tls_scan
from scanners.breach_scan import run_breach_scan


st.set_page_config(
    page_title="RedFlag",
    page_icon="🚩",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Global styles ──────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* ══════════════════════════════════════════════════════════════
   REDFLAG  —  Design System v5 · ULTRAVIOLET
   Fonts  : Space Grotesk + IBM Plex Mono
   Palette: Void violet-black · Electric violet · Neon crimson · Cyan
══════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');

/* ── Base ── */
[data-testid="stAppViewContainer"] { background: #07060f !important; }
[data-testid="stHeader"]           { display: none !important; }
[data-testid="stMainBlockContainer"] { padding-top: 0 !important; max-width: 100% !important; }
[data-testid="stAppViewBlockContainer"] { padding: 0 2rem !important; }
html, body, [class*="css"],
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
.stCheckbox label, .stSlider label, .stMultiSelect label,
.stCaption, .stAlert p, button { font-family: 'Space Grotesk', -apple-system, sans-serif !important; }

/* ── TOP NAVBAR ── */
.rf-topnav {
    display: flex; align-items: center; padding: 0 24px;
    height: 52px; background: #0b0917;
    border-bottom: 1px solid #1d1735;
    margin: 0 -2rem 20px; gap: 0;
    position: sticky; top: 0; z-index: 999;
}
.rf-brand {
    display: flex; align-items: center; gap: 12px; text-decoration: none;
}
.rf-brand-icon {
    width: 32px; height: 32px; background: linear-gradient(135deg, #ff3b5f 0%, #8b5cf6 100%);
    border-radius: 9px; display: flex; align-items: center; justify-content: center;
    font-size: 0.6rem; color: white; font-weight: 900; letter-spacing: 0.05em;
    box-shadow: 0 2px 14px rgba(255,59,95,0.35), 0 2px 18px rgba(139,92,246,0.3); flex-shrink: 0;
}
.rf-brand-text { display: flex; flex-direction: column; gap: 1px; }
.rf-brand-name {
    font-size: 1.05rem; font-weight: 800; color: #f1edfe;
    letter-spacing: -0.02em; font-family: 'Space Grotesk', sans-serif; line-height: 1;
}
.rf-brand-sub {
    font-size: 0.55rem; font-weight: 600; color: #4d4274;
    letter-spacing: 0.1em; text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace; line-height: 1;
}
.rf-engines-text {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.58rem; font-weight: 600;
    color: #2c2253; letter-spacing: 0.08em; text-transform: uppercase;
    padding: 4px 14px; border-left: 1px solid #1d1735;
    margin: 0 16px;
}
.rf-nav-right { display: flex; align-items: center; gap: 10px; }

/* ── METRIC CARDS ── */
.rf-metric {
    background: #130f23;
    border: 1px solid #261d46;
    border-radius: 14px 14px 0 0;
    padding: 18px 16px 16px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s ease, box-shadow 0.25s ease;
    cursor: pointer;
}
.rf-metric::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    border-radius: 14px 14px 0 0;
}
.rf-metric:hover { transform: translateY(-2px); }
.rf-metric .label {
    font-size: 0.58rem; font-weight: 700; letter-spacing: 0.18em;
    text-transform: uppercase; color: #4d4274; margin-bottom: 10px;
    font-family: 'IBM Plex Mono', monospace;
}
.rf-metric .value {
    font-size: 2.6rem; font-weight: 700; line-height: 1;
    font-family: 'IBM Plex Mono', monospace; letter-spacing: -0.03em;
}
.rf-metric.red::before    { background: linear-gradient(90deg, #ff3b5f, #c1124d); }
.rf-metric.red .value     { color: #ff3b5f; }
.rf-metric.red:hover      { box-shadow: 0 8px 32px rgba(255,59,95,0.2); border-color: rgba(255,59,95,0.2); }
.rf-metric.orange::before { background: linear-gradient(90deg, #ff7849, #d8490e); }
.rf-metric.orange .value  { color: #ff7849; }
.rf-metric.orange:hover   { box-shadow: 0 8px 32px rgba(255,120,73,0.18); border-color: rgba(255,120,73,0.2); }
.rf-metric.yellow::before { background: linear-gradient(90deg, #fbbf24, #d97706); }
.rf-metric.yellow .value  { color: #fbbf24; }
.rf-metric.yellow:hover   { box-shadow: 0 8px 32px rgba(251,191,36,0.15); border-color: rgba(251,191,36,0.18); }
.rf-metric.green::before  { background: linear-gradient(90deg, #2dd4a0, #0d9468); }
.rf-metric.green .value   { color: #2dd4a0; }
.rf-metric.green:hover    { box-shadow: 0 8px 32px rgba(45,212,160,0.16); border-color: rgba(45,212,160,0.18); }
.rf-metric.blue::before   { background: linear-gradient(90deg, #8b5cf6, #6d28d9); }
.rf-metric.blue .value    { color: #b39dfb; }
.rf-metric.blue:hover     { box-shadow: 0 8px 32px rgba(139,92,246,0.18); border-color: rgba(139,92,246,0.18); }

/* ── SECTION LABEL ── */
.rf-section-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.2em; text-transform: uppercase; color: #4d4274;
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 12px; margin-top: 4px;
}
.rf-section-label::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, #1d1735 0%, transparent 100%);
}

/* ── BADGES ── */
.badge {
    display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 5px;
    font-size: 0.59rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace;
}
.badge-dk   { background: rgba(255,59,95,0.12);  color: #ff8298; border: 1px solid rgba(255,59,95,0.3); }
.badge-crit { background: rgba(255,120,73,0.12); color: #ff7849; border: 1px solid rgba(255,120,73,0.3); }
.badge-mod  { background: rgba(251,191,36,0.1);  color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.badge-man  { background: rgba(45,212,160,0.1);  color: #2dd4a0; border: 1px solid rgba(45,212,160,0.25); }
.badge-unk  { background: rgba(125,119,149,0.08);color: #7d7795; border: 1px solid rgba(125,119,149,0.2); }
.badge-inet { background: rgba(139,92,246,0.1);  color: #b39dfb; border: 1px solid rgba(139,92,246,0.3); }
.badge-part { background: rgba(34,211,238,0.1); color: #22d3ee; border: 1px solid rgba(124,58,237,0.3); }
.badge-int  { background: rgba(45,212,160,0.08); color: #2dd4a0; border: 1px solid rgba(45,212,160,0.22); }
.badge-ukn  { background: rgba(125,119,149,0.08);color: #7d7795; border: 1px solid rgba(55,65,81,0.22); }

/* ── FINDING CARDS ── */
@keyframes pulse-dk {
    0%,100% { box-shadow: 0 0 0 0 rgba(255,59,95,0.25); }
    50%      { box-shadow: 0 0 0 4px rgba(255,59,95,0); }
}
.finding-card {
    background: #130f23;
    border: 1px solid #261d46;
    border-left: 3px solid #261d46;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 8px;
    transition: background 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
}
.finding-card:hover { background: #181230; }
.finding-card.dk   { border-left-color: #ff3b5f; animation: pulse-dk 3s ease-in-out infinite; }
.finding-card.crit { border-left-color: #ff7849; }
.finding-card.mod  { border-left-color: #fbbf24; }
.finding-card.man  { border-left-color: #2dd4a0; }
.finding-card.dk:hover   { border-color: rgba(255,59,95,0.25);  box-shadow: 0 4px 24px rgba(255,59,95,0.12); }
.finding-card.crit:hover { border-color: rgba(255,120,73,0.25); box-shadow: 0 4px 24px rgba(255,120,73,0.10); }
.finding-card.mod:hover  { border-color: rgba(251,191,36,0.22); box-shadow: 0 4px 20px rgba(251,191,36,0.07); }
.finding-card.man:hover  { border-color: rgba(45,212,160,0.2);  box-shadow: 0 4px 20px rgba(45,212,160,0.07); }
.finding-card h4 {
    color: #d8d2f0; font-size: 0.94rem; font-weight: 600;
    margin: 0 0 7px; font-family: 'Space Grotesk', sans-serif;
    line-height: 1.45; letter-spacing: -0.01em;
}
.finding-card .meta {
    color: #5b4e85; font-size: 0.76rem; margin-bottom: 12px;
    display: flex; gap: 8px; flex-wrap: wrap; align-items: center;
}
.finding-card .fc-divider { border: none; border-top: 1px solid #1d1735; margin: 11px 0; }
.finding-card .field-label {
    color: #4d4274; font-size: 0.57rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.15em;
    margin-bottom: 4px; font-family: 'IBM Plex Mono', monospace;
}
.finding-card .field-value { color: #6c5f97; font-size: 0.83rem; margin-bottom: 10px; line-height: 1.65; }
.finding-card .score-pill {
    background: #0b0917; border: 1px solid #261d46; border-radius: 10px;
    padding: 12px 14px; text-align: center; min-width: 70px; flex-shrink: 0;
}
.finding-card .score-pill .s-label {
    color: #4d4274; font-size: 0.55rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.15em; font-family: 'IBM Plex Mono', monospace;
    display: block; margin-bottom: 4px;
}
.finding-card .score-pill .s-value {
    font-size: 1.75rem; font-weight: 700; font-family: 'IBM Plex Mono', monospace;
    line-height: 1; letter-spacing: -0.03em;
}

/* ── MINI FINDING CARDS (Overview right panel) ── */
.fmc {
    background: #130f23; border: 1px solid #261d46; border-left: 3px solid #261d46;
    border-radius: 10px; padding: 12px 16px; margin-bottom: 6px;
    display: flex; align-items: flex-start; gap: 12px;
    transition: background 0.15s ease;
}
.fmc:hover { background: #181230; }
.fmc.dk   { border-left-color: #ff3b5f; }
.fmc.crit { border-left-color: #ff7849; }
.fmc.mod  { border-left-color: #fbbf24; }
.fmc.man  { border-left-color: #2dd4a0; }
.fmc-icon {
    width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.8rem; background: #1d1735;
}
.fmc-icon.dk   { background: rgba(255,59,95,0.1); }
.fmc-icon.crit { background: rgba(255,120,73,0.1); }
.fmc-icon.mod  { background: rgba(251,191,36,0.08); }
.fmc-icon.man  { background: rgba(45,212,160,0.08); }
.fmc-body { flex: 1; min-width: 0; }
.fmc-title {
    font-size: 0.83rem; font-weight: 600; color: #d8d2f0;
    font-family: 'Space Grotesk', sans-serif; margin-bottom: 4px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.fmc-desc {
    font-size: 0.74rem; color: #5b4e85; font-family: 'Space Grotesk', sans-serif;
    line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 1;
    -webkit-box-orient: vertical; overflow: hidden;
}
.fmc-meta {
    display: flex; align-items: center; gap: 6px; margin-top: 4px;
}
.fmc-port {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.66rem; color: #4d4274;
}
.fmc-score {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; font-weight: 700;
    margin-left: auto;
}

/* ── STATUS DOTS ── */
.rf-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; flex-shrink: 0;
}
@keyframes warn-blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.rf-dot.ok   { background: #2dd4a0; box-shadow: 0 0 7px rgba(45,212,160,0.9); }
.rf-dot.warn { background: #fbbf24; box-shadow: 0 0 7px rgba(251,191,36,0.9); animation: warn-blink 2s infinite; }
.rf-dot.err  { background: #ff3b5f; box-shadow: 0 0 7px rgba(255,59,95,0.9); }
.rf-dot.off  { background: #2c2253; }

/* ── SCANNER PIPELINE ── */
.rf-pipeline-h {
    background: #130f23; border: 1px solid #261d46;
    border-radius: 14px; padding: 16px 20px 14px; margin-bottom: 12px;
}
.rf-pipeline-header {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.2em; text-transform: uppercase; color: #4d4274;
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #1d1735;
    display: flex; align-items: center; gap: 8px;
}
.rf-pipeline-flow {
    display: flex; align-items: center; justify-content: space-between;
    position: relative; gap: 0;
}
.rf-pipeline-flow::before {
    content: ''; position: absolute; top: 11px; left: 28px; right: 28px;
    height: 1px; background: linear-gradient(90deg, #2c2253, #3e316e 50%, #2c2253);
    z-index: 0;
}
.rf-pipeline-step {
    display: flex; flex-direction: column; align-items: center; gap: 6px;
    padding: 0 8px; z-index: 1; background: #130f23; min-width: 60px;
    cursor: default;
}
.rf-pipeline-step .step-dot { margin-bottom: 0; }
.rf-pipeline-step .step-name {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.67rem; font-weight: 600;
    color: #6c5f97; white-space: nowrap;
}
.rf-pipeline-step .step-status {
    font-size: 0.6rem; color: #4d4274; font-family: 'Space Grotesk', sans-serif;
    white-space: nowrap; text-align: center;
}
.rf-pipeline-step .step-status.ok   { color: #2dd4a0; }
.rf-pipeline-step .step-status.warn { color: #fbbf24; }
.rf-pipeline-arrow {
    color: #2c2253; font-size: 0.8rem; padding-top: 14px; flex-shrink: 0;
}

/* ── TARGET / INFO PANEL ── */
.rf-target-panel {
    background: #130f23; border: 1px solid #261d46;
    border-radius: 12px; padding: 14px 16px 8px; margin-bottom: 10px;
}
.rf-tp-row {
    display: grid; grid-template-columns: 86px 1fr;
    align-items: baseline; margin-bottom: 9px; gap: 8px;
}
.rf-tp-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.15em; text-transform: uppercase; color: #4d4274;
}
.rf-tp-value {
    font-size: 0.83rem; color: #d8d2f0;
    font-family: 'IBM Plex Mono', monospace; word-break: break-all;
}

/* ── SHODAN SNAPSHOT ── */
.rf-shodan {
    background: #110d24; border: 1px solid #30255b;
    border-left: 3px solid #8b5cf6; border-radius: 12px; padding: 14px 16px 8px;
}
.rf-shodan-row {
    display: grid; grid-template-columns: 90px 1fr;
    align-items: baseline; margin-bottom: 9px; gap: 8px;
}
.rf-shodan-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.15em; text-transform: uppercase; color: #4d4274;
}
.rf-shodan-value { font-size: 0.83rem; color: #968ab8; font-family: 'Space Grotesk', sans-serif; }

/* ── DEAL-KILLER ALERT BANNER ── */
.dk-alert {
    background: linear-gradient(135deg, rgba(255,59,95,0.07), rgba(193,18,77,0.04));
    border: 1px solid rgba(255,59,95,0.2);
    border-left: 4px solid #ff3b5f;
    border-radius: 12px; padding: 14px 18px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 14px;
}
.dk-alert-body { flex: 1; }
.dk-alert-title { font-size: 0.84rem; font-weight: 700; color: #ff3b5f; font-family: 'Space Grotesk', sans-serif; margin-bottom: 2px; }
.dk-alert-sub   { font-size: 0.77rem; color: rgba(255,59,95,0.6); font-family: 'Space Grotesk', sans-serif; }
.dk-alert-count { font-family: 'IBM Plex Mono', monospace; font-size: 2rem; font-weight: 700; color: #ff3b5f; line-height: 1; flex-shrink: 0; }

/* ── ASSET INVENTORY NOTICE ── */
.inv-notice {
    border-radius: 10px; padding: 11px 16px; margin-bottom: 16px;
    font-size: 0.82rem; font-family: 'Space Grotesk', sans-serif;
    display: flex; align-items: center; gap: 10px;
}
.inv-notice.active { background: rgba(45,212,160,0.05); border: 1px solid rgba(45,212,160,0.2); border-left: 3px solid #2dd4a0; color: #2dd4a0; }
.inv-notice.warn   { background: rgba(251,191,36,0.04);  border: 1px solid rgba(251,191,36,0.18); border-left: 3px solid #fbbf24; color: #fbbf24; }

/* ── DIVIDERS ── */
.rf-divider { border: none; border-top: 1px solid #1d1735; margin: 14px 0; }

/* ── SCAN INPUT ── */
[data-testid="stTextInput"] input {
    background: #130f23 !important; border: 1px solid #2c2253 !important;
    border-radius: 12px !important; color: #f1edfe !important;
    font-size: 0.93rem !important; font-family: 'Space Grotesk', sans-serif !important;
    padding: 13px 18px !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #8b5cf6 !important;
    box-shadow: 0 0 0 3px rgba(139,92,246,0.15) !important;
}
[data-testid="stTextInput"] input::placeholder { color: #4d4274 !important; }
[data-testid="stTextInput"] label {
    color: #4d4274 !important; font-size: 0.57rem !important; font-weight: 700 !important;
    letter-spacing: 0.18em !important; text-transform: uppercase !important;
    font-family: 'IBM Plex Mono', monospace !important;
}

/* ── PRIMARY BUTTON ── */
[data-testid="stButton"] > button[kind="primary"],
[data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%) !important;
    border: 1px solid rgba(139,92,246,0.4) !important;
    border-radius: 10px !important; font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 700 !important; font-size: 0.86rem !important; color: white !important;
    box-shadow: 0 4px 20px rgba(139,92,246,0.35) !important;
    transition: box-shadow 0.15s ease, transform 0.12s ease !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover {
    box-shadow: 0 6px 28px rgba(139,92,246,0.55) !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] > button[kind="primary"]:active,
[data-testid="stBaseButton-primary"]:active { transform: translateY(0) !important; }

/* ── DOWNLOAD BUTTONS ── */
[data-testid="stDownloadButton"] > button {
    background: #130f23 !important; border: 1px solid #2c2253 !important;
    border-radius: 10px !important; color: #6c5f97 !important;
    font-family: 'Space Grotesk', sans-serif !important; font-weight: 500 !important;
    transition: all 0.15s ease !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #8b5cf6 !important; color: #b39dfb !important;
    box-shadow: 0 2px 18px rgba(139,92,246,0.2) !important;
}

/* ── TABS — full-width segmented command bar ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: none !important;
    gap: 6px !important;
    background: rgba(19,15,35,0.7) !important;
    border: 1px solid #261d46 !important;
    border-radius: 16px !important;
    padding: 6px !important;
    width: 100% !important;
    display: flex !important;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
}
[data-testid="stTabs"] button[role="tab"] {
    flex: 1 1 0 !important;
    justify-content: center !important;
    font-family: 'IBM Plex Mono', monospace !important; font-weight: 600 !important;
    font-size: 0.7rem !important; color: #5b4e85 !important;
    letter-spacing: 0.14em !important; text-transform: uppercase !important;
    padding: 11px 8px !important;
    border-bottom: none !important;
    transition: color 0.15s ease, background 0.18s ease !important;
    background: transparent !important; border-radius: 11px !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    color: #f1edfe !important;
    background: linear-gradient(135deg, rgba(139,92,246,0.3), rgba(109,40,217,0.16)) !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 4px 18px rgba(139,92,246,0.22) !important;
}
[data-testid="stTabs"] button[role="tab"]:hover { color: #968ab8 !important; }
[data-testid="stTabs"] [data-baseweb="tab-highlight"],
[data-testid="stTabs"] [data-baseweb="tab-border"] { display: none !important; }

/* ── EXPANDERS ── */
[data-testid="stExpander"] details {
    background: #130f23 !important; border: 1px solid #2c2253 !important;
    border-radius: 12px !important; transition: border-color 0.15s ease !important;
}
[data-testid="stExpander"] details:hover {
    border-color: #3e316e !important;
}
[data-testid="stExpander"] details[open] {
    border-color: #8b5cf644 !important;
}
[data-testid="stExpander"] summary {
    font-family: 'Space Grotesk', sans-serif !important; font-weight: 600 !important;
    font-size: 0.84rem !important; color: #968ab8 !important; padding: 14px 18px !important;
}
[data-testid="stExpander"] summary:hover { color: #d8d2f0 !important; }
[data-testid="stExpander"] details > div { padding: 2px 18px 16px !important; }
[data-testid="stExpander"] [data-testid="stCaptionContainer"] p {
    color: #4d4274 !important; font-family: 'Space Grotesk', sans-serif !important;
    font-size: 0.75rem !important; letter-spacing: 0 !important;
}

/* ── FILE UPLOADER ── */
[data-testid="stFileUploader"] section {
    background: #07060f !important; border: 1px dashed #2c2253 !important;
    border-radius: 10px !important;
}
[data-testid="stFileUploader"] section:hover {
    border-color: #8b5cf6 !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] {
    color: #4d4274 !important; font-family: 'Space Grotesk', sans-serif !important;
    font-size: 0.78rem !important;
}

/* ── SCAN HERO INPUT (override for the borderless look) ── */
.scan-hero [data-testid="stTextInput"] input {
    background: #07060f !important;
    border: 1px solid #372b64 !important;
    border-radius: 10px !important;
    font-size: 1rem !important;
    padding: 14px 20px !important;
    height: 50px !important;
}
.scan-hero [data-testid="stTextInput"] input:focus {
    border-color: #8b5cf6 !important;
    box-shadow: 0 0 0 3px rgba(139,92,246,0.12) !important;
}

/* ── MULTISELECT ── */
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
    background: #130f23 !important; border-color: #2c2253 !important;
    border-radius: 10px !important;
}

/* ── CHECKBOX ── */
[data-testid="stCheckbox"] label {
    font-size: 0.85rem !important; color: #6c5f97 !important;
    font-family: 'Space Grotesk', sans-serif !important;
}

/* ── CAPTION ── */
[data-testid="stCaptionContainer"] p {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.71rem !important; color: #4d4274 !important; letter-spacing: 0.02em !important;
}

/* ── ALERTS ── */
[data-testid="stAlertContainer"] { border-radius: 10px !important; }

/* ── METRIC CARD — bottom action tab ── */
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button,
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondaryFormSubmit"] button {
    background:      #0b0917 !important;
    border:          1px solid #261d46 !important;
    border-top:      none !important;
    border-radius:   0 0 14px 14px !important;
    box-shadow:      none !important;
    color:           #3e316e !important;
    font-size:       0.56rem !important;
    font-family:     'IBM Plex Mono', monospace !important;
    font-weight:     700 !important;
    letter-spacing:  0.14em !important;
    text-transform:  uppercase !important;
    padding:         7px 0 6px !important;
    margin-top:      -1px !important;
    width:           100% !important;
    min-height:      0 !important;
    height:          28px !important;
    transition:      color 0.18s ease, background 0.18s ease !important;
    cursor:          pointer !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    [data-testid="stBaseButton-secondary"] button:hover {
    color:      #b39dfb !important;
    background: #161129 !important;
    box-shadow: none !important;
    transform:  none !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5))
    > div:first-child [data-testid="stBaseButton-secondary"] { display: none; }

/* ── ENGINE PILLS (kept for backwards-compat, not used in navbar) ── */
.rf-engine-pills { display: flex; gap: 4px; align-items: center; }
.rf-epill {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.58rem; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    color: #4d4274; background: #130f23; border: 1px solid #261d46;
    border-radius: 5px; padding: 4px 9px;
}

/* ── PRE-SCAN WELCOME CARDS ── */
.rf-prescan-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px;
}
.rf-prescan-card {
    background: #130f23; border: 1px solid #261d46; border-radius: 14px;
    padding: 20px 18px; position: relative; overflow: hidden;
}
.rf-prescan-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    border-radius: 14px 14px 0 0;
}
.rf-prescan-card.blue::before  { background: linear-gradient(90deg, #8b5cf6, #6d28d9); }
.rf-prescan-card.red::before   { background: linear-gradient(90deg, #ff3b5f, #c1124d); }
.rf-prescan-card.green::before { background: linear-gradient(90deg, #2dd4a0, #0d9468); }
.rf-prescan-card .pc-num {
    font-size: 2rem; font-weight: 700; font-family: 'IBM Plex Mono', monospace;
    line-height: 1; margin-bottom: 10px;
}
.rf-prescan-card.blue .pc-num  { color: #8b5cf6; }
.rf-prescan-card.red .pc-num   { color: #ff3b5f; }
.rf-prescan-card.green .pc-num { color: #2dd4a0; }
.rf-prescan-card .pc-title {
    font-size: 0.82rem; font-weight: 700; color: #d8d2f0;
    font-family: 'Space Grotesk', sans-serif; margin-bottom: 6px;
}
.rf-prescan-card .pc-body {
    font-size: 0.75rem; color: #5b4e85; font-family: 'Space Grotesk', sans-serif; line-height: 1.6;
}
.rf-status-dot-wrap {
    display: flex; align-items: center; gap: 6px;
    padding: 5px 12px; background: rgba(45,212,160,0.06);
    border: 1px solid rgba(45,212,160,0.15); border-radius: 20px;
}

/* ── SCAN HERO ── */
.rf-scan-hero {
    position: relative; overflow: hidden;
    background: linear-gradient(135deg, #170f2f 0%, #0d0a1c 60%, #07060f 100%);
    border: 1px solid #261d46; border-radius: 18px;
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
    background: radial-gradient(circle, rgba(139,92,246,0.12) 0%, transparent 70%);
    right: 10%; top: -30px;
}
.rf-hero-glow-red {
    width: 200px; height: 160px;
    background: radial-gradient(circle, rgba(255,59,95,0.08) 0%, transparent 70%);
    right: 30%; bottom: -20px;
}
.rf-hero-content {
    position: relative; z-index: 2;
    max-width: 62%;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #07060f; }
::-webkit-scrollbar-thumb { background: #261d46; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #372b64; }
</style>
""", unsafe_allow_html=True)


# ── Design System v5.1 — DEPTH & GLOW layer ─────────────────────────────────────
# Appended on top of v5 so every shared surface gains glassmorphism, layered
# shadows, and soft accent glows without touching any tab markup.
st.markdown("""
<style>
/* ── Ambient atmosphere: corner glows + faint blueprint grid ── */
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(1100px 640px at 6% -10%, rgba(139,92,246,0.09), transparent 55%),
        radial-gradient(950px 620px at 102% 110%, rgba(255,59,95,0.06), transparent 55%),
        radial-gradient(800px 500px at 80% -5%, rgba(34,211,238,0.04), transparent 60%),
        repeating-linear-gradient(0deg, rgba(139,92,246,0.022) 0px, rgba(139,92,246,0.022) 1px, transparent 1px, transparent 44px),
        repeating-linear-gradient(90deg, rgba(139,92,246,0.022) 0px, rgba(139,92,246,0.022) 1px, transparent 1px, transparent 44px),
        #07060f !important;
    background-attachment: fixed !important;
}

/* ── Metric cards: frosted glass + accent glow + neon value ── */
.rf-metric {
    background: linear-gradient(165deg, rgba(28,40,68,0.55) 0%, rgba(14,21,34,0.88) 100%) !important;
    backdrop-filter: blur(10px) saturate(125%);
    -webkit-backdrop-filter: blur(10px) saturate(125%);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.05), 0 10px 30px rgba(0,0,0,0.45);
}
.rf-metric::after {
    content: ''; position: absolute; top: -34%; left: 50%; transform: translateX(-50%);
    width: 78%; height: 66%; border-radius: 50%;
    filter: blur(30px); opacity: 0.55; z-index: 0; pointer-events: none;
}
.rf-metric .label, .rf-metric .value { position: relative; z-index: 1; }
.rf-metric.red::after    { background: radial-gradient(circle, rgba(255,59,95,0.34), transparent 70%); }
.rf-metric.orange::after { background: radial-gradient(circle, rgba(255,120,73,0.30), transparent 70%); }
.rf-metric.yellow::after { background: radial-gradient(circle, rgba(251,191,36,0.24), transparent 70%); }
.rf-metric.green::after  { background: radial-gradient(circle, rgba(45,212,160,0.26), transparent 70%); }
.rf-metric.blue::after   { background: radial-gradient(circle, rgba(139,92,246,0.30), transparent 70%); }
.rf-metric.red .value    { text-shadow: 0 0 22px rgba(255,59,95,0.55); }
.rf-metric.orange .value { text-shadow: 0 0 22px rgba(255,120,73,0.5); }
.rf-metric.yellow .value { text-shadow: 0 0 22px rgba(251,191,36,0.45); }
.rf-metric.green .value  { text-shadow: 0 0 22px rgba(45,212,160,0.45); }
.rf-metric.blue .value   { text-shadow: 0 0 22px rgba(139,92,246,0.5); }
.rf-metric:hover {
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 16px 44px rgba(0,0,0,0.6) !important;
}

/* ── Panels: translucent glass so the ambient glow reads through ── */
.rf-target-panel, .rf-pipeline-h {
    background: rgba(15,22,35,0.72) !important;
    backdrop-filter: blur(9px) saturate(115%);
    -webkit-backdrop-filter: blur(9px) saturate(115%);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 8px 26px rgba(0,0,0,0.42);
}
.rf-shodan {
    background: rgba(12,20,34,0.74) !important;
    backdrop-filter: blur(9px) saturate(115%);
    -webkit-backdrop-filter: blur(9px) saturate(115%);
    box-shadow: inset 0 1px 0 rgba(139,92,246,0.10), 0 8px 26px rgba(0,0,0,0.42),
                0 0 34px rgba(139,92,246,0.05);
}

/* ── Finding + mini cards: subtle glass depth at rest ── */
.finding-card {
    background: rgba(15,22,35,0.70) !important;
    backdrop-filter: blur(7px);
    -webkit-backdrop-filter: blur(7px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 6px 20px rgba(0,0,0,0.35);
}
.fmc {
    background: rgba(15,22,35,0.66) !important;
    backdrop-filter: blur(7px);
    -webkit-backdrop-filter: blur(7px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 5px 16px rgba(0,0,0,0.3);
}

/* ── Scan hero + deal-killer alert + pre-scan cards: more depth ── */
.rf-scan-hero {
    box-shadow: 0 22px 54px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04);
}
.dk-alert {
    box-shadow: 0 0 44px rgba(255,59,95,0.10), inset 0 1px 0 rgba(255,255,255,0.04);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
}
.rf-prescan-card {
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 10px 30px rgba(0,0,0,0.42);
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    transition: transform 0.2s ease, box-shadow 0.25s ease;
}
.rf-prescan-card:hover {
    transform: translateY(-2px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 16px 40px rgba(0,0,0,0.55);
}

/* ── Active tab: soft electric glow ── */
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    text-shadow: 0 0 16px rgba(139,92,246,0.5);
}

/* ── Expanders: lift off the page ── */
[data-testid="stExpander"] details {
    box-shadow: 0 6px 20px rgba(0,0,0,0.32);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
}
</style>
""", unsafe_allow_html=True)



# ── Design System v6 — COMMAND RAIL layout layer ────────────────────────────────
# Sidebar rail, command strip, editorial hero, and deal-verdict banner styles.
st.markdown("""
<style>
/* ── SIDEBAR command rail ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b0917 0%, #07060f 100%) !important;
    border-right: 1px solid #1d1735 !important;
    min-width: 304px !important;
}
[data-testid="stSidebar"]::after {
    content: ''; position: absolute; top: 0; right: 0; bottom: 0; width: 1px;
    background: linear-gradient(180deg, rgba(139,92,246,0.35), transparent 40%);
    pointer-events: none;
}
.rf-side-brand {
    display: flex; align-items: center; gap: 12px;
    padding: 8px 2px 16px; border-bottom: 1px solid #1d1735; margin-bottom: 16px;
}
.rf-side-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.57rem; font-weight: 700;
    letter-spacing: 0.22em; text-transform: uppercase; color: #4d4274; margin: 6px 0 8px;
}
[data-testid="stSidebar"] [data-testid="stExpander"] details {
    background: #0b0917 !important; border: 1px solid #1d1735 !important;
    border-radius: 10px !important;
}
[data-testid="stSidebar"] [data-testid="stExpander"] summary {
    padding: 10px 14px !important; font-size: 0.76rem !important;
}
[data-testid="stSidebar"] [data-testid="stFileUploader"] section {
    background: #07060f !important;
}
.rf-side-engines { margin-top: 22px; padding-top: 16px; border-top: 1px solid #1d1735; }
.rf-engine-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 5px; }
.rf-engine-grid span {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.55rem; font-weight: 600;
    letter-spacing: 0.04em; text-transform: uppercase; color: #5b4e85;
    background: #130f23; border: 1px solid #261d46; border-radius: 6px;
    padding: 5px 0; text-align: center;
}
.rf-side-status {
    display: flex; align-items: center; gap: 4px; margin-top: 14px;
    font-family: 'IBM Plex Mono', monospace; font-size: 0.62rem;
    color: #2dd4a0; font-weight: 600; letter-spacing: 0.05em;
}

/* ── COMMAND STRIP ── */
.rf-cmdstrip {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 18px; margin: 12px 0 18px;
    background: rgba(19,15,35,0.6); border: 1px solid #1d1735; border-radius: 12px;
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
}
.rf-cmd-crumb {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.64rem; font-weight: 700;
    letter-spacing: 0.14em; text-transform: uppercase; color: #5b4e85;
}
.rf-cmd-sep { color: #372b64; }
.rf-cmd-target { font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: #d8d2f0; }
.rf-cmd-chip {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.56rem; font-weight: 700;
    letter-spacing: 0.18em; color: #5b4e85;
    background: #130f23; border: 1px solid #261d46; border-radius: 20px; padding: 4px 12px;
}
.rf-cmd-chip.live { color: #2dd4a0; background: rgba(45,212,160,0.07); border-color: rgba(45,212,160,0.25); }

/* ── HERO v2 — editorial pre-scan ── */
.rf-hero2 { padding: 52px 8px 34px; max-width: 920px; }
.rf-hero2-kicker {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.6rem; font-weight: 700;
    letter-spacing: 0.32em; color: #8b5cf6; margin-bottom: 20px;
}
.rf-hero2-title {
    font-family: 'Space Grotesk', sans-serif; font-size: 3.6rem; font-weight: 700;
    line-height: 1.05; letter-spacing: -0.03em; color: #f1edfe; margin: 0 0 20px;
}
.rf-hero2-title .grad {
    background: linear-gradient(100deg, #ff3b5f, #8b5cf6 70%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
}
.rf-hero2-sub { font-size: 0.96rem; color: #6c5f97; line-height: 1.75; max-width: 660px; margin-bottom: 36px; }
.rf-hero2-steps { display: flex; align-items: stretch; gap: 10px; flex-wrap: wrap; }
.rf-hero2-steps .step {
    display: flex; flex-direction: column; gap: 3px;
    background: rgba(19,15,35,0.7); border: 1px solid #261d46; border-radius: 12px;
    padding: 12px 16px; min-width: 158px;
}
.rf-hero2-steps .n { font-family: 'IBM Plex Mono', monospace; font-size: 0.6rem; font-weight: 700; color: #8b5cf6; letter-spacing: 0.18em; }
.rf-hero2-steps .t { font-size: 0.84rem; font-weight: 700; color: #d8d2f0; }
.rf-hero2-steps .d { font-size: 0.7rem; color: #5b4e85; }
.rf-hero2-steps .arrow { align-self: center; color: #372b64; }

/* ── FEATURE CARDS (pre-scan) ── */
.rf-feat {
    background: linear-gradient(165deg, rgba(28,22,48,0.6), rgba(11,9,23,0.9));
    border: 1px solid #261d46; border-radius: 16px; padding: 22px 20px; height: 100%;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 10px 30px rgba(0,0,0,0.42);
}
.rf-feat .num { font-family: 'IBM Plex Mono', monospace; font-size: 2rem; font-weight: 700; line-height: 1; margin-bottom: 12px; display: block; }
.rf-feat .ttl { font-size: 0.88rem; font-weight: 700; color: #d8d2f0; margin-bottom: 7px; }
.rf-feat .bod { font-size: 0.76rem; color: #5b4e85; line-height: 1.7; }
.rf-feat.violet .num  { color: #8b5cf6; }
.rf-feat.crimson .num { color: #ff3b5f; }
.rf-feat.green .num   { color: #2dd4a0; }

/* ── DEAL VERDICT banner ── */
.rf-verdict {
    display: flex; align-items: center; gap: 26px;
    padding: 22px 28px; margin: 4px 0 20px;
    border-radius: 18px; border: 1px solid #261d46;
    background: linear-gradient(135deg, rgba(19,15,35,0.92), rgba(11,9,23,0.96));
    position: relative; overflow: hidden;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 14px 40px rgba(0,0,0,0.5);
}
.rf-verdict::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
.rf-verdict.dk::before   { background: linear-gradient(180deg, #ff3b5f, #c1124d); }
.rf-verdict.crit::before { background: #ff7849; }
.rf-verdict.mod::before  { background: #fbbf24; }
.rf-verdict.man::before  { background: #2dd4a0; }
.rf-verdict-score { text-align: center; min-width: 96px; padding-right: 26px; border-right: 1px solid #1d1735; }
.rf-verdict-score .v { font-family: 'IBM Plex Mono', monospace; font-size: 3rem; font-weight: 700; line-height: 1; display: block; }
.rf-verdict.dk .v   { color: #ff3b5f; text-shadow: 0 0 26px rgba(255,59,95,0.5); }
.rf-verdict.crit .v { color: #ff7849; text-shadow: 0 0 26px rgba(255,120,73,0.4); }
.rf-verdict.mod .v  { color: #fbbf24; text-shadow: 0 0 26px rgba(251,191,36,0.35); }
.rf-verdict.man .v  { color: #2dd4a0; text-shadow: 0 0 26px rgba(45,212,160,0.35); }
.rf-verdict-score .cap { font-family: 'IBM Plex Mono', monospace; font-size: 0.55rem; letter-spacing: 0.18em; text-transform: uppercase; color: #4d4274; }
.rf-verdict-main { flex: 1; }
.rf-verdict-kicker { font-family: 'IBM Plex Mono', monospace; font-size: 0.58rem; font-weight: 700; letter-spacing: 0.22em; text-transform: uppercase; color: #4d4274; margin-bottom: 4px; }
.rf-verdict-label { font-family: 'Space Grotesk', sans-serif; font-size: 1.7rem; font-weight: 700; letter-spacing: -0.01em; line-height: 1.1; }
.rf-verdict.dk .rf-verdict-label   { color: #ff3b5f; }
.rf-verdict.crit .rf-verdict-label { color: #ff7849; }
.rf-verdict.mod .rf-verdict-label  { color: #fbbf24; }
.rf-verdict.man .rf-verdict-label  { color: #2dd4a0; }
.rf-verdict-msg { font-size: 0.78rem; color: #6c5f97; margin-top: 4px; }
.rf-verdict-stats { display: flex; gap: 24px; }
.rf-verdict-stats > div { text-align: center; }
.rf-verdict-stats .num { font-family: 'IBM Plex Mono', monospace; font-size: 1.5rem; font-weight: 700; display: block; line-height: 1; }
.rf-verdict-stats .lbl { font-family: 'IBM Plex Mono', monospace; font-size: 0.52rem; letter-spacing: 0.16em; text-transform: uppercase; color: #4d4274; }
.c-dk   { color: #ff3b5f; }
.c-crit { color: #ff7849; }
.c-mod  { color: #fbbf24; }
.c-man  { color: #2dd4a0; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

TIER_COLOR = {
    "deal_killer": "#ff3b5f",
    "critical":    "#ff7849",
    "moderate":    "#fbbf24",
    "manageable":  "#2dd4a0",
    "unscored":    "#7d7795",
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
    if score >= 75: return "#ff3b5f"
    if score >= 50: return "#ff7849"
    if score >= 25: return "#fbbf24"
    return "#2dd4a0"

def format_label(value):
    if value is None: return "—"
    return str(value).replace("_", " ").title()

_TIER_DOT_COLORS = {
    "deal_killer": "#ff3b5f",
    "critical":    "#ff7849",
    "moderate":    "#fbbf24",
    "manageable":  "#2dd4a0",
}

def tier_dot_html(tier_val: str, size: int = 9) -> str:
    """Return a small glowing dot as an HTML span — replaces emoji tier icons."""
    c = _TIER_DOT_COLORS.get(tier_val, "#7d7795")
    return (
        f'<span style="display:inline-block;width:{size}px;height:{size}px;'
        f'border-radius:50%;background:{c};flex-shrink:0;'
        f'box-shadow:0 0 5px {c}99;"></span>'
    )



def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _embed_html(html: str, height: int = 0, scrolling: bool = False):
    """Render raw HTML + JS inside a sandboxed iframe.

    Calls ``st._main._html`` — the exact implementation that the now-deprecated
    ``st.components.v1.html`` wraps. We call it directly to avoid the in-browser
    deprecation warning while keeping JS-in-iframe behaviour, which the public
    alternatives cannot provide: ``st.html`` renders inline (no iframe) and
    ``st.iframe`` accepts a URL only (no raw HTML). Used for the pyvis attack
    graph and the metric-card → Findings tab switcher.
    """
    return st._main._html(html, height=height, scrolling=scrolling)


def _build_attack_graph_html(graph_data) -> str | None:
    """
    Build a pyvis/vis.js attack path graph and return the full HTML string.
    Returns None if pyvis is not installed.
    """
    try:
        from pyvis.network import Network
    except ImportError:
        return None

    import json, tempfile, os

    LEVEL  = {"INTERNET": 0, "HOST": 1, "SVC": 2, "CVE": 3}
    SIZE   = {"INTERNET": 55, "HOST": 45, "SVC": 32, "CVE": 26}
    FSIZE  = {"INTERNET": 15, "HOST": 12, "SVC": 10, "CVE": 10}

    def _lyr(nid):
        if nid == "INTERNET":       return "INTERNET"
        if nid.startswith("HOST:"): return "HOST"
        if nid.startswith("SVC:"):  return "SVC"
        return "CVE"

    net = Network(
        height="680px",
        width="100%",
        bgcolor="#070510",
        font_color="#d8d2f0",
        directed=True,
        notebook=False,
    )

    for node in graph_data.nodes:
        lyr     = _lyr(node.id)
        is_inet = node.id == "INTERNET"
        net.add_node(
            node.id,
            label=node.label,
            title=node.title,
            color={
                "background": node.color,
                "border":     "#ffffff33" if not is_inet else "#b39dfb",
                "highlight":  {"background": node.color, "border": "#ffffff"},
                "hover":      {"background": node.color, "border": "#ffffff88"},
            },
            size=SIZE[lyr],
            font={
                "size":        FSIZE[lyr],
                "color":       "#f1edfe",
                "face":        "monospace",
                "strokeWidth": 4,
                "strokeColor": "#070510",
            },
            shape="diamond" if is_inet else "dot",
            shadow={"enabled": True, "color": node.color + "55", "size": 18, "x": 0, "y": 0},
            level=LEVEL[lyr],
            borderWidth=2,
            borderWidthSelected=3,
        )

    for edge in graph_data.edges:
        net.add_edge(
            edge.source,
            edge.target,
            color={"color": edge.color, "opacity": 0.55, "highlight": edge.color, "hover": "#ffffff"},
            width=max(1.8, edge.width),
            arrows={"to": {"enabled": True, "scaleFactor": 0.9, "type": "arrow"}},
            smooth={"type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.45},
            hoverWidth=1.5,
            selectionWidth=2,
        )

    net.set_options(json.dumps({
        "layout": {
            "hierarchical": {
                "enabled":            True,
                "direction":          "UD",
                "sortMethod":         "directed",
                "levelSeparation":    200,
                "nodeSpacing":        160,
                "treeSpacing":        260,
                "blockShifting":      True,
                "edgeMinimization":   True,
                "parentCentralization": True,
            }
        },
        "physics": {"enabled": False},
        "interaction": {
            "hover":        True,
            "tooltipDelay": 60,
            "zoomView":     True,
            "dragView":     True,
        },
        "nodes": {"borderWidth": 2},
        "edges": {"selectionWidth": 2},
    }))

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        net.save_graph(f.name)
        _fname = f.name
    with open(_fname, encoding="utf-8") as f:
        html = f.read()
    os.unlink(_fname)

    # ── Patch styles so everything matches Design System v4 ───────────────────
    _css = """
<style>
  html, body { background: #070510 !important; margin: 0; padding: 0; }
  #mynetwork {
    background: radial-gradient(ellipse at 50% 0%, #141036 0%, #070510 70%) !important;
    border: 1px solid #261d46 !important;
    border-radius: 14px !important;
  }
  div.vis-tooltip {
    background: #130f23 !important;
    border: 1px solid #261d46 !important;
    color: #d8d2f0 !important;
    font-family: 'Space Grotesk', -apple-system, sans-serif !important;
    font-size: 12px !important;
    border-radius: 10px !important;
    padding: 10px 14px !important;
    max-width: 300px !important;
    line-height: 1.6 !important;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6) !important;
    pointer-events: none !important;
  }
</style>
"""
    return html.replace("</head>", _css + "</head>")


# ── Sidebar — command rail ────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
<div class="rf-side-brand">
  <div class="rf-brand-icon">RF</div>
  <div class="rf-brand-text">
    <span class="rf-brand-name">RedFlag</span>
    <span class="rf-brand-sub">M&amp;A Cyber Due Diligence</span>
  </div>
</div>
""", unsafe_allow_html=True)

    st.markdown('<div class="rf-side-label">Scan target</div>', unsafe_allow_html=True)
    target = st.text_input(
        "TARGET_LABEL",
        value="scanme.nmap.org",
        placeholder="domain or IP — e.g. scanme.nmap.org",
        label_visibility="collapsed",
    )
    run_scan = st.button("Run Comprehensive Scan", width="stretch", type="primary")
    fast_mode = st.checkbox("Fast Scan Mode", value=False,
                            help="Top 200 ports · version-intensity 3 · ~2x faster. May miss uncommon ports.")

    st.markdown('<div class="rf-side-label" style="margin-top:20px;">Intelligence uploads</div>',
                unsafe_allow_html=True)

    with st.expander("Shodan JSON — 0 credits"):
        st.caption("Target-provided Shodan export. Replaces the live API call.")
        shodan_json_file = st.file_uploader(
            "Shodan JSON", type=["json"], label_visibility="collapsed", key="shodan_json_upload"
        )
    with st.expander("OpenVAS XML — verified CVEs"):
        st.caption("Verified CVE findings with CONFIRMED evidence strength.")
        openvas_file = st.file_uploader("OpenVAS XML", type=["xml"], label_visibility="collapsed", key="ov_upload")
    with st.expander("OWASP ZAP XML — web layer"):
        st.caption("Web application findings — SQLi, XSS, misconfigurations.")
        zap_file = st.file_uploader("ZAP XML", type=["xml"], label_visibility="collapsed", key="zap_upload")
    with st.expander("Asset inventory — Excel"):
        st.caption("Maps hosts to Crown Jewel / Regulated tiers. Unlocks deal-killer rules.")
        asset_file = st.file_uploader("Asset Inventory Excel", type=["xlsx", "xls"], label_visibility="collapsed", key="asset_upload")

    st.markdown("""
<div class="rf-side-engines">
  <div class="rf-side-label">Engines</div>
  <div class="rf-engine-grid">
    <span>Nmap</span><span>Shodan</span><span>OpenVAS</span><span>ZAP</span>
    <span>Vulners</span><span>DNS</span><span>TLS</span><span>Breach</span>
  </div>
  <div class="rf-side-status"><span class="rf-dot ok"></span>&nbsp; All systems operational</div>
</div>
""", unsafe_allow_html=True)

# ── Command strip (main-area header) ──────────────────────────────────────────

_strip_live = "findings" in st.session_state
_strip_tgt  = st.session_state.get("clean_target", "no target scanned yet")
st.markdown(f"""
<div class="rf-cmdstrip">
  <span class="rf-cmd-crumb">RedFlag console</span>
  <span class="rf-cmd-sep">/</span>
  <span class="rf-cmd-target">{_strip_tgt}</span>
  <span style="flex:1"></span>
  <span class="rf-cmd-chip {'live' if _strip_live else ''}">{'ASSESSMENT LIVE' if _strip_live else 'STANDBY'}</span>
</div>
""", unsafe_allow_html=True)

# ── Scan execution ────────────────────────────────────────────────────────────

if run_scan:
    if not target.strip():
        st.error("Please enter a valid target.")
    else:
        try:
            with st.spinner("Scanning target · Vulners · Shodan · DNS · TLS · Breach check — this may take 45–90s..."):
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

                # ── DNS & Email Security ──────────────────────────────────────
                dns_findings: list = []
                dns_summary: dict  = {}
                try:
                    dns_findings = run_dns_scan(clean_target)
                    dns_summary  = {"count": len(dns_findings), "success": True}
                except Exception as _e:
                    dns_summary  = {"count": 0, "success": False, "error": str(_e)}
                all_findings += dns_findings

                # ── TLS / Certificate Health ──────────────────────────────────
                tls_findings: list = []
                tls_summary: dict  = {}
                try:
                    _https_ports = list({
                        f.port for f in nmap_findings
                        if f.port and (
                            (f.service or "").lower() in ("https", "ssl") or f.port == 443
                        )
                    })
                    tls_findings, tls_summary = run_tls_scan(clean_target, _https_ports)
                except Exception as _e:
                    tls_summary = {"count": 0, "success": False, "error": str(_e)}
                all_findings += tls_findings

                # ── Breach / Dark Web Exposure ────────────────────────────────
                breach_findings: list = []
                breach_summary: dict  = {}
                try:
                    breach_findings, breach_summary = run_breach_scan(
                        clean_target, [resolved_ip]
                    )
                except Exception as _e:
                    breach_summary = {"count": 0, "success": False, "error": str(_e)}
                all_findings += breach_findings

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
            st.session_state["dns_findings"]     = dns_findings
            st.session_state["dns_summary"]      = dns_summary
            st.session_state["tls_findings"]     = tls_findings
            st.session_state["tls_summary"]      = tls_summary
            st.session_state["breach_findings"]  = breach_findings
            st.session_state["breach_summary"]   = breach_summary

            deal_killers = sum(1 for f in findings if str(getattr(f.deal_tier, "value", f.deal_tier)) == "deal_killer")
            if deal_killers:
                st.error(f"⚠️  Scan complete — **{deal_killers} deal-killer finding{'s' if deal_killers > 1 else ''}** detected across {len(findings)} total findings.")
            else:
                st.success(f"✅  Scan complete — {len(findings)} findings for **{clean_target}**.")

        except Exception as e:
            st.error(f"Scan failed: {e}")

# ── Pre-scan welcome state ───────────────────────────────────────────────────

if "findings" not in st.session_state:
    st.markdown("""
<div class="rf-hero2">
  <div class="rf-hero2-kicker">M&amp;A CYBERSECURITY DUE DILIGENCE</div>
  <h1 class="rf-hero2-title">Know exactly what<br>you're <span class="grad">acquiring</span>.</h1>
  <div class="rf-hero2-sub">Eight scanners, one weighted risk model, a single deal-room verdict.
  Point RedFlag at a target in the left rail and get an evidence-backed picture of the cyber
  liability you are about to buy — before the ink dries.</div>
  <div class="rf-hero2-steps">
    <div class="step"><span class="n">01</span><span class="t">Enter target</span><span class="d">Domain or IP in the left rail</span></div>
    <div class="arrow">→</div>
    <div class="step"><span class="n">02</span><span class="t">Run the sweep</span><span class="d">Nmap · Shodan · DNS · TLS · Breach</span></div>
    <div class="arrow">→</div>
    <div class="step"><span class="n">03</span><span class="t">Read the verdict</span><span class="d">Deal-killer rules &amp; weighted scores</span></div>
    <div class="arrow">→</div>
    <div class="step"><span class="n">04</span><span class="t">Export the report</span><span class="d">CSV · PDF · cost model</span></div>
  </div>
</div>
""", unsafe_allow_html=True)

    pc1, pc2, pc3 = st.columns(3)
    with pc1:
        st.markdown(
            '<div class="rf-feat violet"><span class="num">8</span>'
            '<div class="ttl">Scanners, one risk picture</div>'
            '<div class="bod">Nmap, Shodan, OpenVAS, ZAP, Vulners, CISA KEV, DNS security and TLS '
            'certificate checks merge into a single unified finding list.</div></div>',
            unsafe_allow_html=True,
        )
    with pc2:
        st.markdown(
            '<div class="rf-feat crimson"><span class="num">0–100</span>'
            '<div class="ttl">Weighted risk score per finding</div>'
            '<div class="bod">CVE severity, exposure, data sensitivity and exploit availability. '
            'Deal-killer conditions bypass scoring and flag immediately.</div></div>',
            unsafe_allow_html=True,
        )
    with pc3:
        st.markdown(
            '<div class="rf-feat green"><span class="num">6</span>'
            '<div class="ttl">Deal-room report tabs</div>'
            '<div class="bod">Overview, Findings, Attack Path, Maturity, Cost &amp; Budget and Export — '
            'including a What-If simulator to price pre-close remediation.</div></div>',
            unsafe_allow_html=True,
        )

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

    # ── Deal verdict banner ───────────────────────────────────────────────────
    _avg_all = sum(f.risk_score for f in findings) / len(findings) if findings else 0.0
    if n_dk:
        _v_lbl, _v_cls, _v_msg = "DEAL KILLER", "dk", "Active blockers detected — escalate before any close."
    elif _avg_all >= 75:
        _v_lbl, _v_cls, _v_msg = "CRITICAL", "crit", "Severe exposure — price protection and pre-close remediation required."
    elif _avg_all >= 50:
        _v_lbl, _v_cls, _v_msg = "MODERATE", "mod", "Material gaps — negotiate remediation commitments into the deal."
    else:
        _v_lbl, _v_cls, _v_msg = "MANAGEABLE", "man", "Risk absorbable within a standard post-close integration budget."
    st.markdown(f"""
<div class="rf-verdict {_v_cls}">
  <div class="rf-verdict-score"><span class="v">{_avg_all:.0f}</span><span class="cap">avg risk</span></div>
  <div class="rf-verdict-main">
    <div class="rf-verdict-kicker">Deal verdict — {clean_target} · {resolved_ip}</div>
    <div class="rf-verdict-label">{_v_lbl}</div>
    <div class="rf-verdict-msg">{_v_msg}</div>
  </div>
  <div class="rf-verdict-stats">
    <div><span class="num c-dk">{n_dk}</span><span class="lbl">killers</span></div>
    <div><span class="num c-crit">{n_crit}</span><span class="lbl">critical</span></div>
    <div><span class="num c-mod">{n_mod}</span><span class="lbl">moderate</span></div>
    <div><span class="num c-man">{n_man}</span><span class="lbl">manageable</span></div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────────────────

    tab_overview, tab_findings, tab_attack, tab_maturity, tab_cost, tab_export = st.tabs(
        ["  Overview  ", "  Findings  ", "  Attack Path  ", "  Maturity Assessment  ", "  Cost & Budget  ", "  Export  "]
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
            if st.button("View all ›", key="mc_dk", width="stretch"):
                st.session_state["tier_preset"]         = "deal_killer"
                st.session_state["_switch_to_findings"] = True
        with mc3:
            st.markdown(metric_card("Critical", n_crit, "orange"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_crit", width="stretch"):
                st.session_state["tier_preset"]         = "critical"
                st.session_state["_switch_to_findings"] = True
        with mc4:
            st.markdown(metric_card("Moderate", n_mod, "yellow"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_mod", width="stretch"):
                st.session_state["tier_preset"]         = "moderate"
                st.session_state["_switch_to_findings"] = True
        with mc5:
            st.markdown(metric_card("Manageable", n_man, "green"), unsafe_allow_html=True)
            if st.button("View all ›", key="mc_man", width="stretch"):
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

        # ── Breach alert banner ───────────────────────────────────────────────
        _breach_sum = st.session_state.get("breach_summary", {})
        if _breach_sum.get("breach_found"):
            _n_breach = _breach_sum.get("total", 0)
            st.markdown(f"""
            <div style="background:linear-gradient(135deg,rgba(255,59,95,0.07),rgba(193,18,77,0.04));
                        border:1px solid rgba(255,59,95,0.25);border-left:4px solid #ff3b5f;
                        border-radius:12px;padding:14px 18px;margin-bottom:14px;
                        display:flex;align-items:center;gap:14px;">
              <div style="width:36px;height:36px;background:rgba(255,59,95,0.1);border-radius:9px;
                          display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                     stroke="#ff3b5f" stroke-width="2" stroke-linecap="round">
                  <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
              </div>
              <div style="flex:1;">
                <div style="font-size:0.84rem;font-weight:700;color:#ff3b5f;
                            font-family:'Space Grotesk',sans-serif;margin-bottom:2px;">
                  Breach Exposure Detected — Target Indexed in Public Breach Database
                </div>
                <div style="font-size:0.77rem;color:rgba(255,59,95,0.6);
                            font-family:'Space Grotesk',sans-serif;">
                  {_n_breach} live exposure(s) found via LeakIX — these are already known to attackers
                </div>
              </div>
              <div style="font-family:'IBM Plex Mono',monospace;font-size:2rem;
                          font-weight:700;color:#ff3b5f;line-height:1;flex-shrink:0;">{_n_breach}</div>
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
                All findings default to <code style="font-family:'IBM Plex Mono',monospace;font-size:0.77rem;">UNKNOWN</code>.
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
                    marker=dict(colors=colors, line=dict(color="#07060f", width=3)),
                    textinfo="label+percent",
                    textfont=dict(size=10, color="#6c5f97", family="IBM Plex Mono"),
                    hovertemplate="<b>%{label}</b><br>%{value} findings (%{percent})<extra></extra>",
                ))
                fig.update_layout(
                    showlegend=True,
                    legend=dict(
                        font=dict(color="#6c5f97", size=11, family="Space Grotesk"),
                        bgcolor="rgba(0,0,0,0)", x=0.5, xanchor="center", y=-0.05,
                        orientation="h",
                    ),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=8, b=32, l=8, r=8), height=260,
                    annotations=[dict(
                        text=f"<b>{n_total}</b><br><span style='font-size:10px;color:#4d4274'>total</span>",
                        x=0.5, y=0.5, font_size=28, font_color="#d8d2f0",
                        font=dict(family="IBM Plex Mono"), showarrow=False,
                    )],
                )
                st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

            # Risk Profile Summary (collapsible)
            avg_score = sum(f.risk_score for f in findings) / len(findings) if findings else 0
            top_exposure = max(
                set(str(getattr(f.exposure, "value", f.exposure)) for f in findings),
                key=lambda e: {"internet_facing": 3, "partner": 2, "internal": 1}.get(e, 0),
                default="unknown"
            )
            with st.expander("Risk Profile Summary", expanded=False):
                st.markdown(f"""
                <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;">
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:9px;padding:12px;">
                      <div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;
                                  color:#4d4274;font-family:'IBM Plex Mono',monospace;margin-bottom:4px;">Avg Risk Score</div>
                      <div style="font-size:1.5rem;font-weight:700;color:{score_color(avg_score)};
                                  font-family:'IBM Plex Mono',monospace;">{avg_score:.1f}</div>
                    </div>
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:9px;padding:12px;">
                      <div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;
                                  color:#4d4274;font-family:'IBM Plex Mono',monospace;margin-bottom:4px;">Max Exposure</div>
                      <div style="font-size:0.82rem;font-weight:600;color:#d8d2f0;
                                  font-family:'IBM Plex Mono',monospace;margin-top:4px;">{top_exposure.replace("_"," ").upper()}</div>
                    </div>
                  </div>
                  <div style="color:#5b4e85;font-size:0.79rem;line-height:1.7;">
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
            _posture_c = "#ff3b5f" if n_dk else ("#ff7849" if n_crit >= 3 else ("#fbbf24" if n_mod >= 3 else "#2dd4a0"))

            with st.expander("Deployment Status", expanded=False):
                st.markdown(f"""
                <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
                  <div style="display:flex;align-items:center;justify-content:space-between;
                              margin-bottom:10px;padding:10px 14px;
                              background:#07060f;border:1px solid #1d1735;border-radius:9px;">
                    <span style="font-size:0.78rem;color:#5b4e85;font-family:'Space Grotesk',sans-serif;">Overall Posture</span>
                    <span style="font-size:0.86rem;font-weight:700;color:{_posture_c};
                                 font-family:'IBM Plex Mono',monospace;">{_posture}</span>
                  </div>
                  <div style="color:#4d4274;font-size:0.76rem;line-height:1.8;">
                    <span style="color:#2dd4a0;">●</span> {_scanners_active} of 5 scanners active &nbsp;·&nbsp;
                    <span style="color:{'#2dd4a0' if _asset_c else '#fbbf24'};">●</span>
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
                '<span style="font-size:0.55rem;font-family:\'IBM Plex Mono\',monospace;'
                'color:#22d3ee;background:rgba(34,211,238,0.1);border:1px solid rgba(34,211,238,0.25);'
                'border-radius:4px;padding:2px 7px;font-weight:700;letter-spacing:0.1em;">TARGET-PROVIDED</span>'
                if shodan_source == "external_json" else
                '<span style="font-size:0.55rem;font-family:\'IBM Plex Mono\',monospace;'
                'color:#2dd4a0;background:rgba(45,212,160,0.1);border:1px solid rgba(45,212,160,0.25);'
                'border-radius:4px;padding:2px 7px;font-weight:700;letter-spacing:0.1em;">LIVE API</span>'
            )

            # Extended scanner state for pipeline display
            _dns_sum    = st.session_state.get("dns_summary",    {})
            _tls_sum    = st.session_state.get("tls_summary",    {})
            _breach_s   = st.session_state.get("breach_summary", {})
            _dns_count  = _dns_sum.get("count", 0)
            _tls_count  = len(st.session_state.get("tls_findings", []))
            _br_count   = _breach_s.get("total", 0)

            dns_ps = _ps(
                "ok" if _dns_sum.get("success") else "off",
                "DNS",
                f"{_dns_count} findings" if _dns_count else ("ok" if _dns_sum.get("success") else "—"),
                "ok" if _dns_count else ("warn" if _dns_sum.get("success") else ""),
            )
            tls_ps = _ps(
                "ok" if _tls_sum.get("certs_checked", 0) or _tls_sum.get("subdomains_ct", 0) else
                ("warn" if _tls_sum else "off"),
                "TLS",
                f"{_tls_count} findings" if _tls_count else
                (f"{_tls_sum.get('certs_checked',0)} cert(s)" if _tls_sum else "—"),
                "ok" if _tls_count else "",
            )
            breach_ps = _ps(
                "err" if _breach_s.get("breach_found") else
                ("ok" if _breach_s.get("error") is None and "total" in _breach_s else "off"),
                "Breach",
                f"{_br_count} found" if _br_count else ("clean" if "total" in _breach_s else "—"),
                "warn" if _br_count else ("ok" if "total" in _breach_s else ""),
            )

            st.markdown(f"""
            <div class="rf-pipeline-h" style="margin-bottom:14px;">
              <div class="rf-pipeline-header">
                Scanner Status
                <span style="margin-left:auto;font-size:0.6rem;color:#4d4274;">
                  {clean_target} &nbsp;·&nbsp; {resolved_ip}
                </span>
              </div>
              <div class="rf-pipeline-flow">
                {nmap_ps}{vuln_ps}{shod_ps}{ov_ps}{zap_ps}
              </div>
              <div style="height:1px;background:#161129;margin:10px 0 8px;"></div>
              <div class="rf-pipeline-flow" style="justify-content:space-evenly;">
                {dns_ps}{tls_ps}{breach_ps}
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
                cve_color  = "#ff3b5f" if vuln_count else "#2dd4a0"

                st.markdown(f"""
                <div class="rf-shodan" style="margin-bottom:14px;">
                  <div style="font-family:'IBM Plex Mono',monospace;font-size:0.6rem;font-weight:700;
                              letter-spacing:0.18em;text-transform:uppercase;color:#8b5cf6;
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
                      <span class="rf-shodan-value" style="font-family:'IBM Plex Mono',monospace;font-size:0.74rem;color:#b39dfb;">{ports_str}</span>
                    </div>
                    <div class="rf-shodan-row">
                      <span class="rf-shodan-label">CVEs</span>
                      <span class="rf-shodan-value" style="color:{cve_color};font-weight:700;font-family:'IBM Plex Mono',monospace;">{vuln_count}</span>
                    </div>
                  </div>
                  {('<div style="margin-top:10px;border-top:1px solid #30255b;padding-top:10px;">'
                    + '<div style="font-size:0.56rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;'
                    + 'color:#4d4274;font-family:\'IBM Plex Mono\',monospace;margin-bottom:6px;">CVE Lists</div>'
                    + "<div style='display:flex;flex-wrap:wrap;gap:5px;'>"
                    + "".join(f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.62rem;color:#6c5f97;'
                              f'background:#07060f;border:1px solid #2c2253;border-radius:4px;padding:2px 8px;">{c}</span>'
                              for c in shodan_result["vulns"][:8])
                    + (f'<span style="font-size:0.62rem;color:#4d4274;padding:2px 8px;">+{len(shodan_result["vulns"])-8} more</span>'
                       if len(shodan_result["vulns"]) > 8 else "")
                    + "</div></div>") if shodan_result.get("vulns") else ""}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.warning(shodan_result.get("error", "Shodan enrichment unavailable."))

            # ── DNS Security card ─────────────────────────────────────────
            _dns_findings_list = st.session_state.get("dns_findings", [])
            if _dns_sum.get("success") is not None:
                _dns_ok  = not bool(_dns_findings_list)
                _dns_col = "#2dd4a0" if _dns_ok else "#fbbf24"
                _dns_lbl = "All Checks Passed" if _dns_ok else f"{len(_dns_findings_list)} Gap(s) Found"
                _dns_rows = ""
                for _df in _dns_findings_list[:4]:
                    _check = (_df.raw_data or {}).get("check", "dns")
                    _dns_rows += (
                        f'<div style="display:flex;justify-content:space-between;'
                        f'align-items:center;padding:5px 0;border-bottom:1px solid #161129;">'
                        f'<span style="font-size:0.76rem;color:#6c5f97;font-family:\'Inter\',sans-serif;">'
                        f'{_df.title[:55]}{"…" if len(_df.title)>55 else ""}</span>'
                        f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.7rem;'
                        f'color:#fbbf24;font-weight:700;">{_df.cvss_score}</span></div>'
                    )
                st.markdown(f"""
                <div style="background:#110d24;border:1px solid #30255b;border-left:3px solid {_dns_col};
                            border-radius:12px;padding:14px 16px;margin-bottom:12px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.6rem;font-weight:700;
                                letter-spacing:0.18em;text-transform:uppercase;color:{_dns_col};">
                      DNS &amp; EMAIL SECURITY
                    </div>
                    <span style="font-size:0.65rem;font-weight:700;color:{_dns_col};
                                 font-family:'IBM Plex Mono',monospace;">{_dns_lbl}</span>
                  </div>
                  {_dns_rows if _dns_rows else
                   '<div style="font-size:0.76rem;color:#2dd4a0;font-family:\'Inter\',sans-serif;">'
                   '✓ SPF, DMARC, DKIM, and DNSSEC all configured correctly.</div>'}
                </div>""", unsafe_allow_html=True)

            # ── TLS Health card ───────────────────────────────────────────
            _tls_findings_list = st.session_state.get("tls_findings", [])
            if _tls_sum:
                _tls_ok  = not bool(_tls_findings_list)
                _tls_col = "#2dd4a0" if _tls_ok else ("#ff3b5f" if _tls_sum.get("expired") else "#fbbf24")
                _tls_lbl = "All Checks Passed" if _tls_ok else f"{len(_tls_findings_list)} Issue(s) Found"
                _tls_rows = ""
                for _tf in _tls_findings_list[:3]:
                    _tls_rows += (
                        f'<div style="display:flex;justify-content:space-between;'
                        f'align-items:center;padding:5px 0;border-bottom:1px solid #161129;">'
                        f'<span style="font-size:0.76rem;color:#6c5f97;font-family:\'Inter\',sans-serif;">'
                        f'{_tf.title[:55]}{"…" if len(_tf.title)>55 else ""}</span>'
                        f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.7rem;'
                        f'color:#fbbf24;font-weight:700;">{_tf.cvss_score}</span></div>'
                    )
                _ct_count = _tls_sum.get("subdomains_ct", 0)
                st.markdown(f"""
                <div style="background:#110d24;border:1px solid #30255b;border-left:3px solid {_tls_col};
                            border-radius:12px;padding:14px 16px;margin-bottom:12px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.6rem;font-weight:700;
                                letter-spacing:0.18em;text-transform:uppercase;color:{_tls_col};">
                      TLS / CERTIFICATE HEALTH
                    </div>
                    <span style="font-size:0.65rem;font-weight:700;color:{_tls_col};
                                 font-family:'IBM Plex Mono',monospace;">{_tls_lbl}</span>
                  </div>
                  {_tls_rows if _tls_rows else
                   '<div style="font-size:0.76rem;color:#2dd4a0;font-family:\'Inter\',sans-serif;">'
                   '✓ No expired certs, no deprecated TLS versions found.</div>'}
                  {(f'<div style="margin-top:6px;font-size:0.72rem;color:#5b4e85;'
                    f'font-family:\'Inter\',sans-serif;">CT logs: {_ct_count} subdomain(s) found</div>')
                   if _ct_count else ""}
                </div>""", unsafe_allow_html=True)

            # ── Mini findings list ────────────────────────────────────────
            st.markdown('<div class="rf-section-label">Top Findings</div>', unsafe_allow_html=True)

            TIER_CSS_MAP = {"deal_killer": "dk", "critical": "crit", "moderate": "mod", "manageable": "man"}

            for f in findings[:6]:
                t_val  = str(getattr(f.deal_tier, "value", f.deal_tier))
                t_cls  = TIER_CSS_MAP.get(t_val, "")
                t_icon = tier_dot_html(t_val, 10)
                sc     = score_color(f.risk_score)
                port_label = f":{f.port}" if f.port else ""
                svc_label  = f.service or ""
                desc_short = (f.description[:80] + "…") if len(f.description) > 80 else f.description

                st.markdown(f"""
                <div class="fmc {t_cls}">
                  <div class="fmc-icon {t_cls}"
                       style="display:flex;align-items:center;justify-content:center;">
                    {t_icon}
                  </div>
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
                    f"color:#4d4274;font-family:\"IBM Plex Mono\",monospace;'>"
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

            # Apply preset tier filter from metric card click (Overview → Findings navigation).
            # The multiselect is driven entirely through session_state (no `default=`) to avoid
            # Streamlit's "default value + session state" conflict warning.
            _all_tiers = sorted(df["Deal Tier"].dropna().unique())
            if "tier_filter_ms" not in st.session_state:
                st.session_state["tier_filter_ms"] = _all_tiers
            else:
                # Drop any tiers no longer present in the current scan (stale-state repair)
                st.session_state["tier_filter_ms"] = [
                    t for t in st.session_state["tier_filter_ms"] if t in _all_tiers
                ]
            if "tier_preset" in st.session_state:
                _preset = st.session_state.pop("tier_preset")
                if _preset in _all_tiers:
                    st.session_state["tier_filter_ms"] = [_preset]

            # Filters
            st.markdown('<div class="rf-section-label">Filter Findings</div>', unsafe_allow_html=True)
            fc1, fc2, fc3 = st.columns(3)
            with fc1:
                selected_tiers = st.multiselect(
                    "Deal Tier",
                    options=_all_tiers,
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
                width="stretch",
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
                            &nbsp;<span style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
                                              color:#4d4274;">{row['Host']} &nbsp;·&nbsp; :{port_svc} &nbsp;·&nbsp; {row['Scanner']}</span>
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
                              <span style="font-family:'IBM Plex Mono',monospace;font-size:0.76rem;
                                           color:#6c5f97;">{evid_label}</span>
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

            # ══════════════════════════════════════════════════════════════
            # What-If Scenario Simulator — Feature 6
            # ══════════════════════════════════════════════════════════════
            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
            st.markdown("""
            <div style="border-top:1px solid #1d1735;padding-top:20px;">
              <div style="font-family:'IBM Plex Mono',monospace;font-size:0.57rem;font-weight:700;
                          letter-spacing:0.2em;text-transform:uppercase;color:#4d4274;
                          display:flex;align-items:center;gap:10px;margin-bottom:4px;">
                What-If Scenario Simulator
                <div style="flex:1;height:1px;background:linear-gradient(90deg,#1d1735,transparent);"></div>
              </div>
              <div style="font-size:0.78rem;color:#5b4e85;font-family:'Space Grotesk',sans-serif;
                          margin-bottom:14px;line-height:1.6;">
                Mark findings as resolved pre-close and instantly see how the risk profile changes.
                Use this to quantify the value of each remediation demand in M&amp;A negotiations.
              </div>
            </div>""", unsafe_allow_html=True)

            # Build options: "Title (score)" for each finding
            _wi_options = {
                f.id: f"{f.title[:70]} — score {f.risk_score:.0f}"
                for f in findings
            }
            _wi_selected_ids = st.multiselect(
                "Select findings to mark as pre-close remediation",
                options=list(_wi_options.keys()),
                format_func=lambda fid: _wi_options.get(fid, fid),
                key="whatif_remediated",
                placeholder="Choose findings the seller will fix before close...",
            )

            if _wi_selected_ids:
                from analysis.triage import triage_all as _triage_all

                _remaining = [f for f in findings if f.id not in _wi_selected_ids]
                _simulated = _triage_all(_remaining) if _remaining else []

                # Compute deltas
                _orig_score  = sum(f.risk_score for f in findings) / len(findings) if findings else 0
                _sim_score   = sum(f.risk_score for f in _simulated) / len(_simulated) if _simulated else 0
                _delta_score = _orig_score - _sim_score

                _orig_dk  = sum(1 for f in findings   if str(getattr(f.deal_tier,"value",f.deal_tier)) == "deal_killer")
                _sim_dk   = sum(1 for f in _simulated if str(getattr(f.deal_tier,"value",f.deal_tier)) == "deal_killer")
                _orig_crit = sum(1 for f in findings   if str(getattr(f.deal_tier,"value",f.deal_tier)) == "critical")
                _sim_crit  = sum(1 for f in _simulated if str(getattr(f.deal_tier,"value",f.deal_tier)) == "critical")

                # Overall tier before / after
                def _overall_tier(fs):
                    if any(str(getattr(f.deal_tier,"value",f.deal_tier)) == "deal_killer" for f in fs):
                        return "DEAL KILLER", "#ff3b5f"
                    avg = sum(f.risk_score for f in fs) / len(fs) if fs else 0
                    if avg >= 75: return "CRITICAL", "#ff7849"
                    if avg >= 50: return "MODERATE", "#fbbf24"
                    return "MANAGEABLE", "#2dd4a0"

                _orig_tier_lbl, _orig_tier_col  = _overall_tier(findings)
                _sim_tier_lbl,  _sim_tier_col   = _overall_tier(_simulated)

                st.html(f"""
                <div style="background:linear-gradient(135deg,#110c26,#07060f);
                            border:1px solid #261d46;border-radius:14px;padding:20px 24px;
                            margin-top:8px;">
                  <div style="font-size:0.6rem;font-weight:700;letter-spacing:0.18em;
                              text-transform:uppercase;color:#4d4274;
                              font-family:'IBM Plex Mono',monospace;margin-bottom:16px;">
                    Simulated Risk Profile — {len(_wi_selected_ids)} finding(s) marked as resolved
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;">
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:10px;padding:14px;">
                      <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.14em;
                                  text-transform:uppercase;color:#4d4274;
                                  font-family:'IBM Plex Mono',monospace;margin-bottom:6px;">Avg Score</div>
                      <div style="font-size:1.4rem;font-weight:700;font-family:'IBM Plex Mono',monospace;
                                  color:{score_color(_orig_score)};line-height:1;">{_orig_score:.1f}</div>
                      <div style="font-size:0.68rem;color:#5b4e85;margin-top:4px;">
                        → <span style="color:{score_color(_sim_score)};font-weight:700;">{_sim_score:.1f}</span>
                        &nbsp;<span style="color:#2dd4a0;">▼ {_delta_score:.1f}</span>
                      </div>
                    </div>
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:10px;padding:14px;">
                      <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.14em;
                                  text-transform:uppercase;color:#4d4274;
                                  font-family:'IBM Plex Mono',monospace;margin-bottom:6px;">Deal Killers</div>
                      <div style="font-size:1.4rem;font-weight:700;font-family:'IBM Plex Mono',monospace;
                                  color:#ff3b5f;line-height:1;">{_orig_dk}</div>
                      <div style="font-size:0.68rem;color:#5b4e85;margin-top:4px;">
                        → <span style="color:{'#2dd4a0' if _sim_dk == 0 else '#ff3b5f'};font-weight:700;">{_sim_dk}</span>
                        {('<span style="color:#2dd4a0;">&nbsp;✓ cleared</span>' if _sim_dk == 0 and _orig_dk > 0 else "")}
                      </div>
                    </div>
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:10px;padding:14px;">
                      <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.14em;
                                  text-transform:uppercase;color:#4d4274;
                                  font-family:'IBM Plex Mono',monospace;margin-bottom:6px;">Critical</div>
                      <div style="font-size:1.4rem;font-weight:700;font-family:'IBM Plex Mono',monospace;
                                  color:#ff7849;line-height:1;">{_orig_crit}</div>
                      <div style="font-size:0.68rem;color:#5b4e85;margin-top:4px;">
                        → <span style="color:{'#2dd4a0' if _sim_crit < _orig_crit else '#ff7849'};font-weight:700;">{_sim_crit}</span>
                      </div>
                    </div>
                    <div style="background:#07060f;border:1px solid #1d1735;border-radius:10px;padding:14px;">
                      <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.14em;
                                  text-transform:uppercase;color:#4d4274;
                                  font-family:'IBM Plex Mono',monospace;margin-bottom:6px;">Deal Tier</div>
                      <div style="font-size:0.85rem;font-weight:700;font-family:'IBM Plex Mono',monospace;
                                  color:{_orig_tier_col};line-height:1.3;">{_orig_tier_lbl}</div>
                      <div style="font-size:0.68rem;color:#5b4e85;margin-top:4px;">
                        → <span style="color:{_sim_tier_col};font-weight:700;">{_sim_tier_lbl}</span>
                        {('<span style="color:#2dd4a0;">&nbsp;✓ improved</span>' if _sim_tier_lbl != _orig_tier_lbl else "")}
                      </div>
                    </div>
                  </div>
                  <div style="margin-top:12px;padding-top:12px;border-top:1px solid #1d1735;
                              font-size:0.74rem;color:#5b4e85;font-family:'Space Grotesk',sans-serif;line-height:1.6;">
                    Remediating the selected {len(_wi_selected_ids)} finding(s) reduces the average risk score
                    by <strong style="color:#d8d2f0;">{_delta_score:.1f} points</strong>
                    ({len(findings) - len(_simulated)} fewer findings in scope).
                  </div>
                </div>""")
            else:
                st.markdown(
                    "<div style='padding:12px 0;font-size:0.75rem;color:#4d4274;"
                    "font-family:\"IBM Plex Mono\",monospace;'>"
                    "Select one or more findings above to simulate the impact of pre-close remediation.</div>",
                    unsafe_allow_html=True,
                )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Maturity Assessment
    # ══════════════════════════════════════════════════════════════════════════════

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Attack Path
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_attack:
        from analysis.graph_builder import build_attack_graph

        _graph = build_attack_graph(findings)

        # ── Stat cards ───────────────────────────────────────────────────────────
        _inet_hosts  = sum(1 for n in _graph.nodes if n.id.startswith("HOST:") and
                           any(e.source == "INTERNET" and e.target == n.id for e in _graph.edges))
        _total_hosts = sum(1 for n in _graph.nodes if n.id.startswith("HOST:"))
        _cve_count   = sum(1 for n in _graph.nodes if n.id.startswith("CVE:"))
        _svc_count   = sum(1 for n in _graph.nodes if n.id.startswith("SVC:"))
        _dk_count    = sum(1 for f in findings if str(getattr(f.deal_tier,"value",f.deal_tier)) == "deal_killer"
                           and str(getattr(f.exposure,"value",f.exposure)) == "internet_facing")

        st.markdown("""
        <div style="margin-bottom:20px;">
          <div style="font-size:1.05rem;font-weight:700;color:#f1edfe;
                      font-family:'Space Grotesk',sans-serif;letter-spacing:-0.01em;margin-bottom:4px;">
            Attack Path Analysis
          </div>
          <div style="font-size:0.8rem;color:#5b4e85;font-family:'Space Grotesk',sans-serif;line-height:1.6;">
            Visualises how an attacker moves from the internet through exposed services to reach
            vulnerabilities. Hover any node for full details. Drag to pan &middot; scroll to zoom.
          </div>
        </div>""", unsafe_allow_html=True)

        _sc1, _sc2, _sc3, _sc4 = st.columns(4)
        for _col, _lbl, _val, _color in [
            (_sc1, "Exposed Hosts",    _inet_hosts,  "#8b5cf6"),
            (_sc2, "Total Hosts",      _total_hosts, "#6c5f97"),
            (_sc3, "CVEs on Path",     _cve_count,   "#ff3b5f" if _cve_count else "#6c5f97"),
            (_sc4, "Deal Killers Exposed", _dk_count, "#ff3b5f" if _dk_count else "#2dd4a0"),
        ]:
            _col.markdown(f"""
            <div style="background:#130f23;border:1px solid #261d46;border-radius:12px;
                        padding:14px 16px;text-align:center;margin-bottom:16px;">
              <div style="font-family:'IBM Plex Mono',monospace;font-size:0.55rem;font-weight:700;
                          letter-spacing:0.18em;text-transform:uppercase;color:#4d4274;
                          margin-bottom:8px;">{_lbl}</div>
              <div style="font-size:2.2rem;font-weight:700;font-family:'IBM Plex Mono',monospace;
                          color:{_color};line-height:1;">{_val}</div>
            </div>""", unsafe_allow_html=True)

        # ── Graph ────────────────────────────────────────────────────────────────
        if len(_graph.nodes) <= 1:
            st.info("Not enough findings to build an attack path. Run a scan first.")
        else:
            _html = _build_attack_graph_html(_graph)
            if _html is None:
                st.warning("pyvis is not installed. Run `pip install pyvis` to enable this view.")
            else:
                _embed_html(_html, height=700, scrolling=False)

        # ── Legend ───────────────────────────────────────────────────────────────
        st.markdown("""
        <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:center;
                    padding:12px 18px;background:#0b0917;border:1px solid #1d1735;
                    border-radius:10px;margin-top:4px;">
          <span style="font-family:'IBM Plex Mono',monospace;font-size:0.57rem;font-weight:700;
                       letter-spacing:0.18em;text-transform:uppercase;color:#4d4274;">Node colour</span>
          <span style="display:flex;align-items:center;gap:7px;font-size:0.74rem;color:#6c5f97;">
            <span style="width:10px;height:10px;border-radius:50%;background:#ff3b5f;flex-shrink:0;
                         box-shadow:0 0 6px #ff3b5f88;display:inline-block;"></span>Deal Killer
          </span>
          <span style="display:flex;align-items:center;gap:7px;font-size:0.74rem;color:#6c5f97;">
            <span style="width:10px;height:10px;border-radius:50%;background:#ff7849;flex-shrink:0;
                         box-shadow:0 0 6px #ff784988;display:inline-block;"></span>Critical
          </span>
          <span style="display:flex;align-items:center;gap:7px;font-size:0.74rem;color:#6c5f97;">
            <span style="width:10px;height:10px;border-radius:50%;background:#fbbf24;flex-shrink:0;
                         box-shadow:0 0 6px #fbbf2488;display:inline-block;"></span>Moderate
          </span>
          <span style="display:flex;align-items:center;gap:7px;font-size:0.74rem;color:#6c5f97;">
            <span style="width:10px;height:10px;border-radius:50%;background:#2dd4a0;flex-shrink:0;
                         box-shadow:0 0 6px #2dd4a088;display:inline-block;"></span>Manageable
          </span>
          <span style="margin-left:12px;font-family:'IBM Plex Mono',monospace;font-size:0.57rem;
                       font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#4d4274;">Shapes</span>
          <span style="font-size:0.74rem;color:#6c5f97;">◆ Internet entry &nbsp;● Host / Service / CVE</span>
          <span style="margin-left:auto;font-size:0.72rem;color:#4d4274;font-family:'Space Grotesk',sans-serif;">
            Hover any node for details &nbsp;·&nbsp; Drag to pan &nbsp;·&nbsp; Scroll to zoom
          </span>
        </div>""", unsafe_allow_html=True)

    with tab_maturity:

        st.markdown('<div class="rf-section-label">Inside-Out Maturity Assessment</div>', unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:0.82rem;color:#6c5f97;font-family:\"Space Grotesk\",sans-serif;"
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
                    f"text-transform:uppercase;color:#ff3b5f;font-family:\"IBM Plex Mono\",monospace;"
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
                width="stretch",
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
            ov_color = "#ff3b5f" if assessment.is_deal_blocker else ("#fbbf24" if assessment.has_gaps else "#2dd4a0")
            ov_label = "DEAL-BLOCKER" if assessment.is_deal_blocker else ("GAPS PRESENT" if assessment.has_gaps else "ACCEPTABLE")

            st.markdown(f"""
            <div style="background:linear-gradient(160deg,#130f23,#0b0917);border:1px solid {ov_color}33;
                        border-radius:14px;padding:20px 24px;margin-bottom:24px;
                        display:flex;align-items:center;gap:24px;">
              <div style="text-align:center;min-width:80px;">
                <div style="font-size:3rem;font-weight:700;color:{ov_color};
                            font-family:'IBM Plex Mono',monospace;line-height:1;">{overall:.1f}<span style="font-size:1.2rem;color:#4d4274;">/5</span></div>
                <div style="font-size:0.55rem;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;
                            color:{ov_color};font-family:'IBM Plex Mono',monospace;margin-top:4px;">{ov_label}</div>
              </div>
              <div style="flex:1;">
                <div style="font-size:0.9rem;font-weight:700;color:#d8d2f0;
                            font-family:'Space Grotesk',sans-serif;margin-bottom:6px;">Overall Maturity Score</div>
                <div style="font-size:0.78rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.6;">
                  {assessment.completion_pct:.0f}% of questions answered &nbsp;&middot;&nbsp;
                  {len(assessment.domain_scores)} domains assessed
                </div>
              </div>
            </div>""", unsafe_allow_html=True)

            # Domain score cards
            st.markdown('<div class="rf-section-label">Domain Scores</div>', unsafe_allow_html=True)

            _SEV_COLORS = {
                "deal_blocker": ("#ff3b5f", "DEAL-BLOCKER"),
                "below_min":    ("#fbbf24", "BELOW MIN"),
                "acceptable":   ("#b39dfb", "ACCEPTABLE"),
                "at_target":    ("#2dd4a0", "AT TARGET"),
            }

            domain_cols = st.columns(2)
            for di, ds in enumerate(assessment.domain_scores):
                sev_val   = str(ds.gap_severity.value if hasattr(ds.gap_severity, "value") else ds.gap_severity)
                sev_color, sev_label = _SEV_COLORS.get(sev_val, ("#6c5f97", "N/A"))
                bar_pct = int(ds.score / 5 * 100)
                with domain_cols[di % 2]:
                    st.markdown(f"""
                    <div style="background:linear-gradient(160deg,#130f23,#0b0917);
                                border:1px solid #261d46;border-radius:12px;
                                padding:16px 18px;margin-bottom:12px;">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <div style="font-size:0.8rem;font-weight:700;color:#d7d0ef;
                                    font-family:'Space Grotesk',sans-serif;">{ds.label}</div>
                        <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                                    text-transform:uppercase;color:{sev_color};
                                    font-family:'IBM Plex Mono',monospace;">{sev_label}</div>
                      </div>
                      <div style="display:flex;align-items:center;gap:12px;">
                        <div style="flex:1;height:6px;background:#161129;border-radius:3px;">
                          <div style="width:{bar_pct}%;height:6px;background:{sev_color};
                                      border-radius:3px;transition:width 0.3s;"></div>
                        </div>
                        <div style="font-size:1.1rem;font-weight:700;color:{sev_color};
                                    font-family:'IBM Plex Mono',monospace;min-width:36px;
                                    text-align:right;">{ds.score:.1f}</div>
                      </div>
                      <div style="margin-top:8px;display:flex;gap:16px;">
                        <span style="font-size:0.7rem;color:#4d4274;font-family:'IBM Plex Mono',monospace;">
                          Min acceptable: <span style="color:#6c5f97;">{ds.acceptable_min}</span>
                        </span>
                        <span style="font-size:0.7rem;color:#4d4274;font-family:'IBM Plex Mono',monospace;">
                          Target: <span style="color:#6c5f97;">{ds.recommended}</span>
                        </span>
                        <span style="font-size:0.7rem;color:#4d4274;font-family:'IBM Plex Mono',monospace;">
                          Answered: <span style="color:#6c5f97;">{ds.answered}/{ds.total_questions}</span>
                        </span>
                      </div>
                    </div>""", unsafe_allow_html=True)

            # Gap narrative
            if gap_report and gap_report.has_any_gaps:
                st.markdown('<div class="rf-section-label">Gap Analysis</div>', unsafe_allow_html=True)
                mat_narrative = build_maturity_narrative(assessment)
                if mat_narrative:
                    st.markdown(
                        f"<div style='font-size:0.85rem;color:#d7d0ef;font-family:\"Space Grotesk\",sans-serif;"
                        f"line-height:1.75;padding:16px;background:#0b0917;border-radius:10px;"
                        f"border-left:3px solid #fbbf24;margin-bottom:16px;'>{mat_narrative}</div>",
                        unsafe_allow_html=True,
                    )

                for gap in gap_report.deal_blocker_gaps + gap_report.below_min_gaps:
                    st.markdown(f"""
                    <div style="background:#0b0917;border:1px solid #ff3b5f33;border-radius:10px;
                                border-left:3px solid #ff3b5f;padding:14px 18px;margin-bottom:10px;">
                      <div style="font-size:0.82rem;font-weight:700;color:#ff3b5f;
                                  font-family:'Space Grotesk',sans-serif;margin-bottom:4px;">
                        {gap.label} — Score {gap.current_score:.1f} (need {gap.acceptable_min})
                      </div>
                      <div style="font-size:0.78rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;
                                  line-height:1.65;">{gap.rationale}</div>
                    </div>""", unsafe_allow_html=True)
        else:
            st.markdown(
                "<div style='padding:40px;text-align:center;color:#4d4274;"
                "font-family:\"IBM Plex Mono\",monospace;font-size:0.78rem;'>"
                "Complete the questionnaire above and click Run Maturity Assessment to see results.</div>",
                unsafe_allow_html=True,
            )

    # ══════════════════════════════════════════════════════════════════════════════
    # Tab: Cost & Budget
    # ══════════════════════════════════════════════════════════════════════════════

    with tab_cost:

        st.markdown('<div class="rf-section-label">Remediation Cost & Budget</div>', unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:0.82rem;color:#6c5f97;font-family:\"Space Grotesk\",sans-serif;"
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

        if st.button("Generate Cost Estimate", width="content"):
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
                    f"<div style='font-size:0.85rem;color:#d7d0ef;font-family:\"Space Grotesk\",sans-serif;"
                    f"line-height:1.75;padding:16px;background:#0b0917;border-radius:10px;"
                    f"border-left:3px solid #b39dfb;margin-bottom:20px;'>{cost_narrative}</div>",
                    unsafe_allow_html=True,
                )

            # ── Scenario summary cards ─────────────────────────────────────────
            st.markdown('<div class="rf-section-label">Cost Scenarios</div>', unsafe_allow_html=True)
            sc_low  = next((s for s in rollup.scenarios if str(s.scenario_type) == "low"),  None)
            sc_base = next((s for s in rollup.scenarios if str(s.scenario_type) == "base"), None)
            sc_high = next((s for s in rollup.scenarios if str(s.scenario_type) == "high"), None)

            sc_col1, sc_col2, sc_col3 = st.columns(3)
            for sc_col, sc, sc_label, sc_color in [
                (sc_col1, sc_low,  "Low Scenario",  "#2dd4a0"),
                (sc_col2, sc_base, "Base Scenario", "#b39dfb"),
                (sc_col3, sc_high, "High Scenario", "#ff3b5f"),
            ]:
                with sc_col:
                    if sc:
                        st.markdown(f"""
                        <div style="background:linear-gradient(160deg,#130f23,#0b0917);
                                    border:1px solid #261d46;border-radius:14px;padding:20px 16px;">
                          <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.18em;
                                      text-transform:uppercase;color:#4d4274;
                                      font-family:'IBM Plex Mono',monospace;margin-bottom:10px;">{sc_label}</div>
                          <div style="font-size:2.2rem;font-weight:700;color:{sc_color};
                                      font-family:'IBM Plex Mono',monospace;line-height:1;">
                            ${sc.total_usd:,.0f}
                          </div>
                          <div style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:6px;">
                            <div style="font-size:0.72rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;">
                              <span style="color:#fbbf24;font-weight:700;">CapEx</span><br>
                              ${sc.capex_usd:,.0f}
                            </div>
                            <div style="font-size:0.72rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;">
                              <span style="color:#2dd4a0;font-weight:700;">OpEx</span><br>
                              ${sc.opex_usd:,.0f}
                            </div>
                          </div>
                        </div>""", unsafe_allow_html=True)

            st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

            # ── Review gate ────────────────────────────────────────────────────
            if rollup.has_flagged_items:
                flagged_items = [i for i in rollup.line_items if i.needs_review]
                st.markdown(f"""
                <div style="background:#150a1d;border:1px solid #ff3b5f44;border-radius:12px;
                            border-left:3px solid #ff3b5f;padding:16px 20px;margin-bottom:16px;">
                  <div style="font-size:0.82rem;font-weight:700;color:#ff3b5f;
                              font-family:'Space Grotesk',sans-serif;margin-bottom:6px;">
                    ⚠  {len(flagged_items)} Item(s) Require Human Review Before Export
                  </div>
                  <div style="font-size:0.78rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.65;">
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
                width="stretch",
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
                            width="stretch",
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
                            width="stretch",
                        )
                    except ImportError:
                        st.info("Install openpyxl for XLSX export: `pip install openpyxl`")
                    except Exception as e_xlsx:
                        st.error(f"XLSX export failed: {e_xlsx}")

        else:
            st.markdown(
                "<div style='padding:40px;text-align:center;color:#4d4274;"
                "font-family:\"IBM Plex Mono\",monospace;font-size:0.78rem;'>"
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

            dk_color  = "#ff8298" if n_dk   else "#2dd4a0"
            crt_color = "#ff7849" if n_crit else "#4d4274"

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
                <span class="rf-tp-value" style="color:#d7d0ef;">{n_total}</span>
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
                <span class="rf-tp-value" style="color:#453a6b;">{n_mod}</span>
              </div>
              <div class="rf-tp-row">
                <span class="rf-tp-label">Manageable</span>
                <span class="rf-tp-value" style="color:#453a6b;">{n_man}</span>
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
                    width="stretch",
                )

            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

            pdf_file = generate_pdf_report(findings, clean_target, resolved_ip)
            with open(pdf_file, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f,
                    file_name=pdf_file.split("\\")[-1].split("/")[-1],
                    mime="application/pdf",
                    width="stretch",
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
        _embed_html(
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
    "<hr style='border:none;border-top:1px solid #1d1735;margin:48px 0 0;'>",
    unsafe_allow_html=True,
)

_fp_col, _fc_col, _copy_col = st.columns([4, 4, 4])

with _fp_col:
    with st.expander("\U0001f4c4  Privacy Policy"):
        st.markdown(
            """<div style="padding:6px 0 4px;">
  <div style="font-size:1rem;font-weight:800;color:#d8d2f0;
              font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Privacy Policy</div>
  <div style="font-size:0.65rem;color:#4d4274;font-family:'IBM Plex Mono',monospace;
              margin-bottom:16px;">Effective: May 2026 &middot; RedFlag v3</div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#ff3b5f;font-family:'IBM Plex Mono',monospace;margin-bottom:5px;">01 &middot; Data We Process</div>
    <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
      RedFlag processes only data you explicitly provide: scan targets, uploaded files (OpenVAS, ZAP,
      Shodan JSON, Asset Excel), and scan outputs stored locally in
      <code style="font-family:'IBM Plex Mono',monospace;color:#b39dfb;">data/results/</code>.
      <strong style="color:#988cbb;">No personal data</strong> is collected.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#ff3b5f;font-family:'IBM Plex Mono',monospace;margin-bottom:5px;">02 &middot; How Data Is Processed</div>
    <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
      All processing is <strong style="color:#988cbb;">local</strong>. Outbound API calls enrich
      findings only &mdash; <strong style="color:#988cbb;">Shodan</strong> (1 credit/scan),
      <strong style="color:#988cbb;">NVD/NIST</strong> (public CVSS),
      <strong style="color:#988cbb;">CISA KEV</strong> (public feed),
      <strong style="color:#988cbb;">Vulners</strong> (NSE exploit metadata).
      Each request contains only the IP or CVE ID queried.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#ff3b5f;font-family:'IBM Plex Mono',monospace;margin-bottom:5px;">03 &middot; Data Retention</div>
    <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
      No data is retained on remote servers. Scan files live only in your local
      <code style="font-family:'IBM Plex Mono',monospace;color:#b39dfb;">data/results/</code> folder.
      In-session state clears on restart.
    </div>
  </div>

  <div style="margin-bottom:14px;">
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#ff3b5f;font-family:'IBM Plex Mono',monospace;margin-bottom:5px;">04 &middot; Responsible Use</div>
    <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
      Use RedFlag only against systems you own or have
      <strong style="color:#988cbb;">explicit written authorisation</strong> to assess.
      The developers accept no liability for misuse.
    </div>
  </div>

  <div>
    <div style="font-size:0.58rem;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;
                color:#ff3b5f;font-family:'IBM Plex Mono',monospace;margin-bottom:5px;">05 &middot; Changes &amp; Contact</div>
    <div style="font-size:0.82rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.75;">
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
  <div style="font-size:1rem;font-weight:800;color:#d8d2f0;
              font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Get in Touch</div>
  <div style="font-size:0.65rem;color:#4d4274;font-family:'IBM Plex Mono',monospace;
              margin-bottom:14px;">RedFlag &middot; M&amp;A Cybersecurity Intelligence</div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:16px;">
    <div style="background:linear-gradient(145deg,#130f23,#0b0917);
                border:1px solid #261d46;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128737;&#65039;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#d8d2f0;
                  font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Security Questions</div>
      <div style="font-size:0.75rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.55;">
        Methodology, scoring, M&amp;A interpretation.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#130f23,#0b0917);
                border:1px solid #261d46;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#129309;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#d8d2f0;
                  font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Partnerships</div>
      <div style="font-size:0.75rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.55;">
        Enterprise, white-label, advisory.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#130f23,#0b0917);
                border:1px solid #261d46;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128027;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#d8d2f0;
                  font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Bug Reports</div>
      <div style="font-size:0.75rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.55;">
        Unexpected behaviour or feature ideas.
      </div>
    </div>
    <div style="background:linear-gradient(145deg,#130f23,#0b0917);
                border:1px solid #261d46;border-radius:9px;padding:12px;">
      <div style="font-size:1rem;margin-bottom:5px;">&#128203;</div>
      <div style="font-size:0.77rem;font-weight:700;color:#d8d2f0;
                  font-family:'Space Grotesk',sans-serif;margin-bottom:3px;">Privacy Enquiries</div>
      <div style="font-size:0.75rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;line-height:1.55;">
        Questions about how RedFlag handles data.
      </div>
    </div>
  </div>

  <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#97;&#100;&#105;&#116;&#121;&#97;&#97;&#118;&#101;&#108;&#48;&#48;&#55;&#64;&#103;&#109;&#97;&#105;&#108;&#46;&#99;&#111;&#109;"
     style="display:block;text-align:center;
            background:linear-gradient(160deg,#ff3b5f,#c1124d);
            color:#fff;text-decoration:none;font-family:'Space Grotesk',sans-serif;
            font-weight:700;font-size:0.83rem;letter-spacing:0.05em;
            padding:11px 20px;border-radius:10px;
            box-shadow:0 4px 22px rgba(255,59,95,0.4);margin-bottom:14px;">
    &#9993;&nbsp; Send Message
  </a>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
    <div style="font-size:0.76rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;">
      <span style="color:#2dd4a0;font-weight:700;">General enquiries</span><br>Within 2 business days
    </div>
    <div style="font-size:0.76rem;color:#6c5f97;font-family:'Space Grotesk',sans-serif;">
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
        "<span style='font-size:0.6rem;font-family:\"IBM Plex Mono\",monospace;"
        "color:#221a3d;letter-spacing:0.1em;'>"
        "&#169; 2026 RedFlag &nbsp;&middot;&nbsp; M&amp;A Cybersecurity Intelligence"
        "</span></div>",
        unsafe_allow_html=True,
    )
