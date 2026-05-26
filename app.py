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
/* ── Base ── */
[data-testid="stAppViewContainer"] { background: #0e1117; }
[data-testid="stHeader"] { background: transparent; }

/* ── Metric cards ── */
.rf-metric {
    background: #1a1d27;
    border: 1px solid #2a2d3a;
    border-radius: 12px;
    padding: 18px 20px;
    text-align: center;
}
.rf-metric .label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #6b7280;
    margin-bottom: 6px;
}
.rf-metric .value {
    font-size: 2.2rem;
    font-weight: 700;
    line-height: 1;
}
.rf-metric.red   { border-top: 3px solid #ef4444; }
.rf-metric.red   .value { color: #ef4444; }
.rf-metric.orange { border-top: 3px solid #f97316; }
.rf-metric.orange .value { color: #f97316; }
.rf-metric.yellow { border-top: 3px solid #eab308; }
.rf-metric.yellow .value { color: #eab308; }
.rf-metric.green  { border-top: 3px solid #22c55e; }
.rf-metric.green  .value { color: #22c55e; }
.rf-metric.blue   { border-top: 3px solid #3b82f6; }
.rf-metric.blue   .value { color: #e2e8f0; }

/* ── Tier badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}
.badge-dk   { background: #3b1212; color: #ef4444; border: 1px solid #ef4444; }
.badge-crit { background: #3b1e0a; color: #f97316; border: 1px solid #f97316; }
.badge-mod  { background: #2d2a0a; color: #eab308; border: 1px solid #eab308; }
.badge-man  { background: #0a2d1a; color: #22c55e; border: 1px solid #22c55e; }
.badge-unk  { background: #1e1e2e; color: #6b7280; border: 1px solid #374151; }

/* ── Exposure badges ── */
.badge-inet { background: #0a1e3b; color: #60a5fa; border: 1px solid #3b82f6; }
.badge-part { background: #1a1e2d; color: #a78bfa; border: 1px solid #7c3aed; }
.badge-int  { background: #1a2d1a; color: #4ade80; border: 1px solid #166534; }
.badge-ukn  { background: #1e1e2e; color: #6b7280; border: 1px solid #374151; }

/* ── Finding card ── */
.finding-card {
    background: #1a1d27;
    border: 1px solid #2a2d3a;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 12px;
}
.finding-card h4 {
    color: #f1f5f9;
    font-size: 1rem;
    font-weight: 600;
    margin: 0 0 6px 0;
}
.finding-card .meta { color: #9ca3af; font-size: 0.82rem; margin-bottom: 14px; }
.finding-card .field-label { color: #6b7280; font-size: 0.75rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 2px; }
.finding-card .field-value { color: #cbd5e1; font-size: 0.88rem; margin-bottom: 12px; }
.finding-card .score-pill {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 14px;
    text-align: center;
}
.finding-card .score-pill .s-label { color: #6b7280; font-size: 0.7rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.06em; }
.finding-card .score-pill .s-value { font-size: 1.6rem; font-weight: 700; }

/* ── Info panel ── */
.info-panel {
    background: #1a1d27;
    border: 1px solid #2a2d3a;
    border-radius: 12px;
    padding: 18px 20px;
}
.info-panel .ip-label { color: #6b7280; font-size: 0.72rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 2px; }
.info-panel .ip-value { color: #e2e8f0; font-size: 0.9rem; margin-bottom: 10px; }
.info-panel .status-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }

/* ── Divider ── */
.rf-divider { border: none; border-top: 1px solid #2a2d3a; margin: 20px 0; }

/* ── Scan bar ── */
[data-testid="stTextInput"] input {
    background: #1a1d27 !important;
    border: 1px solid #2a2d3a !important;
    border-radius: 8px !important;
    color: #e2e8f0 !important;
    font-size: 0.95rem !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #ef4444 !important;
    box-shadow: 0 0 0 2px rgba(239,68,68,0.2) !important;
}

/* ── Tab styling ── */
[data-testid="stTabs"] button { font-weight: 600; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0e1117; }
::-webkit-scrollbar-thumb { background: #2a2d3a; border-radius: 3px; }
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
<div style="display:flex; align-items:center; gap:12px; margin-bottom:4px;">
    <span style="font-size:2rem;">🚩</span>
    <div>
        <h1 style="margin:0; font-size:1.8rem; font-weight:800; color:#f1f5f9; letter-spacing:-0.02em;">RedFlag</h1>
        <p style="margin:0; color:#6b7280; font-size:0.85rem;">Cybersecurity Due Diligence · M&A Risk Intelligence</p>
    </div>
</div>
<hr class="rf-divider">
""", unsafe_allow_html=True)

# ── Scan controls ─────────────────────────────────────────────────────────────

scan_col1, scan_col2 = st.columns([5, 1])
with scan_col1:
    target = st.text_input(
        "target",
        value="scanme.nmap.org",
        placeholder="Enter target IP, hostname, or subnet — e.g. scanme.nmap.org",
        label_visibility="collapsed"
    )
with scan_col2:
    run_scan = st.button("🔍  Run Scan", use_container_width=True, type="primary")

upload_col1, upload_col2, upload_col3 = st.columns(3)

with upload_col1:
    with st.expander("Upload OpenVAS XML (optional)"):
        st.caption("Export the XML report from OpenVAS / Greenbone and upload to merge verified CVE findings.")
        openvas_file = st.file_uploader("OpenVAS XML", type=["xml"], label_visibility="collapsed", key="ov_upload")

with upload_col2:
    with st.expander("Upload ZAP XML (optional)"):
        st.caption("Export the XML report from OWASP ZAP and upload to merge web application findings.")
        zap_file = st.file_uploader("ZAP XML", type=["xml"], label_visibility="collapsed", key="zap_upload")

with upload_col3:
    with st.expander("Upload Asset Inventory Excel (optional)"):
        st.caption("Upload an Excel file mapping host IPs to data sensitivity tiers (Crown Jewel, Regulated, Sensitive, Low). Unlocks the most impactful deal-killer rules.")
        st.markdown(
            "<small style='color:#6b7280'>Required columns: <code>IP</code> (or Host) · <code>Sensitivity</code></small>",
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
                xml_file          = run_nmap_scan(clean_target)
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

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    _asset_hosts_loaded = st.session_state.get("asset_hosts", 0)
    if _asset_hosts_loaded:
        st.markdown(f"""
        <div style="background:#0a1e0a; border:1px solid #166534; border-left:4px solid #22c55e;
                    border-radius:8px; padding:12px 16px; font-size:0.83rem; color:#4ade80;">
            <strong>✅ Asset Inventory Loaded</strong> &nbsp;—&nbsp;
            {_asset_hosts_loaded} hosts classified. Data sensitivity is factored into all scores.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:#1e1a0a; border:1px solid #92400e; border-left:4px solid #f59e0b;
                    border-radius:8px; padding:12px 16px; font-size:0.83rem; color:#fbbf24;">
            <strong>⚠️ Data Sensitivity Not Assessed</strong> &nbsp;—&nbsp;
            All findings score <code>data_sensitivity = UNKNOWN</code> (25% of the risk model).
            Upload an asset inventory Excel to classify hosts as Crown Jewel, Regulated, or Sensitive
            and unlock the most impactful deal-killer rules.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # Charts + Shodan panel
    chart_col, shodan_col = st.columns([1, 1])

    with chart_col:
        # Donut chart — tier breakdown
        labels = []
        values = []
        colors = []
        for tier, count in [
            ("Deal Killer", n_dk),
            ("Critical",    n_crit),
            ("Moderate",    n_mod),
            ("Manageable",  n_man),
        ]:
            if count:
                labels.append(tier)
                values.append(count)
                colors.append(TIER_COLOR[tier.lower().replace(" ", "_")])

        if values:
            fig = go.Figure(go.Pie(
                labels=labels,
                values=values,
                hole=0.65,
                marker=dict(colors=colors, line=dict(color="#0e1117", width=2)),
                textinfo="label+percent",
                textfont=dict(size=12, color="#e2e8f0"),
                hovertemplate="<b>%{label}</b><br>%{value} findings<extra></extra>",
            ))
            fig.update_layout(
                showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=10, b=10, l=10, r=10),
                height=240,
                annotations=[dict(
                    text=f"<b>{n_total}</b><br><span style='font-size:11px;color:#6b7280'>findings</span>",
                    x=0.5, y=0.5, font_size=22, font_color="#f1f5f9",
                    showarrow=False
                )],
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        # Top findings by score — horizontal bar
        top_n = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:8]
        if top_n:
            bar_labels = [f.title[:40] + "…" if len(f.title) > 40 else f.title for f in top_n]
            bar_values = [f.risk_score for f in top_n]
            bar_colors = [score_color(s) for s in bar_values]

            fig2 = go.Figure(go.Bar(
                x=bar_values,
                y=bar_labels,
                orientation="h",
                marker=dict(color=bar_colors, line=dict(width=0)),
                hovertemplate="<b>%{y}</b><br>Risk Score: %{x:.1f}<extra></extra>",
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(range=[0, 100], gridcolor="#2a2d3a", tickfont=dict(color="#6b7280"), title=""),
                yaxis=dict(autorange="reversed", tickfont=dict(color="#cbd5e1", size=11), title=""),
                margin=dict(t=4, b=4, l=4, r=4),
                height=260,
            )
            st.markdown("<p style='color:#6b7280;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px;'>Top Findings by Risk Score</p>", unsafe_allow_html=True)
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    with shodan_col:
        # Scan info panel
        nmap_status     = "✅ Completed"
        shodan_status   = "✅ Connected" if shodan_result.get("success") else "❌ Unavailable"
        vulners_count   = st.session_state.get("vulners_count", 0)
        vulners_status  = f"✅ {vulners_count} CVEs found" if vulners_count else "— Script not installed"
        openvas_count   = st.session_state.get("openvas_count", 0)
        openvas_matched = st.session_state.get("openvas_matched", 0)
        zap_count       = st.session_state.get("zap_count", 0)
        asset_hosts     = st.session_state.get("asset_hosts", 0)
        ov_status       = f"✅ {openvas_count} findings ({openvas_matched} merged)" if openvas_count else "— Not uploaded"
        zap_status      = f"✅ {zap_count} findings" if zap_count else "— Not uploaded"
        asset_status    = f"✅ {asset_hosts} hosts classified" if asset_hosts else "— Not uploaded"

        st.markdown(f"""
        <div class="info-panel">
            <div class="ip-label">Target</div>
            <div class="ip-value">{clean_target}</div>
            <div class="ip-label">Resolved IP</div>
            <div class="ip-value">{resolved_ip}</div>
            <div class="ip-label">Nmap</div>
            <div class="ip-value">{nmap_status}</div>
            <div class="ip-label">Vulners NSE</div>
            <div class="ip-value">{vulners_status}</div>
            <div class="ip-label">Shodan</div>
            <div class="ip-value">{shodan_status}</div>
            <div class="ip-label">OpenVAS</div>
            <div class="ip-value">{ov_status}</div>
            <div class="ip-label">ZAP</div>
            <div class="ip-value">{zap_status}</div>
            <div class="ip-label">Asset Inventory</div>
            <div class="ip-value">{asset_status}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        # Shodan snapshot panel
        if shodan_result.get("success"):
            ports_str = ", ".join(map(str, shodan_result.get("ports", []))) or "—"
            vuln_count = len(shodan_result.get("vulns", []))
            org = shodan_result.get("organization") or "Unknown"
            isp = shodan_result.get("isp") or "Unknown"
            country = shodan_result.get("country") or "Unknown"
            city = shodan_result.get("city") or "Unknown"

            st.markdown(f"""
            <div class="info-panel">
                <div class="ip-label">Organization</div>
                <div class="ip-value">{org}</div>
                <div class="ip-label">ISP</div>
                <div class="ip-value">{isp}</div>
                <div class="ip-label">Location</div>
                <div class="ip-value">{city}, {country}</div>
                <div class="ip-label">Open Ports Observed</div>
                <div class="ip-value">{ports_str}</div>
                <div class="ip-label">CVEs Associated</div>
                <div class="ip-value" style="color:{'#ef4444' if vuln_count else '#22c55e'};font-weight:600">{vuln_count}</div>
            </div>
            """, unsafe_allow_html=True)

            if shodan_result["vulns"]:
                with st.expander(f"View {len(shodan_result['vulns'])} associated CVEs"):
                    top_cves = shodan_result["vulns"][:10]
                    rest = shodan_result["vulns"][10:]
                    st.markdown(" ".join(
                        f'<span class="badge badge-dk">{c}</span>' for c in top_cves
                    ), unsafe_allow_html=True)
                    if rest:
                        st.caption(f"+ {len(rest)} more CVEs")
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

        st.caption(f"Showing **{len(filtered_df)}** of {len(df)} findings")

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
        show_details = st.checkbox("Show detailed finding cards", value=False)

        if not filtered_df.empty and show_details:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            for _, row in filtered_df.iterrows():
                tier_val = str(row["Deal Tier"]).lower().replace(" ", "_")
                sc = score_color(row["Risk Score"])
                tier_html  = tier_badge_html(tier_val)
                exp_html   = exposure_badge_html(str(row["Exposure"]).lower().replace(" ", "_"))
                evid_label = format_label(row["Evidence"])

                st.markdown(f"""
                <div class="finding-card">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div style="flex:1; min-width:0; padding-right:16px;">
                            <h4>{row['Title']}</h4>
                            <div class="meta">
                                {tier_html}&nbsp;&nbsp;{exp_html}
                                &nbsp;&nbsp;<span style="color:#6b7280;font-size:0.78rem;">Evidence: {evid_label}</span>
                            </div>
                            <div style="display:grid; grid-template-columns:1fr 1fr; gap:0 24px;">
                                <div>
                                    <div class="field-label">Host</div>
                                    <div class="field-value">{row['Host']}</div>
                                </div>
                                <div>
                                    <div class="field-label">Port / Service</div>
                                    <div class="field-value">{row['Port'] if row['Port'] else '—'} / {row['Service']}</div>
                                </div>
                                <div>
                                    <div class="field-label">Description</div>
                                    <div class="field-value">{row['Description']}</div>
                                </div>
                                <div>
                                    <div class="field-label">Remediation</div>
                                    <div class="field-value">{row['Remediation']}</div>
                                </div>
                            </div>
                        </div>
                        <div class="score-pill" style="min-width:72px;">
                            <div class="s-label">Score</div>
                            <div class="s-value" style="color:{sc}">{row['Risk Score']:.1f}</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# Tab: Export
# ══════════════════════════════════════════════════════════════════════════════

with tab_export:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    exp_col, _ = st.columns([2, 3])
    with exp_col:
        st.markdown(f"""
        <div class="info-panel">
            <div class="ip-label">Target</div>
            <div class="ip-value">{clean_target}</div>
            <div class="ip-label">Total Findings</div>
            <div class="ip-value">{n_total}</div>
            <div class="ip-label">Deal Killers</div>
            <div class="ip-value" style="color:{'#ef4444' if n_dk else '#22c55e'};font-weight:600">{n_dk}</div>
            <div class="ip-label">Critical</div>
            <div class="ip-value" style="color:#f97316;font-weight:600">{n_crit}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

        csv_file = export_findings_csv(findings)
        with open(csv_file, "rb") as f:
            st.download_button(
                label="⬇️  Download CSV Report",
                data=f,
                file_name=csv_file.split("\\")[-1].split("/")[-1],
                mime="text/csv",
                use_container_width=True,
            )

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        pdf_file = generate_pdf_report(findings, clean_target, resolved_ip)
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="⬇️  Download PDF Report",
                data=f,
                file_name=pdf_file.split("\\")[-1].split("/")[-1],
                mime="application/pdf",
                use_container_width=True,
            )
