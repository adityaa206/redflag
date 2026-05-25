from fpdf import FPDF
import datetime

class PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(180, 30, 30)
        self.cell(0, 8, "REDFLAG - PROJECT BRIEF", align="R")
        self.ln(4)
        self.set_draw_color(180, 30, 30)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 6, f"Page {self.page_no()} | Generated {datetime.date.today()}", align="C")

    def section_title(self, text):
        self.ln(4)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(180, 30, 30)
        self.cell(0, 8, text)
        self.ln(1)
        self.set_draw_color(220, 180, 180)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)
        self.set_text_color(30, 30, 30)

    def sub_title(self, text):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(50, 50, 50)
        self.cell(0, 7, text)
        self.ln(5)
        self.set_text_color(30, 30, 30)

    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 6, text)
        self.ln(2)

    def bullet(self, text, indent=8):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.set_x(10 + indent)
        self.cell(5, 6, chr(149))
        self.multi_cell(0, 6, text)

    def code_block(self, text):
        self.set_font("Courier", "", 9)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, text, fill=True)
        self.set_font("Helvetica", "", 10)
        self.ln(2)

    def kv(self, key, value):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(40, 40, 40)
        self.cell(50, 6, key + ":")
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, value)


pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# ── Cover block ───────────────────────────────────────────────────────────────
pdf.set_font("Helvetica", "B", 26)
pdf.set_text_color(180, 30, 30)
pdf.ln(6)
pdf.cell(0, 14, "RedFlag", align="C")
pdf.ln(12)
pdf.set_font("Helvetica", "", 13)
pdf.set_text_color(60, 60, 60)
pdf.cell(0, 8, "Cybersecurity Due Diligence Tool - Project Brief", align="C")
pdf.ln(6)
pdf.set_font("Helvetica", "I", 10)
pdf.set_text_color(120, 120, 120)
pdf.cell(0, 6, f"Generated: {datetime.date.today()}", align="C")
pdf.ln(10)
pdf.set_draw_color(180, 30, 30)
pdf.set_line_width(0.6)
pdf.line(30, pdf.get_y(), 180, pdf.get_y())
pdf.ln(10)

# ── 1. What RedFlag Is ────────────────────────────────────────────────────────
pdf.section_title("1. What RedFlag Is")
pdf.body(
    "RedFlag is a multi-scanner cybersecurity due-diligence tool built for M&A assessments. "
    "It combines findings from multiple security scanners, normalises them into a shared internal "
    "schema, scores them using a weighted risk model, and presents the results through a Streamlit "
    "web UI with a downloadable CSV report.\n\n"
    "The goal is not to produce disconnected scanner outputs. The goal is a single unified "
    "risk picture where every scanner contributes evidence to one common score."
)

# ── 2. Current Scanner Status ─────────────────────────────────────────────────
pdf.section_title("2. Current Scanner Status")
pdf.body("Each scanner goes through two integration stages:")
pdf.bullet("Stage A - Connectivity and data-display validation (prove it works, show raw output in UI)")
pdf.bullet("Stage B - Risk-scoring integration (merge signals into the central triage engine)")
pdf.ln(4)

statuses = [
    ("Nmap",    "Stage A + B complete", "Primary scan engine. Produces open port / service findings. Fully wired into triage."),
    ("Shodan",  "Stage A + B complete", "Host enrichment. Upgrades exposure and exploit status for internet-visible ports."),
    ("OpenVAS", "Not yet started",      "Verified vulnerability scanner. Will provide confirmed CVEs and CVSS scores."),
    ("ZAP",     "Not yet started",      "Web application scanner. Will provide HTTP-layer findings."),
]
for name, status, desc in statuses:
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(30, 6, name)
    pdf.set_font("Helvetica", "I", 10)
    color = (0, 140, 0) if "complete" in status else (160, 100, 0)
    pdf.set_text_color(*color)
    pdf.cell(50, 6, status)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(70, 70, 70)
    pdf.multi_cell(0, 6, desc)
    pdf.ln(1)

# ── 3. Repository Structure ───────────────────────────────────────────────────
pdf.section_title("3. Repository Structure")
pdf.code_block(
    "Redflag/\n"
    "  app.py                    Streamlit frontend and orchestration\n"
    "  config.py                 Configuration\n"
    "  .env                      API keys (SHODAN_API_KEY etc.)\n"
    "\n"
    "  scanners/\n"
    "    nmap_scan.py            Runs nmap -sV --open, saves XML output\n"
    "    shodan_scan.py          Shodan api.host() lookup + enrichment logic\n"
    "    openvas_parse.py        Placeholder - not yet integrated\n"
    "    zap_scan.py             Placeholder - not yet integrated\n"
    "\n"
    "  analysis/\n"
    "    schema.py               Finding data model (Pydantic) + all enums\n"
    "    parser.py               Parses Nmap XML into Finding objects\n"
    "    triage.py               Weighted risk scoring and deal-tier logic\n"
    "    parsers/                Format-specific sub-parsers (nmap_xml, openvas_xml, pdf, excel)\n"
    "\n"
    "  reports/\n"
    "    generator.py            CSV export\n"
    "\n"
    "  tests/\n"
    "    test_triage.py          Triage unit tests\n"
    "\n"
    "  data/results/             Nmap XML output files and CSV reports"
)

# ── 4. End-to-End Pipeline ────────────────────────────────────────────────────
pdf.section_title("4. End-to-End Pipeline (Current)")
pdf.body("When the user clicks Run Scan, the following steps execute in order:")
steps = [
    ("1. Nmap scan",        "nmap_scan.py runs nmap -sV --open on the target. Saves raw XML to data/results/."),
    ("2. XML parsing",      "parser.py reads the XML. For each open port it creates a Finding object with: cvss_score=3.5 (default), exposure inferred from service name (http/ssh/rdp etc. = PARTNER, else INTERNAL), data_sensitivity=UNKNOWN, exploit_status=UNKNOWN, scanner_source=NMAP."),
    ("3. Shodan lookup",    "app.py resolves the target hostname to an IP (socket.gethostbyname), then calls shodan_scan.lookup_host(ip). This costs exactly 1 Shodan API credit per scan."),
    ("4. Shodan enrichment","enrich_findings_with_shodan() iterates every Finding. If the finding's port appears in Shodan's observed port list: exposure is upgraded to INTERNET_FACING, evidence_strength is set to CORRELATED (Nmap + Shodan agree), if Shodan reports any CVEs and exploit_status is still UNKNOWN it is upgraded to PUBLIC_EXPLOIT and cvss_score is floored at 6.5. Shodan context metadata (org, ASN, ISP, country, city, hostnames, domains, ports, vulns) is stored on every finding's raw_data field regardless."),
    ("5. Triage / scoring", "triage_all() runs triage() on each Finding. triage() first checks override rules (deal-killer fast-paths), then calls calculate_score() which produces a 0-100 weighted score."),
    ("6. Session state",    "Findings, shodan_result, resolved_ip, and clean_target are stored in st.session_state so filter/slider interactions don't trigger a re-scan."),
    ("7. UI render",        "app.py renders: info bar, Shodan detail expander, summary metrics, filter controls (tier multiselect, exposure multiselect, score slider), findings table with ProgressColumn for risk score, detailed finding cards (toggleable), CSV download button."),
]
for title, desc in steps:
    pdf.sub_title(title)
    pdf.body(desc)

# ── 5. Risk Scoring Model ─────────────────────────────────────────────────────
pdf.section_title("5. Risk Scoring Model (triage.py)")
pdf.body(
    "The final risk score is a number from 0 to 100, calculated as a weighted sum of four factors "
    "and then multiplied by an evidence-strength adjustment."
)
pdf.ln(2)
pdf.sub_title("Step 1 - Weighted base score")
pdf.code_block(
    "score = (cvss_normalised * 0.35)\n"
    "      + (exposure_score  * 0.25)\n"
    "      + (sensitivity_score * 0.25)\n"
    "      + (exploit_score   * 0.15)"
)
factors = [
    ("CVSS (35%)",         "Normalised from 0-10 to 0-100. Default is 3.5 (Nmap). Shodan floors it at 6.5 for matched ports with CVEs."),
    ("Exposure (25%)",     "INTERNET_FACING=100, PARTNER=60, INTERNAL=30, UNKNOWN=50."),
    ("Data Sensitivity (25%)", "CROWN_JEWEL=100, REGULATED=85, SENSITIVE=55, LOW=20, UNKNOWN=50."),
    ("Exploit Status (15%)",   "ACTIVE_EXPLOITATION=100, PUBLIC_EXPLOIT=65, NO_EXPLOIT=10, UNKNOWN=30."),
]
for name, desc in factors:
    pdf.bullet(f"{name}: {desc}")
pdf.ln(4)

pdf.sub_title("Step 2 - Evidence strength multiplier")
pdf.body("The base score is multiplied by an evidence confidence factor:")
evidence = [
    ("CONFIRMED  (1.00)", "OpenVAS / ZAP verified finding - no reduction."),
    ("CORRELATED (0.95)", "Port seen by both Nmap and Shodan - small reduction."),
    ("INFERRED   (0.85)", "Shodan-only signal - larger reduction (banner-based, not verified)."),
    ("UNKNOWN    (0.90)", "Default for Nmap-only findings."),
]
for name, desc in evidence:
    pdf.bullet(f"{name} - {desc}")
pdf.ln(4)

pdf.sub_title("Step 3 - Deal-tier classification")
tiers = [
    ("DEAL_KILLER", "Override rules fire before scoring. Any active exploitation, crown-jewel asset internet-facing with CVSS >= 9.0, regulated data internet-facing with CVSS >= 9.5, or manual active-compromise tag => score forced to 100, tier forced to DEAL_KILLER."),
    ("CRITICAL",    "Score >= 75."),
    ("MODERATE",    "Score >= 50."),
    ("MANAGEABLE",  "Score < 50."),
]
for name, desc in tiers:
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(32, 6, name)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, desc)
    pdf.ln(1)

# ── 6. Data Model ─────────────────────────────────────────────────────────────
pdf.section_title("6. Data Model (schema.py)")
pdf.body(
    "Every scanner produces Finding objects. The Finding Pydantic model is the single "
    "shared representation across the entire pipeline."
)
pdf.code_block(
    "Finding fields:\n"
    "  id                UUID (auto)\n"
    "  title             Human-readable finding name\n"
    "  host              IP address\n"
    "  port              Integer port number\n"
    "  service           Service name (http, ssh, etc.)\n"
    "  cve_id            Optional CVE identifier\n"
    "  cvss_score        0.0 - 10.0\n"
    "  description       What was found\n"
    "  remediation       How to fix it\n"
    "  exposure          ExposureLevel enum\n"
    "  data_sensitivity  DataSensitivity enum\n"
    "  exploit_status    ExploitStatus enum\n"
    "  evidence_strength EvidenceStrength enum\n"
    "  scanner_source    ScannerSource enum (which scanner produced this)\n"
    "  raw_data          Dict - scanner-specific metadata (Shodan context stored here)\n"
    "  risk_score        Final 0-100 score (set by triage)\n"
    "  deal_tier         DealTier enum (set by triage)\n"
    "  override_reason   Text explanation if a deal-killer rule fired\n"
    "  discovered_at     UTC timestamp"
)

# ── 7. Shodan Integration Detail ──────────────────────────────────────────────
pdf.section_title("7. Shodan Integration Detail")
pdf.body(
    "Shodan is used as an enrichment layer, not a primary scanner. One api.host() call "
    "per scan (1 credit). The enrichment logic in enrich_findings_with_shodan() applies "
    "the following rules per finding:"
)
rules = [
    "Shodan context (org, ASN, ISP, country, city, hostnames, domains, all observed ports, all CVEs) is written to finding.raw_data for every finding regardless of port match.",
    "finding.raw_data['shodan_port_match'] = True/False - records whether this specific port was seen by Shodan.",
    "If the port is in Shodan's observed list: exposure is upgraded to INTERNET_FACING, evidence_strength is set to CORRELATED.",
    "If the port matches AND Shodan reports CVEs AND exploit_status is still UNKNOWN: exploit_status is upgraded to PUBLIC_EXPLOIT, cvss_score is floored at 6.5 (conservative - Shodan CVEs are banner-based, not verified).",
    "Findings whose ports are NOT in Shodan's list are not penalised - they keep their Nmap-derived exposure level.",
    "exploit_status is only upgraded if it is currently UNKNOWN - a future OpenVAS/ZAP ACTIVE_EXPLOITATION status will never be overwritten by Shodan.",
]
for r in rules:
    pdf.bullet(r)
    pdf.ln(1)

# ── 8. What Is NOT Done Yet ───────────────────────────────────────────────────
pdf.section_title("8. What Is Not Done Yet")
gaps = [
    ("OpenVAS integration", "openvas_parse.py exists but is not connected to the pipeline. Will provide verified CVEs, real CVSS scores, and CONFIRMED evidence_strength."),
    ("ZAP integration",     "zap_scan.py exists but is not connected. Will provide web application findings."),
    ("CVSS from CVE IDs",   "Shodan returns CVE IDs but not CVSS scores. Currently all Shodan-enriched findings get cvss_score floored at 6.5. A future NVD API lookup could provide real CVSS per CVE."),
    ("data_sensitivity",    "All findings currently default to UNKNOWN. A future asset inventory layer (e.g. Excel upload) would classify assets as CROWN_JEWEL, REGULATED, etc., enabling the highest-impact deal-killer rules."),
    ("Multi-host scans",    "Subnet scans (e.g. 192.168.1.0/24) produce multiple hosts. Shodan is currently queried only for the single resolved IP of the target hostname. Multi-host Shodan lookups are not yet implemented."),
]
for name, desc in gaps:
    pdf.sub_title(name)
    pdf.body(desc)

# ── 9. Credit Efficiency Notes ────────────────────────────────────────────────
pdf.section_title("9. Shodan Credit Efficiency")
notes = [
    "api.host() = 1 credit per IP. This is the most efficient Shodan call available.",
    "Results are stored in st.session_state - the same scan result is reused across all filter/slider interactions without a new API call.",
    "Future multi-host support should batch or cache Shodan results, not query per-finding.",
    "Test the merge logic using saved Shodan JSON fixtures rather than live lookups during development.",
]
for n in notes:
    pdf.bullet(n)
    pdf.ln(1)

# ── Save ──────────────────────────────────────────────────────────────────────
output_path = r"c:\Users\Adityaa\OneDrive\Desktop\Redflag\redflag_project_brief.pdf"
pdf.output(output_path)
print(f"PDF saved: {output_path}")
