# RedFlag — Project Context for Claude

## What This Project Is

**RedFlag** is a cybersecurity due-diligence tool built for M&A (mergers and acquisitions) assessments. It scans a target IP/host, enriches findings with multiple data sources, scores everything using a weighted risk model, and presents the results in a Streamlit web UI with a downloadable CSV report.

The core philosophy: every scanner contributes evidence to one unified risk picture — not disconnected scanner outputs.

Run with: `streamlit run app.py`

---

## Repository Structure

```
Redflag/
  app.py                    Streamlit frontend + full orchestration pipeline
  config.py                 (empty/placeholder)
  .env                      API keys — SHODAN_API_KEY is set here
  generate_brief.py         Script that generates redflag_project_brief.pdf using fpdf2

  scanners/
    nmap_scan.py            Runs nmap -sV --open, saves XML to data/results/
    shodan_scan.py          Shodan api.host() lookup + enrichment logic (CURRENT)
    shodan_scan.py.bak      Old version of Shodan enrichment (simpler, before correlated evidence was added)
    openvas_parse.py        PLACEHOLDER — empty, not integrated
    zap_scan.py             PLACEHOLDER — empty, not integrated

  analysis/
    schema.py               Pydantic Finding model + all enums (single source of truth)
    parser.py               Parses Nmap XML into Finding objects (delegates to parsers/nmap_xml.py)
    triage.py               Weighted risk scoring + deal-tier classification
    parsers/
      nmap_xml.py           Low-level Nmap XML parser (currently inline in parser.py; this file is empty)
      openvas_xml.py        PLACEHOLDER — empty
      excel_assets.py       PLACEHOLDER — empty
      pdf_report.py         PLACEHOLDER — empty

  reports/
    generator.py            CSV export (findings_to_dataframe + export_findings_csv)

  tests/
    test_triage.py          PLACEHOLDER — empty (no tests written yet)

  data/results/             Nmap XML scan outputs + CSV reports (gitignored)
```

---

## End-to-End Pipeline (app.py, triggered on "Run Scan")

1. **Nmap scan** — `run_nmap_scan(target)` calls `nmap -sV --open`, saves XML to `data/results/`
2. **Parse XML** — `analyze_nmap_file(xml_file)` → list of `Finding` objects. Default values per finding:
   - `cvss_score = 3.5`
   - `exposure = PARTNER` if service is http/https/ssh/rdp/ftp/telnet, else `INTERNAL`
   - `data_sensitivity = UNKNOWN`
   - `exploit_status = UNKNOWN`
   - `scanner_source = NMAP`
   - `evidence_strength = CONFIRMED`
3. **Shodan lookup** — `socket.gethostbyname(target)` → IP → `lookup_host(ip)` (1 API credit per scan)
4. **Shodan enrichment** — `enrich_findings_with_shodan(findings, shodan_result)`:
   - All Shodan context (org, ASN, ISP, country, city, hostnames, domains, ports, vulns) written to every `finding.raw_data`
   - If finding's port is in Shodan's port list: `exposure → INTERNET_FACING`, `evidence_strength → CORRELATED`
   - If port matches AND Shodan has CVEs AND `exploit_status == UNKNOWN`: `exploit_status → PUBLIC_EXPLOIT`, `cvss_score` floored at 6.5
   - `finding.raw_data['shodan_port_match']` = True/False
5. **Triage/scoring** — `triage_all(findings)` → sorted list (highest score first)
6. **Session state** — results stored in `st.session_state` so UI interactions don't re-trigger scan
7. **UI render** — info bar, Shodan expander, summary metrics, filters (tier, exposure, score slider), findings table, detail cards, CSV download

---

## Risk Scoring Model (triage.py)

### Weighted base score (0–100)
```
score = (cvss_normalised * 0.35)
      + (exposure_score  * 0.25)
      + (sensitivity_score * 0.25)
      + (exploit_score   * 0.15)
```

**Factor lookup tables:**

| Factor | Values |
|--------|--------|
| Exposure | INTERNET_FACING=100, PARTNER=60, INTERNAL=30, UNKNOWN=50 |
| Data Sensitivity | CROWN_JEWEL=100, REGULATED=85, SENSITIVE=55, LOW=20, UNKNOWN=50 |
| Exploit Status | ACTIVE_EXPLOITATION=100, PUBLIC_EXPLOIT=65, NO_EXPLOIT=10, UNKNOWN=30 |

### Evidence strength multiplier
Applied after base score:
- CONFIRMED = 1.00 (OpenVAS/ZAP verified)
- CORRELATED = 0.95 (Nmap + Shodan agree)
- INFERRED = 0.85 (Shodan-only, banner-based)
- UNKNOWN = 0.90 (Nmap-only default)

### Deal-tier override rules (fire BEFORE scoring → score forced to 100)
- `exploit_status == ACTIVE_EXPLOITATION` → **DEAL_KILLER**
- `data_sensitivity == CROWN_JEWEL` AND `cvss >= 9.0` AND `exposure == INTERNET_FACING` → **DEAL_KILLER**
- `data_sensitivity == REGULATED` AND `cvss >= 9.5` AND `exposure == INTERNET_FACING` → **DEAL_KILLER**
- `override_reason` contains "active compromise" (manual flag) → **DEAL_KILLER**

### Score-to-tier (after scoring)
- >= 75 → CRITICAL
- >= 50 → MODERATE
- < 50 → MANAGEABLE

---

## Data Model (schema.py — Pydantic)

```python
class Finding(BaseModel):
    id: str                        # UUID auto-generated
    cve_id: Optional[str]
    title: str
    host: Optional[str]            # IP address
    port: Optional[int]
    service: Optional[str]         # e.g. "http", "ssh"
    cvss_score: float              # 0.0–10.0
    description: str
    remediation: str
    exposure: ExposureLevel        # internet_facing | partner | internal | unknown
    data_sensitivity: DataSensitivity  # crown_jewel | regulated | sensitive | low | unknown
    exploit_status: ExploitStatus  # active_exploitation | public_exploit | no_exploit | unknown
    scanner_source: ScannerSource  # nmap | shodan | openvas | zap | vulners | pdf_upload | excel_upload | email_attachment | manual
    evidence_strength: EvidenceStrength  # confirmed | correlated | inferred | unknown
    raw_data: Optional[dict]       # Shodan context + scanner metadata stored here
    risk_score: float              # 0–100, set by triage
    deal_tier: DealTier            # deal_killer | critical | moderate | manageable | unscored
    override_reason: Optional[str] # Explanation if deal-killer rule fired
    discovered_at: datetime        # UTC
```

---

## Current Scanner Status

| Scanner | Status | Notes |
|---------|--------|-------|
| Nmap | ✅ Stage A + B complete | Primary scan engine |
| Shodan | ✅ Stage A + B complete | Enrichment layer, 1 credit/scan |
| OpenVAS | ❌ Not started | `openvas_parse.py` is empty placeholder |
| ZAP | ❌ Not started | `zap_scan.py` is empty placeholder |

---

## Known Gaps / What Is Not Done Yet

1. **OpenVAS integration** — will provide verified CVEs, real CVSS scores, `CONFIRMED` evidence strength
2. **ZAP integration** — will provide web application layer findings
3. **Real CVSS per CVE** — Shodan returns CVE IDs but not CVSS scores; currently floors at 6.5. NVD API lookup needed
4. **data_sensitivity enrichment** — all findings default to `UNKNOWN`; needs an asset inventory layer (e.g. Excel upload via `excel_assets.py`) to classify hosts as CROWN_JEWEL/REGULATED/etc. This matters a lot because the most impactful deal-killer rules depend on it
5. **Multi-host Shodan** — subnet scans produce multiple hosts but Shodan is only queried for the single resolved IP of the hostname; multi-host batching not yet implemented
6. **Tests** — `tests/test_triage.py` is empty; no test coverage yet

---

## Environment / Dependencies

- Python (uses venv in `venv/`)
- Key packages: `streamlit`, `pydantic`, `pandas`, `python-nmap`, `shodan`, `python-dotenv`, `fpdf2`
- Nmap binary must be installed at `C:\Program Files (x86)\Nmap\nmap.exe` or `C:\Program Files\Nmap\nmap.exe`
- `.env` file contains `SHODAN_API_KEY`

---

## Shodan Credit Notes

- `api.host()` = 1 credit per IP (most efficient call)
- Results cached in `st.session_state` — no repeat API calls during a session
- When adding multi-host support: batch/cache Shodan results, never query per-finding
- During development: use saved Shodan JSON fixtures, not live API calls

---

## UI Structure (app.py)

- **Scan Controls** — target input + Run Scan button
- **Info bar** (3 columns) — Target, Scan Status, Shodan Snapshot
- **Shodan Enrichment Details** — collapsible expander with full host metadata + CVE list
- **Summary metrics** — Total Findings, Deal Killers, Critical, Moderate, Manageable
- **Filter Findings** — Deal Tier multiselect, Exposure multiselect, Risk Score slider
- **Findings Table** — sortable dataframe with ProgressColumn for risk score
- **Detailed Findings** — toggleable cards with description + remediation per finding
- **Export Report** — CSV download button

---

## File Naming Conventions

- Nmap XML outputs: `data/results/nmap_{target}_{YYYYMMDD_HHMMSS}.xml`
- CSV reports: `data/results/redflag_report_{YYYYMMDD_HHMMSS}.csv`
