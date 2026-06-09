<div align="center">

# 🚩 RedFlag
### M&A Cybersecurity Due Diligence Platform

**Scan. Score. Decide.**

RedFlag is an end-to-end cybersecurity assessment platform built for mergers & acquisitions.
It aggregates evidence from multiple scanners, scores every finding with an SSVC/EPSS-aligned
risk model, checks DNS/email security, TLS health, and breach exposure, assesses the target's
internal security maturity, estimates remediation costs, and visualises attack paths — all in a
single Streamlit application.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-34d399?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-86%20passing-34d399?style=flat-square)

</div>

---

## What RedFlag Does

When evaluating a target company for acquisition, security risk is one of the hardest things to price.
RedFlag automates the technical layer of that assessment:

1. **Scans** the target's internet-facing attack surface (Nmap + Shodan)
2. **Enriches** findings with exploit intelligence (CISA KEV, NVD, Vulners)
3. **Merges** uploaded scanner outputs (OpenVAS, ZAP) into a single finding set
4. **Scores** every finding using a weighted risk model (exploit status, exposure, CVSS, data sensitivity)
5. **Checks** DNS/email security controls (SPF, DMARC, DKIM, DNSSEC)
6. **Validates** TLS certificate health and discovers shadow subdomains via CT logs
7. **Queries** breach databases for prior compromise exposure (LeakIX)
8. **Assesses** the target's internal security programme maturity across 7 domains
9. **Estimates** remediation costs with low / base / high scenarios and CapEx/OpEx split
10. **Visualises** the attack path from internet to vulnerabilities as an interactive graph
11. **Generates** a deterministic narrative report and downloadable CSV, PDF, and XLSX exports

---

## Features

### 🔍 Multi-Scanner Intelligence

| Scanner | Type | What It Finds |
|---------|------|---------------|
| **Nmap** | Active scan | Open ports, services, banners |
| **Shodan** | Passive OSINT | Internet-visible attack surface, org/ASN/geo |
| **OpenVAS / GVM** | Authenticated scan | Verified CVEs, configuration flaws |
| **OWASP ZAP** | DAST | Web application vulnerabilities (SQLi, XSS, etc.) |
| **Vulners NSE** | Exploit intel | CVE-to-exploit mapping from Nmap scripts |
| **CISA KEV** | Active exploitation | Known-exploited CVE cross-reference |
| **NVD API** | CVSS enrichment | Real CVSS v3.1 scores for every CVE |
| **DNS Scanner** | Config audit | SPF, DMARC, DKIM, DNSSEC presence and policy |
| **TLS Scanner** | Cert health | Expiry, weak TLS versions, CT log subdomain discovery |
| **Breach Scanner** | OSINT | Prior breach and exposure indexing via LeakIX |

### 📊 Risk Scoring (SSVC/EPSS-Aligned)

Every finding receives a 0–100 risk score computed from four weighted factors:

```
Score = (Exploit Status × 0.30) + (Exposure × 0.25) + (CVSS × 0.25) + (Data Sensitivity × 0.20)
```

Findings are classified into four deal tiers:
- 🔴 **Deal Killer** — Active exploitation or critical asset at risk; blocks deal close
- 🟠 **Critical** — Remediate within 30 days of close
- 🟡 **Moderate** — 90-day post-close security roadmap
- 🟢 **Manageable** — Standard security hygiene backlog

### 🌐 DNS & Email Security

Automatically checks the target domain for the four essential email security controls:

- **SPF** — Sender Policy Framework; prevents unauthorised mail servers from spoofing the domain
- **DMARC** — Enforces SPF/DKIM policy and controls failure handling; a missing DMARC record means anyone can impersonate the target's domain
- **DKIM** — Cryptographic email signing; verifies mail authenticity in transit
- **DNSSEC** — Protects DNS records from tampering and cache poisoning

Each missing or misconfigured record is converted to a scored Finding and contributes to the overall deal tier. A missing DMARC policy is flagged as Critical exposure because it represents an active, exploitable spoofing risk that becomes the acquirer's liability on day one.

### 🔒 TLS Certificate Health

Connects to all HTTPS ports discovered by Nmap and checks:

- **Certificate expiry** — flags anything expiring within 30 days as Moderate, within 7 days as Critical
- **TLS version** — TLS 1.0 and 1.1 are deprecated and a compliance violation under PCI-DSS; their presence is flagged immediately
- **Shadow subdomain discovery** — queries the crt.sh certificate transparency log (free, public) for every certificate ever issued for the target domain, revealing forgotten subdomains that may be running unpatched, unmonitored services

### 🕵️ Breach Exposure Check

Queries LeakIX — a free internet-wide security scanner — for any indexed exposure associated with the target's domain and IP addresses. Returns findings for:

- Exposed databases (MongoDB, Elasticsearch, Redis instances accessible without authentication)
- Leaked configuration files and credential dumps
- Known-compromised services indexed by the security research community

A confirmed breach hit is classified as DEAL_KILLER and surfaced with a prominent alert banner in the Overview tab. This answers the single most important question in any acquisition: **has this company already been compromised?**

### 🏛️ Maturity Assessment

A 23-question inside-out assessment across 7 security domains:

> Identity & Access · Network Security · Endpoint Security · Application Security ·
> Data Protection · Incident Response · Third-Party Risk

Each domain is scored 0–5 and compared against a configurable corporate acquisition standard.
Gaps below the deal-blocker threshold are flagged separately from technical scan findings. Every maturity gap also feeds into the Cost Engine — the gap between current score and required score drives a separate set of remediation cost line items.

### 💰 Cost & Budget Engine

- Estimates remediation cost per finding and per maturity gap using a YAML-driven pricing catalog
- Deduplicates identical remediations across multiple findings (e.g. 10 SSH findings → 1 line item)
- Outputs **low / base / high** scenarios with full **CapEx vs OpEx** breakdown
- Human review gate: flagged items (high-variance estimates, deal-killer findings) must be acknowledged before export
- Exports as CSV or XLSX

### 🎯 What-If Scenario Simulator

An interactive negotiation tool in the Findings tab. Select any combination of findings and mark them as "pre-close remediation" — the simulator instantly recalculates the full risk profile without those findings:

- New average risk score and delta from current
- Whether any deal-killers are cleared
- Whether the overall deal tier improves

Turns security findings into quantified negotiating leverage. You can tell the seller exactly which issues to fix and show the precise risk reduction if they do — backed by the same scoring model that produced the original assessment.

### 🗺️ Attack Path Visualisation

A dedicated **Attack Path** tab displaying an interactive vis.js graph of how an attacker moves from the open internet through exposed services to reach specific vulnerabilities. Built with four hierarchical layers:

```
INTERNET  →  Exposed Hosts  →  Services (port/protocol)  →  CVEs
```

- Every node is coloured by its worst deal tier (red → orange → amber → green)
- Internal-only hosts are shown but have no edge from INTERNET — immediately visible isolation
- Hover any node for full details: CVE ID, CVSS score, risk score, exposure level, service info
- Fully interactive: zoom, pan, drag — powered by vis.js hierarchical layout
- Stat cards at the top show: Exposed Hosts / Total Hosts / CVEs on Path / Deal Killers Exposed

### 📝 Narrative Template Engine

Deterministic narrative text generated from 25+ YAML-backed template blocks — no LLM required.
Same input always produces the same output. Covers executive summary, maturity gaps, cost rationale,
per-finding context, and remediation priority guidance.

---

## Getting Started

### Prerequisites

- Python 3.10+
- [Nmap](https://nmap.org/download.html) installed and on `PATH`
  - Windows default: `C:\Program Files (x86)\Nmap\nmap.exe`
- (Optional) Shodan API key for live lookups
- (Optional) Vulners API key for exploit enrichment

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/adityaa206/redflag.git
cd redflag

# 2. Create and activate a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
# Edit .env and add your keys (see Configuration section)

# 5. Launch the app
streamlit run app.py
```

### Configuration

Create a `.env` file in the project root:

```env
# Required for live Shodan lookups (1 credit per IP)
SHODAN_API_KEY=your_shodan_api_key_here

# Optional — enables exploit confirmation via Vulners API
VULNERS_API_KEY=your_vulners_api_key_here
```

> **No API keys?** You can still run a full assessment:
> - Upload a Shodan JSON export (target-provided or from your account) instead of a live query
> - Upload OpenVAS and ZAP XML exports for verified scanner data
> - NVD and CISA KEV use public APIs (no key required)
> - DNS, TLS, and breach checks require no API keys at all

---

## Usage

### Running a Scan

1. Open the app at `http://localhost:8501`
2. Enter the target hostname or IP in the scan bar
3. (Optional) Upload supplementary scanner outputs using the upload row:
   - **Shodan JSON** — target-provided host export (saves API credits)
   - **OpenVAS XML** — GVM/OpenVAS scan report
   - **ZAP XML** — OWASP ZAP active scan report
   - **Asset Inventory (Excel)** — classifies hosts as Crown Jewel / Regulated / Sensitive
4. Click **Run Comprehensive Scan**

DNS, TLS, and breach checks run automatically alongside the Nmap scan — no extra configuration needed.

### Using the Mock Data Files

Test the full pipeline without running a real scan using the included fixtures:

| File | Use In |
|------|--------|
| `tests/fixtures/mock_openvas.xml` | OpenVAS XML upload |
| `tests/fixtures/mock_zap.xml` | ZAP XML upload |
| `tests/fixtures/sample_assessment.json` | Reference / integration tests |

The mock OpenVAS file includes: EternalBlue, PrintNightmare, Log4Shell, default credentials, Telnet, Redis exposure, TLS misconfiguration, and missing security headers.

The mock ZAP file includes: SQL injection, reflected XSS, IDOR, CSRF absence, directory listing, cookie flags, vulnerable jQuery, and exposed Spring Actuator endpoints.

### Tab Guide

| Tab | What You Do |
|-----|------------|
| **Overview** | Risk dashboard — metric cards, donut chart, DNS/TLS/breach summary cards, target intel, scanner pipeline status |
| **Findings** | Filter and drill into individual findings; What-If simulator to quantify pre-close remediation value |
| **Attack Path** | Interactive vis.js graph of attacker movement from internet to vulnerabilities; stat cards showing exposed hosts and CVE counts |
| **Maturity Assessment** | Complete the 23-question security programme questionnaire; see domain scores vs. acquisition standard |
| **Cost & Budget** | Generate remediation cost model; review flagged items; download CSV or XLSX |
| **Export** | Download full CSV report and PDF report |

---

## Architecture

```
RedFlag/
├── app.py                      Streamlit UI + scan orchestration pipeline
│
├── scanners/
│   ├── nmap_scan.py            Nmap runner + Vulners NSE parser
│   ├── shodan_scan.py          Shodan live lookup + parse_shodan_json()
│   ├── openvas_parse.py        OpenVAS XML parser
│   ├── zap_scan.py             OWASP ZAP XML parser
│   ├── vulners_parse.py        Vulners NSE block parser
│   ├── vulners_enrich.py       Vulners API exploit confirmation
│   ├── kev_lookup.py           CISA KEV feed (cached per session)
│   ├── dns_scan.py             SPF / DMARC / DKIM / DNSSEC checks
│   ├── tls_scan.py             Cert expiry, TLS version, CT log subdomain scan
│   └── breach_scan.py          LeakIX breach and exposure check
│
├── analysis/
│   ├── schema.py               Pydantic Finding model + all enums
│   ├── parser.py               Nmap XML → Finding objects
│   ├── triage.py               Weighted risk scoring + deal-tier classification
│   ├── maturity.py             Inside-Out Maturity Assessment engine
│   ├── standards_compare.py    Gap analysis vs. corporate standard
│   ├── graph_builder.py        Attack path graph node/edge builder
│   └── parsers/
│       └── excel_assets.py     Asset inventory Excel parser
│
├── cost/
│   ├── schema.py               CostTriple, CostLineItem, CostRollup, enums
│   ├── catalog.py              CVE/service/tier → CostLineItem lookup
│   ├── estimator.py            Findings + gaps → raw CostLineItems
│   ├── deduplicator.py         Merge duplicate remediation items
│   ├── scenario_engine.py      Low / base / high scenario builder
│   ├── rollup.py               Aggregate + run_cost_pipeline()
│   └── exporters.py            CSV and XLSX export (review gate enforced)
│
├── narrative/
│   ├── blocks.py               Condition-based YAML block selector
│   ├── engine.py               Context builders + narrative functions
│   └── report_builder.py       Full structured report dict
│
├── config/
│   ├── loader.py               Cached YAML loader
│   ├── maturity_questions.yaml 7 domains, 23 questions (0–5 scale)
│   ├── corporate_standard.yaml Per-domain deal-blocker thresholds
│   ├── pricing_benchmarks.yaml Labour rates, tool costs, effort hours
│   ├── remediation_catalog.yaml CVE/service/tier/maturity cost entries
│   └── narrative_blocks.yaml   25+ narrative template blocks
│
├── reports/
│   ├── generator.py            CSV export
│   └── pdf_report.py           PDF export (fpdf2) + cost section
│
└── tests/
    ├── test_triage.py          24 tests — risk scoring engine
    ├── test_maturity.py        20 tests — maturity assessment
    ├── test_estimator.py       27 tests — cost estimation pipeline
    ├── test_narrative_engine.py 19 tests — narrative template engine
    ├── test_integration.py      7 tests — end-to-end pipeline
    └── fixtures/
        ├── sample_assessment.json  Representative scan + maturity answers
        ├── mock_openvas.xml        8 realistic OpenVAS findings
        └── mock_zap.xml            8 realistic ZAP web app findings
```

### Data Flow

```
Nmap XML ──→ analyze_nmap_file()
               │
               ├──→ parse_vulners_from_nmap_xml()
               │
Shodan ────────┼──→ enrich_findings_with_shodan()  ←── CISA KEV + NVD
               │
OpenVAS XML ───┼──→ merge_openvas_with_nmap()
               │
ZAP XML ───────┼──→ merge_zap_with_nmap()
               │
Excel ─────────┼──→ apply_sensitivity_to_findings()
               │
DNS ───────────┼──→ run_dns_scan()    (SPF / DMARC / DKIM / DNSSEC)
               │
TLS ───────────┼──→ run_tls_scan()    (cert expiry / TLS version / CT log)
               │
Breach ────────┼──→ run_breach_scan() (LeakIX domain + IP check)
               │
               ▼
           triage_all()  →  [Finding, risk_score, deal_tier]
               │
    ┌──────────┼──────────┬──────────────┐
    ▼          ▼          ▼              ▼
Maturity    Cost       Attack Path    Narrative
Assessment  Pipeline   Graph          Engine
    │          │       build_attack_  build_report()
    │          │       graph()            │
    └──────────┴──────────┴──────────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
         CSV / PDF               XLSX export
```

---

## Tech Stack

| Layer | Library |
|-------|---------|
| UI | [Streamlit](https://streamlit.io) |
| Data validation | [Pydantic v2](https://docs.pydantic.dev) |
| Data manipulation | [pandas](https://pandas.pydata.org) |
| Charts | [Plotly](https://plotly.com/python/) |
| Attack path graph | [pyvis](https://pyvis.readthedocs.io) (vis.js) |
| PDF generation | [fpdf2](https://py-fpdf2.readthedocs.io) |
| XLSX export | [openpyxl](https://openpyxl.readthedocs.io) |
| Nmap integration | [python-nmap](https://xael.org/pages/python-nmap-en.html) |
| Shodan integration | [shodan](https://shodan.readthedocs.io) |
| DNS queries | [dnspython](https://www.dnspython.org) |
| TLS/cert parsing | [cryptography](https://cryptography.io) |
| Config | [PyYAML](https://pyyaml.org) |
| Env vars | [python-dotenv](https://github.com/theskumar/python-dotenv) |
| Testing | [pytest](https://pytest.org) |

---

## Running Tests

```bash
# Run all 86 tests
pytest tests/ -v

# Run a specific module
pytest tests/test_triage.py -v
pytest tests/test_maturity.py -v
pytest tests/test_estimator.py -v
pytest tests/test_integration.py -v
```

---

## Scoring Reference

### Risk Score Formula

```python
base_score = (
    (cvss / 10.0 * 100)  * 0.25  +   # CVSS
    exposure_score        * 0.25  +   # Exposure level
    sensitivity_score     * 0.20  +   # Data sensitivity
    exploit_score         * 0.30      # Exploit status (primary signal)
)
risk_score = base_score * evidence_multiplier
```

### Deal-Killer Override Rules (score forced to 100)

| Condition | Reason |
|-----------|--------|
| `exploit_status == ACTIVE_EXPLOITATION` | CVE in CISA Known Exploited Vulnerabilities catalogue |
| `data_sensitivity == CROWN_JEWEL` AND `cvss >= 9.0` AND `internet_facing` | Critical exposure of most sensitive asset |
| `data_sensitivity == REGULATED` AND `cvss >= 9.5` AND `internet_facing` | Regulatory liability at critical severity |

### Lookup Tables

| Exposure Level | Score | Exploit Status | Score | Evidence | Multiplier |
|---------------|-------|----------------|-------|----------|------------|
| Internet Facing | 100 | Active Exploitation | 100 | Confirmed | 1.00 |
| Partner | 60 | Public Exploit | 65 | Correlated | 0.95 |
| Internal | 30 | Unknown | 30 | Inferred | 0.85 |
| Unknown | 50 | No Exploit | 10 | External | 0.80 |

---

## Customisation

All thresholds, weights, pricing, and narrative text are YAML-driven — no code changes needed:

| File | What to Change |
|------|---------------|
| `config/__init__.py` | Scoring weights, tier thresholds |
| `config/corporate_standard.yaml` | Per-domain maturity deal-blocker thresholds |
| `config/pricing_benchmarks.yaml` | Labour rates, tool costs, effort hours |
| `config/remediation_catalog.yaml` | CVE/service/tier cost mappings |
| `config/narrative_blocks.yaml` | Report narrative text |
| `config/maturity_questions.yaml` | Assessment questions and domain structure |

---

## Roadmap

- [ ] AI-generated executive summary (plain-English paragraph report for non-technical stakeholders)
- [ ] Compliance gap mapping (ISO 27001 / NIST CSF / SOC 2 / GDPR / PCI-DSS)
- [ ] 30/60/90 day post-acquisition remediation roadmap generator
- [ ] Public GitHub repository secret scanner (trufflehog integration)
- [ ] Multi-target comparison view (side-by-side risk, maturity, and cost across acquisition candidates)
- [ ] Multi-host Shodan (subnet scan support)
- [ ] Auto-merge cost PDF section into main report
- [ ] `requirements.txt` with pinned versions
- [ ] Docker Compose for one-command startup

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Security & Privacy

RedFlag processes only data you explicitly provide. No scan data is sent to any third party beyond:

- **Shodan** (1 credit per IP for live lookups) — only the target IP is sent
- **NVD/NIST** (public CVSS API) — only CVE IDs are sent
- **CISA KEV** (public feed) — downloaded once per session, no data sent
- **Vulners** (optional NSE/API) — only CVE IDs are sent
- **LeakIX** (free breach API) — only the target domain and IP are sent
- **crt.sh** (public CT log API) — only the target domain is sent

All scan outputs are stored locally in `data/results/` and are excluded from version control.

---

<div align="center">
<sub>Built for M&A cybersecurity due diligence &nbsp;·&nbsp; Not a replacement for professional penetration testing</sub>
</div>
