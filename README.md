<div align="center">

# 🚩 RedFlag
### M&A Cybersecurity Due Diligence Platform

**Scan. Score. Decide.**

RedFlag is an end-to-end cybersecurity assessment platform built for mergers & acquisitions.
It aggregates evidence from multiple scanners, scores every finding with an SSVC/EPSS-aligned
risk model, checks DNS/email security, TLS health, and breach exposure, assesses the target's
internal security maturity, plans Day-1 connectivity, estimates remediation costs, and reasons
about attack paths like an attacker — all in a single **Reflex** web application.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Reflex](https://img.shields.io/badge/Reflex-0.9-5b4ee9?style=flat-square&logo=react&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-34d399?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-143%20passing-34d399?style=flat-square)

**[📚 Full documentation →](docs/README.md)**

</div>

---

## What RedFlag Does

When evaluating a target company for acquisition, security risk is one of the hardest things to price.
RedFlag automates the technical layer of that assessment:

1. **Scans** the target's internet-facing attack surface (Nmap + Shodan + Nuclei)
2. **Enriches** findings with exploit intelligence (CISA KEV, EPSS, NVD, Vulners)
3. **Merges** uploaded scanner outputs (OpenVAS, ZAP, Nuclei) into a single finding set
4. **Scores** every finding with a weighted, EPSS-aware risk model (exploit status, exposure, CVSS, data sensitivity)
5. **Checks** DNS/email security controls (SPF, DMARC, DKIM, DNSSEC)
6. **Validates** TLS certificate health and discovers shadow subdomains via CT logs
7. **Queries** breach databases for prior compromise exposure (LeakIX)
8. **Assesses** the target's internal security programme maturity across 7 domains
9. **Plans** a Day-1 Safe Harbor connectivity model with phase gates
10. **Estimates** remediation costs with low / base / high scenarios and CapEx/OpEx split
11. **Reasons** about attack paths like an attacker (MITRE ATT&CK mind-map) and **measures** them as a graph (chokepoints, blast radius, paths to crown jewels)
12. **Learns** from every scan — a self-improving, offline knowledge base that gets sharper over time
13. **Generates** a deterministic narrative report and downloadable CSV and PDF exports

---

## Features

### 🔍 Multi-Scanner Intelligence

| Scanner | Type | What It Finds |
|---------|------|---------------|
| **Nmap** | Active scan | Open ports, services, banners |
| **Shodan** | Passive OSINT | Internet-visible attack surface, org/ASN/geo |
| **Nuclei** | Template DAST | Confirmed vulns, exposed panels, default creds, misconfigs |
| **OpenVAS / GVM** | Authenticated scan | Verified CVEs, configuration flaws |
| **OWASP ZAP** | DAST | Web application vulnerabilities (SQLi, XSS, etc.) |
| **Vulners NSE** | Exploit intel | CVE-to-exploit mapping from Nmap scripts |
| **CISA KEV** | Active exploitation | Known-exploited CVE cross-reference |
| **EPSS** | Exploit prediction | Probability each CVE is exploited in the next 30 days |
| **NVD API** | CVSS enrichment | Real CVSS v3.1 scores for every CVE |
| **DNS Scanner** | Config audit | SPF, DMARC, DKIM, DNSSEC presence and policy |
| **TLS Scanner** | Cert health | Expiry, weak TLS versions, CT log subdomain discovery |
| **Breach Scanner** | OSINT | Prior breach and exposure indexing via LeakIX |

A live scan and any uploaded scanner outputs **fuse into one finding set** — uploads correlate
into the Nmap layer (upgrading evidence strength), they don't replace it. You can also run with
**uploads only** (no live target), or enable **Fast Scan Mode** for a quicker top-200-port sweep.

### 📊 Risk Scoring (SSVC/EPSS-Aligned)

Every finding receives a 0–100 risk score computed from four weighted factors:

```
Score = (Exploit Status × 0.30) + (Exposure × 0.25) + (CVSS × 0.25) + (Data Sensitivity × 0.20)
```

The base score is then multiplied by an **evidence-strength** factor (Confirmed 1.00 →
External 0.80), so a verified OpenVAS/ZAP/Nuclei finding outranks a banner-only inference at the same severity.

The model is forward-looking, not just severity-based: **EPSS** (FIRST.org Exploit Prediction
Scoring System) is fetched for every CVE, and a high exploitation probability promotes an
otherwise-unknown finding's exploit status — so a "92%-likely-to-be-exploited" CVE is ranked
like one with a public exploit, even before it lands in CISA KEV.

Findings are classified into four deal tiers:
- 🔴 **Deal Killer** — Active exploitation or critical asset at risk; blocks deal close
- 🟠 **Critical** — Remediate within 30 days of close
- 🟡 **Moderate** — 90-day post-close security roadmap
- 🟢 **Manageable** — Standard security hygiene backlog

### 🧠 Attacker-Brain & Attack-Path Mind-Map

A dedicated **Attack Path** tab that thinks like an attacker — **no LLM, no API, fully offline, $0**.
It maps every finding to the **MITRE ATT&CK** techniques it enables, then chains them into a
kill-chain and renders the result as a radial **mind-map**:

```
INTERNET entry  →  Exploitation  →  Lateral movement  →  Impact
```

- A precomputed SVG **mind-map** centred on the target, with stage branches coloured by deal tier
- An **attacker's playbook** — numbered steps, each mapped to a MITRE technique (e.g. `T1190`,
  `T1110`, `T1078`) that links straight to its page on attack.mitre.org
- A reachability **kill-chain** and host→service breakdown showing exactly what is reachable from
  the public internet
- Built from the findings' own enriched exploit status (CISA KEV / public exploit), so real
  attacker intel rides along for free

### 🧬 Self-Improving Brain Memory

RedFlag's attacker-brain gets **smarter with every scan** — not by training a model, but by
**remembering**. A persistent, offline knowledge base accumulates everything it has seen:

- Stored as a real **Obsidian vault** at `~/RedFlag-Brain` (`brain.json` index + Markdown notes
  for every Scan / Technique / CVE, wired together with `[[wikilinks]]`). Open that folder in
  Obsidian and use **Graph View** to literally see the brain.
- On each scan it **recalls** prior knowledge first — "this CVE has appeared in 3 prior scans · KEV",
  "this exact kill-chain has been seen before" — then **learns** the new scan, bumping prevalence
  weights for techniques, CVEs, services and attack paths.
- A **Refresh threat intel** button pulls the free **CISA KEV** feed into the brain on demand.
- **Fresh clones don't start empty.** The repo ships a sanitized seed
  (`analysis/brain_seed/brain.json`) — aggregate technique/CVE/service/path prevalence + KEV,
  with target identities stripped — and a new install bootstraps from it on first run. Refresh
  the shipped seed from your own accumulated brain at any time with `python -m analysis.brain_memory`.
- No GPU, no training loop, no paid API. It improves by accumulating and retrieving, on your machine.

### 🕸️ Graph Analysis

Where the attacker-brain *narrates* the kill-chain, the **Graph analysis** panel *measures* it.
The estate is modelled as a directed graph (`INTERNET → host → service`, plus lateral-movement
pivots) and analysed with [networkx](https://networkx.org/) to answer questions the narrative can't:

- **Chokepoints** — which host/service, if fixed, severs the most attack paths (highest-leverage
  remediation), ranked by removal impact and betweenness centrality
- **Blast radius** — how many assets are reachable from the public internet
- **Shortest path to crown jewels** — the exact route from the internet to crown-jewel / regulated data

Turns the attack path from descriptive into quantitative — *"patch this one box and 6 attack
paths die."* Fully local, no extra compute concerns.

### 🌐 DNS & Email Security

Automatically checks the target domain for the four essential email security controls:

- **SPF** — prevents unauthorised mail servers from spoofing the domain
- **DMARC** — enforces SPF/DKIM policy; a missing DMARC record means anyone can impersonate the domain
- **DKIM** — cryptographic email signing; verifies mail authenticity in transit
- **DNSSEC** — protects DNS records from tampering and cache poisoning

Each missing or misconfigured record becomes a scored Finding. A missing DMARC policy is flagged
as Critical exposure — an active, exploitable spoofing risk that becomes the acquirer's liability on day one.

### 🔒 TLS Certificate Health

Connects to every HTTPS port Nmap discovers and checks:

- **Certificate expiry** — flags anything expiring within 30 days (Moderate) / 7 days (Critical)
- **TLS version** — TLS 1.0/1.1 are deprecated and a PCI-DSS violation; flagged immediately
- **Shadow subdomain discovery** — queries the free crt.sh certificate-transparency log for every
  cert ever issued for the domain, revealing forgotten, unmonitored subdomains

### 🕵️ Breach Exposure Check

Queries LeakIX — a free internet-wide security scanner — for indexed exposure on the target's
domain and IPs: exposed databases (MongoDB/Elasticsearch/Redis without auth), leaked config and
credential dumps, and known-compromised services. A confirmed breach hit is classified as a
**Deal Killer** and surfaced prominently. It answers the single most important acquisition
question: **has this company already been compromised?**

### 🏛️ Maturity Assessment

A 23-question inside-out assessment across 7 security domains:

> Identity & Access · Network Security · Endpoint Security · Application Security ·
> Data Protection · Incident Response · Third-Party Risk

Each domain is scored 0–5 and compared against a configurable corporate acquisition standard.
Gaps below the deal-blocker threshold are flagged separately from technical scan findings, and
every gap feeds the Cost Engine as its own remediation line items.

### 🛡️ Day-1 Safe Harbor Blueprint

A dedicated **Day 1 plan** tab that turns the assessment into a connectivity decision for the
moment the deal closes. It recommends a posture on the integration ladder —
**Isolate → Broker → Federate → Integrate** — backed by control pillars, pass/blocked phase
gates, and a phased (P0–P3) remediation roadmap, so you know exactly what must be true before
the two networks touch.

### 💰 Cost & Budget Engine

- Estimates remediation cost per finding and per maturity gap using a YAML-driven pricing catalog
- Deduplicates identical remediations across findings (e.g. 10 SSH findings → 1 line item)
- Outputs **low / base / high** scenarios with full **CapEx vs OpEx** breakdown
- A human-review gate flags high-variance and deal-killer items before export
- **What-If** controls: switch scenario, scope to deal-killers/criticals, and toggle whether
  maturity gaps are included — the totals recompute live

### 📝 Narrative Template Engine

Deterministic narrative text generated from YAML-backed template blocks — **no LLM required**.
Same input always produces the same output. Covers executive summary, maturity gaps, cost
rationale, per-finding context, and remediation priority guidance.

---

## Getting Started

### What You Need Before Starting

| Requirement | Windows | macOS |
|-------------|---------|-------|
| Python 3.11+ | [python.org/downloads](https://www.python.org/downloads/) | `brew install python` or [python.org](https://www.python.org/downloads/) |
| Git | [git-scm.com](https://git-scm.com/download/win) | Pre-installed, or `brew install git` |
| Nmap | [nmap.org/download](https://nmap.org/download.html#windows) | `brew install nmap` |
| Node.js 18+ | Installed automatically by Reflex on first run, or [nodejs.org](https://nodejs.org) | Same |
| Shodan API key | Optional — free tier at [shodan.io](https://shodan.io) | Same |
| Vulners API key | Optional — free tier at [vulners.com](https://vulners.com) | Same |

> **No API keys?** You can still run a full assessment — see [No API Keys](#no-api-keys) below.

> Reflex compiles a small Next.js frontend on first launch (one-time, ~1 min) and needs Node.js;
> it will offer to install it automatically if it isn't found.

---

### Installation — Windows

Open **PowerShell** and follow these steps exactly.

#### Step 1 — Verify Python
```powershell
python --version
```
You should see `Python 3.11.x` or higher. If not, install from [python.org/downloads](https://www.python.org/downloads/) and **tick "Add Python to PATH"**.

#### Step 2 — Install Nmap
Download the **stable self-installer** from [nmap.org/download.html](https://nmap.org/download.html#windows), run it with defaults, then verify:
```powershell
nmap --version
```

#### Step 3 — Clone the repository
```powershell
git clone https://github.com/adityaa206/redflag.git
cd redflag
```

#### Step 4 — Create and activate a virtual environment
```powershell
python -m venv venv
venv\Scripts\activate
```
Your prompt will show `(venv)`. **Activate it every time you open a new terminal.**

#### Step 5 — Install dependencies
```powershell
pip install -r requirements.txt
```

#### Step 6 — Set up your API keys
```powershell
copy .env.example .env
notepad .env
```
Fill in your keys (see [Configuration](#configuration)), then save and close.

#### Step 7 — Launch the app
```powershell
python -m reflex run
```
Open **http://localhost:3000** in your browser. (First run compiles the frontend — give it a minute.)

---

### Installation — macOS

Open **Terminal** and follow these steps.

#### Step 1 — Install Homebrew (if needed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2 — Install Python, Git, and Nmap
```bash
brew install python git nmap
python3 --version   # 3.11+
nmap --version
```

#### Step 3 — Clone the repository
```bash
git clone https://github.com/adityaa206/redflag.git
cd redflag
```

#### Step 4 — Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 5 — Install dependencies
```bash
pip install -r requirements.txt
```

#### Step 6 — Set up your API keys
```bash
cp .env.example .env
nano .env          # or: open -e .env
```

#### Step 7 — Launch the app
```bash
python -m reflex run
```
Open **http://localhost:3000** in your browser.

---

### Running the App After First Install

**Windows:**
```powershell
cd redflag
venv\Scripts\activate
python -m reflex run
```

**macOS:**
```bash
cd redflag
source venv/bin/activate
python -m reflex run
```

---

### Configuration

Edit `.env` in the project root:

```env
# Optional — live Shodan lookups (1 credit per IP queried)
SHODAN_API_KEY=your_shodan_api_key_here

# Optional — per-CVE exploit confirmation via Vulners
VULNERS_API_KEY=your_vulners_api_key_here
```

- **Shodan** — [account.shodan.io](https://account.shodan.io) → API Key (free tier)
- **Vulners** — [vulners.com/userinfo](https://vulners.com/userinfo) → API Keys (free tier)

#### No API Keys?

You can run a complete assessment with zero API keys:

| What you lose | Workaround |
|---------------|------------|
| Live Shodan lookups | Upload a Shodan JSON export instead (target-provided or from your account) |
| Vulners exploit confirmation | Findings still score; exploit status defaults to UNKNOWN |
| Nothing else | NVD, CISA KEV, DNS, TLS, and breach checks all work with no keys |

---

### Troubleshooting

**`'nmap' is not recognized` / `nmap: command not found`**
- Reinstall Nmap and ensure it's on PATH (`C:\Program Files (x86)\Nmap` on Windows; `brew install nmap` on macOS).

**`python: command not found` (macOS)** — use `python3`, or `brew install python` to alias it.

**`ModuleNotFoundError` when launching** — your virtual environment isn't active. Activate it first.

**Port 3000 or 8000 already in use** — another Reflex instance is running. Stop it, or run on alternate ports:
```bash
python -m reflex run --frontend-port 3001 --backend-port 8001
```

**The scan starts but returns no findings** — Nmap isn't on PATH. Verify with `nmap --version`.

**First launch is slow / asks to install Node** — Reflex builds the frontend once and needs Node.js; let it install or install Node 18+ yourself.

---

## Usage

### Running a Scan

1. Open **http://localhost:3000**
2. Enter the target hostname or IP in the scan bar (optional if you only upload files)
3. (Optional) Stage supplementary scanner outputs in the upload slots — the filename chips show what's staged:
   - **Shodan JSON** — target-provided host export (saves API credits)
   - **OpenVAS XML** — GVM/OpenVAS scan report
   - **ZAP XML** — OWASP ZAP active scan report
   - **Nuclei JSONL** — `nuclei -jsonl` output (run it anywhere; no local binary needed)
   - **Asset Inventory (Excel)** — classifies hosts as Crown Jewel / Regulated / Sensitive
4. (Optional) Toggle **Fast Scan Mode** for a quicker top-200-port sweep
5. Click **Run scan**

DNS, TLS, and breach checks run automatically alongside the Nmap scan. The live scan and every
staged file fuse into one finding set.

### Using the Mock Data Files

Test the full pipeline without a live scan using the included fixtures:

| File | Use In |
|------|--------|
| `tests/fixtures/mock_openvas.xml` | OpenVAS XML upload |
| `tests/fixtures/mock_zap.xml` | ZAP XML upload |
| `tests/fixtures/sample_assessment.json` | Reference / integration tests |

The mock OpenVAS file includes EternalBlue, PrintNightmare, Log4Shell, default credentials,
Telnet, Redis exposure, TLS misconfiguration, and missing security headers. The mock ZAP file
includes SQL injection, reflected XSS, IDOR, missing CSRF protection, directory listing, cookie
flags, vulnerable jQuery, and exposed Spring Actuator endpoints.

### Tab Guide

| Tab | What You Do |
|-----|------------|
| **Overview** | Risk dashboard — verdict, tier counts, risk-breakdown donut, findings table |
| **Findings** | Filter and drill into individual findings |
| **Attack Path** | Attacker-brain mind-map, MITRE playbook, kill-chain, and the self-improving brain-memory panel |
| **Maturity** | Complete the 23-question questionnaire; see domain scores vs. acquisition standard |
| **Day 1 Plan** | Recommended connectivity model, control pillars, phase gates, and P0–P3 roadmap |
| **Cost** | Generate the remediation cost model; What-If controls; review flagged items |
| **Export** | Download the CSV report and PDF reports (full / Day-1 / cost) |

---

## Architecture

```
RedFlag/
├── rxconfig.py                 Reflex config (app_name="redflag_ui")
│
├── redflag_ui/                 ← Reflex presentation layer (no business logic)
│   ├── redflag_ui.py           rx.App + 9 routed pages
│   ├── state.py                RedFlagState — run_scan pipeline, view-models, brain learn/recall, exports
│   ├── components/             shell (nav + scan bar + 5 upload slots + footer), ui helpers
│   └── pages/                  overview, findings, attack, maturity, day1, cost, export, legal
│
├── scanners/
│   ├── nmap_scan.py            Nmap runner (full / fast mode)
│   ├── shodan_scan.py          Shodan live lookup + parse_shodan_json()
│   ├── nuclei_scan.py          Nuclei runner + JSONL parser + correlation merge
│   ├── openvas_parse.py        OpenVAS XML parse + correlation merge
│   ├── zap_scan.py             OWASP ZAP XML parse + correlation merge
│   ├── vulners_parse.py        Vulners NSE block parser
│   ├── vulners_enrich.py       Vulners API exploit confirmation
│   ├── kev_lookup.py           CISA KEV cross-reference
│   ├── epss_scan.py            EPSS exploitation-probability enrichment
│   ├── dns_scan.py             SPF / DMARC / DKIM / DNSSEC checks
│   ├── tls_scan.py             Cert expiry, TLS version, crt.sh CT-log subdomains
│   └── breach_scan.py          LeakIX breach and exposure check
│
├── analysis/
│   ├── schema.py               Pydantic Finding model + all enums
│   ├── parser.py               Nmap XML → Finding objects
│   ├── triage.py               Weighted risk scoring + deal-tier classification
│   ├── maturity.py             Inside-out maturity assessment engine
│   ├── standards_compare.py    Gap analysis vs. corporate standard
│   ├── day1.py                 Day-1 Safe Harbor connectivity blueprint
│   ├── attack_brain.py         ★ Offline MITRE ATT&CK attacker-brain + mind-map SVG
│   ├── attack_graph.py         ★ networkx chokepoints / blast radius / crown-jewel paths
│   ├── brain_memory.py         ★ Self-improving Obsidian-vault knowledge base
│   ├── graph_builder.py        Legacy attack-graph builder (superseded by attack_brain)
│   └── parsers/excel_assets.py Asset-inventory Excel parser
│
├── cost/                       schema · catalog · estimator · deduplicator · scenario_engine · rollup · exporters
├── narrative/                  blocks · engine · report_builder (deterministic, YAML-backed)
├── config/                     loader + 6 YAMLs (maturity, corporate standard, pricing, remediation, narrative, day1)
├── reports/                    generator (CSV) · pdf_report (full / Day-1 / cost PDF)
├── assets/                     redflag.css (the whole emerald design) + favicon
├── docs/                       full documentation set (handover · technical · ops · user · legal)
└── tests/                      143 engine tests (pytest) + fixtures
```

### Data Flow

```
Nmap XML ──→ analyze_nmap_file()
               ├──→ parse_vulners_from_nmap_xml()
Shodan ────────┼──→ enrich_findings_with_shodan()  ←── CISA KEV + NVD
Nuclei ────────┼──→ merge_nuclei_with_nmap()        (live binary or JSONL upload)
OpenVAS XML ───┼──→ merge_openvas_with_nmap()
ZAP XML ───────┼──→ merge_zap_with_nmap()
Excel ─────────┼──→ apply_sensitivity_to_findings()
DNS/TLS/Breach ┼──→ run_dns_scan() / run_tls_scan() / run_breach_scan()
EPSS ──────────┼──→ enrich_findings_with_epss()     (exploit probability + promote)
               ▼
           triage_all()  →  [Finding, risk_score, deal_tier]
               │
   ┌───────────┼───────────┬────────────────────┬─────────────┐
   ▼           ▼           ▼                    ▼             ▼
Maturity     Day-1       Cost              Attacker-Brain   Narrative
Assessment   Blueprint   Pipeline          + Attack-Graph   Engine
   │           │           │                analyze_attack_  │
   │           │           │                paths() / graph  │
   │           │           │                + brain_memory   │
   └───────────┴───────────┴────────────────────┴────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
         CSV / PDF              ~/RedFlag-Brain (Obsidian vault)
```

---

## Tech Stack

| Layer | Library |
|-------|---------|
| UI | [Reflex](https://reflex.dev) (compiles to Next.js/React) |
| Data validation | [Pydantic v2](https://docs.pydantic.dev) |
| Data manipulation | [pandas](https://pandas.pydata.org) |
| Attack-path mind-map | Precomputed SVG (no JS graph library) |
| Graph analytics | [networkx](https://networkx.org) (chokepoints / blast radius / paths) |
| Risk donut | CSS conic-gradient (no chart library) |
| PDF generation | [fpdf2](https://py-fpdf2.readthedocs.io) |
| XLSX export | [openpyxl](https://openpyxl.readthedocs.io) |
| Nmap integration | [python-nmap](https://xael.org/pages/python-nmap-en.html) |
| Shodan integration | [shodan](https://shodan.readthedocs.io) |
| DNS queries | [dnspython](https://www.dnspython.org) |
| TLS/cert parsing | [cryptography](https://cryptography.io) |
| Config | [PyYAML](https://pyyaml.org) |
| Env vars | [python-dotenv](https://github.com/theskumar/python-dotenv) |
| Knowledge base | Plain JSON + Markdown ([Obsidian](https://obsidian.md)-compatible vault) |
| Testing | [pytest](https://pytest.org) |

---

## Running Tests

```bash
# Run all 143 engine tests
pytest tests/ -v

# Run a specific module
pytest tests/test_triage.py -v
pytest tests/test_epss.py -v
pytest tests/test_nuclei.py -v
pytest tests/test_attack_graph.py -v
pytest tests/test_day1.py -v
pytest tests/test_integration.py -v
```

The test suite covers the scoring, maturity, cost, narrative, Day-1, and end-to-end engine
pipelines — all independent of the UI layer. See [docs/testing/TEST_PLAN.md](docs/testing/TEST_PLAN.md)
for the per-module coverage map and what is deliberately **not** covered.

---

## Documentation

The complete documentation set lives in **[`docs/`](docs/README.md)**.

| Core documents | |
|---|---|
| **[Handover](docs/handover/HANDOVER.md)** | Project status, what shipped, where everything lives |
| **[Authorized Use](docs/legal/AUTHORIZED_USE.md)** | ⚠️ **Read before running any scan** |
| **[User Guide](docs/user/USER_GUIDE.md)** | Running an assessment, tab by tab |
| **[Installation](docs/operations/INSTALLATION.md)** | Full setup for Windows and macOS |

| Technical | |
|---|---|
| [Architecture](docs/technical/ARCHITECTURE.md) | Layering, component and data-flow diagrams |
| [Data Model](docs/technical/DATA_MODEL.md) | The `Finding` object and every enum |
| [Module Reference](docs/technical/MODULE_REFERENCE.md) | Public signatures and side effects |
| [Configuration](docs/technical/CONFIGURATION.md) | Every `.env` variable, constant and YAML knob |
| [Integrations](docs/technical/INTEGRATIONS.md) | Each external tool: endpoints, keys, degradation |
| [Brain Knowledge Base](docs/technical/BRAIN_KNOWLEDGE_BASE.md) | The self-improving offline memory |

| Also | |
|---|---|
| [Results Interpretation](docs/user/RESULTS_INTERPRETATION.md) | What every number means, and how far to trust it |
| [Limitations](docs/testing/LIMITATIONS.md) | Honest accuracy caveats |
| [Troubleshooting](docs/operations/TROUBLESHOOTING.md) | Symptom → cause → fix |
| [Architecture Decision Records](docs/process/adr/README.md) | Why the eight big choices were made |
| [Roadmap](docs/process/ROADMAP.md) · [Changelog](CHANGELOG.md) | Where it goes next; what has shipped |
| [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) | How to help; how to report a vulnerability |

---

## Scoring Reference

### Risk Score Formula

```python
base_score = (
    exploit_score         * 0.30  +   # Exploit status (primary signal)
    exposure_score        * 0.25  +   # Exposure level
    (cvss / 10.0 * 100)   * 0.25  +   # CVSS
    sensitivity_score     * 0.20      # Data sensitivity
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
| Internal | 30 | Unknown | 30 | Unknown | 0.90 |
| Unknown | 50 | No Exploit | 10 | Inferred | 0.85 |
| | | | | External | 0.80 |

---

## Customisation

All thresholds, weights, pricing, and narrative text are YAML/config-driven — no code changes needed:

| File | What to Change |
|------|---------------|
| `config/__init__.py` | Scoring weights, tier thresholds, Nmap args |
| `config/corporate_standard.yaml` | Per-domain maturity deal-blocker thresholds |
| `config/pricing_benchmarks.yaml` | Labour rates, tool costs, effort hours |
| `config/remediation_catalog.yaml` | CVE/service/tier cost mappings |
| `config/narrative_blocks.yaml` | Report narrative text |
| `config/maturity_questions.yaml` | Assessment questions and domain structure |
| `config/day1_blueprint.yaml` | Day-1 connectivity models, pillars, gates |

The attacker-brain's knowledge base lives at `~/RedFlag-Brain` (override with `REDFLAG_BRAIN_DIR`).

---

## Roadmap

- [x] Day-1 Safe Harbor connectivity blueprint with phase gates
- [x] Attack-path reasoning that thinks like an attacker (MITRE ATT&CK mind-map)
- [x] Self-improving, offline knowledge base (learns by remembering across scans)
- [ ] Optional free-tier LLM layer over the brain for generative narrative (no paid API)
- [ ] Compliance gap mapping (ISO 27001 / NIST CSF / SOC 2 / GDPR / PCI-DSS)
- [ ] Public-repo secret scanning (trufflehog integration)
- [ ] Multi-target comparison view (risk / maturity / cost across candidates)
- [ ] Multi-host Shodan (subnet scan support)
- [ ] Docker Compose for one-command startup

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Security & Privacy

RedFlag processes only data you explicitly provide. No scan data is sent to any third party beyond:

- **Shodan** (1 credit per IP for live lookups) — only the target IP is sent
- **NVD/NIST** (public CVSS API) — only CVE IDs are sent
- **CISA KEV** (public feed) — downloaded on demand, no data sent
- **Vulners** (optional NSE/API) — only CVE IDs are sent
- **LeakIX** (free breach API) — only the target domain and IP are sent
- **crt.sh** (public CT log API) — only the target domain is sent

Scan outputs are written to a local temp directory, and the attacker-brain knowledge base is
stored locally at `~/RedFlag-Brain` — neither leaves your machine, and both are excluded from
version control. The only brain data committed to the repo is the **sanitized seed**
(`analysis/brain_seed/brain.json`): aggregate pattern knowledge with all scanned-target
identities stripped, so shipping it never reveals who was assessed.

---

<div align="center">
<sub>Built for M&A cybersecurity due diligence &nbsp;·&nbsp; Not a replacement for professional penetration testing</sub>
</div>
