# RedFlag

RedFlag is a Streamlit-based cybersecurity due diligence platform for mergers and acquisitions. It combines network discovery, external threat intelligence, vulnerability scanner outputs, and a weighted triage model to help identify findings that could materially affect a deal. [web:377][web:373]

## Highlights

- Multi-source findings pipeline: Nmap, Shodan, Vulners, OpenVAS, ZAP, and asset inventory Excel.
- Weighted risk scoring with M&A-focused deal tiers: Deal Killer, Critical, Moderate, Manageable.
- Evidence-aware triage: confirmed scanner results score differently from inferred or external-only intelligence.
- Export-ready outputs: interactive dashboard, CSV report, and PDF report.

## What it does

RedFlag starts with an Nmap scan to discover open ports and exposed services, then enriches the results with Shodan, Vulners, CISA KEV, and NVD CVSS data. Optional OpenVAS XML, ZAP XML, and Excel asset inventory uploads add confirmed vulnerability data, web application findings, and business sensitivity context to the same unified finding model.

This lets the project answer a more useful question than “what is vulnerable?” — it answers “what is risky enough to affect an acquisition?”

## Architecture

```text
Target IP / Host
    |
    +--> Nmap scan --> Nmap XML parser --> base findings
    |
    +--> Vulners NSE parse -------------> CVE findings / exploit enrichment
    |
    +--> Shodan lookup -----------------> internet exposure + standalone CVE findings
    |
    +--> OpenVAS XML upload -----------> confirmed vulnerability findings
    |
    +--> ZAP XML upload ---------------> web application findings
    |
    +--> Asset Excel upload -----------> data sensitivity mapping
    |
    +--> CISA KEV + NVD + Vulners -----> exploit status + CVSS enrichment
    |
    +--> triage_all() -----------------> risk score + deal tier
    |
    +--> Streamlit dashboard ----------> table, filters, cards, charts, exports
```

## Repository structure

```text
redflag/
├── app.py
├── config.py
├── analysis/
│   ├── schema.py
│   ├── parser.py
│   ├── triage.py
│   └── parsers/
│       └── excel_assets.py
├── scanners/
│   ├── nmap_scan.py
│   ├── shodan_scan.py
│   ├── openvas_parse.py
│   ├── zap_scan.py
│   ├── vulners_parse.py
│   ├── vulners_enrich.py
│   └── kev_lookup.py
└── reports/
    ├── generator.py
    └── pdf_report.py
```

## Core tools

### Nmap

Nmap is the base discovery layer. RedFlag uses it to identify live services, open ports, and service versions, then converts the XML output into normalized `Finding` objects.

### Shodan

Shodan adds external visibility. It confirms whether services are internet-facing, contributes host-level vulnerability intelligence, and can generate standalone findings from Shodan-observed CVEs and risky exposed ports.

### Vulners

Vulners is used in two ways: through the `vulners.nse` Nmap script and through API-based exploit lookups. It helps associate detected services with CVEs and upgrades exploit status when public exploit evidence exists.

### OpenVAS / Greenbone

OpenVAS contributes confirmed vulnerability findings from exported XML reports. These results can be merged with Nmap findings by host and port to strengthen evidence and improve CVSS accuracy.

### OWASP ZAP

ZAP adds the web application layer. XML reports are parsed into findings for issues such as insecure headers, cross-site scripting, and other web-specific weaknesses that network scanners may miss.

### CISA KEV + NVD

CISA KEV is used to detect actively exploited CVEs, and the NVD API is used to retrieve official CVSS scores. Together, they improve exploit-status accuracy and risk scoring quality.

## Risk model

Each finding is scored using weighted inputs:

- CVSS score
- Exposure level
- Data sensitivity
- Exploit status
- Evidence strength multiplier

Override rules can immediately classify a finding as a **Deal Killer** if it represents active exploitation or an unacceptable combination of criticality, exposure, and business sensitivity.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/adityaa206/redflag.git
cd redflag
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

If your repo includes `requirements.txt`:

```bash
pip install -r requirements.txt
```

If not, install the main packages used by the project:

```bash
pip install streamlit pandas plotly python-dotenv python-nmap requests openpyxl fpdf2 shodan
```

You also need the Nmap binary installed locally because `python-nmap` calls the real Nmap executable.

### 4. Configure environment variables

Create a `.env` file in the project root.

Example:

```env
SHODAN_API_KEY=your_shodan_key_here
VULNERS_API_KEY=your_vulners_key_here
NVD_API_KEY=your_nvd_key_here
```

Notes:
- `SHODAN_API_KEY` is required for Shodan enrichment.
- `VULNERS_API_KEY` is optional; the project will still run without it.
- `NVD_API_KEY` is recommended to avoid slow rate-limited CVSS lookups.

## Running the app

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal, usually `http://localhost:8501`.

## Usage flow

1. Enter a target IP, host, or subnet.
2. Choose normal mode or Fast Scan.
3. Click **Run Scan**.
4. Optionally upload:
   - OpenVAS XML
   - ZAP XML
   - Asset inventory Excel
5. Review summary cards, charts, and filtered findings.
6. Export the final results as CSV or PDF.

## Optional inputs

### OpenVAS XML

Use this when you want confirmed vulnerability findings from Greenbone/OpenVAS. Export the report as XML from the OpenVAS interface and upload it in RedFlag.

### ZAP XML

Use this for web applications. Generate a ZAP XML report after an automated or active scan and upload it to merge web-layer issues into the same risk model.

### Asset inventory Excel

Use this to map hosts to business sensitivity levels such as Crown Jewel, Regulated, or Sensitive. This is important because the strongest deal-killer rules depend on business context, not just technical severity.

Expected columns are flexible, but the file should include:
- an IP / host column
- a sensitivity / classification column

## Example scenarios

- External infrastructure review of a target company's public IP range.
- Combining Nmap and OpenVAS results for a more defensible due diligence report.
- Reviewing a customer-facing web app by merging ZAP findings into the same executive dashboard.
- Highlighting internet-facing crown-jewel assets as pre-close blockers.

## Outputs

RedFlag currently supports:

- Interactive Streamlit dashboard
- Findings table with filters and score bars
- Detailed finding cards
- CSV export
- PDF report export

## Important notes

- Only scan systems you own or have explicit permission to assess.
- Shodan, OpenVAS, and ZAP can surface sensitive findings; handle outputs accordingly.
- The app is designed as a due-diligence analysis tool, not as a replacement for a full penetration test.

## Roadmap ideas

- Add authentication and user session history
- Add report branding / executive summary customization
- Add cloud asset ingestion
- Add ticketing integrations for remediation tracking
- Add historical comparison between scan runs

## Contributing

1. Create a feature branch.
2. Make your changes.
3. Test the Streamlit flow and report exports.
4. Open a pull request with a clear summary.

## License

Add your preferred license here, for example MIT.
