# Module Reference

Public API per package. Every signature below is copied from the source, not paraphrased.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

**Legend** — 🌐 makes a network call · 💾 writes to disk · ⚙️ reads YAML config (cached) ·
🔑 behaviour changes with an API key · ⚠️ mutates its argument in place

---

## `scanners/` — the collection layer

The only package permitted to perform network I/O. **Every function here degrades to an empty
result rather than raising**, so one dead feed cannot fail a scan.

### `scanners/nmap_scan.py`

```python
def find_nmap() -> str | None
def vulners_nse_available() -> bool
def run_nmap_scan(target: str, output_dir: str = "data/results", fast_mode: bool = False) -> str
```

- `find_nmap()` — probes two fixed Windows paths: `C:\Program Files (x86)\Nmap\nmap.exe` then
  `C:\Program Files\Nmap\nmap.exe`. Returns `None` if neither exists.
  **Note:** this is Windows-only path probing; it does not consult `PATH`.
- `vulners_nse_available()` — `True` if `vulners.nse` sits in Nmap's `scripts/` directory.
- `run_nmap_scan()` 🌐💾🔑 — the one function in the codebase that **does raise**:
  `FileNotFoundError` if Nmap is not installed. Writes
  `{output_dir}/nmap_{target}_{YYYYMMDD_HHMMSS}.xml` and returns its path. Uses `NMAP_SCAN_ARGS`
  or `NMAP_FAST_ARGS`, and appends `--script vulners --script-args vulners.mincvss=5.0`
  (plus `api_key=` if `VULNERS_API_KEY` is set) when the NSE script is present.

### `scanners/shodan_scan.py`

```python
def fetch_cvss_from_nvd(cve_id: str) -> float
def fetch_cvss_batch(cve_ids: list[str]) -> dict[str, float]
def parse_shodan_json(data: dict) -> dict
def lookup_host(ip_address)
def enrich_findings_with_shodan(findings, shodan_result)
def create_shodan_findings(shodan_result, host, max_cves=SHODAN_MAX_CVES)
```

- `fetch_cvss_from_nvd()` 🌐 — `services.nvd.nist.gov`, 8 s timeout. Prefers CVSS v3.1, then
  v3.0, then v2; **falls back to 6.5** on any failure. Cached in-process in `_nvd_cache`.
- `fetch_cvss_batch()` 🌐 — parallel fetch capped at **5 workers** to respect NVD's unauthenticated
  5-requests-per-30-seconds limit. Skips anything already cached.
- `parse_shodan_json()` — normalises an uploaded Shodan host record into the same dict shape
  `lookup_host()` returns, and tags it `source: "external_json"`. Handles `vulns` as either a list
  or a dict. **Raises `ValueError`** with a readable message if the payload has no `ip_str`/`ip`.
- `lookup_host()` 🌐🔑 — costs **1 Shodan credit per IP**. Returns `{"success": False, "error": …}`
  when `SHODAN_API_KEY` is unset or the API errors.
- `enrich_findings_with_shodan()` ⚠️🌐 — for findings whose port Shodan also observed: sets
  `exposure = INTERNET_FACING`, `evidence_strength = CORRELATED`, applies KEV/exploit status, and
  may raise `cvss_score` from NVD. Adds Shodan org/ASN/geo context to every finding's `raw_data`.
- `create_shodan_findings()` 🌐 — builds **standalone** findings (not merged): one per CVE up to
  `SHODAN_MAX_CVES` (10), plus one per risky observed port from a 12-entry table. All are
  `EXTERNAL` evidence and `INTERNET_FACING`.

### `scanners/nuclei_scan.py`

```python
def find_nuclei() -> str | None
def nuclei_available() -> bool
def parse_nuclei_jsonl(text_or_path: str) -> list[Finding]
def run_nuclei_scan(target: str, fast_mode: bool = False, timeout: int = 300) -> list[Finding]
def merge_nuclei_with_nmap(nmap_findings: list[Finding],
                           nuclei_findings: list[Finding]) -> list[Finding]
```

- `find_nuclei()` — cross-platform: `shutil.which("nuclei")` first, then `~/go/bin`,
  `C:\Program Files\Nuclei\`, `/usr/local/bin`, `/opt/homebrew/bin`.
- `parse_nuclei_jsonl()` — accepts either a file path or raw JSONL text. Severity maps to CVSS:
  `critical 9.5 · high 7.5 · medium 5.5 · low 3.0 · info 0.0`. Cross-references CISA KEV.
- `run_nuclei_scan()` 🌐 — subprocess with a 300 s default timeout. **Returns `[]` if the binary
  is absent** rather than raising.
- `merge_nuclei_with_nmap()` ⚠️ — correlates by `(host, port)`; upgrades matches to `CONFIRMED`.

### `scanners/openvas_parse.py`

```python
def parse_openvas_xml(xml_file: str) -> list[Finding]
def merge_openvas_with_nmap(nmap_findings: list[Finding],
                            openvas_findings: list[Finding]) -> list[Finding]
```

Handles both `<report><results>` and bare `<results>` document shapes. Extracts CVE refs and CVSS
from either the `<result>` or its `<nvt>`, and derives exploit status from CVSS plus the GVM
threat level.

### `scanners/zap_scan.py`

```python
def parse_zap_xml(xml_file: str) -> list[Finding]
def merge_zap_with_nmap(nmap_findings: list[Finding],
                        zap_findings: list[Finding]) -> list[Finding]
```

Web-layer findings only. Exposure is derived from the port and whether the site was HTTPS.

### `scanners/vulners_parse.py`

```python
def parse_vulners_from_nmap_xml(xml_file: str) -> list[Finding]
def merge_vulners_with_nmap(nmap_findings: list[Finding],
                            vulners_findings: list[Finding]) -> list[Finding]
```

Reads the NSE script output block already embedded in the Nmap XML — **no extra network call**.
Filters by `VULNERS_MIN_CVSS` (5.0) and `VULNERS_STANDALONE_MIN_CVSS` (7.0).

### `scanners/vulners_enrich.py`

```python
def has_public_exploit(cve_id: str) -> bool
def get_exploit_status_from_vulners(cve_id: str, current_status: ExploitStatus) -> ExploitStatus
```

🌐🔑 `vulners.com/api/v3/search/lucene/`, 6 s timeout, cached per process.
**Upgrade only:** never downgrades `ACTIVE_EXPLOITATION`, and no-ops silently without a key.

### `scanners/kev_lookup.py`

```python
def fetch_kev_catalog() -> dict[str, dict]
def is_kev(cve_id: str) -> bool
def get_kev_entry(cve_id: str) -> dict | None
```

🌐 The free CISA KEV JSON feed, 10 s timeout, cached in-process for the session. On failure the
cache becomes `{}` — every lookup then returns `False`/`None`, silently.

### `scanners/epss_scan.py`

```python
EPSS_PROMOTE_THRESHOLD = 0.50

def fetch_epss(cve_ids) -> dict
def enrich_findings_with_epss(findings: list, scores: dict | None = None) -> list
```

🌐 `api.first.org/data/v1/epss`, batched **100 CVEs per request**, 15 s timeout, no key needed.
`enrich_findings_with_epss()` ⚠️ attaches `epss_score`/`epss_percentile` and, at ≥ 0.50, promotes
`UNKNOWN`/`NO_EXPLOIT` to `PUBLIC_EXPLOIT`, setting `raw_data["epss_promoted"] = True`. Passing
`scores` explicitly bypasses the network — this is how the tests run offline.

### `scanners/dns_scan.py`

```python
def run_dns_scan(domain: str) -> list[Finding]
```

🌐 DNS over `dnspython`, 8 s lifetime per query. **Returns `[]` immediately for a bare IP.**
Produces findings for: missing SPF (5.3), multiple SPF records (4.0), `+all` (6.0), `~all` (3.5),
missing DMARC (6.5), `p=none` (4.5), no DKIM across 12 common selectors (4.0, `INFERRED`),
and no DNSSEC (3.0).

### `scanners/tls_scan.py`

```python
def run_tls_scan(domain: str, https_ports: list[int] | None = None) -> tuple[list[Finding], dict]
```

🌐 Direct TLS connections (8 s timeout, certificate verification disabled so an expired or
self-signed certificate can still be *inspected*), plus `crt.sh` for certificate-transparency
subdomain discovery. Returns `([], {"skipped": ...})` for a bare IP. Port 443 is always included.

### `scanners/breach_scan.py`

```python
def run_breach_scan(domain: str, ips: list[str]) -> tuple[list[Finding], dict]
```

🌐 LeakIX `/domain/{domain}` and `/host/{ip}`, 12 s timeout, no key required.
**Capped at the first 2 IPs** to avoid rate limiting. Event classification:
credential/secret leak → CVSS 9.5 + `ACTIVE_EXPLOITATION`; exposed database → 8.5 +
`ACTIVE_EXPLOITATION`; exposed `.git` → 7.5; exposed backup → 7.0; anything else → 6.0.

---

## `analysis/` — the reasoning layer

Pure and deterministic. No network calls anywhere except `brain_memory.ingest_kev()`.

### `analysis/schema.py`

Declares `Finding` plus `ExposureLevel`, `DataSensitivity`, `ExploitStatus`, `DealTier`,
`ScannerSource`, `EvidenceStrength`. Full reference: [DATA_MODEL.md](DATA_MODEL.md).

### `analysis/parser.py`

```python
def parse_nmap_xml(xml_file: str) -> list[Finding]
def analyze_nmap_file(xml_file: str) -> list[Finding]
```

Skips hosts that are not `up` and ports that are not `open`. Assigns a **flat CVSS of 3.5** —
Nmap confirms a service is open, not that it is vulnerable — and sets `evidence_strength =
CONFIRMED` (the port genuinely is open). Exposure is `PARTNER` for the eight services in
`SERVICE_EXPOSED`, else `INTERNAL`. Twelve services have curated description and remediation text.

### `analysis/triage.py`

```python
EXPOSURE_SCORES: dict        # INTERNET_FACING 100 · PARTNER 60 · INTERNAL 30 · UNKNOWN 50
SENSITIVITY_SCORES: dict     # CROWN_JEWEL 100 · REGULATED 85 · SENSITIVE 55 · LOW 20 · UNKNOWN 50
EXPLOIT_SCORES: dict         # ACTIVE_EXPLOITATION 100 · PUBLIC_EXPLOIT 65 · UNKNOWN 30 · NO_EXPLOIT 10
EVIDENCE_MULTIPLIERS: dict   # CONFIRMED 1.00 · CORRELATED 0.95 · UNKNOWN 0.90 · INFERRED 0.85 · EXTERNAL 0.80

def check_override_rules(finding: Finding) -> tuple[bool, str]
def calculate_base_score(finding: Finding) -> float
def apply_evidence_adjustment(score: float, finding: Finding) -> float
def calculate_score(finding: Finding) -> float
def score_to_tier(score: float) -> DealTier
def triage(finding: Finding) -> Finding
def triage_all(findings: list[Finding]) -> list[Finding]
```

`triage()` ⚠️ mutates and returns the same object. `triage_all()` returns a **new list sorted by
`risk_score` descending**. Override rules run before scoring and short-circuit to 100.

### `analysis/maturity.py`

```python
def score_domain(domain_key: str, answers: dict[str, int]) -> Optional[DomainScore]
def run_assessment(answers: dict[str, int], target: str = "") -> MaturityAssessment
def get_all_question_ids() -> list[str]
def get_domain_questions(domain_key: str) -> list[dict]
def get_all_domains() -> list[tuple[str, str]]
```

⚙️ Answers are clamped to 0–5. **Only answered questions contribute to the denominator**, so a
partially completed questionnaire is not penalised as if the unanswered questions scored zero.
The overall score weights all seven domains equally.

### `analysis/standards_compare.py`

```python
def compare_to_standard(assessment: MaturityAssessment) -> GapReport
def format_gap_summary(gap_report: GapReport) -> str
```

⚙️ Domains at `AT_TARGET` are excluded entirely. Each gap carries `catalog_key = f"{domain}_gap"`,
which is what the cost engine looks up.

### `analysis/day1.py`

```python
def is_remote_access(finding, cfg: Optional[dict] = None) -> bool
def assign_phase(finding, cfg: Optional[dict] = None) -> str
def build_roadmap(findings: list, gap_report=None, cfg: Optional[dict] = None) -> dict
def build_pillars(findings: list, assessment=None, cfg: Optional[dict] = None) -> list[Pillar]
def build_gates(findings: list, assessment=None, cfg: Optional[dict] = None) -> list[IntegrationGate]
def recommend_connectivity(findings: list, assessment=None,
                           gates: Optional[list[IntegrationGate]] = None,
                           cfg: Optional[dict] = None) -> tuple[str, str, str]
def build_day1_blueprint(findings: list, assessment=None, gap_report=None,
                         target: str = "") -> Day1Blueprint
```

⚙️ All behaviour is driven by `config/day1_blueprint.yaml`.

- `assign_phase()` walks the ordered `phase_rules` and returns the **first** match.
- `recommend_connectivity()` walks `["integrate", "federate", "broker", "isolate"]` and picks the
  **first tier whose gate passes** — the most integrated posture the evidence justifies. `isolate`
  is the floor and always passes. The returned rationale names the blockers for the next tier up.
- `build_day1_blueprint()` degrades gracefully: with findings but no questionnaire it still
  produces posture, roadmap and the remote-access pillar, marking the other two "not assessed".

### `analysis/attack_brain.py`

```python
def analyze_attack_paths(findings: list, target: str = "") -> AttackPlan
def build_mindmap_svg(plan: AttackPlan, target: str = "") -> str
```

Offline MITRE ATT&CK expert system — no LLM, no network. Maps each finding to techniques by
service and port (web → `T1190`, SSH → `T1110`/`T1133`, RDP → `T1133`/`T1110`, SMB → `T1210`,
FTP/Telnet → `T1078`, databases → `T1190`, fallback → `T1595`). Builds four mind-map stages
(Entry points, Exploitation, Lateral movement, Impact), each capped at four children.
`build_mindmap_svg()` returns a raw SVG string for `rx.html`, sized 1000×820 with radii 205/322.

### `analysis/attack_graph.py`

```python
def analyze_graph(findings: list, target: str = "") -> GraphReport
```

Builds a `networkx.DiGraph`: `INTERNET → host → host:port service`, plus pivot edges from every
internet-facing host to every internal host. Computes blast radius via `descendants()`,
chokepoints by node-removal impact tie-broken on betweenness centrality (top 6), and shortest
crown-jewel paths (top 4, crown jewels before regulated).
**Degrades to an empty `GraphReport` if networkx is not importable.**

### `analysis/brain_memory.py`

```python
class BrainMemory:
    VERSION = 1
    def __init__(self, root: str | None = None)
    def recall(self, findings: list, plan) -> tuple[str, list[BrainInsight]]
    def learn_from_scan(self, findings: list, plan, target: str = "") -> None
    def stats(self) -> BrainStats
    def top_techniques(self, limit: int = 6) -> list[BrainInsight]
    def ingest_kev(self) -> tuple[bool, str, int]
    def export_seed(self, dest: str | None = None) -> str
```

💾 Root resolution order: constructor argument → `$REDFLAG_BRAIN_DIR` → `~/RedFlag-Brain`.
`recall()` must be called **before** `learn_from_scan()`. `ingest_kev()` 🌐 is the only network
call in `analysis/`. `export_seed()` strips the `targets` map before writing.
`_save()` and `_write_vault()` swallow all exceptions so the brain can never break a scan.
Full detail: [BRAIN_KNOWLEDGE_BASE.md](BRAIN_KNOWLEDGE_BASE.md).

### `analysis/parsers/excel_assets.py`

```python
def parse_asset_excel(excel_file: str) -> dict[str, DataSensitivity]
def apply_sensitivity_to_findings(findings: list[Finding],
                                  asset_map: dict[str, DataSensitivity]) -> list[Finding]
```

Column detection is case-insensitive: host column from `ip`/`host`/`ip_address`/`hostname`/
`address`; sensitivity column from any name containing `sensitiv` or `classif`, or exactly `tier`.
**Raises `ValueError`** if either column is missing.
`apply_sensitivity_to_findings()` ⚠️ **only upgrades findings that are currently `UNKNOWN`** — it
never downgrades a classification.

### `analysis/graph_builder.py`

**Legacy.** Superseded by `attack_brain.py` and `attack_graph.py`; not imported anywhere in the
codebase. See [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §3.

---

## `cost/` — the costing engine

### `cost/catalog.py`

```python
def lookup_finding(finding) -> CostLineItem
def lookup_maturity_gap(gap) -> CostLineItem
```

⚙️ Resolution order for a finding: **CVE override → service entry → deal-tier fallback →
`default`**. Anything resolving to `default` is flagged `ZERO_ESTIMATE` for human review.

### `cost/estimator.py`

```python
def estimate_from_findings(findings: list) -> list[CostLineItem]
def estimate_from_gaps(gap_report) -> list[CostLineItem]
```

Skips `UNSCORED` findings. Always adds the `DEAL_KILLER_ITEM` review flag to deal-killer items.

### `cost/deduplicator.py`

```python
def deduplicate(items: list[CostLineItem]) -> list[CostLineItem]
```

Buckets on `catalog_key::category`. Merged cost is deliberately **conservative**: `min(low)`,
`max(base)`, `max(high)`. Items keyed `default` or already flagged `ZERO_ESTIMATE` are never
merged — each needs individual scoping. Merged items gain the `DUPLICATE` flag, plus
`HIGH_VARIANCE` if the spread exceeds 3×.

### `cost/scenario_engine.py`

```python
def build_scenarios(items: list[CostLineItem]) -> list[CostScenario]
```

Returns exactly three scenarios. `MIXED` CapEx/OpEx items split 50/50.

### `cost/day1_costing.py`

```python
def estimate_from_day1(blueprint, headcount=None, catalog: dict | None = None,
                       overrides: dict | None = None) -> list[CostLineItem]
def cost_all_models(headcount=None, catalog: dict | None = None,
                    overrides: dict | None = None) -> dict[str, CostTriple]
def compute_accuracy(items: list, headcount_assumed: bool = False,
                     catalog: dict | None = None) -> tuple[float, float]
```

⚙️ Produces `bucket="integration"` items, kept separate from remediation and **never deduplicated
against it**. Six scale modes: `fixed`, `per_user`, `per_user_year`, `per_user_month`,
`per_priv_user_year`, `tsa_runrate`. `overrides` maps an item key to a firm vendor quote, which
collapses the triple to a single figure and pins confidence to `HIGH`.
`cost_all_models()` prices every rung so the UI can show the cost of integrating faster.

### `cost/simulation.py`

```python
def estimate_uncertainty(items, headcount_assumed: bool = False) -> Uncertainty
```

Closed-form, deterministic — **no Monte Carlo sampling**. Each item is a triangular distribution
widened by its confidence (`high 1.0 · medium 1.25 · low 1.6`). Items aggregate with **partial
correlation (0.35)**, so independent errors partly cancel without the band becoming
unrealistically tight. Yields a P10/P50/P90 80% interval (z = 1.2816), widened by 1.15× when the
headcount was assumed, and clamped to a ±8–55% band.

### `cost/rollup.py`

```python
def build_rollup(items: list[CostLineItem], target: str = "",
                 headcount_assumed: bool = False) -> CostRollup
def run_cost_pipeline(findings: list, gap_report=None, target: str = "",
                      include_maturity_gaps: bool = True, blueprint=None,
                      include_integration: bool = True, headcount=None,
                      overrides: dict | None = None) -> CostRollup
```

`run_cost_pipeline()` is **the entry point** to the cost engine: estimate → deduplicate →
(optionally) add the Day-1 integration budget → scenarios → rollup.

### `cost/exporters.py`

```python
def export_rollup_csv(rollup, output_path: Optional[str] = None) -> bytes
def export_rollup_xlsx(rollup, output_path: Optional[str] = None) -> bytes
```

💾 when `output_path` is given; both always return the bytes.

---

## `narrative/` — deterministic prose

### `narrative/blocks.py`

```python
def select_block(section: str, context: dict) -> Optional[str]
def select_all_blocks(section: str, context: dict) -> list[str]
def list_sections() -> list[str]
```

⚙️ Blocks are sorted by `priority` ascending; **the first whose `when` conditions all match
wins**. `{variable}` placeholders are substituted from the context; unknown placeholders are left
untouched. Floats ≥ 1000 format with thousands separators, otherwise to one decimal place.

### `narrative/engine.py`

```python
def build_executive_summary(findings: list, target: str = "",
                            assessment=None, rollup=None) -> str
def build_maturity_narrative(assessment) -> str
def build_cost_narrative(rollup) -> str
def build_day1_narrative(blueprint) -> str
def build_finding_narrative(finding) -> str
def build_remediation_priority(finding) -> str
def build_full_context(findings: list, target: str = "",
                       assessment=None, rollup=None) -> dict
```

Each builder assembles a context dict from the engine objects, then calls `select_block()`.
Same input, same sentence, every time — no randomness, no model.

### `narrative/report_builder.py`

```python
def build_report(findings: list, target: str = "", assessment=None, rollup=None) -> dict
```

---

## `reports/` — serialisation

### `reports/generator.py`

```python
def findings_to_dataframe(findings) -> pandas.DataFrame
def export_findings_csv(findings, output_dir="data/results") -> str
```

💾 The DataFrame has 17 columns, with every enum rendered as `Title Case` text.

### `reports/pdf_report.py`

```python
def generate_pdf_report(findings: list, target: str, resolved_ip: str,
                        scan_date: str | None = None,
                        output_dir: str = "data/results") -> str
def generate_day1_section(pdf_path: str, blueprint, narrative_text: str = "") -> str
def generate_cost_section(pdf_path: str, rollup, narrative_text: str = "") -> str
```

💾 fpdf2. The two `generate_*_section` functions **append to an existing PDF path**. All text
passes through `_safe()`, which strips characters outside the embedded font — fpdf2 raises on an
unencodable glyph, so new symbols must be checked before use.

> **Gap:** `generate_cost_section()` covers the remediation bucket only. The Day-1 integration
> budget, the ladder costs and the accuracy readout are shown in the UI but do not appear in the
> cost PDF. Tracked in
> [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §3.

---

## `config/` — configuration

### `config/__init__.py`

```python
WEIGHT_CVSS = 0.25; WEIGHT_EXPOSURE = 0.25
WEIGHT_SENSITIVITY = 0.20; WEIGHT_EXPLOIT = 0.30
TIER_THRESHOLD_CRITICAL = 75; TIER_THRESHOLD_MODERATE = 50
SHODAN_MAX_CVES = 10
VULNERS_MIN_CVSS = 5.0; VULNERS_STANDALONE_MIN_CVSS = 7.0
NMAP_SCAN_ARGS = "-sV --open -T4 --max-retries 2"
NMAP_FAST_ARGS = "-sV --open -T4 --top-ports 200 --version-intensity 3 --max-retries 1"
```

Also re-exports the loader helpers so `from config import get_pricing_benchmarks` works.

### `config/loader.py`

```python
def reload_all() -> None
def get_maturity_questions() -> dict
def get_corporate_standard() -> dict
def get_pricing_benchmarks() -> dict
def get_remediation_catalog() -> dict
def get_narrative_blocks() -> dict
def get_day1_blueprint() -> dict
def get_day1_cost_catalog() -> dict
def get_labour_rate(role: str, scenario: str = "base") -> float
def get_effort_hours(task_key: str, scenario: str = "base") -> float
def get_tool_cost(tool_key: str, scenario: str = "base") -> float
def get_domain_standard(domain: str) -> dict
def get_overall_deal_blocker_threshold() -> float
```

⚙️ Every file is loaded once and cached for the process lifetime. **A YAML edit needs an app
restart** — or `reload_all()`, which exists for the tests.

---

## `redflag_ui/` — presentation

### `redflag_ui/state.py`

```python
def build_view(findings: list, target: str,
               assessment=None, gap_report=None) -> dict      # pure; testable

class RedFlagState(rx.State):
    def run_scan(self)                                        # the pipeline (generator; yields to update the UI)
    async def upload_shodan|openvas|zap|nuclei|asset(self, files)
    def clear_shodan|openvas|zap|nuclei|asset(self)
    def submit_maturity(self, form_data: dict)
    def reset_maturity(self)
    def refresh_threat_intel(self)                            # → BrainMemory.ingest_kev()
    def set_cost_scenario|set_cost_scope|toggle_cost_maturity(self, ...)
    def set_cost_headcount(self, value)
    def apply_quotes(self, form_data: dict) / clear_quotes(self)
    def download_csv|download_pdf|download_day1_pdf|download_cost_pdf(self)
```

`build_view()` is a **module-level pure function**, which is what makes the view-model layer
testable without Reflex.

Backend-only vars (leading underscore, never serialised to the browser): `_findings`,
`_assessment`, `_gap_report`, `_rollup`, `_staged`, `_resolved_ip`.

`_SCAN_DIR = os.path.join(tempfile.gettempdir(), "redflag_scans")` — Nmap output **must** stay
outside the worktree; see [KNOWLEDGE_TRANSFER.md](../handover/KNOWLEDGE_TRANSFER.md) §2.

### `redflag_ui/redflag_ui.py`

Constructs `rx.App` and registers nine routes: `/`, `/findings`, `/attack`, `/maturity`, `/day1`,
`/cost`, `/export`, `/privacy`, `/contact`. Every page uses `on_load=RedFlagState.ensure_loaded`.

---

## Related documents

- [DATA_MODEL.md](DATA_MODEL.md) — the objects these functions operate on
- [ARCHITECTURE.md](ARCHITECTURE.md) — how they compose
- [INTEGRATIONS.md](INTEGRATIONS.md) — the endpoints behind every 🌐
- [CONFIGURATION.md](CONFIGURATION.md) — the YAML behind every ⚙️
