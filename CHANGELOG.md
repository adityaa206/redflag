# Changelog

All notable changes to RedFlag are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on version history.** The repository has **no git tags and no formal releases**. The
> entries below are reconstructed from the commit history on `main` and grouped into dated
> milestones. Only the `1.0.0 — Handover` entry represents a deliberate version boundary; the
> earlier headings are development milestones, not published releases.
>
> ⚠️ TODO(Adi): if this project is to be versioned properly going forward, tag the handover commit
> as `v1.0.0` (`git tag -a v1.0.0 -m "Handover release"`).

---

## [Unreleased]

### Added
- Complete documentation set under `docs/` — handover, technical, operations, user, testing, legal
  and process groups, plus eight Architecture Decision Records.
- Root community files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, this changelog.
- `tools/` — `mdpdf.py` and `build_docs_pdf.py`, which render `docs/` into a bookmarked PDF and
  one PDF per document.
- Module docstrings and explanatory comments across `analysis/`, `scanners/`, `reports/` and
  `config/`. No behaviour change.
- `tests/fixtures/mock_nuclei.jsonl`, previously present on disk but absent from version control.

### Fixed
- **`.gitignore` no longer excludes the documentation.** A blanket `*.md` rule silently excluded
  every Markdown file; `README.md` predated the rule and stayed tracked, which masked the effect.
  Explicit negations now version `docs/` and the community files while leaving agent and scratch
  notes local.
- `README.md` stated 128 tests in three places. The suite contains **143**.

### Removed
- `lib/` — 2.7 MB of vendored JavaScript from the superseded pyvis attack-graph implementation,
  with no remaining code references.

### Known issues
- **No `LICENSE` file exists** although `README.md` declares MIT. Requires the copyright holder's
  name — see [docs/legal/LICENSES_AND_ATTRIBUTION.md](docs/legal/LICENSES_AND_ATTRIBUTION.md).
- The README's mock-fixture table omits `mock_nuclei.jsonl`.
- The README's Scoring Reference lists three deal-killer override rules; the code implements four.

---

## [1.0.0] — 2026-07-27 — Handover

The state of the project at handover: a complete M&A cybersecurity due-diligence platform with
fourteen integrations, five analysis engines, a two-bucket cost model, and 143 passing tests.

### Summary of capabilities

- **Collection** — Nmap, Shodan, Nuclei, OpenVAS, ZAP, Vulners NSE, DNS, TLS/crt.sh, LeakIX,
  Excel asset inventory
- **Enrichment** — CISA KEV, NVD CVSS, Vulners API, FIRST.org EPSS
- **Analysis** — weighted risk scoring, 7-domain maturity assessment, Day-1 Safe Harbor Blueprint,
  MITRE ATT&CK attacker-brain, networkx attack graph, self-improving knowledge base
- **Costing** — remediation and integration budgets, low/base/high scenarios, CapEx/OpEx split,
  variance-based 80% confidence interval, vendor-quote overrides
- **Output** — deterministic narrative, CSV, three PDF reports
- **Interface** — Reflex web application, nine routed pages

---

## [0.9.0] — 2026-07-02 — Day-1 integration budget

### Added
- **Day-1 integration budget** (`cost/day1_costing.py`, `config/day1_cost_catalog.yaml`) — prices
  the recommended connectivity model as a separate `integration` cost bucket, with sourced 2026
  benchmark pricing citing a real source per line item.
- **Ladder costing** — `cost_all_models()` prices every rung of the connectivity ladder, so the UI
  can show what integrating faster would cost.
- **Estimate accuracy readout** — a variance-based 80% confidence interval (P10/P50/P90) in
  `cost/simulation.py`, replacing naive band-averaging. Triangular distributions widened by
  confidence, aggregated with partial correlation.
- **Vendor-quote overrides** — a firm quote replaces the benchmark for a line item, pins it to
  `HIGH` confidence, collapses its range to a single figure, and clears its high-variance flag.
- Headcount input driving per-user integration costs; an assumed headcount widens the accuracy
  band by 15%.

### Changed
- `CostRollup` gained `remediation_total`, `integration_total`, `accuracy_band_pct`,
  `accuracy_pct` and the `ci_low`/`ci_p50`/`ci_high` interval.
- `CostLineItem` gained a `bucket` field (`"remediation"` | `"integration"`).
- `RemediationCategory` gained an `INTEGRATION` member.

*Commits: `764d9b4`, `25ebe58`, `a0f982a`*

---

## [0.8.0] — 2026-06-30 — Nuclei, EPSS and graph analytics

### Added
- **Nuclei integration** (`scanners/nuclei_scan.py`) — runs the local binary if present, or ingests
  uploaded JSONL. Correlation-merges into the Nmap layer. Degrades to `[]` when absent.
- **EPSS scoring** (`scanners/epss_scan.py`) — FIRST.org exploitation probability, batched 100 CVEs
  per request, no API key. A score of ≥ 0.50 promotes an unknown exploit status to `PUBLIC_EXPLOIT`
  ([ADR-0007](docs/process/adr/0007-epss-exploit-promotion.md)).
- **Attack-graph analytics** (`analysis/attack_graph.py`) — networkx model of the estate producing
  chokepoints ranked by removal impact, blast radius, and shortest paths to crown-jewel data.
- `epss_score` and `epss_percentile` fields on `Finding`.
- A fifth upload slot for Nuclei JSONL.

### Changed
- `networkx` added to `requirements.txt`.
- README data-flow diagram updated to include Nuclei, EPSS and the graph.

*Commits: `55b5150`, `2180e2c`*

---

## [0.7.0] — 2026-06-29 — Migration to Reflex

The largest structural change in the project's history.

### Added
- **Reflex UI** (`redflag_ui/`) — nine routed pages, `RedFlagState` with view-model flattening,
  `assets/redflag.css` implementing the "Executive Editorial / emerald" design.
- **Sanitised brain seed** (`analysis/brain_seed/brain.json`) — a fresh clone bootstraps
  pre-loaded rather than empty. `export_seed()` strips the `targets` map so publishing it never
  reveals who was scanned.

### Removed
- **Streamlit `app.py`** and all Streamlit dependencies (`streamlit`, `plotly`, `pyvis`).
- The Streamlit UI test suite — **not replaced**, leaving `redflag_ui/` without coverage.

### Notes
- **The migration required zero changes to any engine.** `analysis/`, `cost/`, `narrative/`,
  `reports/` and `scanners/` were untouched — see
  [ADR-0004](docs/process/adr/0004-reflex-ui-framework.md).
- Introduced the constraint that runtime writes must stay **outside** the worktree: Nmap output to
  `%TEMP%/redflag_scans`, the brain to `~/RedFlag-Brain`. A write inside the tree trips Reflex's
  file-watcher and resets backend state mid-scan.

*Commits: `23774bc`, `bf0d606`, `ece88d9`, `64c31c7`*

---

## [0.6.0] — 2026-06-24 — Day-1 Safe Harbor Blueprint

### Added
- **Day-1 engine** (`analysis/day1.py`, `config/day1_blueprint.yaml`):
  - A four-rung connectivity ladder — Isolate → Broker → Federate → Integrate — with cited
    industry sources per model.
  - Tier entry gates with `no_finding` and `maturity_min` criterion types. The engine recommends
    the **highest tier whose gate passes**.
  - Three review pillars (Identity Sources, Network Boundaries, Remote Access Pathways) with RAG
    status and status-keyed recommendations.
  - A P0–P3 fix-first roadmap driven by ordered, first-match phase rules.
  - Remote-access pathway detection across 16 service names and 15 ports.
- `build_day1_narrative()` in the narrative engine.
- A Day-1 PDF report section.

*Commit: `f6329fd`*

---

## [0.5.0] — 2026-06-08 to 2026-06-15 — Attack path and UI iteration

### Added
- **Attacker-brain** (`analysis/attack_brain.py`) — an offline MITRE ATT&CK expert system mapping
  findings to techniques, chaining them into a kill-chain, and rendering a radial mind-map as SVG.
  No LLM, no network ([ADR-0001](docs/process/adr/0001-no-llm.md)).
- **Brain memory** (`analysis/brain_memory.py`) — a persistent knowledge base that recalls before
  it learns, and writes an Obsidian-compatible vault
  ([ADR-0005](docs/process/adr/0005-offline-brain-learn-by-remembering.md)).
- Attack Path tab.

### Changed
- Design System v5 (ULTRAVIOLET) theme revamp.
- Fixed a raw-HTML rendering bug on the Findings view; removed deprecated API usage.
- Corrected the Python version floor; dropped unused dependencies.

*Commits: `35206a3`, `6fb3b11`, `22add93`, `b8222bb`, `a53bf12`*

---

## [0.4.0] — 2026-06-05 — Phase 1 scanners

### Added
- **DNS/email security scanner** — SPF, DMARC, DKIM (12 common selectors) and DNSSEC checks, each
  gap becoming a scored finding.
- **TLS certificate health scanner** — expiry, weak TLS versions, and crt.sh certificate-
  transparency subdomain discovery.
- **Breach exposure scanner** — LeakIX domain and host lookup, classifying credential leaks and
  exposed databases as actively exploited.
- **What-If simulator** for the cost model.

*Commit: `774e49d`*

---

## [0.3.0] — 2026-05-29 — Maturity, cost and narrative engines

### Added
- **Maturity assessment** (`analysis/maturity.py`) — 23 questions across 7 domains, weighted
  scoring, with only answered questions counting toward a domain score.
- **Standards comparison** (`analysis/standards_compare.py`) — gap report against a configurable
  corporate acquisition standard.
- **Cost engine** (`cost/`) — catalogue → estimator → deduplicator → scenario engine → rollup, with
  low/base/high triples, CapEx/OpEx split and a human-review gate.
- **Narrative engine** (`narrative/`) — deterministic, YAML-backed template blocks
  ([ADR-0002](docs/process/adr/0002-deterministic-yaml-narrative.md)).
- Config YAMLs: `maturity_questions`, `corporate_standard`, `pricing_benchmarks`,
  `remediation_catalog`, `narrative_blocks`.

*Commit: `51cf3cd`*

---

## [0.2.0] — 2026-05-25 to 2026-05-28 — Scanner pipeline

### Added
- **Vulners NSE** parsing from Nmap XML, with optional API-key support.
- **OpenVAS/GVM XML** and **OWASP ZAP XML** parsing with correlation merge into the Nmap layer
  ([ADR-0008](docs/process/adr/0008-uploads-correlate-not-replace.md)).
- **PDF report** generation via fpdf2.
- **Configuration centralisation** into `config/`.
- Comprehensive README.

### Fixed
- `FPDFUnicodeEncodingException` — non-ASCII characters are now stripped before PDF output.
- Vulners NSE pipeline status now distinguishes "installed" from "not installed".

### Changed
- `CLAUDE.md` removed from tracking.

*Commits: `eb4cecc`, `f4052fa`, `4bdbe07`, `dbd2607`, `4307768`, `a8a844f`*

---

## [0.1.0] — 2026-05-25 — Initial commit

### Added
- The `Finding` Pydantic model and all enums (`analysis/schema.py`).
- Nmap XML parsing (`analysis/parser.py`).
- **Weighted risk scoring** with an evidence-strength multiplier and deal-killer overrides
  (`analysis/triage.py`) — [ADR-0006](docs/process/adr/0006-evidence-strength-multiplier.md).
- Shodan integration with CISA KEV cross-reference and NVD CVSS lookup.
- CSV export.

*Commit: `72bb001`*

---

## Related documents

- [docs/handover/PROJECT_REPORT.md](docs/handover/PROJECT_REPORT.md) §9 — the timeline in narrative form
- [docs/process/ROADMAP.md](docs/process/ROADMAP.md) — what comes next
- [docs/process/adr/](docs/process/adr/README.md) — why the big changes were made
- [docs/handover/KNOWN_ISSUES_AND_BACKLOG.md](docs/handover/KNOWN_ISSUES_AND_BACKLOG.md) — outstanding work
