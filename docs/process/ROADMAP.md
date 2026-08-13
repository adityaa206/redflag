# Roadmap

Where RedFlag could go if the project continues.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> **Scope.** This document records **direction** — the capabilities the product could acquire and
> the rationale for each. Concrete tasks, including defects and technical debt with file paths,
> are recorded separately in
> [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md).

---

## Completed

Everything below shipped and is in the handover build.

| Capability | Landed |
|---|---|
| Multi-scanner fusion with correlation merge (Nmap, Shodan, OpenVAS, ZAP, Nuclei, Vulners) | 0.2.0 – 0.8.0 |
| Weighted risk scoring with evidence-strength multiplier and deal-killer overrides | 0.1.0 |
| Maturity assessment: 23 questions, 7 domains, corporate-standard comparison | 0.3.0 |
| Cost engine: catalogue, dedup, low/base/high scenarios, CapEx/OpEx, review gate | 0.3.0 |
| Deterministic YAML narrative engine | 0.3.0 |
| DNS, TLS/crt.sh and breach scanners | 0.4.0 |
| Attacker-brain: MITRE ATT&CK kill-chain and radial mind-map | 0.5.0 |
| Self-improving offline knowledge base with an Obsidian vault | 0.5.0 |
| Day-1 Safe Harbor Blueprint: ladder, gates, pillars, P0–P3 roadmap | 0.6.0 |
| Reflex UI migration with zero engine changes | 0.7.0 |
| Sanitised brain seed so fresh clones start pre-loaded | 0.7.0 |
| EPSS exploitation probability with status promotion | 0.8.0 |
| networkx attack-graph: chokepoints, blast radius, crown-jewel paths | 0.8.0 |
| Day-1 integration budget with variance-based confidence interval and vendor quotes | 0.9.0 |
| Complete documentation set | 1.0.0 |

---

## Near term — finish what is started

Small, well-defined, and each closes a visible gap. Roughly a week in total.

### 1. Repository hygiene *(hours)*

Add the missing `LICENSE`; commit `tests/fixtures/mock_nuclei.jsonl`; correct the README's test
count from 128 to 143; delete the dead `analysis/graph_builder.py` and root `config.py`, porting
the scoring-weight rationale comments into `config/__init__.py` first.

### 2. Integration budget in the cost PDF *(days)*

`reports/pdf_report.generate_cost_section()` prices remediation only. The `CostRollup` already
carries `integration_total`, `accuracy_pct` and the P10/P50/P90 interval — this is a reporting
gap, not a modelling one, and it is the one place the UI is ahead of the exports.

### 3. Log swallowed scanner exceptions *(hours)*

`run_scan` wraps each scanner in `except Exception: pass`. The resilience is right; the silence is
not. Log the exception and surface a "some sources were unavailable" hint in the notice bar. This
also mitigates the biggest interpretive risk in the product — a clean report produced by dead
feeds looking identical to a clean report produced by live ones.

### 4. An NVD API key *(hours)*

Free to obtain and raises the rate limit substantially above the unauthenticated 5 requests / 30 s
that currently makes CVSS enrichment the pipeline's slowest step. **The highest
value-per-hour item on this list**, and it stays inside
[ADR-0003](adr/0003-free-no-paid-api.md).

### 5. Tests for `build_view()` and `export_seed()` *(days)*

`build_view()` is already a pure module-level function; a handful of tests would cover a large
surface. `export_seed()` is the six-line boundary between local memory and published data, and it
is currently unguarded — assert that `targets` is stripped and that nothing else names a host.

### 6. Continuous integration *(hours)*

A GitHub Actions workflow running `pytest tests/ -v` on push. The suite needs no network, no
secrets and no binaries, so it works in a stock runner with only `pip install -r requirements.txt`.

---

## Medium term — the M&A product

These are the features that would most change what RedFlag is worth to a deal team.

### 7. Compliance gap mapping — **highest business value**

Map findings and maturity domains onto ISO 27001, NIST CSF, SOC 2, GDPR and PCI-DSS control
families.

*Why it matters:* deal teams and their counsel think in frameworks. "Seven findings map to
ISO 27001 A.9 Access Control, three of which are deal-blocking" is a sentence that goes straight
into a diligence report. It also turns the maturity questionnaire's seven domains from an internal
construct into something an auditor recognises.

*Why it fits:* the maturity domains already align closely with control families. This is largely a
new YAML plus a view — the same pattern as every other config-driven feature.

### 8. Multi-target comparison

Assess several targets and compare risk, maturity and cost side by side.

*Why it matters:* an acquirer usually evaluates a shortlist. Comparative risk is a different and
often more useful question than absolute risk.

*Why it is hard:* **the only item on this roadmap that forces an architectural change.** RedFlag
holds one assessment in memory per session and persists nothing. This needs a real store, an
identity for each assessment, and a decision about how long results are retained — which
immediately engages the retention concerns in
[SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) §6. Do this last.

### 9. Secret scanning

Integrate trufflehog to scan the target's public repositories for leaked credentials.

*Why it matters:* leaked credentials in a public repository are among the highest-severity, most
directly exploitable findings possible — and squarely a deal-killer class.

*Why it fits:* it slots into the existing scanner contract exactly — produce `Finding` objects,
never raise. A `SECRETS` member on `ScannerSource` and a new module.

*Caution:* scanning a target's public repositories is OSINT, but it should still be inside the
engagement's scope. See [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) §4.

### 10. Multi-host Shodan

`lookup_host()` handles one IP. Shodan's search API supports `net:` queries for a whole range.

*Caution:* credit cost scales per IP, which pushes against
[ADR-0003](adr/0003-free-no-paid-api.md). Make it opt-in with a clear credit estimate before it
runs.

### 11. UI test coverage

`redflag_ui/` has no tests at all — the largest single gap in the suite. Item 5 covers
`build_view()`; this is the rest: upload handling, the `run_scan` orchestration, and page
rendering.

---

## Longer term — direction

### 12. Optional LLM narrative layer

The one roadmap item that touches a settled decision. If built, it must be **additive and clearly
labelled** — never replacing or altering a deterministic output. Free-tier or local only, per
[ADR-0003](adr/0003-free-no-paid-api.md).

Read [ADR-0001](adr/0001-no-llm.md) before starting. The reasons for excluding an LLM —
reproducibility, auditability and the fact that these documents inform a commercial decision —
have not changed. A generative layer over the brain's retrieval is the defensible version;
regenerating the executive summary is not.

### 13. Docker Compose

One-command startup. Complicated by two things: Nmap's binary requirement (and the Nmap Public
Source License's restrictions on redistribution — see
[LICENSES_AND_ATTRIBUTION.md](../legal/LICENSES_AND_ATTRIBUTION.md) §4), and Reflex's Node
frontend build. Worth doing for reproducibility, but neither trivial nor purely technical.

### 14. Continuous monitoring

RedFlag is point-in-time. A deal takes months, and the target's posture moves. Scheduled re-scans
with change detection — *"three new internet-facing services since the last assessment"* — would
be genuinely valuable during a live deal, and would give the brain a much richer corpus.

### 15. Remediation verification

Re-scan after remediation and prove which findings are actually closed. Turns RedFlag from a
diligence tool into a post-close integration tool, and gives the P0–P3 roadmap a feedback loop.

### 16. Recency weighting in the brain

Today the brain never forgets and never ages knowledge — a CVE seen a year ago carries the same
weight as one seen last week. Whether that is right is an open design question flagged in
[ADR-0005](adr/0005-offline-brain-learn-by-remembering.md). Worth answering before the corpus gets
large enough that it matters.

---

## Suggested priority

| Priority | Items | Rationale |
|---|---|---|
| **Do first** | 1, 3, 4, 6 | Hours each; each removes a real defect or risk |
| **Do next** | 2, 5 | Close the two gaps where the product is ahead of its exports and its tests |
| **Highest value** | 7 — compliance mapping | Changes what the tool is worth to its actual audience |
| **High value, high cost** | 8 — multi-target | Forces persistence; plan it properly |
| **Opportunistic** | 9, 10, 11 | Well-scoped, independent, each fits an existing pattern |
| **Only with intent** | 12 — LLM layer | Re-read [ADR-0001](adr/0001-no-llm.md) first |
| **Someday** | 13, 14, 15, 16 | Direction rather than plan |

---

## Related documents

- [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) — the concrete task list
- [adr/](adr/README.md) — the decisions several of these items would touch
- [CHANGELOG.md](../../CHANGELOG.md) — what has already shipped
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — the gaps several of these would close
- [TEST_PLAN.md](../testing/TEST_PLAN.md) §7 — the coverage gaps behind items 5 and 11
