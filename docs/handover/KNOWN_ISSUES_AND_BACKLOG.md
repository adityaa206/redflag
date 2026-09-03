# Known Issues & Backlog

Outstanding defects, unbuilt features, technical debt, and a suggested order of work.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Known defects

Each is verified against the code. None prevents a scan from running.

### 1.1 `LICENSE` file was missing — resolved

`README.md` stated *"MIT — see LICENSE for details"* and linked to `LICENSE`, but no such file
was present, which left the repository strictly **all rights reserved** — a licence claim with no
licence text is ambiguous rather than permissive. A standard MIT `LICENSE` is now committed at the
repository root and matches the README's declaration. Recorded in
[LICENSES_AND_ATTRIBUTION.md](../legal/LICENSES_AND_ATTRIBUTION.md) §1.

### 1.2 The README's test count was stale — resolved

`README.md` stated **128 passing tests** in three places: the badge, the architecture tree and
the "Running Tests" section. The suite contains **143 tests**, all passing. All three references
now state 143. Recorded in [TEST_PLAN.md](../testing/TEST_PLAN.md).

### 1.3 `.gitignore` excluded the entire documentation set — resolved

`.gitignore` contained a blanket `*.md` rule. Because `README.md` was committed before that rule
landed, git kept tracking it, which masked the problem — but **any new Markdown file was silently
ignored**, including this entire `docs/` tree, `CONTRIBUTING.md`, `SECURITY.md` and
`CHANGELOG.md`.

Explicit negations now version the published documentation and the root community files, while
agent and scratch notes remain local. The whole `docs/` tree, the community files and `LICENSE`
are tracked; anything generated stays out, with one deliberate exception —
`docs/RedFlag_Documentation.pdf`, the rendered book, is versioned so it can be read without
building it.

### 1.4 `tests/fixtures/mock_nuclei.jsonl` was untracked — resolved

The Nuclei mock fixture (4.2 KB) was present on disk but absent from version control, so a fresh
clone could not reproduce the documented Nuclei upload workflow. It is now committed alongside the
OpenVAS and ZAP mocks.

### 1.5 The README fixture table omitted the Nuclei mock — resolved

`README.md` → *Using the Mock Data Files* listed `mock_openvas.xml`, `mock_zap.xml` and
`sample_assessment.json`, but not `mock_nuclei.jsonl`. The table now lists all four. Also
documented in [USER_GUIDE.md](../user/USER_GUIDE.md).

### 1.6 The README documented three deal-killer override rules — resolved

`analysis/triage.py` → `check_override_rules()` implements **four**; the README's Scoring
Reference listed three, omitting the manual analyst flag that fires when `override_reason`
contains `"active compromise"`. The README table now lists all four. The full set is documented in
[RESULTS_INTERPRETATION.md](../user/RESULTS_INTERPRETATION.md) §3.

---

## 2. Incomplete features

From the README roadmap, unchecked items — none are started.

| Feature | Notes |
|---|---|
| **Free-tier LLM narrative layer over the brain** | Explicitly optional and additive. Must not replace the deterministic engine — see [ADR-0001](../process/adr/0001-no-llm.md) and [ADR-0002](../process/adr/0002-deterministic-yaml-narrative.md). |
| **Compliance gap mapping** (ISO 27001 / NIST CSF / SOC 2 / GDPR / PCI-DSS) | The maturity domains map cleanly onto control families; this is largely a new YAML plus a view. Highest business value of the unbuilt items. |
| **Public-repo secret scanning** (trufflehog) | Would slot in as a new module under `scanners/` producing `Finding` objects, exactly like the existing scanners. |
| **Multi-target comparison view** | Requires persistence beyond a single in-memory run; the largest architectural change on the list. |
| **Multi-host Shodan / subnet support** | `lookup_host()` is single-IP today. Shodan's search API supports `net:` queries; credit cost scales per IP. |
| **Docker Compose one-command startup** | Complicated by the Nmap binary requirement and by Reflex's Node.js frontend build. |

---

## 3. Technical debt

| Item | Location | Assessment |
|---|---|---|
| **Legacy attack-graph builder** | `analysis/graph_builder.py` (182 lines) | Superseded by `analysis/attack_brain.py` and `analysis/attack_graph.py`. Still carries an old "Design System v4" colour palette. A repository-wide search for `graph_builder` returns no importers, so it is dead code and safe to delete. |
| **Shadowed legacy constants module** | `config.py` at the repository root (43 lines) | Python resolves the `config/` **package** before the `config.py` **module**, so `from config import WEIGHT_CVSS` always reads `config/__init__.py`. The root file is dead. It was the only place the *rationale* for the scoring weights was written down; those comments now live at the top of `config/__init__.py`, so the file can be deleted without losing anything. |
| **Streamlit-era docstring** | `analysis/maturity.py` → `get_all_question_ids()` | Docstring says *"used to build the Streamlit form"*. Streamlit is gone; the Reflex form is built by `_build_maturity_form()` in `redflag_ui/state.py`. Cosmetic. |
| **Broad `except Exception` in the scan pipeline** | `redflag_ui/state.py` → `run_scan` | Deliberate: it is what makes a twelve-integration pipeline survive one feed being down. The trade-off is that a genuine bug in a scanner is swallowed silently. Consider logging the exception rather than passing. |
| **Duplicated `_higher_exploit` / `_is_ip` helpers** | `scanners/{openvas_parse,zap_scan,nuclei_scan,vulners_parse}.py`; `scanners/{dns_scan,tls_scan,breach_scan}.py` | Four and three near-identical copies respectively. Candidates for a shared `scanners/_common.py`. Low risk, low urgency. |
| **`reports/pdf_report.generate_cost_section` is remediation-only** | `reports/pdf_report.py` | The Day-1 **integration budget** (the `integration` bucket, ladder costs, accuracy readout) is displayed in the UI but is not represented in the cost PDF. The rollup already carries `integration_total`, `accuracy_pct` and `ci_low/ci_p50/ci_high`. |
| **No Risk Scorecard view-model** | `redflag_ui/state.py` | A simple High/Medium/Low scorecard summary was considered but never built. |
| **`data/results/` is vestigial** | Repository | Default `output_dir` for `run_nmap_scan()` and `export_findings_csv()`, but the UI overrides both to a temp directory. Git-ignored. Harmless. |

---

## 4. Inline debt markers in code

The source carries **none**. A repository-wide search for `TODO`, `FIXME`, `XXX` and `HACK` across
all `.py` files returns two matches, both false positives — literal `CVE-XXXX-XXXX` placeholder
strings inside comments in `scanners/shodan_scan.py` and `scanners/openvas_parse.py`.

---

## 5. Suggested order of work

Every defect in §1 is closed. What follows is unbuilt work, ordered by value against effort.

1. **Cover `redflag_ui/` with tests.** The engines carry 143 tests; the interface layer carries
   none, because the Streamlit suite was retired in the migration and not replaced. The view-model
   flattening in `state.py` is real logic and is currently verified only by running the app.
2. **Extend the cost PDF to cover the integration budget** (§3). The figures are already computed;
   this is a reporting gap, and the one area where the interface is ahead of the exports.
3. **Compliance gap mapping** (§2). The highest-value unbuilt feature for the M&A audience, and it
   reuses the existing maturity domains and YAML pattern.
4. **Remove the dead code** — `analysis/graph_builder.py` and the root `config.py` (§3). Both are
   confirmed unimported.
5. **Log rather than discard scanner exceptions** (§3).
6. **Secret scanning via trufflehog** (§2), which fits the existing scanner contract.
7. **Multi-target comparison** (§2), last, as the only item requiring an architectural change.

---

## Related documents

- [ROADMAP.md](../process/ROADMAP.md) — direction, as opposed to the concrete tasks here
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — accuracy caveats that are *by design*, not bugs
- [TEST_PLAN.md](../testing/TEST_PLAN.md) — what is and is not covered by tests
