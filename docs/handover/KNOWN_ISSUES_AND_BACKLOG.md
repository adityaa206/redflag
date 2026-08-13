# Known Issues & Backlog

Everything not finished: defects found, unbuilt features, technical debt, and a recommended order
of attack.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Defects found during the documentation pass

These are real, verified against the code on 2026-07-27. None break a running scan.

### 1.1 No `LICENSE` file exists — **highest priority**

`README.md` states *"MIT — see LICENSE for details"* and links to `LICENSE`, but no such file is
present in the repository (`git ls-files` returns nothing for it). The repository is therefore,
strictly, **all rights reserved** — publishing code with a licence claim but no licence text
creates ambiguity for anyone who forks or reuses it.

**Fix:** add a standard MIT `LICENSE` file naming the copyright holder and year. This requires
the owner's legal name, so it has not been created automatically.

> ⚠️ TODO(Adi): supply the copyright holder name for the `LICENSE` file, or confirm the project
> should not be MIT-licensed and correct the README instead.

### 1.2 The README's test count is stale

`README.md` claims **128 passing tests** in three places (badge, architecture tree, "Running
Tests"). The suite actually contains **143 tests**, all passing.

> ⚠️ DISCREPANCY: code/test suite says 143 tests; `README.md` says 128.

**Fix:** update the three README references. Recorded in
[TEST_PLAN.md](../testing/TEST_PLAN.md).

### 1.3 `.gitignore` ignored the entire documentation set — **fixed**

`.gitignore` contained a blanket `*.md` rule. Because `README.md` was committed before that rule
landed, git kept tracking it, which masked the problem — but **any new Markdown file was silently
ignored**, including this entire `docs/` tree, `CONTRIBUTING.md`, `SECURITY.md` and
`CHANGELOG.md`.

**Fixed on 2026-07-27** by adding explicit negations for the published documentation while
keeping `CLAUDE.md`, `AGENTS.md` and scratch notes local. Verify with:

```bash
git check-ignore -v docs/README.md   # should report the negation, not an ignore
git status --short docs/             # should list the docs as untracked/new
```

### 1.4 `tests/fixtures/mock_nuclei.jsonl` is untracked

The Nuclei mock fixture exists on disk (4.2 KB) but has never been committed, so a fresh clone
cannot reproduce the documented "upload a mock Nuclei file" workflow. The OpenVAS and ZAP mocks
*are* committed.

**Fix:** `git add tests/fixtures/mock_nuclei.jsonl` and commit.

### 1.5 The README fixture table omits the Nuclei mock

`README.md` → *Using the Mock Data Files* lists `mock_openvas.xml`, `mock_zap.xml` and
`sample_assessment.json`, but not `mock_nuclei.jsonl`. Fixed in
[USER_GUIDE.md](../user/USER_GUIDE.md); the README still needs updating.

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
| **Legacy attack-graph builder** | `analysis/graph_builder.py` (182 lines) | Superseded by `analysis/attack_brain.py` and `analysis/attack_graph.py`. Not imported by the Reflex UI. Still carries an old "Design System v4" colour palette. **Safe to delete** once you confirm nothing imports it. |
| **Shadowed legacy constants module** | `config.py` at the repository root (43 lines) | Python resolves the `config/` **package** before the `config.py` **module**, so `from config import WEIGHT_CVSS` always reads `config/__init__.py`. The root file is dead — but it is the only place the *rationale* for the scoring weights is written down. Port those comments into `config/__init__.py` before deleting it. |
| **Streamlit-era docstring** | `analysis/maturity.py` → `get_all_question_ids()` | Docstring says *"used to build the Streamlit form"*. Streamlit is gone; the Reflex form is built by `_build_maturity_form()` in `redflag_ui/state.py`. Cosmetic. |
| **Broad `except Exception` in the scan pipeline** | `redflag_ui/state.py` → `run_scan` | Deliberate: it is what makes a twelve-integration pipeline survive one feed being down. The trade-off is that a genuine bug in a scanner is swallowed silently. Consider logging the exception rather than passing. |
| **Duplicated `_higher_exploit` / `_is_ip` helpers** | `scanners/{openvas_parse,zap_scan,nuclei_scan,vulners_parse}.py`; `scanners/{dns_scan,tls_scan,breach_scan}.py` | Four and three near-identical copies respectively. Candidates for a shared `scanners/_common.py`. Low risk, low urgency. |
| **`reports/pdf_report.generate_cost_section` is remediation-only** | `reports/pdf_report.py` | The Day-1 **integration budget** (the `integration` bucket, ladder costs, accuracy readout) is displayed in the UI but is not represented in the cost PDF. The rollup already carries `integration_total`, `accuracy_pct` and `ci_low/ci_p50/ci_high`. |
| **No Risk Scorecard view-model** | `redflag_ui/state.py` | A simple High/Medium/Low scorecard summary was considered but never built. |
| **`data/results/` is vestigial** | Repository | Default `output_dir` for `run_nmap_scan()` and `export_findings_csv()`, but the UI overrides both to a temp directory. Git-ignored. Harmless. |

---

## 4. Open `TODO` / `FIXME` markers in code

A repository-wide search for `TODO`, `FIXME`, `XXX` and `HACK` across all `.py` files returns
**no genuine markers**. The two matches are false positives — literal `CVE-XXXX-XXXX` placeholder
strings in comments:

- `scanners/shodan_scan.py:113`
- `scanners/openvas_parse.py:39`

The code carries no outstanding inline debt markers.

---

## 5. Suggested next steps, in priority order

1. **Add the `LICENSE` file** (§1.1). One file; removes a legal ambiguity on a public repository.
2. **Commit `tests/fixtures/mock_nuclei.jsonl`** (§1.4) and correct the README's test count and
   fixture table (§1.2, §1.5). All three are minutes of work.
3. **Delete the dead code** — `analysis/graph_builder.py` and the root `config.py` (§3). Confirm
   with `grep -rn "graph_builder\|^import config$"` first.
4. **Extend the cost PDF to cover the integration budget** (§3). The data is already computed;
   this is a reporting gap, and it is the one place the UI is ahead of the exports.
5. **Compliance gap mapping** (§2). The highest-value unbuilt feature for the M&A audience, and
   it reuses the existing maturity domains and YAML pattern.
6. **Log rather than swallow scanner exceptions** (§3). Small change, large debugging benefit.
7. **Secret scanning via trufflehog** (§2). Slots into the existing scanner contract cleanly.
8. **Multi-target comparison** (§2). Do this last — it is the only item that forces an
   architectural change (persistence).

---

## Related documents

- [ROADMAP.md](../process/ROADMAP.md) — direction, as opposed to the concrete tasks here
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — accuracy caveats that are *by design*, not bugs
- [TEST_PLAN.md](../testing/TEST_PLAN.md) — what is and is not covered by tests
- [DOC_STATUS.md](../DOC_STATUS.md) — the full TODO and discrepancy register
