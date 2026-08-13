# Developer Onboarding

Getting productive in the RedFlag codebase.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Setup

```bash
git clone https://github.com/adityaa206/redflag.git
cd redflag
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env        # optional — both keys are optional
pytest tests/ -v            # expect: 143 passed
```

Full detail, including prerequisites and the optional binaries:
[INSTALLATION.md](INSTALLATION.md).

> **Do not put the checkout in OneDrive or any synced folder.** The sync engine fights Reflex's
> Node build.

---

## 2. Project layout tour

```
Redflag/
├── rxconfig.py           Reflex config (app_name="redflag_ui")
├── requirements.txt      Pinned dependencies
├── .env                  Secrets (git-ignored)
│
├── redflag_ui/           PRESENTATION — no business logic
│   ├── redflag_ui.py     rx.App + 9 routes
│   ├── state.py          RedFlagState: the pipeline + all view-models
│   ├── components/       shell (nav, scan bar, 5 upload slots), ui helpers
│   └── pages/            one module per route
│
├── scanners/             COLLECTION — the only layer that touches the network
├── analysis/             REASONING — pure, deterministic, offline
│   ├── schema.py         the Finding model + 6 enums
│   └── triage.py         the scoring model
├── cost/                 Costing: catalog → estimator → dedupe → scenarios → rollup
├── narrative/            Deterministic template prose
├── reports/              CSV + PDF serialisation
├── config/               loader.py + 7 YAMLs + scoring constants
├── assets/               redflag.css — the entire visual design
└── tests/                143 tests + fixtures
```

The full responsibility table is in [ARCHITECTURE.md](../technical/ARCHITECTURE.md) §5.

---

## 3. Running in development

```bash
python -m reflex run
```

Frontend <http://localhost:3000>, backend <http://localhost:8000>. Hot reload is on: editing a
Python file under `redflag_ui/` recompiles and refreshes the browser.

**Two consequences of hot reload:**

1. **A compile error crashes the dev server.** Before a risky component edit, render-check it in
   the venv instead of relying on the live server:

   ```python
   from redflag_ui.pages.day1 import day1
   day1().render()      # surfaces VarTypeError / binding errors immediately
   ```

2. **Writing inside the worktree during a scan resets backend state.** The file-watcher sees the
   write, hot-reloads, and the findings vanish. This is exactly why Nmap output goes to
   `%TEMP%/redflag_scans` and the brain to `~/RedFlag-Brain`. Never change that.

Alternate ports:

```bash
python -m reflex run --frontend-port 3001 --backend-port 8001
```

---

## 4. Running the tests

```bash
pytest tests/ -v                  # everything — 143 tests, ~9 seconds
pytest tests/test_triage.py -v    # one module
pytest tests/ -k "day1"           # by keyword
pytest tests/ -x                  # stop at the first failure
```

The suite is fast and needs **no network and no target** — every external call is either injected
(EPSS takes a `scores` dict) or replaced by a fixture. Keep it that way: a test that hits the
network is a test that will fail on a plane.

Coverage map and what is deliberately untested:
[TEST_PLAN.md](../testing/TEST_PLAN.md).

---

## 5. Where business logic lives — and where it must not

| Kind of change | Where it goes |
|---|---|
| Scoring, weights, tiers | `analysis/triage.py` + `config/__init__.py` |
| A new evidence source | `scanners/` + a `ScannerSource` member |
| Maturity questions or thresholds | `config/maturity_questions.yaml`, `config/corporate_standard.yaml` |
| Day-1 rules, gates, models | `config/day1_blueprint.yaml` |
| Prices | `config/pricing_benchmarks.yaml`, `config/remediation_catalog.yaml`, `config/day1_cost_catalog.yaml` |
| Report wording | `config/narrative_blocks.yaml` |
| How something is *displayed* | `redflag_ui/pages/`, `redflag_ui/components/`, `assets/redflag.css` |
| Flattening engine output for display | `redflag_ui/state.py` view-models |

**The governing rule:** a change that would alter a number in a report does not belong in
`redflag_ui/`. The Streamlit to Reflex migration was inexpensive because this boundary had been
maintained from the outset.

---

## 6. Conventions used in this codebase

Match what is there rather than importing your own style.

- **`from __future__ import annotations`** at the top of most modules; modern generics
  (`list[Finding]`, `str | None`) throughout.
- **Dataclasses for engine outputs**, Pydantic for models that need validation
  (`Finding`, the `cost/` schema).
- **Section banner comments** mark logical blocks:

  ```python
  # ── Phase assignment + roadmap ────────────────────────────────────────────────
  ```

- **A leading underscore means private to the module** (`_matches`, `_v`, `_worst_tier`).
- **Enum normalisation is always** `str(getattr(x, "value", x))` — usually a local `_v()` helper.
  **Never `str(x)`**: on an enum member that yields `"DealTier.CRITICAL"` and silently breaks
  every comparison.
- **Scanners never raise.** Wrap network I/O and return `[]` or an unchanged input. The two
  deliberate exceptions are `run_nmap_scan()` (missing binary) and `parse_asset_excel()` /
  `parse_shodan_json()` (malformed upload), which raise because the user needs to know.
- **Upgrade, never downgrade.** Merge and enrichment helpers use `_higher_exploit()` and
  `max()` on CVSS so a correlation can only strengthen a finding.
- **Config is read through `config/loader.py`**, never by opening a YAML directly, and never from
  `redflag_ui/`.
- **Backend-only Reflex vars carry a leading underscore** so raw engine objects are not
  serialised to the browser.
- Docstrings are the module- and public-function-level narrative kind — explaining *why*, not
  restating the signature.

---

## 7. How to add things

### A new scanner

1. `scanners/my_scanner.py` producing `Finding` objects.
2. Either a standalone `run_my_scan(target) -> list[Finding]` (like DNS/TLS) **or** a
   `parse_my_x()` + `merge_my_with_nmap()` pair (like OpenVAS/ZAP/Nuclei).
3. Add a `ScannerSource` member in `analysis/schema.py`.
4. Set `evidence_strength` honestly — it multiplies the score. `CONFIRMED` means *verified*, not
   *observed*.
5. Wrap all I/O so failure returns `[]`.
6. Call it from `RedFlagState.run_scan` at the right position — before `triage_all()`, and
   before EPSS if it can add CVEs.
7. Need an upload slot? Add to `_SLOTS` in `redflag_ui/components/shell.py` and add
   `upload_*`/`clear_*` handlers in `state.py`.
8. Add a fixture under `tests/fixtures/` and tests against it.

### A new config knob

Add the key to the relevant YAML; add a loader accessor if it needs one; read it in the engine;
document it in [CONFIGURATION.md](../technical/CONFIGURATION.md). Remember the loader caches per
process — restart to see the change.

### A new page

Create `redflag_ui/pages/my_page.py` returning `shell("Title", ...)`, then add it to `_PAGES` in
`redflag_ui/redflag_ui.py`. Build the view-model in `state.py`; keep the page module free of
logic.

### A new cost item or report sentence

No code needed. Add an entry to `config/remediation_catalog.yaml` (or
`config/day1_cost_catalog.yaml`), or a block to `config/narrative_blocks.yaml`.

---

## 8. Principal source files

| File | Lines | Significance |
|---|---|---|
| `analysis/schema.py` | 91 | The `Finding` model and all six enums — the vocabulary shared by every other module |
| `analysis/triage.py` | 115 | The scoring model: lookup tables, the weighted formula, the override rules |
| `redflag_ui/state.py` | 1339 | `RedFlagState.run_scan` — the pipeline; and every view-model |
| `analysis/day1.py` | 423 | The connectivity ladder, tier gates, review pillars and phase rules |
| `cost/rollup.py` | 168 | `run_cost_pipeline` — the entry point to the cost engine |
| `tests/test_triage.py` | 258 | The executable specification for the scoring model |

Corresponding reference material: [DATA_MODEL.md](../technical/DATA_MODEL.md),
[RESULTS_INTERPRETATION.md](../user/RESULTS_INTERPRETATION.md),
[ARCHITECTURE.md](../technical/ARCHITECTURE.md) and
[KNOWLEDGE_TRANSFER.md](../handover/KNOWLEDGE_TRANSFER.md).

---

## 9. Candidate first changes

Items 1 to 3 of [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §5 are
self-contained and suitable as an initial contribution:

1. Add the missing `LICENSE` file.
2. Commit `tests/fixtures/mock_nuclei.jsonl` and correct the README's stale test count.
3. Remove the dead `analysis/graph_builder.py` and root `config.py`, having first ported the
   scoring-weight rationale comments into `config/__init__.py`.

The branch, test and pull-request workflow is defined in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

---

## Related documents

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — branch, test and PR workflow
- [ARCHITECTURE.md](../technical/ARCHITECTURE.md) — structure and extension points
- [MODULE_REFERENCE.md](../technical/MODULE_REFERENCE.md) — signatures and side effects
- [TEST_PLAN.md](../testing/TEST_PLAN.md) — the suite
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — when the dev server misbehaves
