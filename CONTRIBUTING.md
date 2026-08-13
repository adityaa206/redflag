# Contributing to RedFlag

Thanks for your interest. This is the short version — for depth, see
[docs/operations/DEVELOPER_ONBOARDING.md](docs/operations/DEVELOPER_ONBOARDING.md).

---

## Before you start

**RedFlag is a security scanner.** Contributions must not add capability for unauthorised
scanning, exploitation, or evasion of detection. RedFlag observes and reasons; it never attacks.
Read [docs/legal/AUTHORIZED_USE.md](docs/legal/AUTHORIZED_USE.md).

**Never commit a secret.** API keys live in `.env`, which is git-ignored. If you accidentally
commit one, rotate it first and clean the history second.

---

## Setup

```bash
git clone https://github.com/adityaa206/redflag.git
cd redflag
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
pytest tests/ -v            # expect: 143 passed
```

Two environment constraints:

- **Do not put the checkout in OneDrive, Dropbox or any synced folder.** The sync engine fights
  Reflex's Node build and produces `EBUSY` errors and a blank page.
- **Nmap is required for live scanning** and is discovered by absolute Windows path, not `PATH`.
  See [docs/operations/INSTALLATION.md](docs/operations/INSTALLATION.md).

---

## Branch and commit

```bash
git checkout -b short-descriptive-name
```

Never commit directly to `main`.

Commit messages: a short imperative subject line describing the effect, matching the existing
history.

```
Add EPSS exploitation-probability enrichment
Fix Vulners NSE pipeline status: distinguish installed vs not-installed
docs: sync README data-flow diagram with Nuclei / EPSS / graph
```

---

## Test

```bash
pytest tests/ -v            # everything
pytest tests/test_triage.py -v
pytest tests/ -k "day1"
```

**All 143 tests must pass before you open a PR.**

New behaviour requires a test. The suite observes three rules, which contributions should follow:

1. **No network access, ever.** Inject external data instead: EPSS takes a `scores` dict, Nuclei
   takes inline JSONL, OpenVAS and ZAP take fixture files. A test that hits the internet fails on
   a plane and lies in CI.
2. **No mocking framework.** The engines are pure functions over plain objects; construct real
   `Finding` objects and assert on real output. Needing heavy mocks is a signal the module has the
   wrong dependencies.
3. **Test the contract, not the implementation.** Assert scores, tiers, phases and totals — the
   things a user sees. This is what let the Streamlit → Reflex migration happen without touching
   a single test.

---

## Code conventions

Match the surrounding code rather than importing your own style.

- `from __future__ import annotations`; modern generics (`list[Finding]`, `str | None`).
- Dataclasses for engine outputs; Pydantic where validation is needed.
- Section banner comments mark logical blocks:
  `# ── Phase assignment + roadmap ──────────────────────────────`
- A leading underscore means private to the module.
- **Normalise enums with `str(getattr(x, "value", x))`, never `str(x)`.** On an enum member the
  latter yields `"DealTier.CRITICAL"` and silently breaks every comparison.
- **Scanners never raise.** Wrap network I/O and return `[]` or an unchanged input. The deliberate
  exceptions are `run_nmap_scan()` (missing binary) and the upload parsers (malformed input), which
  raise because the user needs to know.
- **Upgrade, never downgrade.** Merge and enrichment helpers use `_higher_exploit()` and `max()`
  on CVSS, so a correlation can only strengthen a finding.
- Read config through `config/loader.py` — never open a YAML directly, and never from
  `redflag_ui/`.
- Backend-only Reflex vars carry a leading underscore so raw engine objects are not serialised to
  the browser.

### The one architectural rule

**Business logic does not go in `redflag_ui/`.**

If a change would alter a number in a report, it belongs in `analysis/`, `cost/`, `scanners/` or
`config/`. `redflag_ui/` calls engines and flattens their output into view-models. That boundary
is why the interface framework was replaced without modifying a single engine, and it should be
maintained.

### Runtime writes stay outside the worktree

Nmap output goes to `%TEMP%/redflag_scans`; the brain to `~/RedFlag-Brain`. Writing inside the
repository trips Reflex's dev file-watcher, which hot-reloads the backend **mid-scan** and loses
the findings. Do not change these paths.

---

## Adding things

| What | Where | Code needed |
|---|---|---|
| A cost line item | `config/remediation_catalog.yaml` | **None** |
| A Day-1 integration cost | `config/day1_cost_catalog.yaml` | **None** |
| Report wording | `config/narrative_blocks.yaml` | **None** |
| A maturity question | `config/maturity_questions.yaml` | **None** |
| A new scanner | `scanners/` + a `ScannerSource` member | Yes — see below |
| A new page | `redflag_ui/pages/` + `_PAGES` in `redflag_ui.py` | Yes |

**A new scanner** must: produce `Finding` objects; expose either `run_my_scan(target)` or a
`parse_*` + `merge_*_with_nmap` pair; set `evidence_strength` **honestly** (it multiplies the risk
score — `CONFIRMED` means *verified*, not *observed*); wrap all I/O so failure returns `[]`; and
be called from `RedFlagState.run_scan` before `triage_all()`. Add a fixture under
`tests/fixtures/` and tests against it.

Note that YAML edits are cached per process — **restart the app** to see them.

---

## Documentation

Code and docs ship together. If your change alters behaviour, update the relevant document:

| Change | Update |
|---|---|
| Scoring, weights, thresholds | [CONFIGURATION.md](docs/technical/CONFIGURATION.md), [RESULTS_INTERPRETATION.md](docs/user/RESULTS_INTERPRETATION.md) |
| A new integration | [INTEGRATIONS.md](docs/technical/INTEGRATIONS.md), [SECURITY_AND_PRIVACY.md](docs/legal/SECURITY_AND_PRIVACY.md) egress table |
| A public function signature | [MODULE_REFERENCE.md](docs/technical/MODULE_REFERENCE.md) |
| A schema or enum | [DATA_MODEL.md](docs/technical/DATA_MODEL.md) |
| A user-visible feature | [USER_GUIDE.md](docs/user/USER_GUIDE.md) |
| Anything notable | [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` |

**A significant design decision needs an ADR** — see
[docs/process/adr/README.md](docs/process/adr/README.md). Write the costs before the benefits; an
ADR listing only upsides is a press release.

---

## Opening a pull request

1. Rebase or merge the latest `main`.
2. `pytest tests/ -v` — 143 passing.
3. Push and open a PR against `main`.
4. In the description: what changed, why, and how you verified it. Screenshots for UI changes.
5. Link any issue or the backlog item it addresses.

Good first contributions are listed in
[docs/handover/KNOWN_ISSUES_AND_BACKLOG.md](docs/handover/KNOWN_ISSUES_AND_BACKLOG.md) §5 — items
1 to 3 are deliberately sized as a first change.

---

## Reporting

- **A bug in RedFlag** — open a GitHub issue with steps to reproduce, expected versus actual
  behaviour, your OS and Python version, and whether Nmap and Nuclei are installed. Never paste an
  API key or real target data.
- **A security vulnerability in RedFlag itself** — do **not** open a public issue. See
  [SECURITY.md](SECURITY.md).

---

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Related documents

- [docs/operations/DEVELOPER_ONBOARDING.md](docs/operations/DEVELOPER_ONBOARDING.md) — the full guide
- [docs/technical/ARCHITECTURE.md](docs/technical/ARCHITECTURE.md) — structure and extension points
- [docs/testing/TEST_PLAN.md](docs/testing/TEST_PLAN.md) — the suite and its gaps
- [docs/handover/KNOWLEDGE_TRANSFER.md](docs/handover/KNOWLEDGE_TRANSFER.md) — the gotchas
