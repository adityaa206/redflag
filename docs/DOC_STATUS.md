# Documentation Status

Delivery checklist, every unresolved `TODO(Adi)` marker with its location, and every discrepancy
found between the code and the README.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Delivery checklist

### Documentation index

- [x] `docs/README.md` — navigational hub linking every document

### Group A — Handover

- [x] `docs/handover/HANDOVER.md` — status, deliverables, locations, sign-off checklist
- [x] `docs/handover/PROJECT_REPORT.md` — problem, objectives, scope, solution, outcomes, timeline
- [x] `docs/handover/ACCESS_AND_CREDENTIALS.md` — key inventory and transfer template (no secrets)
- [x] `docs/handover/KNOWN_ISSUES_AND_BACKLOG.md` — defects, incomplete features, tech debt
- [x] `docs/handover/KNOWLEDGE_TRANSFER.md` — design principles, non-obvious behaviour, areas requiring care

### Group B — Technical

- [x] `docs/technical/ARCHITECTURE.md` — **with Mermaid component and data-flow diagrams**
- [x] `docs/technical/DATA_MODEL.md` — **all six enums verified from `analysis/schema.py`**
- [x] `docs/technical/MODULE_REFERENCE.md` — **real signatures, copied from source**
- [x] `docs/technical/CONFIGURATION.md` — **real config keys and values from all seven YAMLs**
- [x] `docs/technical/INTEGRATIONS.md` — 14 integrations with endpoints and degradation behaviour
- [x] `docs/technical/BRAIN_KNOWLEDGE_BASE.md` — storage layout, recall/learn, seed sanitisation
- [x] **B7 — in-code docstrings and comments added** (see §4; no behaviour change, 143 tests still pass)

### Group C — Operations

- [x] `docs/operations/INSTALLATION.md`
- [x] `docs/operations/DEVELOPER_ONBOARDING.md`
- [x] `docs/operations/DEPLOYMENT_RUNBOOK.md`
- [x] `docs/operations/TROUBLESHOOTING.md`

### Group D — User

- [x] `docs/user/USER_GUIDE.md`
- [x] `docs/user/RESULTS_INTERPRETATION.md` — **formula verified from `analysis/triage.py`**

### Group E — Testing

- [x] `docs/testing/TEST_PLAN.md` — **real test count (143) with per-file coverage map**
- [x] `docs/testing/LIMITATIONS.md`

### Group F — Legal

- [x] `docs/legal/AUTHORIZED_USE.md`
- [x] `docs/legal/LICENSES_AND_ATTRIBUTION.md` — versions from `requirements.txt`, licences looked up
- [x] `docs/legal/SECURITY_AND_PRIVACY.md`

### Group G — Process

- [x] `CHANGELOG.md` (root, canonical) + `docs/process/CHANGELOG.md` (pointer)
- [x] `docs/process/ROADMAP.md`
- [x] `docs/process/adr/README.md` — ADR index
- [x] `docs/process/adr/0001-no-llm.md`
- [x] `docs/process/adr/0002-deterministic-yaml-narrative.md`
- [x] `docs/process/adr/0003-free-no-paid-api.md`
- [x] `docs/process/adr/0004-reflex-ui-framework.md`
- [x] `docs/process/adr/0005-offline-brain-learn-by-remembering.md`
- [x] `docs/process/adr/0006-evidence-strength-multiplier.md`
- [x] `docs/process/adr/0007-epss-exploit-promotion.md`
- [x] `docs/process/adr/0008-uploads-correlate-not-replace.md`

### Group H — Root community files

- [x] `CONTRIBUTING.md`
- [x] `SECURITY.md`
- [x] `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1, plus project-specific standards
- [x] `README.md` updated with a Documentation section (existing content preserved)
- [ ] **`LICENSE`** — ❌ **not created.** Requires the copyright holder's legal name. See §3.1

### Final

- [x] All `TODO(Adi)` markers catalogued with file and line — §2
- [x] All discrepancies listed — §3
- [x] `docs/DOC_STATUS.md` (this file)

**32 of 33 deliverables complete.** The outstanding item is `LICENSE`, which needs a human
decision.

---

## 2. `TODO(Adi)` markers — 28 items

Facts that only the project owner can supply. Line numbers verified against the current files.

### 2.1 Identity and contacts — 7 markers

| File | Line | Required |
|---|---|---|
| `docs/handover/HANDOVER.md` | 151–153 | Author name and email; supervisor name and email; organisation |
| `docs/handover/HANDOVER.md` | 142 | Recipient of repository ownership, and whether to transfer or add a maintainer |
| `docs/handover/ACCESS_AND_CREDENTIALS.md` | 30 | GitHub username of the receiving owner |
| `SECURITY.md` | 41 | Contact address for vulnerability reports |
| `CODE_OF_CONDUCT.md` | 76 | Contact address for Code of Conduct reports |

### 2.2 Internship context — 5 markers

| File | Line | Required |
|---|---|---|
| `docs/handover/HANDOVER.md` | 28 | Handover date; internship start and end dates |
| `docs/handover/PROJECT_REPORT.md` | 35 | The brief as issued — stated objectives and their author |
| `docs/handover/PROJECT_REPORT.md` | 149 | Real-world usage, or an explicit statement that there was none |
| `docs/handover/PROJECT_REPORT.md` | 178 | Lessons learned, in the author's own words |
| `docs/handover/PROJECT_REPORT.md` | 210 | Mapping of the reconstructed timeline to formal milestones |

### 2.3 Security actions — 2 markers · highest priority

| File | Line | Required |
|---|---|---|
| `docs/handover/ACCESS_AND_CREDENTIALS.md` | 87 | Written confirmation that the previously-exposed Shodan key was rotated and the prior key revoked, with the date |
| `docs/legal/SECURITY_AND_PRIVACY.md` | 101 | A record of the exposure incident and its closure |

These should be completed before handover. An exposed Shodan key permits a third party to consume
the account's credits and to query the API under the owner's identity.

### 2.4 Legal and licensing — 5 markers

| File | Line | Required |
|---|---|---|
| `docs/legal/LICENSES_AND_ATTRIBUTION.md` | 47 | Copyright holder's name for the `LICENSE` file |
| `docs/handover/KNOWN_ISSUES_AND_BACKLOG.md` | 24 | The same, or confirmation that the project should not be MIT-licensed |
| `docs/legal/AUTHORIZED_USE.md` | 213 | Confirmation of the licence position once `LICENSE` exists |
| `docs/legal/AUTHORIZED_USE.md` | 7 | Review of the wording by a supervisor or qualified counsel |
| `docs/legal/LICENSES_AND_ATTRIBUTION.md` | 83 | Verification of dependency licences against the installed distributions |

### 2.5 Infrastructure confirmations — 3 markers

| File | Line | Required |
|---|---|---|
| `docs/operations/DEPLOYMENT_RUNBOOK.md` | 24 | Confirmation that no cloud or hosted deployment exists |
| `docs/handover/ACCESS_AND_CREDENTIALS.md` | 134 | Confirmation that the account inventory is complete |
| `docs/handover/ACCESS_AND_CREDENTIALS.md` | 33 | Clarification of the `upstream` remote (`quadindy/marisk`) and whether the recipient requires access |

### 2.6 Discretionary — 6 markers

| File | Line | Required |
|---|---|---|
| `docs/user/USER_GUIDE.md` | 108 | Screenshot of the Overview tab |
| `docs/user/USER_GUIDE.md` | 139 | Screenshot of the attack mind-map |
| `docs/handover/KNOWLEDGE_TRANSFER.md` | 156 | The author's assessment, in section 4 |
| `docs/legal/LICENSES_AND_ATTRIBUTION.md` | 105 | A full SBOM, if one is required |
| `CHANGELOG.md` | 13 | Tag the handover commit `v1.0.0` if the project is to be versioned |
| `SECURITY.md` | 69 | Confirmation that the stated response times remain realistic after handover |

---

## 3. Discrepancies found

Every fact in this documentation set was verified against the code. Four disagreements with the
README were found. **The documentation records the code's truth in every case.**

### 3.1 No `LICENSE` file exists — ❌ open

`README.md` states *"MIT — see LICENSE for details"* and links to `LICENSE`. **No such file
exists** — `git ls-files` returns nothing, and there is no licence text anywhere in the tree.

**Why it matters:** the default copyright position is all rights reserved. A licence claim without
licence text is ambiguous rather than permissive, which leaves anyone who forks or contributes
without a grant they can rely on.

**Not fixed automatically** — naming a copyright holder is a legal declaration only you can make.
Ready-to-use MIT text is in
[legal/LICENSES_AND_ATTRIBUTION.md](legal/LICENSES_AND_ATTRIBUTION.md) §1.

### 3.2 Test count: README said 128, actual is 143 — ✅ fixed

The suite contains **143 tests**, all passing (verified 2026-07-27, ~9 s). The README claimed 128
in three places.

**Fixed** in `README.md`: the badge, the architecture tree, and the "Running Tests" heading.
Recorded in [testing/TEST_PLAN.md](testing/TEST_PLAN.md).

### 3.3 Deal-killer override rules: README documents three, code implements four — ✅ documented

`analysis/triage.py:check_override_rules()` has a fourth rule the README omits: a manual analyst
flag, triggered when `override_reason` contains the phrase `"active compromise"`.

Documented in [user/RESULTS_INTERPRETATION.md](user/RESULTS_INTERPRETATION.md) §3 and
[technical/DATA_MODEL.md](technical/DATA_MODEL.md). The README's Scoring Reference table could be
updated to match.

### 3.4 README fixture table omits `mock_nuclei.jsonl` — ⚠️ open

The README's *Using the Mock Data Files* section lists three fixtures but not
`tests/fixtures/mock_nuclei.jsonl`, which exists on disk (4.2 KB) — **and has never been
committed**, so a fresh clone cannot reproduce the documented Nuclei upload workflow.

Documented correctly in [user/USER_GUIDE.md](user/USER_GUIDE.md) and
[testing/TEST_PLAN.md](testing/TEST_PLAN.md) §5. Fix:
`git add tests/fixtures/mock_nuclei.jsonl`.

Note the test suite does not depend on it — `test_nuclei.py` injects JSONL inline — so this does
not affect the 143.

---

## 4. Repository fixes applied during this pass

### 4.1 `.gitignore` was ignoring the entire documentation set — ✅ fixed

`.gitignore` contained a blanket `*.md` rule. `README.md` predated it and so remained tracked,
which masked the problem — but **every new Markdown file was silently ignored**, including all of
`docs/`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` and `CHANGELOG.md`. Without this
fix, none of this documentation could have been committed.

Explicit negations were added for the published set, keeping `CLAUDE.md`, `AGENTS.md` and scratch
notes local. Verified:

```bash
git check-ignore -v docs/README.md   # reports the negation, not an ignore
git status --short docs/             # docs listed as untracked/new
```

### 4.2 In-code documentation (task B7) — ✅ complete

Docstrings and explanatory comments added. **No behaviour changed — 143 tests pass before and
after.**

| File | What was added |
|---|---|
| `analysis/triage.py` | Module docstring covering the two-stage model; annotated all four lookup tables with rationale; docstrings on all seven public functions; explained the override short-circuit, why the multiplier is multiplicative, and why `triage_all`'s sort order is a contract |
| `analysis/schema.py` | Module docstring, including the `use_enum_values=True` trap and the `_v()` normalisation rule |
| `analysis/parser.py` | Module docstring explaining the flat CVSS 3.5 and why `CONFIRMED` evidence is honest here |
| `analysis/brain_memory.py` | Ordering contract on `recall()`; monotonic weighting and the deliberate non-feedback into scoring on `learn_from_scan()`; **a prominent warning on `export_seed()` as the publish boundary**; explained the silent-failure trade-off in `_save()` |
| `scanners/epss_scan.py` | Rationale for the 0.50 threshold; annotated the three constraints on promotion, especially why the ceiling is `PUBLIC_EXPLOIT` and not `ACTIVE_EXPLOITATION` |
| `scanners/kev_lookup.py` | Module docstring flagging the most consequential silent degradation in the pipeline, with a diagnostic snippet |
| `scanners/shodan_scan.py` | Module docstring on upload-beats-live and score impact; flagged the silent 6.5 CVSS fallback |
| `scanners/nmap_scan.py` | Module docstring on being the only scanner that raises, and the outside-the-worktree constraint; documented `find_nmap()`'s Windows-only path probing |
| `scanners/vulners_enrich.py` | Module docstring on upgrade-only semantics and how it differs from `vulners_parse.py` |
| `reports/generator.py` | Module and function docstrings, including the temp-directory constraint |
| `config/__init__.py` | **Ported the scoring-weight rationale** from the dead root `config.py` so deleting that file loses nothing; documented tier thresholds, Shodan/Vulners constants and both Nmap argument sets |

---

## 5. Verification performed

| Check | Result |
|---|---|
| Test suite before documentation changes | **143 passed** |
| Test suite after in-code documentation changes | **143 passed** |
| Every enum and member verified against `analysis/schema.py` | ✅ 6 enums |
| Scoring formula and all four lookup tables verified against `analysis/triage.py` | ✅ |
| Weights and thresholds verified against `config/__init__.py` | ✅ |
| Function signatures copied from source, not paraphrased | ✅ |
| Dependency versions taken from `requirements.txt` | ✅ 14 pinned |
| Config keys enumerated by parsing the actual YAMLs | ✅ 7 files |
| Question and domain counts verified (23 questions, 7 domains) | ✅ |
| Test count and per-file breakdown from `pytest --collect-only` | ✅ 143 across 11 files |
| Changelog reconstructed from `git log` | ✅ 29 commits |
| Documentation is visible to git after the `.gitignore` fix | ✅ |
| No secret present in any tracked file | ✅ |

---

## 6. Outstanding actions

**Prior to handover:**

1. **Rotate the exposed Shodan key** and record it (§2.3). Highest priority.
2. **Add the `LICENSE` file** (§3.1). One file; removes a legal ambiguity on a public repository.
3. **Complete the contact and identity markers** (§2.1).
4. `git add tests/fixtures/mock_nuclei.jsonl` (§3.4).
5. **Commit this documentation set.** Confirm it is tracked first:
   `git status --short docs/`.

**Subsequently:**

6. Complete the internship-context markers (§2.2).
7. Obtain review of the authorised-use wording (§2.4).
8. Work through the concrete task list in
   [handover/KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) §5.

---

## Related documents

- [README.md](README.md) — the documentation index
- [handover/HANDOVER.md](handover/HANDOVER.md) — the sign-off checklist
- [handover/KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) — defects and backlog
- [process/ROADMAP.md](process/ROADMAP.md) — forward direction
