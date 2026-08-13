# Documentation Status

Delivery status of the documentation set, the outstanding owner-supplied items, and the points on
which the code and the README diverge.

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
- [x] In-code docstrings and comments across `analysis/`, `scanners/`, `reports/` and `config/`

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

**32 of 33 deliverables complete.** The outstanding item is `LICENSE` — see §3.1.

---

## 2. `TODO(Adi)` markers — 28 items

Facts that only the project owner can supply.

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

An exposed Shodan key permits a third party to consume the account's credits and to query the
API under the owner's identity. Both items should be closed before handover.

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

## 3. Discrepancies between the code and the README

Where the two disagree, the documentation records the behaviour of the code.

### 3.1 No `LICENSE` file exists — open

`README.md` states *"MIT — see LICENSE for details"* and links to `LICENSE`. No such file exists;
`git ls-files` returns nothing for it and there is no licence text anywhere in the tree.

The default copyright position is therefore all rights reserved. A licence claim without licence
text is ambiguous rather than permissive, and leaves anyone who forks or contributes without a
grant they can rely on.

Naming a copyright holder is a legal declaration for the project owner to make. Ready-to-use MIT
text is in [legal/LICENSES_AND_ATTRIBUTION.md](legal/LICENSES_AND_ATTRIBUTION.md) §1.

### 3.2 Test count — resolved

The suite contains **143 tests**, all passing. The README stated 128 in three places: the badge,
the architecture tree and the "Running Tests" section. All three now state 143. Recorded in
[testing/TEST_PLAN.md](testing/TEST_PLAN.md).

### 3.3 Deal-killer override rules — documented

`analysis/triage.py:check_override_rules()` implements four rules; the README documents three.
The omitted rule is the manual analyst flag, triggered when `override_reason` contains the phrase
`"active compromise"`.

The full set is documented in
[user/RESULTS_INTERPRETATION.md](user/RESULTS_INTERPRETATION.md) §3 and
[technical/DATA_MODEL.md](technical/DATA_MODEL.md). The README's Scoring Reference table remains
to be updated.

### 3.4 README fixture table — resolved

The README's *Using the Mock Data Files* section listed three fixtures and omitted
`tests/fixtures/mock_nuclei.jsonl`, which was also absent from version control. The fixture is now
committed and the full set is documented in [user/USER_GUIDE.md](user/USER_GUIDE.md) and
[testing/TEST_PLAN.md](testing/TEST_PLAN.md) §5.

The test suite does not depend on it — `test_nuclei.py` supplies its JSONL inline — so the count
of 143 is unaffected.

### 3.5 `.gitignore` excluded the documentation — resolved

A blanket `*.md` rule excluded every Markdown file from version control. `README.md` predated the
rule and remained tracked, which masked the effect. Explicit negations now version the published
documentation and the root community files while keeping agent and scratch notes local. Recorded
in [handover/KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) §1.3.

---

## 4. Outstanding actions

**Prior to handover:**

1. Rotate the exposed Shodan API key and record the rotation (§2.3).
2. Add the `LICENSE` file (§3.1).
3. Complete the contact and identity markers (§2.1).

**Subsequently:**

4. Complete the internship-context markers (§2.2).
5. Obtain review of the authorised-use wording (§2.4).
6. Address the task list in
   [handover/KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) §5.

---

## Related documents

- [README.md](README.md) — the documentation index
- [handover/HANDOVER.md](handover/HANDOVER.md) — the sign-off checklist
- [handover/KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) — defects and backlog
- [process/ROADMAP.md](process/ROADMAP.md) — forward direction
