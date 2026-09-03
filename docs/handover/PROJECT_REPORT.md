# RedFlag — Project Report

My account of the problem, the approach I took, and what came out of it.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Problem statement

In a merger or acquisition, the acquirer inherits the target's security posture in full — its
unpatched systems, its exposed services, its prior breaches, and its regulatory liabilities — at
the moment the deal closes. Financial and legal due diligence have mature, standardised
processes. Technical security due diligence largely does not.

The practical difficulties are three:

1. **Evidence is fragmented.** An Nmap sweep, a Shodan record, an OpenVAS report and a ZAP scan
   each describe a slice of the same estate in a different vocabulary. Read separately, they
   produce four unranked lists rather than one decision.
2. **Severity is not risk.** A CVSS 9.8 on an internal test box is not the same commercial risk
   as a CVSS 7.5 on an internet-facing system holding regulated data. Deal decisions need the
   second framing, not the first.
3. **Risk is hard to price.** "There are 47 findings" does not tell a deal team what to negotiate.
   "Remediation is $180K–$420K, and connecting the two networks safely on Day 1 costs another
   $310K" does.

RedFlag exists to close that gap: to turn heterogeneous scanner output into one ranked, priced,
sequenced risk picture that a deal team can act on.

---

## 2. Objectives

The objectives I set out to meet, and which the implementation is built against:

- Aggregate multiple scanner sources into a single, deduplicated finding set.
- Score findings on commercial risk, not raw severity.
- Produce an inside-out maturity view to complement the outside-in scan.
- Answer the Day-1 question: *how do we connect the two organisations safely?*
- Attach a defensible cost to the answer.
- Do all of it at **zero running cost** — no paid API, no LLM, no GPU.

---

## 3. Scope

**In scope**

- Single-target assessment (one hostname or IP per run), plus uploaded scanner artefacts.
- Outside-in technical scanning and OSINT enrichment.
- Inside-out maturity questionnaire across seven security domains.
- Risk scoring, Day-1 connectivity planning, cost modelling, attack-path reasoning.
- Deterministic narrative generation and CSV/PDF export.
- Local, single-user operation.

**Out of scope**

- Authenticated or credentialed scanning of the target (RedFlag ingests OpenVAS/ZAP output but
  does not perform authenticated scans itself).
- Multi-target or portfolio comparison.
- Subnet-wide Shodan enumeration (single host only).
- Continuous monitoring — RedFlag is a point-in-time assessment.
- Any form of exploitation. RedFlag observes and reasons; it never attacks.
- Multi-user access control, hosting, or persistence beyond local files.

---

## 4. Solution overview

RedFlag is a thirteen-step pipeline behind a single button. Full detail lives in
[ARCHITECTURE.md](../technical/ARCHITECTURE.md); the shape of it:

1. **Collect** — Nmap scans the target; staged uploads (Shodan JSON, OpenVAS XML, ZAP XML,
   Nuclei JSONL, asset Excel) are read alongside it.
2. **Correlate** — uploaded scanner results are merged into the Nmap layer by `host:port`. A
   match upgrades the existing finding's evidence strength, CVSS and exploit status; it does not
   create a duplicate.
3. **Enrich** — CISA KEV, NVD CVSS, Vulners and FIRST.org EPSS attach exploit intelligence.
   DNS, TLS and breach scanners contribute findings of their own.
4. **Score** — every finding gets a weighted 0–100 risk score, an evidence-strength multiplier,
   and a deal tier; three override rules force a deal-killer verdict outright.
5. **Assess** — the maturity questionnaire produces per-domain scores against a corporate
   standard, generating gaps that feed both the Day-1 roadmap and the cost engine.
6. **Plan** — the Day-1 engine recommends the highest connectivity tier whose entry gate passes,
   and sequences every finding and gap into P0–P3.
7. **Reason** — the attacker-brain chains findings into a MITRE ATT&CK kill-chain and mind-map;
   the attack graph measures chokepoints, blast radius, and paths to crown-jewel data.
8. **Price** — the cost engine converts findings, gaps and the recommended connectivity model
   into low/base/high line items with a CapEx/OpEx split and a confidence interval.
9. **Learn** — the run is folded into a persistent knowledge base so the next scan starts smarter.
10. **Report** — deterministic narrative text plus CSV and three PDF reports.

The subsystems, and why they are separated:

| Subsystem | Responsibility |
|---|---|
| `scanners/` | Talk to the outside world. Every function degrades to empty rather than raising. |
| `analysis/` | Pure, deterministic reasoning over findings. No network, no UI. |
| `cost/` | Convert findings and plans into money. YAML-priced, catalogue-driven. |
| `narrative/` | Template-driven prose. Same context in, same sentence out. |
| `reports/` | Serialisation to CSV and PDF. |
| `config/` | Every tunable number and string, in YAML. |
| `redflag_ui/` | Presentation only. Calls engines, flattens results into view-models. |

The strict separation is the point: the UI was migrated from Streamlit to Reflex without a single
change to the scoring, costing or planning logic.

---

## 5. Key design decisions

Eight decisions shaped the system. Each has a full record in
[docs/process/adr/](../process/adr/README.md).

| # | Decision | One-line rationale |
|---|---|---|
| [0001](../process/adr/0001-no-llm.md) | No LLM anywhere in the core | Deal documents must be reproducible and auditable; a stochastic generator is neither |
| [0002](../process/adr/0002-deterministic-yaml-narrative.md) | Deterministic YAML narrative engine | Analysts can read and edit the exact sentences the tool will print |
| [0003](../process/adr/0003-free-no-paid-api.md) | Entirely free, no paid API | Removes a per-scan cost that would otherwise discourage use |
| [0004](../process/adr/0004-reflex-ui-framework.md) | Reflex as the UI framework | Multi-page routed app in pure Python; Streamlit's rerun model could not carry it |
| [0005](../process/adr/0005-offline-brain-learn-by-remembering.md) | Brain accumulates, never trains | Retrieval over a growing corpus gives compounding value with no GPU and no drift |
| [0006](../process/adr/0006-evidence-strength-multiplier.md) | Evidence-strength multiplier | A confirmed finding should outrank a banner-only inference at equal severity |
| [0007](../process/adr/0007-epss-exploit-promotion.md) | EPSS can promote exploit status | Makes the model forward-looking rather than purely retrospective |
| [0008](../process/adr/0008-uploads-correlate-not-replace.md) | Uploads correlate into Nmap | Preserves the port-level ground truth while raising confidence |

---

## 6. Results and outcomes

**Delivered capabilities** — twelve integrated scanners and feeds, a four-factor weighted scoring
model, a seven-domain maturity assessment, a four-tier Day-1 connectivity planner, two
complementary attack-path engines (narrative and quantitative), a self-improving knowledge base,
a two-bucket cost model with statistical confidence intervals, and four export formats.

**Engineering outcomes**

- 143 automated tests across eleven test modules, covering scoring, maturity, cost, narrative,
  Day-1, EPSS, Nuclei, attack-graph, simulation and end-to-end integration.
- A UI framework migration (Streamlit → Reflex) completed with **zero changes** to the engines —
  a direct validation of the layering.
- Complete configuration externalisation: seven YAML files plus one constants module drive every
  threshold, weight, price, question and sentence.

**Operational status.** RedFlag has been exercised end to end against authorised test targets
and against the committed mock fixtures, which drive the full pipeline — merge, score, assess,
plan, cost, narrate, export — without touching a live host. It has not been used to assess a
real acquisition target, and no client report has been produced from it. It is a complete,
working tool that has not yet been put in front of a live deal.

---

## 7. Objectives met vs. outstanding

| Objective | Status | Note |
|---|---|---|
| Fuse multiple scanners into one finding set | **Met** | Correlation merge for OpenVAS, ZAP, Nuclei; Shodan enrichment; five upload slots |
| Score commercial risk, not severity | **Met** | Four-factor weighting + evidence multiplier + four override rules |
| Inside-out maturity view | **Met** | 23 questions, 7 domains, configurable corporate standard |
| Answer the Day-1 connectivity question | **Met** | Four-tier ladder with pass/blocked gates and a P0–P3 roadmap |
| Price the risk | **Met** | Remediation + integration buckets, low/base/high, 80% CI |
| Zero running cost | **Met** | Every core path works with no API key; optional keys only add enrichment |
| Attack-path reasoning | **Met** | MITRE ATT&CK narrative brain + networkx quantitative graph |
| Compliance framework mapping | **Outstanding** | ISO 27001 / NIST CSF / SOC 2 / GDPR / PCI-DSS mapping not built |
| Multi-target comparison | **Outstanding** | Single target per run |
| Secret scanning | **Outstanding** | trufflehog integration not built |
| Containerised startup | **Outstanding** | No Docker Compose |

Outstanding items are tracked in [ROADMAP.md](../process/ROADMAP.md) and
[KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md).

---

## 8. Lessons learned

**Architectural boundaries pay for themselves at the worst possible moment.** Replacing the
entire user interface — Streamlit for Reflex — took zero changes to `analysis/`, `scanners/`,
`cost/`, `narrative/` and `reports/`. That was not luck. It was the result of a rule I held to
from the first commit: the UI may call an engine and format its output, but it may never contain
a decision. Had scoring logic leaked into the presentation layer, the migration would have meant
rewriting the risk model under time pressure, with the tests no longer describing the thing being
rewritten. The discipline felt pedantic while I was writing it and paid for itself in a single
afternoon.

**Determinism is a feature when the output is evidence.** Choosing a template engine over a
language model constrained what RedFlag can say. What it bought is that the same findings always
produce the same report, every sentence traces to a YAML block someone can read and edit, and a
number in a deal document can be defended line by line. For a tool whose output may inform a
purchase price, being reproducible mattered more than being fluent.

**Constraints shaped the design rather than limiting it.** The requirement to run at zero cost
ruled out commercial vulnerability feeds and forced me toward CISA KEV, FIRST.org EPSS, NVD,
crt.sh and LeakIX. Those turned out to be the right sources anyway: KEV is the authoritative
record of what is actually being exploited, and EPSS is a better predictor of near-term
exploitation than CVSS severity. The free path was also the more defensible one.

**A pipeline with many integrations survives only if every part is allowed to fail.** Fourteen
integrations means fourteen chances for a scan to die on a timeout, a rate limit, a missing
binary or an expired key. Every scanner returns `[]` rather than raising, and the orchestration
catches broadly on purpose. The cost is that a genuine bug can be swallowed silently — a
trade-off I made deliberately and recorded in the tech-debt register rather than leaving implicit.

**Externalising configuration is what makes a scoring model arguable.** Weights, thresholds,
prices, questions and narrative text all live in YAML and one constants module. That means a
disagreement about whether exposure should outweigh CVSS is settled by editing a file and
re-running, not by reading Python. A risk model nobody can adjust is a risk model nobody trusts.

---

## 9. Timeline

Reconstructed from the commit history (dates are commit dates on `origin/main`):

| Date | Milestone |
|---|---|
| 2026-05-25 | Initial commit; scanner pipeline (Vulners NSE, ZAP, OpenVAS), PDF report, config centralisation |
| 2026-05-28 | Comprehensive README |
| 2026-05-29 | Maturity Assessment, Cost Engine and Narrative Template Engine (Build Spec v2) |
| 2026-06-05 | DNS/email security, TLS health, breach check, What-If simulator |
| 2026-06-08 | Attack Path tab |
| 2026-06-09 | `requirements.txt`; Windows + macOS installation guides |
| 2026-06-23 | First Reflex UI variant (Executive Editorial / emerald) |
| 2026-06-24 | Day-1 Safe Harbor Blueprint |
| 2026-06-29 | **Migration to Reflex complete; Streamlit `app.py` retired.** Sanitised brain seed shipped |
| 2026-06-30 | Nuclei scanning, EPSS scoring, attack-graph analytics |
| 2026-07-02 | Day-1 integration budget; variance-based confidence interval; vendor-quote overrides |
| 2026-07-27 | Documentation set for handover |

The work ran continuously from the initial commit on 2026-05-25 to the documentation set on
2026-07-27 — roughly nine weeks. The five natural phases visible above are the scanner pipeline,
the analysis and costing engines, the Phase-1 outside-in scanners, the Reflex migration, and the
Day-1 integration budget.

---

## Related documents

- [HANDOVER.md](HANDOVER.md) — the transition cover document
- [ARCHITECTURE.md](../technical/ARCHITECTURE.md) — how the solution is structured
- [adr/](../process/adr/README.md) — the decision records behind section 5
- [ROADMAP.md](../process/ROADMAP.md) — where it could go next
- [TEST_PLAN.md](../testing/TEST_PLAN.md) — evidence for the quality claims
