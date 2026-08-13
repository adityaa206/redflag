# User Guide

How to run an assessment in RedFlag, tab by tab.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> **Authorisation.** RedFlag performs active scanning. It may be run only against systems the
> operator owns or has explicit written authorisation to assess. See
> [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md).

---

## 1. Running a scan

Open <http://localhost:3000>. The scan bar sits at the top of every page.

### Step 1 — Enter a target *(optional)*

A hostname (`example.com`) or an IP address. The target field is **optional**: if you only want to
process uploaded scanner output, leave it blank and RedFlag skips the live scanners entirely.

Providing a target runs: Nmap, Vulners NSE (if installed), Shodan (if keyed and no upload staged),
Nuclei (if installed), DNS, TLS and the breach check.

### Step 2 — Stage supplementary files *(optional)*

Five upload slots. Each shows a filename chip once staged; a clear button removes it.

| Slot | Format | What it adds |
|---|---|---|
| **Shodan JSON** | `.json` | Internet exposure, org/ASN/geo, known CVEs. **Takes priority over the live API — costs 0 credits** |
| **OpenVAS XML** | `.xml` | Verified CVEs and configuration flaws from a credentialed scan |
| **OWASP ZAP XML** | `.xml` | Web-application findings — SQLi, XSS, IDOR, headers, cookies |
| **Nuclei JSONL** | `.jsonl` | Confirmed vulnerabilities. Run `nuclei -jsonl` anywhere; no local binary needed |
| **Asset inventory** | `.xlsx` | Classifies hosts as Crown Jewel / Regulated / Sensitive — **the only source of data sensitivity** |

**Uploads do not replace the live scan — they correlate into it.** An OpenVAS result matching a
port Nmap already found upgrades that existing finding's evidence strength, CVSS and exploit
status rather than creating a second entry. You get one ranked list, not five.

### Step 3 — Choose the scan mode *(optional)*

**Fast mode** scans the top 200 ports with lower version-probe intensity — roughly 15–25 seconds
versus 40–70 for a full scan. It is also gentler on a fragile target. Full mode finds more.

### Step 4 — Click **Run scan**

DNS, TLS and breach checks run automatically alongside Nmap. When it finishes, the notice bar
reports what was found and **which sources were fused** — for example:

> *Scan complete — 2 deal-killer findings across 47 total findings · sources: live scan, OpenVAS,
> asset inventory.*

The source list records the evidence on which the assessment is based.

### Step 5 — Complete the maturity questionnaire *(recommended)*

Several capabilities stay locked until you do. Without it:

- Two of the three Day-1 review pillars read *"Not assessed"*.
- The Federate and Integrate tier gates **fail automatically** — you cannot prove a posture you
  did not measure.
- No maturity gaps feed the roadmap or the cost model.

Go to **Maturity**, answer what you can, and submit. Only answered questions count, so a partial
questionnaire is not penalised as if the unanswered ones scored zero.

---

## 2. Trying it without a live scan

Use the committed fixtures to exercise the whole pipeline offline:

| File | Upload into |
|---|---|
| `tests/fixtures/mock_openvas.xml` | OpenVAS XML |
| `tests/fixtures/mock_zap.xml` | OWASP ZAP XML |
| `tests/fixtures/mock_nuclei.jsonl` | Nuclei JSONL *(present on disk; see note below)* |
| `tests/fixtures/sample_assessment.json` | Reference data for tests — not an upload |

Leave the target field **blank**, stage one or more files, and click **Run scan**.

The mock OpenVAS file contains EternalBlue, PrintNightmare, Log4Shell, default credentials,
Telnet, Redis exposure, TLS misconfiguration and missing security headers. The mock ZAP file
contains SQL injection, reflected XSS, IDOR, missing CSRF protection, directory listing, cookie
flags, a vulnerable jQuery and an exposed Spring Actuator endpoint.

> `mock_nuclei.jsonl` exists in the working tree but has not been committed, so it may be absent
> in a fresh clone. See
> [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §1.4.

---

## 3. Tab guide

### Overview

The summary view. It presents:

- **The verdict** — Deal Killer / Critical / Moderate / Manageable, with a one-line explanation.
  A single deal-killer finding sets the verdict to Deal Killer regardless of the average.
- **Tier counts** across all findings.
- **A risk-breakdown donut** showing the proportional split by tier.
- **The findings table**, already sorted highest risk first.

This tab is the summary view; the remaining tabs provide the supporting detail.

> ⚠️ TODO(Adi): add a screenshot of the Overview tab.

### Findings

Every finding with its CVE, CVSS, EPSS percentage, host and port, exposure level, evidence
strength and risk score. Filterable by tier.

Each row reads: *what it is · how severe · how likely to be exploited · where it is · how well
corroborated · what that adds up to*. How to interpret those:
[RESULTS_INTERPRETATION.md](RESULTS_INTERPRETATION.md).

### Attack path

Four sections:

- **The attacker's summary** — plain-language: how many internet-facing hosts give a way in, how
  many findings are weaponisable, how many internal hosts are reachable by pivoting.
- **The mind-map** — a radial diagram centred on the target with four branches: Entry points →
  Exploitation → Lateral movement → Impact, coloured by deal tier.
- **The MITRE playbook** — numbered attack steps, each linked to its technique page on
  attack.mitre.org (`T1190`, `T1110`, `T1078`, `T1021`, `T1567`…).
- **Graph analysis** — the quantitative counterpart: **chokepoints** (fix this one host and *N*
  attack paths die), **blast radius** (how many assets are reachable from the internet), and the
  **shortest path to crown-jewel data**.
- **Brain memory** — what RedFlag remembers from previous scans: *"CVE-2021-44228 — seen in 3
  prior scans · KEV"*, *"this exact kill-chain has been seen before"*. The **Refresh threat
  intel** button pulls the current CISA KEV feed.

The mind-map is descriptive; the graph is quantitative. The chokepoint ranking is a
remediation-leverage ranking and is the appropriate basis for prioritisation.

> ⚠️ TODO(Adi): add a screenshot of the attack mind-map.

### Maturity

23 questions across 7 domains: Identity & Access, Network Security, Endpoint Security,
Application Security, Data Protection, Incident Response, Third-Party Risk.

Each question offers six options; **the selected option index is the maturity level, 0 to 5**.
The scores determine the Day-1 tier gates and feed the cost model, so accuracy matters more than
optimism.

Results show each domain's score against the acquirer's `acceptable_min` and `recommended`
thresholds, with a RAG status. Domains at or below their `deal_blocker` threshold are flagged
separately from the scan findings.

The scan sees what is exposed. The questionnaire sees what is governed. The Day-1 plan needs both.

### Day 1 plan

The tab that turns the assessment into a decision for the moment the deal closes.

- **Recommended posture** — one of **Isolate → Broker → Federate → Integrate**. RedFlag
  recommends the *highest* tier whose entry gate passes: the most integrated posture the evidence
  actually justifies.
- **The ladder** — all four tiers, each marked Cleared, Active or Locked.
- **Tier gates** — what unlocks each tier, criterion by criterion, each showing Pass or Blocked
  with its reason. This is where you find out *why* you are stuck on a tier.
- **Review pillars** — Identity Sources, Network Boundaries and Remote Access Pathways, each with
  a RAG status, the evidence behind it, and a concrete recommendation.
- **Fix-first roadmap** — every finding and maturity gap sequenced into four phases:

  | Phase | Window | Meaning |
  |---|---|---|
  | **P0** Pre-Connection Blocker | Before any link | Must be fixed or formally mitigated before the networks touch |
  | **P1** Day-1 Containment | At cutover | Handle behind an isolation boundary |
  | **P2** Stabilise | First 30 days | First-month uplift |
  | **P3** Integration-Ready | Day 30–100 | Hardening to unlock the next tier |

- **Architecture catalog** — all four models with their controls and cited industry sources.

**The P0 list is the most actionable output in the product.** It is the answer to *"what must be
true before we connect?"*

### Cost

Two buckets, kept separate:

- **Remediation** — fixing the findings and maturity gaps.
- **Integration** — standing up the recommended Day-1 connectivity model.

Every figure is a **low / base / high** triple with a CapEx/OpEx split, never a single number.
Alongside it sits an **estimate accuracy** readout — an 80% confidence interval derived from each
line item's confidence, so you can see how much to trust the total.

**What-If controls:**

- **Scenario** — switch between low, base and high.
- **Scope** — restrict to deal-killers, or to deal-killers plus criticals.
- **Include maturity gaps** — toggle whether questionnaire gaps are priced.
- **Headcount** — the acquired company's user count. Several integration costs scale per user, so
  entering a real number materially tightens the accuracy band (a default guess widens it by 15%).
- **Vendor quotes** — replace a benchmark with a firm quote. That pins the item to high
  confidence, collapses its range to a single figure, and clears its high-variance flag.

The **ladder cost** view prices every rung, so you can see what integrating faster would cost.

Items flagged for human review — high variance, deal-killer linked, or no catalogue match — are
listed explicitly. That gate exists so a machine-generated number is never exported as if a human
had checked it.

### Export

| Export | Contents |
|---|---|
| **CSV** | Every finding, 17 columns: title, CVE, host, port, service, scanner, CVSS, risk score, deal tier, exposure, sensitivity, exploit status, evidence, description, remediation, override reason, timestamp |
| **Full PDF** | Executive summary, verdict, findings detail |
| **Day-1 PDF** | The Safe Harbor Blueprint: posture, gates, pillars, roadmap |
| **Cost PDF** | The remediation cost model |

> The cost PDF currently covers the **remediation bucket only** — the Day-1 integration budget,
> the ladder costs and the accuracy readout appear in the UI but not in that export. Tracked in
> [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §3.

---

## 4. A worked sequence

For a real assessment, in this order:

1. **Get written authorisation.** Keep a copy.
2. **Complete the maturity questionnaire** — ideally with the target's IT lead. It unlocks the
   Day-1 gates.
3. **Gather artefacts** — ask the target for any recent OpenVAS/ZAP reports, a Shodan export, and
   an asset inventory with data classifications. The asset inventory matters most: without it,
   nothing is ever classified as crown-jewel or regulated, and two of the three deal-killer rules
   can never fire.
4. **Stage the uploads, enter the target, run the scan.**
5. **Read Overview → Attack path (graph analysis) → Day 1 plan (P0 list) → Cost.**
6. **Review the flagged cost items** before exporting anything.
7. **Export** and attach to the diligence pack.

---

## 5. Getting more out of it

| Want | Do |
|---|---|
| More accurate risk scores | Upload an **asset inventory** — sensitivity is 20% of the weighting |
| Correct internet exposure | Supply a Shodan key or upload a Shodan JSON — exposure is 25% |
| Higher-confidence findings | Upload OpenVAS/ZAP/Nuclei output — evidence strength multiplies the score |
| A tighter cost estimate | Enter a real headcount and any vendor quotes you have |
| Day-1 gates to evaluate at all | Complete the maturity questionnaire |
| Fresher exploit intelligence | Click **Refresh threat intel** on the Attack path tab |
| A faster, gentler scan | Enable **Fast mode** |

---

## Related documents

- [RESULTS_INTERPRETATION.md](RESULTS_INTERPRETATION.md) — what every number means
- [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) — **required reading**
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — what RedFlag cannot tell you
- [TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md) — when a tab is empty or a scan misbehaves
- [INSTALLATION.md](../operations/INSTALLATION.md) — getting it running
