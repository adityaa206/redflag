# Interpreting the Results

What every number RedFlag prints actually means, and how far to trust it.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

Every value in this document is taken from `analysis/triage.py` and `config/__init__.py`, not from
the README.

---

## 1. The risk score

Each finding gets a **0–100 risk score**. It is not a severity rating — it is an estimate of
commercial risk to the deal, which is why a CVSS 9.8 on an unreachable internal box can score
lower than a CVSS 7.5 on an internet-facing system holding regulated data.

Two steps: a weighted base score, then an evidence adjustment.

### Step 1 — the weighted base

```python
cvss_normalized = (cvss_score / 10.0) * 100        # 0–10 → 0–100

base_score = (exploit_score     * 0.30)    # can it actually be exploited?
           + (exposure_score    * 0.25)    # can an attacker reach it?
           + (cvss_normalized   * 0.25)    # how severe is it technically?
           + (sensitivity_score * 0.20)    # what is at risk behind it?
```

The four weights sum to 1.0, so the base score is itself 0–100.

**Why exploitability outweighs severity.** Aligned with CISA's SSVC methodology and EPSS
research: a known-exploited vulnerability demands action regardless of its CVSS, while a
theoretical CVSS 10 with no exploit and no reachability is a backlog item. Exposure and CVSS are
weighted equally because a high CVSS on an unreachable service is genuinely less urgent than a
moderate CVSS on an internet-facing one.

### Step 2 — the evidence adjustment

```python
risk_score = round(base_score * evidence_multiplier, 2)
```

The multiplier is 0.80–1.00, so the worst case is a 20% discount. Two findings with identical
severity, exposure and exploitability differ by up to 20 points depending on how well corroborated
they are — a verified OpenVAS result outranks a banner-only inference. Rationale:
[ADR-0006](../process/adr/0006-evidence-strength-multiplier.md).

---

## 2. The lookup tables

All four verified against `analysis/triage.py`.

### Exposure — can an attacker reach it?

| Level | Score | Set by |
|---|---|---|
| Internet Facing | **100** | Shodan port confirmation; DNS, TLS, breach and Shodan-standalone findings |
| Partner | **60** | `analysis/parser.py` for commonly exposed services (http, https, ssh, rdp, ftp, telnet, vnc, smb, netbios-ssn) |
| Internal | **30** | `analysis/parser.py` default for everything else |
| Unknown | **50** | Not established |

The `INTERNAL` → `INTERNET_FACING` jump is worth **17.5 points** of base score on its own. This is
the largest single mover in the model, and it usually comes from Shodan. **Without Shodan data,
scores materially understate risk.**

### Data sensitivity — what is at risk?

| Level | Score | Meaning |
|---|---|---|
| Crown Jewel | **100** | The organisation's most valuable data or systems |
| Regulated | **85** | GDPR / HIPAA / PCI-DSS scope |
| Sensitive | **55** | Confidential but not regulated |
| Low | **20** | Public or low-value |
| Unknown | **50** | Not classified |

Set from exactly one source: the **asset-inventory Excel upload**. Without it every finding sits
at the neutral 50 — **and two of the three deal-killer override rules become unreachable**,
because both require Crown Jewel or Regulated.

### Exploit status — is it actually exploitable?

| Status | Score | Source |
|---|---|---|
| Active Exploitation | **100** | CISA KEV, or a LeakIX credential/database exposure |
| Public Exploit | **65** | Vulners confirmation, or **EPSS ≥ 0.50 promotion** |
| Unknown | **30** | Nothing established |
| No Exploit | **10** | Confirmed no known exploit |

Note that **Unknown (30) scores higher than No Exploit (10)**. That is deliberate: absence of
evidence is treated as more dangerous than evidence of absence.

### Evidence strength — how well corroborated?

| Strength | Multiplier | Typical source |
|---|---|---|
| Confirmed | **1.00** | Nmap confirmed the port open; OpenVAS/ZAP/Nuclei verified the vulnerability; LeakIX observed the exposure |
| Correlated | **0.95** | Two independent sources agree — usually Nmap plus Shodan |
| Unknown | **0.90** | Not established |
| Inferred | **0.85** | Deduced rather than observed — e.g. no DKIM found across 12 common selectors |
| External | **0.80** | Third-party intelligence, unverified — Shodan's own CVE list |

---

## 3. Deal-killer overrides

Four conditions **bypass scoring entirely**. When one fires, `risk_score` is forced to exactly
**100.0**, the tier becomes `DEAL_KILLER`, and `override_reason` explains why.

| # | Condition | Why |
|---|---|---|
| 1 | `exploit_status == ACTIVE_EXPLOITATION` | The CVE is in CISA KEV — confirmed exploited in the wild. Weaponised code exists now |
| 2 | `data_sensitivity == CROWN_JEWEL` **and** `cvss >= 9.0` **and** `exposure == INTERNET_FACING` | The most valuable asset, critically vulnerable, publicly reachable |
| 3 | `data_sensitivity == REGULATED` **and** `cvss >= 9.5` **and** `exposure == INTERNET_FACING` | Regulatory liability at critical severity, publicly reachable |
| 4 | `override_reason` contains the phrase `"active compromise"` | Manual analyst flag |

**Reading a deal killer:** it is not "a very high score". It is a categorical statement that this
finding alone should stop the deal until it is resolved or contractually mitigated. Rules 2 and 3
can only fire if you uploaded an asset inventory.

---

## 4. The four deal tiers

Score thresholds from `config/__init__.py`.

| Tier | Trigger | What it means | Recommended action |
|---|---|---|---|
| **Deal Killer** | Any override rule | Unacceptable pre-close risk | Escalate before signing. Remediate or contractually mitigate |
| **Critical** | Score **≥ 75** | Severe exposure | Remediate within 30 days of close; obtain a written commitment |
| **Moderate** | Score **≥ 50** | Material gap | 90-day post-close security roadmap |
| **Manageable** | Score **< 50** | Standard hygiene | Normal backlog |
| *Unscored* | Triage has not run | Not yet assessed | Skipped by the cost engine |

### The Overview verdict

The headline verdict is not simply the worst finding:

| Verdict | Condition |
|---|---|
| **Deal Killer** | At least one deal-killer finding — *regardless of the average* |
| **Critical** | No deal killers, but the **average** score ≥ 75 |
| **Moderate** | No deal killers, average ≥ 50 |
| **Manageable** | No deal killers, average < 50 |

One deal killer among a hundred benign findings still produces a Deal Killer verdict. That is
correct — a single actively-exploited internet-facing CVE is not diluted by good hygiene
elsewhere.

---

## 5. EPSS promotion

**EPSS** (Exploit Prediction Scoring System, from FIRST.org) gives the probability that a CVE will
be exploited **in the next 30 days**.

RedFlag fetches it for every CVE and displays it on each finding (`EPSS 92%`). Where it changes
the answer:

> If a CVE has **EPSS ≥ 0.50** and its exploit status is `UNKNOWN` or `NO_EXPLOIT`, that status is
> promoted to `PUBLIC_EXPLOIT` — moving its exploit component from 30 (or 10) to 65.

The effect on the score is **+10.5 points** from `UNKNOWN`, or **+16.5** from `NO_EXPLOIT`.

**Why:** CISA KEV is retrospective — a CVE enters it after exploitation is observed. EPSS is
predictive. A CVE that is 92% likely to be exploited this month should be treated like one with a
known public exploit, not parked because nobody has filed the paperwork yet. Rationale:
[ADR-0007](../process/adr/0007-epss-exploit-promotion.md).

Promotion is marked in the finding's `raw_data` as `epss_promoted: true`. It never downgrades a
finding, and never touches one already at `ACTIVE_EXPLOITATION`.

---

## 6. Reading the Attack Path tab

**The mind-map narrates; the graph measures.** Use them for different questions.

### The MITRE playbook

Numbered attacker steps, each mapped to a MITRE ATT&CK technique with a link to its page. It
describes the **single worst path** — the highest-risk entry point followed through to impact —
not every possible path.

This is derived from your findings by a rule-based expert system, not observed. It answers *"what
would a competent attacker most likely do?"*, not *"what has happened."*

### Graph analysis

| Metric | Question it answers | How to use it |
|---|---|---|
| **Chokepoints** | Which single host or service, if fixed, severs the most attack paths? | **The remediation-leverage ranking.** "Patch this one box and 6 paths die" |
| **Blast radius** | How many assets are reachable from the public internet? | The scale of the exposure |
| **Crown-jewel paths** | The shortest route from the internet to sensitive data | Fewer hops = more urgent |

A caveat on the graph model: lateral movement is modelled as *any* internet-facing host being able
to pivot to *any* internal host. That is a deliberately pessimistic assumption. It is right for a
flat network and overstates risk in a well-segmented one — but you rarely know which you have
before you look, and segmentation is exactly what the maturity questionnaire asks about.

### Brain memory

Prevalence across previous scans: *"seen in 3 prior scans · KEV"*. This is corpus context, not a
judgement about this target. A CVE seen often is a CVE that recurs across the estates you assess —
useful for pattern recognition, irrelevant to this finding's severity.

---

## 7. Reading the Maturity tab

Scores are **0–5 per domain**, a weighted mean of the questions you answered.

| Level | Rough meaning |
|---|---|
| 0 | Nothing in place |
| 1 | Ad hoc, undocumented |
| 2 | Basic controls, inconsistently applied |
| 3 | Defined and mostly consistent |
| 4 | Managed, measured, reviewed |
| 5 | Optimised, automated, continuously improved |

Each domain is compared against three thresholds from `config/corporate_standard.yaml`:

| Threshold | Meaning |
|---|---|
| `deal_blocker` | At or below this → flagged as a maturity deal blocker |
| `acceptable_min` | Below this → a gap requiring an agreed improvement plan |
| `recommended` | The 12-month post-acquisition target |

Most domains are set to `acceptable_min: 2`, `recommended: 3` or `4`, `deal_blocker: 1`.
**Incident Response is the exception** (`deal_blocker: 0`): a missing IR plan is a real gap, but on
its own it is not a reason to walk away.

**Only answered questions count.** A partial questionnaire is not penalised as if the unanswered
questions scored zero — but an unanswered *domain* has no score at all, which causes the Day-1
tier gates that depend on it to fail as *"Not assessed."*

Two things trigger an overall maturity deal-blocker: any single domain at or below its
`deal_blocker` threshold, **or** the mean across all seven domains falling to 1.5 or below.

---

## 8. Reading the Day-1 ladder

RedFlag recommends the **highest tier whose entry gate passes** — the most integrated posture the
evidence justifies, not the safest possible one.

| Tier | What it means | Gate requirements |
|---|---|---|
| **Isolate** | No network route at all. The business runs standalone under a TSA; data moves through a governed clean room | *(none — always available)* |
| **Broker** | Users reach apps through a brokered virtual desktop. Pixels in, no data egress, no network route — a compromised target cannot pivot into the parent | No actively-exploited vulnerabilities |
| **Federate** | Limited identity federation (one-way trust or Entra B2B) plus per-app ZTNA access, replacing legacy VPN/RDP | The above, plus: no internet-facing remote access; Identity and Network maturity ≥ acceptable_min |
| **Integrate** | Full directory consolidation and routed networks | The above, plus: no internet-facing deal-killers; Identity and Network maturity at **recommended** |

**Reading a blocked gate.** Each criterion shows Pass or Blocked with its reason. The tab also
names exactly what would unlock the next tier up. A `maturity_min` criterion **fails when the
domain was never assessed** — you cannot prove a posture you did not measure, so an incomplete
questionnaire pins you to a lower tier.

### The P0–P3 roadmap

Every finding and maturity gap lands in exactly one phase, by the **first matching rule**:

| Phase | Window | What lands here |
|---|---|---|
| **P0** Pre-Connection Blocker | Before any link | Actively exploited · deal killers · internet-facing remote access · internet-facing public exploits · maturity deal-blockers |
| **P1** Day-1 Containment | At cutover | Other internet-facing exposure · partner-exposed remote access |
| **P2** Stabilise | First 30 days | Critical-tier findings · partner-exposed services · below-minimum maturity gaps |
| **P3** Integration-Ready | Day 30–100 | Everything else — internal hygiene |

**The P0 list is the single most actionable output in the product.** It is the literal answer to
*"what must be true before these two networks touch?"*

---

## 9. Reading the Cost tab

### Never a single number

Every figure is a **low / base / high** triple:

- **low** — best case: minimal scope, in-house labour
- **base** — most likely: benchmark rates, standard scope
- **high** — worst case: consultant rates, full scope, overtime

Use **base** for planning and **high** for negotiating a price adjustment.

### Two buckets

| Bucket | What it prices |
|---|---|
| **Remediation** | Fixing the findings and closing the maturity gaps |
| **Integration** | Standing up the recommended Day-1 connectivity model |

They are deliberately separate and never deduplicated against each other — they answer different
questions: *what does the debt cost* versus *what does connecting safely cost*.

### CapEx vs OpEx

CapEx is one-time (tools, infrastructure, architecture); OpEx is recurring (labour,
subscriptions, retainers). Items marked `MIXED` split 50/50. The distinction matters for how the
cost is treated in the deal model.

### Estimate accuracy

The accuracy readout is a **variance-based 80% confidence interval** (P10 / P50 / P90), not an
average of the ranges.

Its honesty is worth understanding. Each line item is treated as a triangular distribution,
widened by its confidence (`high ×1.0`, `medium ×1.25`, `low ×1.6`). Items are then aggregated
with **partial correlation (0.35)** — independent estimating errors partly cancel out, which
tightens the band, but a common-mode market factor stops it becoming unrealistically tight. The
result is clamped to ±8–55%. If the headcount was a default guess rather than a real number, the
band widens by a further 15%.

**This means "±22%" is a genuine statistical statement, not a gesture.** To tighten it: enter the
real headcount, and enter vendor quotes where you have them — a quote pins that item to high
confidence and collapses its range to a single figure.

### Review flags

| Flag | Meaning |
|---|---|
| `HIGH_VARIANCE` | The high/low spread exceeds 3× — scope this manually |
| `ZERO_ESTIMATE` | No catalogue entry matched; it fell through to the default |
| `DEAL_KILLER_ITEM` | Linked to a deal-killer finding — always flagged |
| `DUPLICATE` | Merged from several findings needing the same fix |
| `MANUAL_REQUIRED` | Needs human judgement |

The review gate exists so that a machine-generated number is never exported as if a human had
checked it. **Read the flagged items before exporting.**

### What-If

Switching scenario, restricting scope to deal-killers, toggling maturity gaps, changing headcount
and entering quotes all recompute the totals live — the pipeline is deterministic and fast enough
to re-run on every change.

---

## 10. How much to trust a RedFlag number

**High confidence:** an open port from Nmap; a certificate expiry date; a missing DMARC record; a
LeakIX-indexed exposure. These are observed facts.

**Medium confidence:** the risk score. The formula is deterministic and the weights are
defensible, but the inputs vary in quality — and two of the four dimensions depend on data you may
not have supplied.

**Read with care:**

- **Any assessment run without an asset inventory.** Sensitivity sits at a neutral 50 everywhere,
  and two of the four deal-killer rules cannot fire.
- **Any assessment run without Shodan data.** Exposure is understated, and exposure is 25% of the
  weighting.
- **A clean report when a feed was down.** If CISA KEV was unreachable, no deal-killer override
  fires for an actively-exploited CVE, and the report looks reassuring. If NVD was unreachable,
  every CVE silently scores 6.5. Check the notice bar's source list, and see
  [INTEGRATIONS.md](../technical/INTEGRATIONS.md) §17.
- **The absence of a finding.** RedFlag reports what it observed. It cannot report what it could
  not see — authenticated flaws, internal systems, application logic, insider risk.

**RedFlag is not a penetration test and not a certified audit.** It is a structured, repeatable
first pass that tells you where to point the expensive people. See
[LIMITATIONS.md](../testing/LIMITATIONS.md).

---

## Related documents

- [USER_GUIDE.md](USER_GUIDE.md) — how to produce these results
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — the honest caveats in full
- [DATA_MODEL.md](../technical/DATA_MODEL.md) — the fields behind every value here
- [CONFIGURATION.md](../technical/CONFIGURATION.md) — how to retune the weights and thresholds
- [ADR-0006](../process/adr/0006-evidence-strength-multiplier.md), [ADR-0007](../process/adr/0007-epss-exploit-promotion.md)
