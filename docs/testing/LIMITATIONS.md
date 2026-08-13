# Limitations

An honest account of what RedFlag cannot tell you, and where its output should not be trusted
without corroboration.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. RedFlag is not a penetration test

State this plainly to anyone who receives a RedFlag report.

RedFlag **observes and reasons**. It never exploits anything. It does not attempt authentication,
does not chain vulnerabilities to prove they are reachable, does not test application logic, and
does not verify that a theoretically exploitable finding is exploitable **on this target**.

A penetration test proves impact. RedFlag estimates likelihood and prices consequence. They answer
different questions, and one is not a substitute for the other.

It is also **not a certified audit**. It produces no assurance opinion and satisfies no
compliance requirement on its own.

**What it is for:** a structured, repeatable, low-cost first pass that tells you where to point
the expensive people, and gives a deal team something concrete to negotiate against.

---

## 2. False positives

RedFlag will sometimes report a problem that is not one.

| Source | Why it happens | Mitigation in the product |
|---|---|---|
| **Banner-based service inference** | Nmap identifies a service from its banner. Banners can be wrong, spoofed, or belong to a patched build | Nmap findings carry a flat CVSS of **3.5** — an open port is not a vulnerability |
| **DKIM "not found"** | Selectors are arbitrary names. RedFlag probes 12 common ones; a custom selector reads as absent | That finding alone is marked `INFERRED` (×0.85) rather than `CONFIRMED` |
| **Shodan CVE lists** | Shodan associates CVEs with a host from version fingerprints, not verification. The service may be patched or not affected | Marked `EXTERNAL` evidence (×0.80) |
| **DNS resolver failure** | An empty record set reads as "not configured", so a resolver outage can produce a burst of false SPF/DMARC findings | None — check the resolver if DNS findings appear unexpectedly |
| **Uploaded scanner output** | RedFlag inherits whatever OpenVAS or ZAP reported, including their false positives | Evidence strength reflects the source, but RedFlag cannot re-verify |

**The evidence-strength multiplier is the systemic answer.** A finding RedFlag merely inferred
scores up to 20% below one that a scanner verified. It does not remove false positives, but it
stops them outranking confirmed problems.

---

## 3. False negatives — the more dangerous direction

**The absence of a finding is not evidence of security.** RedFlag reports what it observed from
outside, with the data it was given.

It cannot see:

- Anything behind authentication — application flaws, authenticated API surface, admin panels
- Internal systems not reachable from the scan origin
- Application and business logic flaws
- Configuration weaknesses that produce no external signal
- Insider risk, physical security, social engineering exposure
- Anything on a port outside the scanned range (**Fast mode covers only the top 200 ports**)
- Anything a firewall or IDS blocked during the scan

Upload slots for OpenVAS, ZAP and Nuclei exist precisely because those tools reach places RedFlag
cannot.

---

## 4. Silent degradation — the most important caveat in this document

Every scanner except Nmap **fails silently by design**, so that one dead feed cannot fail a
twelve-integration pipeline. The consequence is that **a report produced with broken feeds looks
identical to one produced with healthy feeds — just cleaner.**

| Feed unavailable | What silently changes | Consequence |
|---|---|---|
| **CISA KEV** | Every `is_kev()` returns `False` | **No deal-killer override fires for an actively-exploited CVE.** The most dangerous finding class becomes invisible |
| **Shodan** | Exposure stays `PARTNER`/`INTERNAL` | Exposure is 25% of the weighting; the `INTERNAL`→`INTERNET_FACING` gap is 17.5 points of base score. **Every score is understated** |
| **NVD** | CVSS silently falls back to **6.5** | A batch of CVEs all score exactly 6.5 — a plausible-looking wrong number, not an error |
| **EPSS** | No probability, no promotion | Loses the forward-looking signal |
| **Vulners** | Exploit status stays `UNKNOWN` | Partly covered by KEV and EPSS |
| **LeakIX** | No breach findings | The "have they already been compromised?" question goes unanswered |

**Before relying on an assessment, confirm the feeds responded.** The notice bar lists the sources
that were fused. Diagnostic commands are in
[TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md) §6; the full failure table is in
[INTEGRATIONS.md](../technical/INTEGRATIONS.md) §17.

---

## 5. What the scoring model depends on that you may not have supplied

Two of the four scoring dimensions come from inputs that are optional.

**Data sensitivity (20% of the weighting)** comes from exactly one source: the asset-inventory
Excel upload. Without it every finding sits at a neutral 50 — **and two of the four deal-killer
override rules become unreachable**, because both require Crown Jewel or Regulated classification.

**Exposure (25% of the weighting)** is corrected to `INTERNET_FACING` primarily by Shodan. Without
Shodan data, `analysis/parser.py`'s conservative `PARTNER`/`INTERNAL` defaults stand.

An assessment run with neither is not wrong, but it is systematically conservative in a way the
report does not announce. Say so when you present it.

---

## 6. Model assumptions worth challenging

These are defensible choices, not facts. A reader entitled to disagree should know they exist.

| Assumption | Where | Why it might be wrong |
|---|---|---|
| The four weights (0.30 / 0.25 / 0.25 / 0.20) | `config/__init__.py` | Reasoned from SSVC and EPSS methodology, but not empirically validated against breach outcomes |
| `UNKNOWN` exploit status scores 30, above `NO_EXPLOIT` at 10 | `analysis/triage.py` | Deliberate precaution — absence of evidence treated as more dangerous than evidence of absence. Inflates scores where enrichment simply did not run |
| Any internet-facing host can pivot to **any** internal host | `analysis/attack_graph.py` | Correct for a flat network; overstates blast radius in a well-segmented one |
| The EPSS promotion threshold is 0.50 | `scanners/epss_scan.py` | A round number, not a calibrated one |
| Nmap findings get a flat CVSS of 3.5 | `analysis/parser.py` | Reasonable for "a port is open", but the same value for Telnet and for an HTTPS endpoint |
| Merged cost items take the **maximum** base | `cost/deduplicator.py` | Conservative by design; overstates cost where a single fix genuinely covers many findings |
| Cost line items correlate at 0.35 | `cost/simulation.py` | A judgement about how much estimating errors cancel. Not measured |
| Pricing benchmarks reflect a 2026 US market | `config/pricing_benchmarks.yaml`, `day1_cost_catalog.yaml` | Materially wrong for other regions or years. Retunable in YAML |
| The corporate standard thresholds | `config/corporate_standard.yaml` | One acquirer's bar. Yours may differ — that is what the YAML is for |

---

## 7. Scope boundaries

| Boundary | Detail |
|---|---|
| **Single target per run** | One hostname or IP. No subnet, no portfolio, no comparison view |
| **Single-host Shodan** | `lookup_host()` queries one IP. No `net:` search support |
| **Point in time** | Not continuous monitoring. Results age from the moment the scan ends |
| **No authenticated scanning** | RedFlag ingests OpenVAS/ZAP output but performs none itself |
| **No compliance mapping** | No ISO 27001 / NIST CSF / SOC 2 / GDPR / PCI-DSS control mapping |
| **No secret scanning** | Public-repository credential scanning is not implemented |
| **Self-reported maturity** | The questionnaire is unverified. It measures what someone said, not what is true |
| **English only** | No localisation |
| **Local, single user** | No multi-user access, no persistence between sessions, no audit trail |
| **Breach data is one source** | LeakIX only. No HIBP, no dark-web monitoring, no paid intelligence |

---

## 8. Coverage limitations

The 143-test suite covers the deterministic engines thoroughly and the following **not at all**:

- The entire Reflex UI layer, including the `run_scan` pipeline orchestration
- All live network paths and their failure modes
- PDF generation
- The brain — including `export_seed()`, the function that decides what is safe to commit

Full detail: [TEST_PLAN.md](TEST_PLAN.md) §7.

---

## 9. Conditions for presenting a report

A RedFlag report should be accompanied by the following disclosures.

| # | Disclosure |
|---|---|
| 1 | The nature of the assessment: a structured first-pass technical review, not a penetration test and not an audit |
| 2 | The inputs supplied — which uploads and feeds were used, and whether an asset inventory was provided. The notice bar's source list is the record |
| 3 | The areas not examined: authenticated surface, internal systems and application logic |
| 4 | The distinction between observed and inferred findings, as recorded in the evidence-strength column |
| 5 | Costs stated as ranges with their accuracy band. The confidence interval is a statistical statement and is lost if the base figure is quoted alone |
| 6 | Confirmation that flagged cost items were reviewed before export, so that no machine-generated figure is presented as reviewed |
| 7 | A recommendation for professional penetration testing where the findings warrant it |

---

## Related documents

- [RESULTS_INTERPRETATION.md](../user/RESULTS_INTERPRETATION.md) — how to read each number
- [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) — the legal boundaries of running it
- [TEST_PLAN.md](TEST_PLAN.md) — what is and is not verified
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — per-feed degradation behaviour
- [CONFIGURATION.md](../technical/CONFIGURATION.md) — retuning the assumptions in §6
