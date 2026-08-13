# Authorized Use

The legal and ethical boundaries governing the operation of RedFlag.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> ⚠️ TODO(Adi): have a supervisor or qualified counsel review this wording before the project is
> relied upon in a commercial engagement. This document is written to be accurate and protective,
> but it **is not legal advice** and its author is not a lawyer.

---

## 1. Authorized use only

**RedFlag may be run only against systems that you own, or that you have explicit, written,
current authorization to assess.**

There is no other permitted use. Specifically, the following are **not** authorization:

- The target being publicly reachable on the internet.
- A verbal "go ahead", a corridor conversation, or an assumption of consent.
- Being engaged on a deal that involves the target.
- The target being a prospective acquisition, supplier, competitor or partner.
- Someone else on the deal team saying it is fine.
- Curiosity, research interest, or the belief that a scan is "harmless".

If you cannot point to a written authorization covering **this target**, **this scope** and
**this time window**, do not run the scan.

**Before every engagement, confirm:**

| # | Check |
|---|---|
| 1 | Written authorization exists, signed by someone with authority to grant it |
| 2 | It names the specific hosts, domains or IP ranges in scope |
| 3 | It covers the dates on which you intend to scan |
| 4 | It explicitly permits **active scanning**, not merely passive research |
| 5 | You have a copy, stored somewhere you can retrieve it later |
| 6 | You know who to contact if a scan causes a problem |

---

## 2. Legal warning

Unauthorized scanning of computer systems is a **criminal offence** in most jurisdictions, and
frequently a civil wrong as well. Depending on where you and the target are located, it may
violate:

| Jurisdiction | Legislation |
|---|---|
| United States | **Computer Fraud and Abuse Act (CFAA)**, 18 U.S.C. § 1030, plus state computer-crime statutes |
| United Kingdom | **Computer Misuse Act 1990**, particularly section 1 (unauthorised access) |
| European Union | **Directive 2013/40/EU** on attacks against information systems, as implemented in each member state |
| India | **Information Technology Act 2000**, sections 43 and 66 |
| Canada | **Criminal Code**, section 342.1 |
| Australia | **Criminal Code Act 1995**, Part 10.7 |

Many of these statutes turn on **access without authorization**, and several do not require proof
of damage, intent to cause harm, or that any data was obtained. Port scanning alone has been
prosecuted.

**The operator bears the responsibility.** Not the tool, not its author, not the employer who
asked for the assessment. If you run the scan, you are the one who scanned.

**Cross-border scanning multiplies the exposure.** A scan originating in one country against a
target in another may engage the laws of both, and possibly of the countries whose networks the
traffic transits. Cloud-hosted targets may sit in a jurisdiction neither party expected. Cloud
providers additionally impose their own acceptable-use terms that may require separate
notification before security testing.

---

## 3. The M&A context specifically

M&A due diligence is an environment where the temptation to scan without authorization is
unusually strong — the information is valuable, the timeline is short, and the target's
cooperation may be limited or politically awkward. Resist it.

**Obtain written authorization from the appropriate deal parties before scanning.** Practical
guidance:

- **Route it through the deal process.** Scanning authorization normally belongs in the diligence
  request list or an access agreement, alongside data-room permissions — not in a side channel.
- **Get it from someone with authority over the systems.** The seller's corporate development
  lead may not be authorized to consent to testing of the target's production infrastructure. The
  target's CTO or CISO usually is.
- **Watch for third-party infrastructure.** A target's systems frequently run on a cloud provider,
  a managed hosting company, or a SaaS platform. **The target may not be able to authorize scanning
  of infrastructure it does not own.** Identify this before scanning, not afterwards.
- **Beware of scope creep.** RedFlag's TLS scanner queries crt.sh and discovers subdomains you
  did not know existed. Those newly discovered hosts are **not automatically in scope**. Scanning
  them is a fresh decision requiring fresh authorization.
- **Deal collapse does not retroactively authorize anything.** Nor does it un-authorize a scan
  that was properly permitted at the time — but it may trigger obligations to delete the results.
  Check the authorization's terms.
- **Keep the record.** Retain the authorization for as long as you retain the results, and at
  least as long as any applicable limitation period. If a question is raised two years later, the
  document is your answer.

---

## 4. Passive versus active — what actually touches the target

Not every RedFlag integration behaves the same way. Understanding which is which matters when
scoping an authorization.

### Actively touches the target

| Integration | What it does |
|---|---|
| **Nmap** | Sends packets directly to the target's ports. This is the loudest thing RedFlag does — it will appear in the target's logs and may trigger IDS alerts |
| **Nuclei** | Sends application-layer requests (template probes) directly to the target |
| **TLS scanner** | Opens TLS connections to each HTTPS port |
| **DNS scanner** | Queries the target's DNS records — low impact, but still directed at the target's infrastructure |

**These require explicit authorization to perform active scanning.** A permission to "look at
public information" does not cover them.

### Queries third-party indexes about the target

| Integration | What is sent, and to whom |
|---|---|
| **Shodan** | The target IP → Shodan |
| **LeakIX** | The target domain and IPs → LeakIX |
| **crt.sh** | The target domain → the certificate-transparency log |
| **NVD, CISA KEV, EPSS, Vulners** | CVE identifiers only — nothing target-identifying |

These do not touch the target. They are OSINT queries against public indexes.

**But treat them as in-scope activity anyway.** Three reasons: they still generate a record of
your interest in the target on a third party's systems; an engagement agreement or NDA may
restrict them independently of any computer-crime statute; and a target's security team monitoring
its own Shodan or certificate-transparency footprint may notice.

### Touches nothing

Uploaded OpenVAS XML, ZAP XML, Nuclei JSONL and asset-inventory Excel files are parsed entirely
locally. No network activity results.

**RedFlag can be run in a fully passive, upload-only mode** — leave the target field blank and
process staged files. Where authorization for active scanning is not available or not yet granted,
this is the correct way to use the tool.

---

## 5. Operational responsibilities

- **Scan timing.** `-T4` is aggressive timing. Against a fragile system, a scan can degrade
  performance or trip alerting. Coordinate with the target's operations team, and prefer **Fast
  mode** where thoroughness is not essential.
- **Do not expose the application to a network.** RedFlag has no authentication. Anyone who can
  reach its backend port can launch an active scan against an arbitrary target *from your machine
  and your IP address*. Keep it on `localhost`.
- **Handle the output as confidential.** A RedFlag report is a map of a company's weaknesses. It
  is more sensitive than most of the material in a data room, and should be distributed
  accordingly.
- **Mind what the brain retains.** RedFlag keeps a durable local record of every target assessed —
  hostnames in `~/RedFlag-Brain/brain.json` and one Markdown note per scan in
  `~/RedFlag-Brain/vault/Scans/`. Nothing expires. If an engagement agreement limits how long you
  may retain records about the target, that obligation covers this directory too. Deleting
  `~/RedFlag-Brain` removes it. See
  [BRAIN_KNOWLEDGE_BASE.md](../technical/BRAIN_KNOWLEDGE_BASE.md).
- **Never publish an unsanitised brain.** `export_seed()` strips the `targets` map before writing
  the shipped seed. Do not commit `~/RedFlag-Brain/brain.json` itself, and do not commit vault
  notes.

---

## 6. No warranty — informational only

RedFlag's output is **informational**. It is not a certified security audit, not a penetration
test, not an assurance opinion, and not a compliance attestation. It satisfies no regulatory
requirement on its own.

Specifically:

- **A clean report is not a certificate of security.** It may reflect broken feeds rather than a
  secure target. Several scanners fail silently by design — if CISA KEV was unreachable, no
  actively-exploited CVE will be flagged, and the report will look reassuring. See
  [LIMITATIONS.md](../testing/LIMITATIONS.md) §4.
- **Findings may be false positives.** Banner-based inference, third-party CVE association and
  ingested scanner output can all be wrong.
- **Absent findings prove nothing.** RedFlag sees an external, unauthenticated, point-in-time
  slice.
- **Costs are estimates.** Benchmark-derived ranges with a stated confidence interval, not quotes.
- **Maturity scores are self-reported and unverified.**
- **Results age immediately.** A scan describes the moment it ran.

Do not represent a RedFlag report as an audit, a penetration test, or a guarantee of any security
property. Where the findings warrant it, recommend a professional penetration test — telling you
where that spend is worthwhile is precisely what RedFlag is for.

---

## 7. Disclaimer of liability

RedFlag is provided **as is**, without warranty of any kind, express or implied, including but not
limited to warranties of merchantability, fitness for a particular purpose, accuracy and
non-infringement.

The authors and contributors accept **no liability** for any claim, damage, loss or other
liability arising from the use of this software or from any decision taken on the basis of its
output — including, without limitation:

- Any consequence of scanning a system without proper authorization
- Any disruption, degradation or outage caused by a scan
- Any deal decision made in reliance on a RedFlag report
- Any loss arising from a false positive or a missed finding
- Any breach of contract, engagement terms or applicable law by an operator

**Responsibility for lawful and authorized use rests entirely with the operator.**

> ⚠️ TODO(Adi): confirm the project's licence position. `README.md` declares MIT but **no
> `LICENSE` file exists in the repository** — see
> [LICENSES_AND_ATTRIBUTION.md](LICENSES_AND_ATTRIBUTION.md) §1. The MIT licence's own warranty
> disclaimer would normally reinforce this section, and it is currently absent.

---

## 8. Pre-scan checklist

Work through this before every engagement.

| # | Check | ✓ |
|---|---|---|
| 1 | Written authorization obtained, signed by someone with authority | ☐ |
| 2 | It names the specific hosts, domains or IP ranges in scope | ☐ |
| 3 | It covers today's date | ☐ |
| 4 | It explicitly permits **active scanning** | ☐ |
| 5 | Third-party-hosted infrastructure identified and separately authorized, or excluded | ☐ |
| 6 | Timing agreed with the target's operations team | ☐ |
| 7 | An escalation contact is available if the scan causes a problem | ☐ |
| 8 | A copy of the authorization is stored where you can retrieve it | ☐ |
| 9 | Retention obligations for the results — and for the brain — understood | ☐ |
| 10 | Everyone receiving the report understands it is not a penetration test | ☐ |

**If any box is unticked, use upload-only mode** — leave the target field blank and process staged
scanner output instead. It exercises the full analysis pipeline without touching the target at all.

---

## Related documents

- [LIMITATIONS.md](../testing/LIMITATIONS.md) — what the output cannot tell you
- [SECURITY_AND_PRIVACY.md](SECURITY_AND_PRIVACY.md) — exactly what data leaves your machine
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — per-integration behaviour and endpoints
- [LICENSES_AND_ATTRIBUTION.md](LICENSES_AND_ATTRIBUTION.md) — licence position and service terms
- [DEPLOYMENT_RUNBOOK.md](../operations/DEPLOYMENT_RUNBOOK.md) §5 — operational cautions
- [USER_GUIDE.md](../user/USER_GUIDE.md) — running an assessment
