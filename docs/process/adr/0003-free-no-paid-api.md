# ADR-0003 — Entirely free, no paid API

**Status:** Accepted

---

## Context

Commercial security-assessment platforms carry per-scan or per-asset pricing. That model changes
behaviour in a way that is easy to miss: **when a scan costs money, people scan less.** In M&A
diligence specifically, this means a marginal target does not get assessed, or a re-scan after
remediation does not happen, or the tool is reserved for the largest deals.

RedFlag was built as an internship project without a budget, so the constraint arrived from
outside. But examining it showed the constraint was worth adopting on the merits.

The question was whether a useful assessment could actually be built from free sources. The
investigation found that the security ecosystem's most authoritative data is already public:

- **CISA KEV** — the definitive list of exploited-in-the-wild vulnerabilities. Free.
- **EPSS (FIRST.org)** — exploitation probability. Free, no key.
- **NVD (NIST)** — CVSS scores. Free, rate-limited without a key.
- **crt.sh** — certificate transparency. Free.
- **LeakIX** — breach and exposure indexing. Free for basic queries.
- **Nmap, Nuclei, OpenVAS, OWASP ZAP** — all free and open source.
- **MITRE ATT&CK** — free, with attribution.

The commercial data would have added: Shodan at scale, richer breach intelligence, vendor-specific
vulnerability feeds. Valuable, but not load-bearing.

## Decision

**RedFlag must produce a complete assessment with zero paid services and zero API keys.**

Concretely:

- **Ten of the fourteen integrations require no key at all.**
- The two keyed integrations — Shodan and Vulners — are **optional**, use free tiers, and gate no
  feature.
- Every keyed path has a free alternative: Shodan has an upload slot that takes priority over the
  live call; Vulners' exploit signal is largely covered by KEV and EPSS.
- No LLM API ([ADR-0001](0001-no-llm.md)), no GPU, no training cost
  ([ADR-0005](0005-offline-brain-learn-by-remembering.md)).

## Consequences

**Costs**

- **Shodan's free tier is limited.** 1 credit per IP means a heavy user runs out. The upload slot
  is the mitigation, but it requires the target to supply an export.
- **NVD's unauthenticated rate limit is 5 requests per 30 seconds.** `fetch_cvss_batch()` caps its
  thread pool at 5 to respect it, which makes CVSS enrichment slow on a large finding set.
- No commercial vulnerability feed, so coverage depends on what CVE data is public.
- LeakIX is the only breach source. No HIBP, no dark-web monitoring, no paid intelligence.
- **Free services can disappear or change terms.** crt.sh and LeakIX have no SLA and no
  contractual commitment to anyone.
- Free feeds are less reliable, which is why every scanner degrades silently — and that
  degradation is itself a real risk. See [LIMITATIONS.md](../../testing/LIMITATIONS.md) §4.

**Benefits**

- **Scan without hesitation.** No approval, no budget line, no per-target arithmetic. The
  behavioural effect is the point.
- Anyone can clone and run it — no procurement, no trial account, no sales call.
- No vendor lock-in and no renewal exposure.
- Fully offline-capable, which matters in a data room with no internet.
- **The constraint improved the product.** Being unable to buy commercial exploit data forced a
  proper look at KEV and EPSS — and EPSS's predictive signal ([ADR-0007](0007-epss-exploit-promotion.md))
  turned out to be genuinely better for M&A than a retrospective commercial feed. The
  attacker-brain and the brain memory ([ADR-0005](0005-offline-brain-learn-by-remembering.md))
  exist because "buy an AI service" was not available.

## Alternatives considered

**A paid Shodan plan.** Would remove the credit limit and enable subnet scanning. Rejected as a
*requirement*; the upload slot covers the common case. If someone has a plan, the tool uses it —
the decision is that it must not *need* one.

**An NVD API key.** Free to obtain and raises the rate limit substantially. Not rejected on
principle — it is simply not implemented. **This is arguably the single highest-value free
improvement available**, since NVD's limit is the pipeline's slowest step, and the key costs
nothing. Worth adding.

**Commercial vulnerability intelligence (Recorded Future, Flashpoint, Mandiant).** Better data,
genuinely. Rejected on cost, and because a tool that requires a five-figure subscription is not a
tool a small deal team will use.

**A freemium model — free core, paid enrichment.** Rejected because it makes the free path the
degraded path, and the degraded path is where most users live. Better to make the free path the
real product.

**Requiring at least one API key.** Would simplify the code by removing the "no key" branches.
Rejected: the ability to clone and run immediately, with nothing, is what makes the tool
adoptable.

---

## Related

- [ADR-0001](0001-no-llm.md) — the same constraint applied to narrative
- [ADR-0005](0005-offline-brain-learn-by-remembering.md) — improvement without a training budget
- [ADR-0007](0007-epss-exploit-promotion.md) — the free feed that improved the model
- [INTEGRATIONS.md](../../technical/INTEGRATIONS.md) §16 — running with no keys
- [LIMITATIONS.md](../../testing/LIMITATIONS.md) §4 — the cost of free feeds failing silently
