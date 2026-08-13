# ADR-0001 — No LLM in the core

**Status:** Accepted

---

## Context

RedFlag produces documents that inform a commercial decision: whether to buy a company, at what
price, and with what warranties. Those documents may be attached to a diligence pack, cited in
negotiation, and read years later by people reconstructing why a decision was made.

Three properties follow from that audience:

1. **Reproducibility.** The same scan data must produce the same report. If two analysts run the
   same assessment and get materially different narratives, neither can be relied upon.
2. **Auditability.** A reader must be able to trace any statement back to the finding and the rule
   that produced it. "The model said so" is not a defensible provenance.
3. **Zero marginal cost.** A hard constraint from [ADR-0003](0003-free-no-paid-api.md).

A large language model was the obvious way to generate fluent narrative from structured findings,
and the temptation was real — the alternative is more work and less elegant prose. It fails all
three properties. Temperature-zero sampling reduces variance but does not eliminate it, and it
does nothing for auditability or cost. Local models remove the cost but add a GPU requirement, a
multi-gigabyte download, and a new class of failure.

There is also a specific risk in this domain: an LLM asked to summarise security findings will
occasionally produce a confident, well-written statement that is not supported by the data. In a
deal document, a plausible-sounding hallucination is worse than no narrative at all.

## Decision

**RedFlag's core contains no LLM, and no dependency on any model — local or remote.**

Every analytical output is produced by deterministic code:

- Risk scoring: a weighted formula plus lookup tables (`analysis/triage.py`)
- Attack-path reasoning: a rule-based MITRE ATT&CK expert system (`analysis/attack_brain.py`)
- Graph analytics: networkx (`analysis/attack_graph.py`)
- Narrative: condition-matched templates ([ADR-0002](0002-deterministic-yaml-narrative.md))
- The knowledge base: accumulation and retrieval, never training
  ([ADR-0005](0005-offline-brain-learn-by-remembering.md))

The README's roadmap lists an *optional* free-tier LLM layer over the brain. If built, it must be
**additive and clearly labelled** — it must never replace or alter a deterministic output.

## Consequences

**Costs**

- The narrative is less fluent than generated prose, and more repetitive across reports.
- Every sentence must be written by hand into `config/narrative_blocks.yaml`. Adding a nuance
  means adding a template and a condition.
- The attacker-brain reasons only about patterns explicitly encoded in it. It cannot recognise a
  novel technique or an unusual chain.
- No natural-language querying of findings.
- Some reviewers will read "no AI" as "unsophisticated". The sophistication is in the scoring and
  the graph analytics, but it is less visible than a chat box.

**Benefits**

- **The same input always produces the same output.** Two analysts, two machines, same report.
- Every statement traces to a finding, a rule and a template — fully auditable.
- **Zero marginal cost per scan.** No API bill, no rate limit, no vendor dependency.
- Fully offline. Works on an air-gapped machine, in a data room with no internet, on a plane.
- No hallucination risk. The tool cannot invent a finding or overstate one.
- No target data is ever sent to a model provider — a genuine concern when the data describes a
  third party's security weaknesses under an NDA.
- The engines are trivially testable: 143 tests, nine seconds, no network, no mocking.

## Alternatives considered

**A hosted LLM API (OpenAI, Anthropic, or similar).** The best narrative quality by a distance.
Rejected on all three counts: it costs money per scan, output varies between runs, and it would
transmit a third party's security findings to a model provider — a hard conversation to have with
a target that agreed to be scanned but not to have its weaknesses uploaded.

**A local open-weights model (Llama, Mistral).** Removes the cost and the egress problem.
Rejected because it adds a GPU expectation and a multi-gigabyte download to a tool otherwise
installable with `pip install -r requirements.txt`, and because it does not solve reproducibility
or auditability — the two properties that actually mattered.

**LLM for narrative only, deterministic scoring.** The most tempting middle ground, and the
closest call. Rejected because the narrative is what most readers actually read. A scored table
nobody reads plus a paragraph that varies between runs is not meaningfully more auditable than a
fully generated report.

**Retrieval-augmented generation over the brain.** Attractive in principle. Deferred rather than
rejected — it remains on the roadmap as an optional layer, precisely because the brain's
retrieval half already works deterministically without it.

---

## Related

- [ADR-0002](0002-deterministic-yaml-narrative.md) — what replaced generated prose
- [ADR-0003](0003-free-no-paid-api.md) — the cost constraint that reinforced this
- [ADR-0005](0005-offline-brain-learn-by-remembering.md) — improvement without training
- [BRAIN_KNOWLEDGE_BASE.md](../../technical/BRAIN_KNOWLEDGE_BASE.md)
