# Architecture Decision Records

The deliberate design choices behind RedFlag, and the reasoning that produced them.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## What an ADR is

An Architecture Decision Record captures a single significant decision: the situation that forced
it, the choice made, what that choice costs as well as what it buys, and what else was considered.

The value is not the decision — that is visible in the code. The value is the **reasoning**, which
is not. Six months later, when someone asks "why doesn't this use an LLM?", the answer should be a
document rather than a guess.

An ADR is **immutable once accepted**. If a decision is later reversed, write a new ADR that
supersedes it rather than editing the original. The history of a system's thinking is part of its
documentation.

Each record uses the standard template: **Title · Status · Context · Decision · Consequences ·
Alternatives considered**.

---

## Index

| # | Decision | Status | One-line rationale |
|---|---|---|---|
| [0001](0001-no-llm.md) | No LLM in the core | Accepted | Deal documents must be reproducible and auditable; a stochastic generator is neither |
| [0002](0002-deterministic-yaml-narrative.md) | Deterministic YAML narrative engine | Accepted | Analysts can read and edit the exact sentences the tool will print |
| [0003](0003-free-no-paid-api.md) | Entirely free — no paid API | Accepted | A per-scan cost changes how a tool is used, not just what it costs |
| [0004](0004-reflex-ui-framework.md) | Reflex as the UI framework | Accepted | A routed multi-page app in pure Python; Streamlit's rerun model could not carry it |
| [0005](0005-offline-brain-learn-by-remembering.md) | The brain accumulates, never trains | Accepted | Retrieval over a growing corpus compounds with no GPU, no drift, and no cost |
| [0006](0006-evidence-strength-multiplier.md) | Evidence-strength multiplier | Accepted | A confirmed finding should outrank a banner-only inference at equal severity |
| [0007](0007-epss-exploit-promotion.md) | EPSS can promote exploit status | Accepted | Makes the risk model forward-looking rather than purely retrospective |
| [0008](0008-uploads-correlate-not-replace.md) | Uploads correlate into the Nmap layer | Accepted | Preserves port-level ground truth while raising confidence — one list, not five |

---

## The through-line

Read together, these eight records describe one system of belief:

**Determinism over sophistication.** ADRs 0001 and 0002 give up generative fluency in exchange for
output that is identical every time and defensible in a deal room. That is the right trade when
the reader is a lawyer.

**Free as a design constraint, not a compromise.** ADR 0003 rules out paid APIs — which forced the
discovery that CISA KEV, EPSS, NVD, crt.sh and LeakIX are all free and all good. The constraint
improved the product.

**Evidence quality is first-class.** ADRs 0006, 0007 and 0008 all concern how confident the tool
should be about what it thinks it knows: corroboration raises a score, prediction can promote
exploitability, and a second opinion strengthens an existing finding rather than duplicating it.

**Value should compound.** ADR 0005 asks how a free, offline tool can get better over time, and
answers with accumulation rather than training.

**The UI is replaceable.** ADR 0004 records a framework migration completed without touching a
single engine — the strongest available evidence that the layering in
[ARCHITECTURE.md](../../technical/ARCHITECTURE.md) is real.

---

## Adding an ADR

1. Copy the structure of an existing record.
2. Number it sequentially: `0009-short-kebab-title.md`.
3. Fill in **Context** honestly — the constraints and pressures as they actually were, including
   the ones that were uncomfortable.
4. State the **Decision** in one sentence.
5. In **Consequences**, write the costs before the benefits. An ADR that lists only upsides is a
   press release.
6. In **Alternatives considered**, say why each was rejected. "We didn't think of it" is a valid
   and useful entry.
7. Add a row to the index above.

---

## Related documents

- [PROJECT_REPORT.md](../../handover/PROJECT_REPORT.md) §5 — these decisions in narrative form
- [ARCHITECTURE.md](../../technical/ARCHITECTURE.md) — the structure they produced
- [ROADMAP.md](../ROADMAP.md) — decisions still to be made
- [KNOWLEDGE_TRANSFER.md](../../handover/KNOWLEDGE_TRANSFER.md) — the tacit reasoning around them
