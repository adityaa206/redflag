# ADR-0005 — The brain accumulates, it never trains

**Status:** Accepted

---

## Context

The attacker-brain (`analysis/attack_brain.py`) is a rule-based expert system. It maps findings to
MITRE ATT&CK techniques and chains them into a kill-chain — and it produces exactly the same
output on the hundredth scan as on the first. It does not improve.

That is a real limitation. An assessment tool used across many targets accumulates something
valuable: which CVEs actually recur, which services are usually internet-facing, which attack
chains keep appearing. A tool that discards that after every run is throwing away its own best
asset.

The obvious framing is "add machine learning". That collided with two prior decisions —
[ADR-0001](0001-no-llm.md) (no model in the core) and [ADR-0003](0003-free-no-paid-api.md) (no
paid services, no GPU) — and with a third problem specific to the domain: **there is no training
signal.** Supervised learning needs labels, and the label RedFlag would want is "did this finding
lead to a breach?", which nobody has. Any trained model would be learning to predict its own prior
outputs.

Restating the goal without the word "learning" clarified it: *what should scan 100 know that scan
1 did not?* The answer is not a better model. It is **more remembered context**.

## Decision

**The brain improves by accumulating and retrieving, never by training.**

`analysis/brain_memory.py` maintains a persistent knowledge base at `~/RedFlag-Brain` (overridable
with `REDFLAG_BRAIN_DIR`):

- `brain.json` — an index of prevalence counts: techniques, CVEs, services, ports, kill-chain
  signatures, deal tiers, and the targets seen.
- `vault/` — a real Obsidian vault of Markdown notes wired together with `[[wikilinks]]`.

Two operations, in a strict order:

1. **`recall(findings, plan)`** runs *first*, reading the prior corpus and returning
   prevalence-weighted insights: *"CVE-2021-44228 — seen in 3 prior scans · KEV"*, *"this exact
   kill-chain has been seen before"*.
2. **`learn_from_scan(findings, plan, target)`** runs *second*, folding this scan in.

The order is not incidental. Learning first would make every CVE report "seen in 1 prior scan" —
tautological rather than informative.

A **sanitised seed** ships in the repository (`analysis/brain_seed/brain.json`) so a fresh clone
starts pre-loaded rather than empty. `export_seed()` strips the `targets` map — the only
target-identifying field — before writing it.

## Consequences

**Costs**

- **The insights are prevalence, not prediction.** "Seen in 3 prior scans" tells you a CVE recurs
  across your estates; it says nothing about this target's risk. It is context, not intelligence.
- **Nothing decays.** A CVE seen once a year ago carries the same weight as one seen last week.
  Whether recency should matter is a genuinely open question.
- The brain does not feed back into scoring. It is presentational — a panel on the Attack path
  tab. It could inform triage; it does not.
- Value scales with corpus size, so a first-time user sees little beyond the shipped seed.
- **Privacy weight.** The local brain accumulates a durable, permanent record of every target
  assessed. Nothing expires. That is a retention obligation someone has to own.
- **`export_seed()` is a single unguarded boundary.** Six lines decide what is safe to publish, and
  they are currently untested.

**Benefits**

- **Genuinely free.** No GPU, no training run, no API, no model file. Pure standard library.
- **Fully deterministic and inspectable.** The brain is a JSON file. You can open it, read it,
  diff it, and see exactly why an insight appeared. No model has that property.
- No drift, no retraining schedule, no reproducibility problem.
- **The vault is a real artefact.** Open `~/RedFlag-Brain/vault` in Obsidian, use Graph View, and
  the accumulated knowledge is literally visible as a graph. That is a better explanation of
  "learning" to a non-technical stakeholder than any accuracy metric.
- Notes you write by hand become part of the brain — there is no training step to re-run.
- The shipped seed means a fresh clone is useful on day one.
- Works offline, on an air-gapped machine.

## Alternatives considered

**Train a model on accumulated findings.** The obvious framing. Rejected on three counts: no
training signal exists (no breach-outcome labels), it would violate
[ADR-0001](0001-no-llm.md) and [ADR-0003](0003-free-no-paid-api.md), and a model trained on
RedFlag's own outputs would learn to reproduce RedFlag's own biases with added opacity.

**A vector database with embeddings over findings.** Semantic similarity search. Rejected as
disproportionate: the queries actually needed are exact lookups — *"have I seen this CVE ID
before?"*, *"have I seen this technique sequence?"* — which a dict answers in constant time. An
embedding model plus a vector store, for exact-match lookups, is a dependency bought for nothing.

**A SQLite knowledge base.** More rigorous than JSON, with real queries. **The closest call.**
Rejected because JSON is human-readable and diffable, which matters for the shipped seed — a
reviewer can read a JSON seed before committing it and cannot read a `.db` file. If the brain
grows to the point where the whole index no longer fits comfortably in memory, revisit this.

**No memory at all.** Simplest. Rejected because discarding the corpus wastes the one asset a
repeatedly-used assessment tool naturally builds.

**Feed prevalence into the risk score.** Tempting — a CVE seen in 8 prior scans could nudge its
score. **Deliberately not done**, because it would make the score depend on the operator's scan
history: the same finding on the same host would score differently on two analysts' machines,
destroying the reproducibility property [ADR-0001](0001-no-llm.md) exists to protect.

---

## Related

- [ADR-0001](0001-no-llm.md) — the no-model constraint
- [ADR-0003](0003-free-no-paid-api.md) — the no-cost constraint
- [BRAIN_KNOWLEDGE_BASE.md](../../technical/BRAIN_KNOWLEDGE_BASE.md) — the full technical reference
- [SECURITY_AND_PRIVACY.md](../../legal/SECURITY_AND_PRIVACY.md) §5 — committed vs. local data
- [TEST_PLAN.md](../../testing/TEST_PLAN.md) §7 — the untested sanitisation boundary
