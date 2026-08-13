# ADR-0006 — Evidence-strength multiplier

**Status:** Accepted

---

## Context

RedFlag fuses evidence from up to twelve sources, and those sources are not equally trustworthy.

Consider two findings that are identical on every scored dimension — same CVSS, same exposure,
same data sensitivity, same exploit status:

- **A:** OpenVAS ran an authenticated check against the host and confirmed the vulnerability is
  present and unpatched.
- **B:** Nmap read a version banner, and Shodan's database associates a CVE with that version
  string.

Under a purely additive weighted model these score identically. That is wrong. A is a verified
fact; B is an inference from a banner that may be stale, spoofed, or belong to a backported build
that was patched without changing its version string.

Getting this wrong has an asymmetric cost. If banner-derived findings outrank verified ones, an
analyst chases false positives, loses confidence in the tool, and eventually stops trusting the
ranking at all — at which point the ranking has no value.

Two shapes of solution were available: change the scored dimensions to encode confidence, or apply
a separate confidence adjustment after scoring.

## Decision

**Every `Finding` carries an `evidence_strength`, and the weighted base score is multiplied by a
factor derived from it.**

```python
risk_score = round(base_score * EVIDENCE_MULTIPLIERS[evidence_strength], 2)
```

| Strength | Multiplier | Meaning | Typical source |
|---|---|---|---|
| `CONFIRMED` | **1.00** | Directly verified by a tool that tested it | Nmap (the port *is* open); OpenVAS/ZAP/Nuclei; LeakIX (observed) |
| `CORRELATED` | **0.95** | Two independent sources agree | Nmap + Shodan port match |
| `UNKNOWN` | **0.90** | Not established | Default |
| `INFERRED` | **0.85** | Deduced rather than observed | "No DKIM found across 12 common selectors" |
| `EXTERNAL` | **0.80** | Third-party intelligence, unverified | Shodan's own CVE associations |

Two supporting rules make it work:

- **Correlation upgrades, never downgrades.** When an OpenVAS, ZAP or Nuclei result matches an
  existing Nmap finding, the finding's evidence strength rises
  ([ADR-0008](0008-uploads-correlate-not-replace.md)). It never falls.
- **The range is deliberately narrow — 0.80 to 1.00.** A maximum 20% discount.

## Consequences

**Costs**

- **Every scanner author must set `evidence_strength` honestly.** It is a judgement call embedded
  in each module, and an over-generous `CONFIRMED` silently inflates scores. This is the weakest
  point in the design: the discipline is convention, not enforcement.
- The multiplier is applied uniformly across all four dimensions, which is a simplification.
  Uncertainty about *exposure* is arguably different from uncertainty about *whether the
  vulnerability exists*.
- **The five values are judgement, not measurement.** Why 0.85 for `INFERRED` rather than 0.75?
  Because it felt proportionate. No empirical validation exists.
- `UNKNOWN` at 0.90 sits above `INFERRED` at 0.85, which is initially counter-intuitive — "we
  don't know" scoring higher than "we deduced it". It is deliberate precaution: an unset default
  should not be penalised more than an explicit weak inference.

**Benefits**

- **A verified finding outranks a banner-only inference at equal severity.** The ranking becomes
  trustworthy, which is the entire point of a ranking.
- **It creates an incentive that shapes behaviour correctly.** Uploading OpenVAS or ZAP output
  visibly moves findings up the list, so users supply better evidence — which makes the assessment
  better. The product rewards the behaviour it wants.
- Provenance is explicit and visible in the UI and the CSV export, so a reader can see *why* a
  finding ranks where it does.
- **The narrow 0.80–1.00 range is a deliberate safety property.** Evidence quality adjusts the
  ranking; it cannot suppress a finding. A `CVSS 10` / internet-facing / actively-exploited finding
  with the weakest possible evidence still scores about 80 and lands in the Critical tier. Weak
  evidence must never hide a severe problem.
- One multiplicative step, trivially auditable and directly tested.

## Alternatives considered

**Encode confidence into the CVSS input instead** — discount the CVSS for weak evidence. Rejected
because it corrupts a standard, externally-defined value. A reader seeing "CVSS 6.2" should be
able to look that CVE up and see 6.2.

**A fifth weighted dimension.** Add evidence as a fifth term in the weighted sum. Rejected because
evidence quality is *not* a risk dimension — it is a statement about how much to trust the other
four. Multiplication expresses that; addition does not. Additively, a finding with perfect
evidence and no risk would score points for being well-verified.

**A wider multiplier range (0.50–1.00).** Sharper separation between verified and inferred.
Rejected as dangerous: at 0.50, a genuinely severe finding with weak evidence could drop from
Critical to Manageable and be deprioritised. **Under-ranking a real vulnerability is a worse
failure than over-ranking a false positive** — the first hides a problem, the second wastes an
hour.

**Filter out low-evidence findings entirely.** Rejected outright. Suppressing a finding because it
is unverified is exactly how a diligence process misses something. Rank it lower and label it
clearly; never hide it.

**Bayesian confidence intervals per finding.** More rigorous in principle. Rejected as
unimplementable — it needs prior probabilities that nobody has, and it would make the score
uninterpretable to the deal team who has to read it.

---

## Related

- [ADR-0008](0008-uploads-correlate-not-replace.md) — how correlation raises evidence strength
- [DATA_MODEL.md](../../technical/DATA_MODEL.md) §2 — the `EvidenceStrength` enum
- [RESULTS_INTERPRETATION.md](../../user/RESULTS_INTERPRETATION.md) §2 — how to read it
- [LIMITATIONS.md](../../testing/LIMITATIONS.md) §2 — false positives and how this mitigates them
