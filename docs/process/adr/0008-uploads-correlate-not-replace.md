# ADR-0008 — Uploaded scanner output correlates into the Nmap layer

**Status:** Accepted

---

## Context

RedFlag accepts scanner output from four external tools — OpenVAS/GVM, OWASP ZAP, Nuclei and
Shodan — alongside its own Nmap scan. These overlap heavily: all five will report something about
`10.0.0.5:443`.

The naive approaches both fail.

**Concatenate everything.** Upload an OpenVAS report and a ZAP report on a live scan, and the same
HTTPS service appears three or four times as separate findings. The list length becomes a function
of how many scanners were run rather than how much risk exists. Deal tier counts inflate. The
Overview donut misleads. Cost estimates double-count. And an analyst reading the list cannot tell
whether three entries mean three problems or one problem seen three times.

**Let uploads replace the Nmap layer.** OpenVAS data is richer, so use it instead. This loses the
one thing Nmap uniquely establishes — the **complete port inventory that RedFlag itself observed**.
It also throws away the Shodan correlation already applied to those findings, and it means the
finding set changes shape depending on upload order.

The project's stated philosophy — *"every scanner contributes evidence to one unified risk
picture, not disconnected scanner outputs"* — pointed at a third option.

## Decision

**Uploaded scanner results are correlated into the existing Nmap findings by `host:port`. A match
upgrades the existing finding in place; only unmatched results become new findings.**

Implemented identically in three modules:

```python
merge_openvas_with_nmap(nmap_findings, openvas_findings)
merge_zap_with_nmap(nmap_findings, zap_findings)
merge_nuclei_with_nmap(nmap_findings, nuclei_findings)
```

On a `(host, port)` match, the existing finding is upgraded:

| Field | Rule |
|---|---|
| `evidence_strength` | Raised toward `CONFIRMED` — a second tool verified it |
| `cvss_score` | `max()` — take the higher severity |
| `exploit_status` | `_higher_exploit()` — never downgrade |
| `cve_id`, `description`, `remediation` | Enriched with the richer detail |

**Upgrade only, in every direction.** A correlation can strengthen a finding; it can never weaken
one. The `_higher_exploit()` helpers and the `max()` on CVSS exist specifically to enforce that.

Shodan follows the same principle through a different function:
`enrich_findings_with_shodan()` upgrades matched findings to `INTERNET_FACING` /`CORRELATED`, and
`create_shodan_findings()` separately creates standalone findings for CVEs and risky ports that
have no Nmap counterpart.

The merge order in `run_scan` is Nmap → Vulners → Shodan → OpenVAS → ZAP → Nuclei → DNS/TLS/breach
→ asset sensitivity → EPSS → triage.

## Consequences

**Costs**

- **Correlation is `host:port` only.** A ZAP finding reported against a URL path rather than a
  port, or an OpenVAS result whose host is a hostname where Nmap recorded an IP, will not match —
  and will be added as a separate finding. Some duplication survives.
- Upgrading in place **loses per-scanner attribution**. The merged finding carries one
  `scanner_source`, so "which tool found this?" is no longer cleanly answerable for correlated
  findings.
- The merge functions mutate their input, which is efficient but makes them harder to reason about
  than pure transformations.
- Three near-identical merge implementations exist — a duplication noted as tech debt in
  [KNOWN_ISSUES_AND_BACKLOG.md](../../handover/KNOWN_ISSUES_AND_BACKLOG.md) §3.
- Upload-only mode (no target, therefore no Nmap layer) takes a different path: uploads are simply
  appended, since there is nothing to correlate into.

**Benefits**

- **One finding per real problem.** Tier counts, the risk donut, and the cost model all describe
  risk rather than scanner count.
- **Nmap's port inventory is preserved** as the structural backbone. RedFlag always knows what it
  itself observed.
- **Evidence strength rises exactly when it should** — when two independent tools agree, which is
  precisely what [ADR-0006](0006-evidence-strength-multiplier.md) is designed to reward.
- **No double-counting in the cost model.** The deduplicator handles catalogue-level duplication;
  this handles finding-level duplication. Both are needed.
- **Uploading more data always improves the assessment and never inflates it.** That property is
  what makes the upload slots safe to use liberally — an analyst can add every artefact the target
  supplies without worrying about distorting the numbers.
- Uniform contract across OpenVAS, ZAP and Nuclei, so adding a fourth correlating scanner is a
  known shape of work.

## Alternatives considered

**Concatenate and deduplicate afterwards.** Add everything, then collapse duplicates in a separate
pass. Rejected because deduplication after the fact must decide which duplicate is canonical and
how to combine their fields — the same merge logic, done later, on a larger set, with the
intermediate inflated state visible if anything fails partway.

**Let uploads replace the Nmap layer.** Rejected: loses RedFlag's own port inventory, discards
Shodan enrichment already applied, and makes the result depend on upload order.

**Keep every scanner's findings separate, in per-source sections.** How most multi-scanner tools
present results. Rejected because it is exactly the problem RedFlag exists to solve — a deal team
needs one ranked list, not five lists to reconcile themselves.

**Correlate on a fingerprint rather than `host:port`** — service name, product, version, CVE.
Would catch more matches, including the port-less cases. Rejected for this version as
over-engineering with a real risk of *false* merges, which would be worse than the duplicates it
prevents: two genuinely distinct problems collapsed into one is a finding lost. **The best
candidate for a future improvement**, if paired with careful tests.

**Correlate on CVE ID.** Would match across hosts. Rejected because the same CVE on two different
hosts is genuinely two findings with different exposure and different remediation work.

---

## Related

- [ADR-0006](0006-evidence-strength-multiplier.md) — what correlation earns a finding
- [DATA_MODEL.md](../../technical/DATA_MODEL.md) §4 — the finding lifecycle
- [ARCHITECTURE.md](../../technical/ARCHITECTURE.md) §4 — merge order in the pipeline
- [MODULE_REFERENCE.md](../../technical/MODULE_REFERENCE.md) — the merge function signatures
- [USER_GUIDE.md](../../user/USER_GUIDE.md) §1 — how this appears to a user
