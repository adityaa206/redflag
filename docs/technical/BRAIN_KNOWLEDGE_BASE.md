# Brain Knowledge Base

RedFlag's self-improving attacker memory: what it is, where it lives, what it stores, and what is
safe to commit.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Concept — learning by remembering

The brain gets sharper with every scan. It does this **without training a model**.

There is no neural network, no fine-tuning, no GPU, no training loop, and no paid API. The brain
is a knowledge base on disk that **accumulates** what every scan has seen — techniques, CVEs,
services, ports, attack paths, deal tiers — and **retrieves** the relevant parts when a new scan
runs. Value compounds because the corpus grows, not because weights are adjusted.

The practical payoff on scan *n* is context that scan 1 could not have:

> *"CVE-2021-44228 — seen in 3 prior scans · KEV"*
> *"This exact kill-chain has been seen before."*

Why this design rather than a model: [ADR-0005](../process/adr/0005-offline-brain-learn-by-remembering.md).

Implementation: [`analysis/brain_memory.py`](../../analysis/brain_memory.py), pure standard
library, ~340 lines, no third-party dependency.

---

## 2. Storage layout

The store lives **outside the project tree**. Two reasons: it is long-term memory that must
survive a `git clean`, and writing inside the worktree trips Reflex's dev file-watcher, which
hot-reloads the backend and destroys state mid-scan.

Root resolution order (`BrainMemory.__init__`):

1. an explicit `root` constructor argument
2. the `REDFLAG_BRAIN_DIR` environment variable
3. `~/RedFlag-Brain` (the default)

```
~/RedFlag-Brain/
├── brain.json          the index — everything the brain knows
└── vault/              a real Obsidian vault
    ├── README.md       written once, on first learn
    ├── Scans/          one note per scan: {target}-{YYYYMMDD-HHMMSS}.md
    ├── Techniques/     one note per MITRE technique: T-T1190.md
    └── CVEs/           one note per CVE: CVE-2021-44228.md
```

### `brain.json` schema

```jsonc
{
  "version": 1,
  "scans": 12,                            // total scans learned
  "first_seen": "2026-06-29T10:14:02Z",
  "last_seen":  "2026-07-02T16:41:55Z",

  "techniques": { "T1190": { "count": 9, "name": "Exploit Public-Facing Application" } },
  "cves":       { "CVE-2021-44228": { "count": 3, "cvss": 10.0,
                                      "kev": true, "services": ["http"] } },
  "services":   { "ssh":  { "count": 14, "inet": 6 } },   // inet = times internet-facing
  "ports":      { "3389": { "count": 4 } },
  "paths":      { "T1190 → T1078 → T1021 → T1567": 2 },   // kill-chain signature → times seen
  "tiers":      { "critical": 41, "deal_killer": 3 },

  "targets":    { "example.com": { "scans": 2, "last": "..." } },   // ← STRIPPED from the seed
  "kev":        { "cves": ["CVE-..."], "count": 1284, "updated": "..." }
}
```

A **kill-chain signature** is the ordered list of MITRE technique IDs from the attack plan, joined
with `→`. It only counts when there are at least two steps. That signature is what lets the brain
recognise "this exact attack path has occurred before" across different targets.

### The Obsidian vault

The `vault/` directory is a genuine [Obsidian](https://obsidian.md) vault. Open it as a vault and
use **Graph View** to see the accumulated knowledge as an actual graph: scan notes link to
technique and CVE notes via `[[wikilinks]]`, so recurring CVEs and techniques become visible hubs.

The `README.md` inside the vault notes that anything *you* add by hand becomes part of the brain's
knowledge too — there is no training step to re-run.

---

## 3. Recall, then learn

Order matters, and it is enforced by the caller in
`redflag_ui/state.py:_learn_and_recall()`:

```python
plan = analyze_attack_paths(self._findings, tgt or "target")
recall_summary, recall_items = brain.recall(self._findings, plan)   # 1. read prior knowledge
brain.learn_from_scan(self._findings, plan, tgt or "target")        # 2. then fold this scan in
```

If you learned first, every CVE in the current scan would report "seen in 1 prior scan" — the
insight would be tautological. Recall must reflect what the brain knew **coming in**.

### `recall(findings, plan) -> (summary, insights)`

- For each CVE in the current findings, looks up its prior `count`. Zero-count CVEs are skipped.
- Returns up to **6 insights**, sorted by prevalence descending, each labelled
  `"seen in N prior scans"` and suffixed `" · KEV"` when the CVE is known-exploited.
- Checks whether the current kill-chain signature has been seen before.
- On the very first run (`scans == 0`) it returns an explanatory first-scan message instead.

### `learn_from_scan(findings, plan, target)` 💾

Increments the scan counter and, for every finding, bumps:

| Bucket | What is incremented |
|---|---|
| `services[svc]` | `count`, plus `inet` when the finding is internet-facing |
| `ports[port]` | `count` |
| `cves[cve]` | `count`; `cvss` takes the running **maximum**; `kev` latches to `true` |
| `tiers[tier]` | `count` |
| `techniques[tid]` | `count`, from the attack plan's steps |
| `paths[signature]` | `count`, when the chain has ≥ 2 steps |
| `targets[target]` | `scans` and `last` timestamp |

Then it writes `brain.json` atomically (temp file + `os.replace`) and refreshes the vault notes.

**Prevalence weighting is monotonic — the brain never forgets and never ages knowledge.** A CVE
seen once in 2026 carries the same evidential weight as one seen last week. Whether recency
*should* matter is an open design question; see
[KNOWLEDGE_TRANSFER.md](../handover/KNOWLEDGE_TRANSFER.md) §4.

### Read helpers

```python
brain.stats() -> BrainStats            # scans, techniques, cves, services, paths, kev_known, vault_path
brain.top_techniques(limit=6)          # most prevalent MITRE techniques across the corpus
```

`stats()` is what renders the brain-memory panel line on the **Attack path** tab:

> *Learned from 12 scans · 9 techniques · 34 CVEs tracked · 1284 known-exploited*

---

## 4. The shipped seed

**A fresh clone does not start with an empty brain.**

The repository ships `analysis/brain_seed/brain.json` (~44 KB). On the first run on a machine with
no `~/RedFlag-Brain/brain.json`, `BrainMemory._load()` calls `_bootstrap_from_seed()`, which
copies the seed into place. From then on the local brain diverges and grows independently.

### Refreshing the seed

```bash
python -m analysis.brain_memory
```

This calls `export_seed()`, which snapshots **this machine's** accumulated brain back into
`analysis/brain_seed/brain.json` and prints a summary. Commit the result to share the knowledge
with everyone who clones.

### What sanitisation does — and what it does not

```python
def export_seed(self, dest=None) -> str:
    data = json.loads(json.dumps(self.data))   # deep copy
    data["targets"] = {}                       # drop who-was-scanned
    ...
```

`export_seed()` strips **exactly one field**: `targets`. That is the only place in `brain.json`
where a scanned host or IP is named. Everything else — technique, CVE, service, port, path and
tier prevalence, plus the KEV list — is aggregate pattern knowledge that reveals nothing about
who was assessed.

> ⚠️ **If you add a new field to `brain.json`, you must decide whether it identifies a target,
> and strip it in `export_seed()` if so.** This one function is the entire boundary between
> "local memory" and "safe to publish". It is the highest-consequence six lines in the codebase.

Note that a *local* brain is **not** sanitised — `~/RedFlag-Brain/brain.json` and the vault's
`Scans/` notes do contain target names. They are outside the repository and therefore never
committed, but they are real records of who you scanned. Treat that directory accordingly.

---

## 5. Threat-intel refresh

```python
brain.ingest_kev() -> (ok: bool, message: str, count: int)
```

Triggered by the **Refresh threat intel** button on the Attack path tab
(`RedFlagState.refresh_threat_intel`). It:

1. Downloads the free CISA Known Exploited Vulnerabilities feed
   (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
   10 s timeout, no key).
2. Stores the sorted CVE list in `brain.json` under `kev`.
3. **Back-fills** `kev: true` on every CVE the brain already knows that appears in the feed.

This is the **only network call anywhere in `analysis/`**, and it is manual and optional. Offline,
it returns `(False, "Couldn't reach the CISA KEV feed (offline?) — …", 0)` and changes nothing.

---

## 6. Configuration and data retention

| Aspect | Behaviour |
|---|---|
| Location | `~/RedFlag-Brain`, overridable with `REDFLAG_BRAIN_DIR` |
| Committed to git | **Only** `analysis/brain_seed/brain.json` (sanitised) |
| Local brain in git | Never — it lives outside the repository entirely |
| Retention | Indefinite. Nothing expires, decays, or is pruned |
| Deletion | Delete `~/RedFlag-Brain`. The next run re-bootstraps from the seed |
| Portability | Plain JSON and Markdown. Copy the directory to move it |
| Failure mode | `_save()` and `_write_vault()` swallow **all** exceptions — the brain can never break a scan, but a failure is also invisible |

**Privacy note.** The local brain accumulates a durable record of every target you have assessed:
hostnames in `targets`, and scan notes naming them in `vault/Scans/`. If you assess third-party
targets under an engagement agreement, that agreement may govern how long you may retain such
records. Deleting `~/RedFlag-Brain` removes them completely. See
[SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) and
[AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md).

**Debugging.** If the brain "isn't learning", check in this order: does `~/RedFlag-Brain` exist,
is it writable, and does `brain.json` have a recent `last_seen`? Because every write is wrapped in
a bare `except: pass`, a permissions problem produces no error message at all.

---

## Related documents

- [ADR-0005](../process/adr/0005-offline-brain-learn-by-remembering.md) — why accumulate rather than train
- [ADR-0001](../process/adr/0001-no-llm.md) — why there is no model here
- [MODULE_REFERENCE.md](MODULE_REFERENCE.md) — the `BrainMemory` API
- [ARCHITECTURE.md](ARCHITECTURE.md) — where the brain sits in the pipeline
- [SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) — committed vs. local data
