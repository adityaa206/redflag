# RedFlag — Handover

The master transition document: what I built, where it lives, and how to pick it up.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Project status

**Status: complete and handed over.** RedFlag runs end to end as a single Reflex web application
with a 143-test engine suite passing. Every capability listed in section 2 is implemented,
wired into the UI, and exercised by tests or by manual run-through.

"Done" here means:

- The full pipeline (scan → enrich → merge → score → assess → plan → cost → narrate → export)
  executes from a single **Run scan** click.
- All thresholds, weights, pricing, questions and narrative text are config-driven; no behaviour
  requires a code change to retune.
- The tool degrades gracefully with no API keys, no Nuclei binary, and no network for the
  optional feeds.
- Documentation for handover is in place (this set).

It does **not** mean the roadmap is exhausted — see
[KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md).

---

## 2. What was delivered

**Scanning and evidence fusion**

- Active Nmap scanning with a full mode and a top-200-port **Fast Scan Mode**.
- Passive Shodan OSINT (live API lookup, or an uploaded Shodan host JSON that takes priority).
- Nuclei template DAST — runs the local binary if present, or ingests uploaded JSONL.
- OpenVAS/GVM XML and OWASP ZAP XML ingestion that **correlate into** the Nmap layer by
  `host:port`, upgrading matched findings rather than replacing them.
- Vulners NSE parsing plus optional Vulners API exploit confirmation.
- DNS/email security audit (SPF, DMARC, DKIM, DNSSEC).
- TLS certificate health plus crt.sh certificate-transparency subdomain discovery.
- LeakIX breach and exposure lookup.
- Excel asset-inventory ingestion that stamps data sensitivity onto matching hosts.

**Intelligence enrichment**

- CISA KEV cross-reference for active-exploitation status.
- NVD CVSS v3.1 lookup with in-process caching and parallel batch fetch.
- FIRST.org EPSS exploitation probability, including **promotion** of a high-probability CVE's
  exploit status.

**Analysis**

- A weighted 0–100 risk score with an evidence-strength multiplier and four deal-killer
  override rules.
- A 23-question / 7-domain maturity assessment compared against a configurable corporate standard.
- A Day-1 Safe Harbor Blueprint: connectivity ladder, tier gates, review pillars, P0–P3 roadmap.
- An offline MITRE ATT&CK attacker-brain that chains findings into a kill-chain and renders a
  radial mind-map as SVG.
- A networkx attack-graph that quantifies chokepoints, blast radius, and shortest paths to
  crown-jewel data.
- A persistent, self-improving knowledge base ("the brain") that accumulates across scans and
  writes an Obsidian-compatible vault.

**Costing and reporting**

- A YAML-driven remediation cost engine with deduplication, low/base/high scenarios, CapEx/OpEx
  split, and a human-review gate.
- A Day-1 **integration budget** that prices the recommended connectivity model — and every rung
  of the ladder — with sourced 2026 pricing, vendor-quote overrides, and a variance-based 80%
  confidence interval.
- A deterministic, YAML-backed narrative engine (no LLM).
- CSV export plus three PDF reports (full, Day-1, cost).

---

## 3. What is not done

Nothing in the shipped feature set is known to be broken. What remains is unbuilt roadmap
work — compliance framework mapping, secret scanning, multi-target comparison, containerised
startup — plus one piece of superseded code that is no longer imported.

Full detail, including the tech-debt register:
[KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md).

---

## 4. Where everything lives

| Thing | Location |
|---|---|
| Repository | `github.com/adityaa206/redflag` (remote `origin`) |
| Working checkout | `C:\Users\Adityaa\Redflag` |
| Documentation | `docs/` (this set) |
| Reflex app entry point | `rxconfig.py` → `redflag_ui/redflag_ui.py` |
| UI state and pipeline | `redflag_ui/state.py` (`RedFlagState.run_scan`) |
| Engines | `analysis/`, `scanners/`, `cost/`, `narrative/`, `reports/` |
| Configuration | `config/` — `__init__.py` constants + seven YAML files |
| Tests and fixtures | `tests/` (143 tests), `tests/fixtures/` |
| Licence | `LICENSE` — MIT |
| Secrets | `.env` in the repo root — **git-ignored**, never committed |
| Scan output (runtime) | `%TEMP%/redflag_scans` (Windows) / `$TMPDIR/redflag_scans` |
| Knowledge base (runtime) | `~/RedFlag-Brain` — override with `REDFLAG_BRAIN_DIR` |
| Shipped brain seed | `analysis/brain_seed/brain.json` (sanitised; identities stripped) |

> The live scan output and the brain deliberately live **outside** the repository tree. Writing
> inside it trips Reflex's dev file-watcher, which hot-reloads the backend mid-scan and loses the
> findings. See [KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md).

---

## 5. How to run it in one minute

```powershell
cd C:\Users\Adityaa\Redflag
.\venv\Scripts\Activate.ps1
python -m reflex run
```

Frontend on <http://localhost:3000>, backend on <http://localhost:8000>. The first launch
compiles a Next.js frontend and needs Node.js 18+ (Reflex offers to install it).

Full instructions, including a clean install from scratch:
[INSTALLATION.md](../operations/INSTALLATION.md).

---

## 6. Access and ownership

RedFlag is a **local-only** tool. There is no hosted deployment, no database, and no cloud
account to transfer. What does need transferring is the repository and, if they are to be reused,
the two optional API keys.

- Full inventory and transfer steps: [ACCESS_AND_CREDENTIALS.md](ACCESS_AND_CREDENTIALS.md)
- Data-handling posture: [SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md)

The repository is `github.com/adityaa206/redflag`. Access is granted through GitHub's
collaborator settings; both procedures — adding a maintainer and transferring ownership
outright — are written out in
[ACCESS_AND_CREDENTIALS.md](ACCESS_AND_CREDENTIALS.md) §1.

---

## 7. Picking it up

Everything needed to run, understand, extend and operate RedFlag is in this documentation set.
The shortest useful path through it:

| To do this | Read |
|---|---|
| Get it running on a new machine | [INSTALLATION.md](../operations/INSTALLATION.md) |
| Understand how it is put together | [ARCHITECTURE.md](../technical/ARCHITECTURE.md) |
| Run an assessment and read the output | [USER_GUIDE.md](../user/USER_GUIDE.md), [RESULTS_INTERPRETATION.md](../user/RESULTS_INTERPRETATION.md) |
| Change a threshold, weight or price | [CONFIGURATION.md](../technical/CONFIGURATION.md) |
| Add a scanner or extend an engine | [DEVELOPER_ONBOARDING.md](../operations/DEVELOPER_ONBOARDING.md), [MODULE_REFERENCE.md](../technical/MODULE_REFERENCE.md) |
| Know what is deliberately *not* guaranteed | [LIMITATIONS.md](../testing/LIMITATIONS.md) |
| Run a scan lawfully | [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) |
| Understand the non-obvious parts before changing them | [KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md) |

The two things worth doing first on a new machine, because they surface most setup problems
immediately, are a clean install and a test run:

```bash
pytest tests/ -v
```

143 tests, no network, no target, no external binary required. If they pass, the engines are
intact and only the environment-specific parts — the Nmap binary and the Node.js frontend build —
remain to be verified, both of which the installation guide covers.

---

## Related documents

- [PROJECT_REPORT.md](PROJECT_REPORT.md) — the narrative account of the work
- [KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md) — what remains
- [KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md) — the non-obvious parts
- [ARCHITECTURE.md](../technical/ARCHITECTURE.md) — how the system is put together
- [INSTALLATION.md](../operations/INSTALLATION.md) — full setup
