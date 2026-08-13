# Troubleshooting

Symptom → cause → fix.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Quick reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `'nmap' is not recognized` / `Could not find nmap.exe` | Nmap not installed, or installed outside the two paths RedFlag probes | [§2.1](#21-nmap-not-found) |
| `ModuleNotFoundError` on launch | Virtual environment not activated | [§2.2](#22-modulenotfounderror) |
| `python: command not found` (macOS) | macOS ships `python3` | Use `python3`, or `brew install python` |
| Port 3000 or 8000 already in use | An earlier instance is still running | [§2.3](#23-port-already-in-use) |
| First launch is very slow / asks to install Node | Reflex is building the frontend | Expected once, ~1 min. [§2.4](#24-slow-first-launch) |
| Scan completes but returns **no findings** | Nmap missing, or the target has no open ports | [§2.5](#25-scan-returns-no-findings) |
| Scan runs, then findings **disappear** | Something wrote inside the worktree and triggered a hot reload | [§2.6](#26-findings-vanish-mid-scan) |
| Blank page / "cannot resolve react" | The checkout is inside OneDrive or another synced folder | [§2.7](#27-blank-page-or-broken-frontend) |
| Everything scores low; nothing is internet-facing | No Shodan key and no Shodan upload | [§3.1](#31-no-shodan-data) |
| No deal killers even with known-exploited CVEs | CISA KEV feed unreachable | [§3.2](#32-kev-feed-unreachable) |
| All CVEs show CVSS exactly 6.5 | NVD unreachable — 6.5 is the silent fallback | [§3.3](#33-every-cvss-is-65) |
| Every finding shows sensitivity "Unknown" | No asset-inventory Excel uploaded | [§3.4](#34-all-findings-unknown-sensitivity) |
| Excel upload fails with a column error | Missing host or sensitivity column | [§3.5](#35-asset-excel-rejected) |
| Shodan JSON upload rejected | Not a Shodan *host* record | [§3.6](#36-shodan-json-rejected) |
| Nuclei never contributes anything | Binary not installed | [§3.7](#37-nuclei-does-nothing) |
| "No DKIM Selector Found" on a domain that has DKIM | Custom selector name | [§3.8](#38-false-dkim-finding) |
| Day-1 tab says "awaits data" | No scan run and no questionnaire completed | [§4.1](#41-day-1-tab-empty) |
| Day-1 always recommends **Isolate** | A gate criterion is failing | [§4.2](#42-day-1-always-recommends-isolate) |
| Maturity gates fail even with good scores | Questionnaire not submitted | [§4.3](#43-maturity-gates-fail-unassessed) |
| Cost is $0 or every item flagged for review | Findings unscored, or nothing matched the catalogue | [§4.4](#44-cost-is-zero-or-everything-flagged) |
| Brain shows 0 scans / never updates | `~/RedFlag-Brain` missing or not writable | [§5.1](#51-brain-not-learning) |
| A YAML edit has no effect | The loader cache is per-process | [§5.2](#52-config-change-not-taking-effect) |
| PDF export raises an encoding error | An unsupported character reached fpdf2 | [§5.3](#53-pdf-export-fails) |
| Dev server dies on save | A compile error in a component | [§5.4](#54-dev-server-crashes-on-edit) |

---

## 2. Installation and startup

### 2.1 Nmap not found

```
Scan failed: Could not find nmap.exe. Check whether Nmap is installed in Program Files.
```

`scanners/nmap_scan.py:find_nmap()` probes **only** two paths and does **not** consult `PATH`:

- `C:\Program Files (x86)\Nmap\nmap.exe`
- `C:\Program Files\Nmap\nmap.exe`

**Windows:** reinstall Nmap with the default install location, then verify:

```powershell
python -c "from scanners.nmap_scan import find_nmap; print(find_nmap())"
```

**macOS/Linux:** a Homebrew Nmap at `/opt/homebrew/bin/nmap` will not be found. Either use
upload-only mode (leave the target blank and stage files), or add your path to `NMAP_PATHS` —
see [INSTALLATION.md](INSTALLATION.md) §7.

### 2.2 ModuleNotFoundError

The virtual environment is not active. The prompt should show `(venv)`.

```powershell
.\venv\Scripts\Activate.ps1     # Windows
source venv/bin/activate        # macOS / Linux
```

If PowerShell blocks the activation script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

If it persists after activating, reinstall: `pip install -r requirements.txt`.

### 2.3 Port already in use

```bash
python -m reflex run --frontend-port 3001 --backend-port 8001
```

Or free the port:

```powershell
netstat -ano | findstr :3000
taskkill /PID <pid> /F
```

```bash
lsof -ti:3000 | xargs kill -9
```

### 2.4 Slow first launch

Expected. Reflex compiles a Next.js frontend into `.web/` on first run — about a minute — and
needs Node.js 18+. Let it install Node, or install it yourself from
[nodejs.org](https://nodejs.org). Later launches reuse the build.

### 2.5 Scan returns no findings

In order of likelihood:

1. **Nmap is not installed** — see §2.1. This is by far the most common cause.
2. **The target genuinely has no open ports** in the scanned range. Try full mode instead of fast
   mode (fast mode only covers the top 200 ports).
3. **You are in upload-only mode with nothing staged.** With no target and no uploads, the scan
   button reports *"Enter a target host or IP, or stage an intelligence file, first."*
4. **A firewall is dropping the scan.** Verify manually: `nmap -sV --open <target>`.

### 2.6 Findings vanish mid-scan

The tell-tale is `Compiling…` appearing in the `reflex run` terminal **during** a scan.

Reflex's development file-watcher monitors the worktree. Any write inside it triggers a hot
reload, which **resets backend state** — the scan finishes but `_findings` has been wiped.

This is why Nmap writes to `%TEMP%/redflag_scans` and the brain to `~/RedFlag-Brain`. If you have
changed either path to something inside the project, change it back. If an editor or a sync client
is touching files in the worktree during a scan, stop it.

### 2.7 Blank page or broken frontend

Symptoms: a blank page, `cannot resolve react`, `EBUSY` errors, or npm repeatedly pruning.

**Cause: the checkout is inside OneDrive, Dropbox or another synced folder.** The sync engine
locks and reshuffles files under `.web/node_modules` while Vite is building.

**Fix:** move the checkout outside the synced folder, for example to `C:\Users\<you>\Redflag`,
then force a clean rebuild:

```powershell
Remove-Item -Recurse -Force .web
python -m reflex run
```

---

## 3. Scanner and enrichment problems

Almost every scanner **degrades silently** — a failure produces no error, just less data. The
symptoms below are how those silences look.

### 3.1 No Shodan data

**Symptom:** every finding shows exposure `Partner` or `Internal`; nothing is `Internet-facing`;
scores look uniformly low.

**Cause:** no `SHODAN_API_KEY`, an API error, or an unresolvable hostname (Shodan needs a
resolved IP).

**Why it matters a lot:** exposure carries 25% of the weighting, and the jump from `INTERNAL`
(30) to `INTERNET_FACING` (100) is the single biggest score mover in the product. Without Shodan,
scores materially understate risk.

**Fix:** add a key to `.env`, or upload a Shodan host JSON in the **Shodan JSON** slot — the
upload takes priority over the live call and costs no credits.

### 3.2 KEV feed unreachable

**Symptom:** no deal-killer findings even though you know a known-exploited CVE is present.

**Cause:** `scanners/kev_lookup.py` could not reach the CISA feed. Its cache becomes `{}` and
every `is_kev()` returns `False`, so the `ACTIVE_EXPLOITATION` override never fires.

**Check:**

```python
from scanners.kev_lookup import fetch_kev_catalog
print(len(fetch_kev_catalog()))    # 0 means the feed failed; expect ~1000+
```

**Fix:** restore connectivity and rescan. EPSS provides partial cover but does not replace KEV.

### 3.3 Every CVSS is 6.5

`fetch_cvss_from_nvd()` returns **6.5 on any failure** — a silent substitution, not an error. If
NVD is unreachable or rate-limited (5 requests / 30 s unauthenticated), a whole batch of CVEs will
score exactly 6.5.

**Check:**

```python
from scanners.shodan_scan import fetch_cvss_from_nvd
print(fetch_cvss_from_nvd("CVE-2021-44228"))   # expect 10.0, not 6.5
```

### 3.4 All findings "Unknown" sensitivity

**Expected behaviour without an asset inventory.** `data_sensitivity` is set from exactly one
source: the **Asset inventory (Excel)** upload.

Consequences: the dimension worth 20% of the weighting scores a neutral 50, and **two of the
three deal-killer override rules can never fire** — both require `CROWN_JEWEL` or `REGULATED`.

**Fix:** upload an `.xlsx` with a host column and a sensitivity column. See §3.5 for the format.

### 3.5 Asset Excel rejected

```
Excel must have an IP/host column and a sensitivity column. Found: [...]
```

Column detection is case-insensitive:

- **Host column:** header must be one of `ip`, `host`, `ip_address`, `hostname`, `address`
- **Sensitivity column:** header must contain `sensitiv` or `classif`, or be exactly `tier`

Accepted values: `crown_jewel` / `crown jewel` / `crownjewel`, `regulated`, `sensitive`, `low`,
`unknown`. Anything else becomes `UNKNOWN`.

**Also:** host values must match the finding's `host` **exactly** — usually the IP address Nmap
reported, not a friendly hostname.

### 3.6 Shodan JSON rejected

```
Could not find 'ip_str' in the uploaded file.
```

The file must be a Shodan **host record**, not a search-results page or an export of multiple
hosts. Produce one with:

```bash
shodan host <ip> --save
```

or from `api.host(ip)` in the Shodan Python client.

### 3.7 Nuclei does nothing

`run_nuclei_scan()` returns `[]` silently when the binary is absent.

**Check:**

```python
from scanners.nuclei_scan import nuclei_available, find_nuclei
print(nuclei_available(), find_nuclei())
```

**Fix:** install Nuclei (`brew install nuclei`, or `go install`), **or** run it elsewhere and
upload the JSONL:

```bash
nuclei -u https://target -jsonl -o out.jsonl
```

Then stage `out.jsonl` in the **Nuclei JSONL** slot. No local binary is ever required.

### 3.8 False DKIM finding

RedFlag probes 12 common DKIM selector names (`default`, `google`, `mail`, `selector1`,
`selector2`, `dkim`, `k1`, `s1`, `s2`, `email`, `mandrill`, `protonmail`). Selectors are
arbitrary, so a domain using a custom name produces a false "No DKIM Selector Found".

This is why that finding alone carries `INFERRED` evidence (×0.85) rather than `CONFIRMED`.
Verify manually:

```bash
dig TXT <your-selector>._domainkey.<domain>
```

To reduce false positives permanently, add your selector to `_DKIM_SELECTORS` in
`scanners/dns_scan.py`.

**Related:** a DNS resolver outage returns empty record lists, which read as "not configured" —
so a resolver problem can produce a burst of false SPF/DMARC/DKIM findings.

---

## 4. Analysis and output problems

### 4.1 Day-1 tab empty

> *Day 1 plan awaits data.*

The tab needs **either** a completed scan **or** a submitted maturity questionnaire. Run one.

### 4.2 Day-1 always recommends Isolate

`recommend_connectivity()` picks the highest tier whose gate **passes**, and `isolate` is the
floor that always passes. Being stuck on Isolate means the Broker gate is failing.

Look at the **Tier gates** section — each criterion shows pass/blocked with its reason. The Broker
gate has exactly one criterion: *no actively-exploited vulnerabilities*. One KEV finding pins you
to Isolate.

Federate additionally requires no internet-facing remote access and `identity_access` +
`network_security` maturity at or above `acceptable_min` — and a **maturity criterion fails if the
domain was never assessed**, which is the most common blocker. See §4.3.

### 4.3 Maturity gates fail "unassessed"

> *Not assessed*

A `maturity_min` criterion fails when the domain has no answers — you cannot prove a posture you
did not measure. Complete and submit the **Maturity** questionnaire. Only answered questions count
toward a domain score, so you do not have to answer all 23 — but the relevant domain must have at
least one answer.

### 4.4 Cost is zero or everything flagged

**Cost is $0:** the cost engine skips findings whose `deal_tier` is `UNSCORED`. If triage has not
run, there is nothing to price. Run a scan first.

**Everything flagged for review:** findings are falling through to the catalogue's `default`
entry, which sets the `ZERO_ESTIMATE` flag deliberately so a human scopes it. Add matching entries
under `service_entries` or `cve_overrides` in `config/remediation_catalog.yaml`.

**Deal-killer items are always flagged** by design (`DEAL_KILLER_ITEM`) — that is not a fault.

**The accuracy band looks wide:** it widens by 1.15× when the headcount is a default guess. Enter
a real headcount in the Cost tab's What-If controls, and enter vendor quotes where you have them —
a quote pins the item to `HIGH` confidence and collapses its spread.

---

## 5. Runtime and development problems

### 5.1 Brain not learning

**Symptom:** the Attack path tab shows 0 scans, or the count never rises.

**Cause:** `BrainMemory._save()` and `_write_vault()` swallow **all** exceptions so the brain can
never break a scan — which means a permissions or disk problem is completely silent.

**Check:**

```python
from analysis.brain_memory import BrainMemory
b = BrainMemory()
print(b.root)          # where it thinks the brain is
print(b.stats())       # scans, techniques, cves, last_seen
```

Then confirm the directory exists and is writable. If `REDFLAG_BRAIN_DIR` is set, check it points
somewhere real.

**Reset:** delete `~/RedFlag-Brain`; the next run re-bootstraps from the shipped seed.

### 5.2 Config change not taking effect

`config/loader.py` caches every YAML for the **life of the process**. Restart the app. In tests,
call `config.loader.reload_all()`.

### 5.3 PDF export fails

fpdf2 raises on a character outside the embedded font. All PDF text passes through `_safe()` in
`reports/pdf_report.py`, which strips non-ASCII — but new content added without going through it
will raise at export time.

If you add a symbol (an arrow, a star, a dash variant) to PDF output, either route it through
`_safe()` or verify the font contains the glyph.

### 5.4 Dev server crashes on edit

A compile error in a Reflex component takes the whole dev server down. Before a risky component
edit, render-check it in the venv:

```python
from redflag_ui.pages.day1 import day1
day1().render()      # surfaces VarTypeError / binding errors without the live server
```

Two recurring causes:

- Passing a `Var` as `class_name` to `rx.upload` → *"Cannot iterate over Var"*. Keep it static and
  put the conditional class on a wrapping `rx.el.div`.
- Building an f-string over a `Var` in a component. Precompute the string in `state.py` instead
  (`bar_w="60%"`, `donut_gradient="conic-gradient(...)"`).

---

## 6. Diagnostic commands

```bash
# Full engine health — expect "143 passed"
pytest tests/ -v

# Binaries
python -c "from scanners.nmap_scan import find_nmap, vulners_nse_available; print(find_nmap(), vulners_nse_available())"
python -c "from scanners.nuclei_scan import find_nuclei; print(find_nuclei())"

# Feeds
python -c "from scanners.kev_lookup import fetch_kev_catalog; print(len(fetch_kev_catalog()))"
python -c "from scanners.epss_scan import fetch_epss; print(fetch_epss(['CVE-2021-44228']))"
python -c "from scanners.shodan_scan import fetch_cvss_from_nvd; print(fetch_cvss_from_nvd('CVE-2021-44228'))"

# Individual scanners (bypasses the pipeline's exception swallowing)
python -c "from scanners.dns_scan import run_dns_scan; print(len(run_dns_scan('example.com')))"

# Config parses
python -c "from config.loader import get_day1_blueprint, get_remediation_catalog; print(len(get_day1_blueprint()), len(get_remediation_catalog()))"

# Brain
python -c "from analysis.brain_memory import BrainMemory; b=BrainMemory(); print(b.root); print(b.stats())"
```

---

## Related documents

- [INSTALLATION.md](INSTALLATION.md) — setup steps referenced above
- [DEPLOYMENT_RUNBOOK.md](DEPLOYMENT_RUNBOOK.md) — routine operations and health checks
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) §17 — the full failure-mode table
- [LIMITATIONS.md](../testing/LIMITATIONS.md) — behaviour that is a limitation, not a bug
- [KNOWLEDGE_TRANSFER.md](../handover/KNOWLEDGE_TRANSFER.md) §2 — the gotchas behind several of these
