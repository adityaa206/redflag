# Deployment Runbook

Operating RedFlag day to day: starting it, stopping it, where it writes, and what to be careful
about.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Deployment model

**RedFlag is a local, single-user desktop application.** There is no server deployment, no
container, no database, no authentication layer, and no multi-user support.

| Aspect | Reality |
|---|---|
| Hosting | None. Runs on the operator's machine |
| Persistence | In-memory per session, plus local files |
| Users | One, on `localhost` |
| Authentication | None — the app assumes a trusted local machine |
| Network exposure | Binds `localhost` only |
| CI/CD | None configured |

> ⚠️ TODO(Adi): confirm no cloud or hosted deployment exists anywhere. This document assumes
> local-only.

**Do not expose the backend port to a network.** There is no authentication, and anyone who can
reach it can launch an active Nmap scan against an arbitrary target from your machine and your IP
address. See [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md).

---

## 2. Starting the application

```powershell
# Windows
cd C:\Users\<you>\Redflag
.\venv\Scripts\Activate.ps1
python -m reflex run
```

```bash
# macOS / Linux
cd ~/redflag
source venv/bin/activate
python -m reflex run
```

| Port | Service |
|---|---|
| **3000** | Frontend (Next.js) — open this in a browser |
| **8000** | Backend (WebSocket state server) |

Both are needed; the frontend talks to the backend over a WebSocket.

**To change ports:**

```bash
python -m reflex run --frontend-port 3001 --backend-port 8001
```

**First launch** compiles the Next.js frontend into `.web/`. This takes roughly a minute, needs
Node.js 18+, and Reflex will offer to install Node if it is missing. Subsequent launches reuse the
build and start in seconds.

---

## 3. Stopping the application

`Ctrl+C` in the terminal running `reflex run` stops both processes.

If a port is left occupied by an orphaned process:

```powershell
# Windows — find and kill whatever holds port 3000
netstat -ano | findstr :3000
taskkill /PID <pid> /F
```

```bash
# macOS / Linux
lsof -ti:3000 | xargs kill -9
```

---

## 4. Where things are written

| Path | Contents | Lifetime | In the repository? |
|---|---|---|---|
| `%TEMP%/redflag_scans/` (`$TMPDIR/redflag_scans` on macOS) | Nmap XML, one file per scan | Until the OS clears temp | **No** |
| `~/RedFlag-Brain/brain.json` | The knowledge-base index | Permanent | **No** |
| `~/RedFlag-Brain/vault/` | Obsidian notes: Scans, Techniques, CVEs | Permanent | **No** |
| `.web/` | Compiled frontend and `node_modules` | Until deleted | No (git-ignored) |
| `.states/`, `reflex.lock/` | Reflex runtime state | Session | No (git-ignored) |
| `uploaded_files/` | Reflex's upload staging area | Session | No |
| Downloads | CSV and PDF exports go to the browser's download folder | Permanent | No |

> **The two runtime paths outside the repository are deliberate and load-bearing.** Reflex's
> development file-watcher monitors the worktree; a write inside it triggers a hot reload that
> **resets backend state mid-scan** and loses the findings. The tell-tale is `Compiling…`
> appearing in the terminal during a scan. Do not "tidy" these paths back into the project.

Scan output and the brain may contain sensitive target data. Both are outside version control,
but they are real records — see §7.

---

## 5. Operational cautions

### Authorisation comes first

RedFlag performs **active scanning**. Nmap sends packets to the target; Nuclei sends application
requests. Run it **only** against systems you own or have explicit written authorisation to
assess. This is not a formality — unauthorised scanning is a criminal offence in many
jurisdictions. Read [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) before your first scan and
keep a record of the authorisation.

### Know which feeds were live

A clean report is not proof the target is clean. If CISA KEV was unreachable, no deal-killer
override will fire for an actively-exploited CVE, and the report will look reassuring. If Shodan
was unavailable, exposure stays `PARTNER`/`INTERNAL` and every score is understated. Before
relying on an assessment, confirm the feeds responded. The full failure-mode table is in
[INTEGRATIONS.md](../technical/INTEGRATIONS.md) §17.

### Scan timing and courtesy

`-T4` is aggressive timing. On a fragile target, or one behind an IDS, a full scan can trip alerts
or degrade a service. **Fast mode** (top 200 ports) is both quicker and gentler. Coordinate
timing with the target's operations team.

### Credit consumption

A live Shodan lookup costs **1 credit per IP**. Staging a Shodan JSON upload skips the API call
entirely and costs nothing — and the upload takes priority over the live call automatically.

### Configuration changes need a restart

`config/loader.py` caches every YAML for the life of the process. Editing a YAML while the app is
running has no effect until you restart it.

---

## 6. Routine operations

### Refresh threat intelligence

**Attack path** tab → **Refresh threat intel**. Pulls the current CISA KEV feed into the brain and
back-fills the `kev` flag on every CVE it already knows. Worth doing before a significant
assessment.

### Refresh the shipped brain seed

```bash
python -m analysis.brain_memory
```

Snapshots your local brain into `analysis/brain_seed/brain.json`, **stripping target identities**,
so a fresh clone starts pre-loaded. Commit the result if you want to share it.

### Reset the brain

```powershell
Remove-Item -Recurse -Force $HOME\RedFlag-Brain
```

The next run re-bootstraps from the shipped seed.

### Clear scan output

```powershell
Remove-Item -Recurse -Force $env:TEMP\redflag_scans
```

### Force a clean frontend rebuild

```powershell
Remove-Item -Recurse -Force .web
python -m reflex run
```

Do this if the UI renders blank or stale after a dependency change.

---

## 7. Data retention

Two locations accumulate records of who you assessed:

- `~/RedFlag-Brain/brain.json` → the `targets` map (hostnames and scan counts)
- `~/RedFlag-Brain/vault/Scans/` → one Markdown note per scan, named after the target

Nothing expires or is pruned. If you assess third-party targets under an engagement agreement,
that agreement may govern how long you may keep such records. Deleting `~/RedFlag-Brain` removes
them entirely.

Note that `analysis/brain_seed/brain.json` — the only brain data in the repository — has the
`targets` map stripped by `export_seed()`. See
[BRAIN_KNOWLEDGE_BASE.md](../technical/BRAIN_KNOWLEDGE_BASE.md) §4.

---

## 8. Logging and observability

There is **no logging framework**. Diagnostics are:

| Source | What it shows |
|---|---|
| The `reflex run` terminal | `[INFO]` lines from the Nmap scanner (binary path, mode, NSE detection, host count), plus Reflex compile output |
| The UI notice bar | Scan result summary — finding count, deal-killer count, and which sources were fused |
| The UI error bar | `Scan failed: …` when the pipeline raises |
| Browser dev tools | Frontend and WebSocket errors |
| A log file | Only if `reflex run` output is explicitly redirected to one. None is created by default, and `*.log` is git-ignored |

Because `run_scan` wraps each scanner in `except Exception: pass`, a scanner failing produces
**no message at all** — it simply contributes nothing. To debug one, call it directly:

```python
from scanners.dns_scan import run_dns_scan
print(run_dns_scan("example.com"))
```

Improving this — logging the swallowed exception rather than passing — is item 6 in
[KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §5.

---

## 9. Health checks

```bash
# Engines healthy?
pytest tests/ -v                    # expect 143 passed

# Nmap reachable?
python -c "from scanners.nmap_scan import find_nmap; print(find_nmap())"

# Nuclei present? (optional)
python -c "from scanners.nuclei_scan import nuclei_available; print(nuclei_available())"

# Brain healthy?
python -c "from analysis.brain_memory import BrainMemory; print(BrainMemory().stats())"

# Config parses?
python -c "from config.loader import get_day1_blueprint; print(len(get_day1_blueprint()))"
```

---

## Related documents

- [INSTALLATION.md](INSTALLATION.md) — first-time setup
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → fix
- [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) — **required reading before operating**
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — failure modes per feed
- [BRAIN_KNOWLEDGE_BASE.md](../technical/BRAIN_KNOWLEDGE_BASE.md) — the persistent store
