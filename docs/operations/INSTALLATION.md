# Installation

A standalone guide to getting RedFlag running on Windows or macOS.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Prerequisites

| Requirement | Why | Windows | macOS |
|---|---|---|---|
| **Python 3.11+** | The whole application | [python.org/downloads](https://www.python.org/downloads/) | `brew install python` |
| **Git** | Cloning the repository | [git-scm.com](https://git-scm.com/download/win) | Pre-installed, or `brew install git` |
| **Nmap** | **Required.** The base scanner — without it a live scan fails | [nmap.org/download](https://nmap.org/download.html#windows) | `brew install nmap` |
| **Node.js 18+** | Reflex compiles a Next.js frontend | Installed automatically by Reflex on first run, or [nodejs.org](https://nodejs.org) | Same |
| Nuclei | *Optional.* Template DAST | [ProjectDiscovery releases](https://github.com/projectdiscovery/nuclei/releases) | `brew install nuclei` |
| Shodan API key | *Optional.* Live exposure lookups | Free tier at [shodan.io](https://shodan.io) | Same |
| Vulners API key | *Optional.* Exploit confirmation | Free tier at [vulners.com](https://vulners.com) | Same |

> **You can run a complete assessment with no API keys and no Nuclei binary.** See §6.

> ⚠️ **Nmap discovery is Windows-path-based.** `scanners/nmap_scan.py:find_nmap()` checks only
> `C:\Program Files (x86)\Nmap\nmap.exe` and `C:\Program Files\Nmap\nmap.exe`. It does not consult
> `PATH`, so a Homebrew install at `/usr/local/bin/nmap` will not be found. On macOS you can still
> use every upload-driven feature; see §7.

---

## 2. Installation — Windows

Open **PowerShell** and run these in order.

### Step 1 — Verify Python

```powershell
python --version
```

Expect `Python 3.11.x` or higher. If not, install from
[python.org/downloads](https://www.python.org/downloads/) and **tick "Add Python to PATH"** during
setup.

### Step 2 — Install Nmap

Download the **stable self-installer** from
[nmap.org/download.html](https://nmap.org/download.html#windows), run it with the default options
(which install to `C:\Program Files (x86)\Nmap`), then verify:

```powershell
nmap --version
```

### Step 3 — Clone the repository

```powershell
git clone https://github.com/adityaa206/redflag.git
cd redflag
```

> **Do not clone into OneDrive, Dropbox, or any synced folder.** The sync engine fights Reflex's
> Node/Vite build and produces `EBUSY` errors and a blank page. Use a path like
> `C:\Users\<you>\Redflag`.

### Step 4 — Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Your prompt will show `(venv)`. **Activate it in every new terminal.**

If PowerShell blocks the activation script, allow it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Step 5 — Install dependencies

```powershell
pip install -r requirements.txt
```

### Step 6 — Configure API keys (optional)

```powershell
copy .env.example .env
notepad .env
```

Fill in whichever keys you have, save, and close. Both are optional — see §6.

### Step 7 — Launch

```powershell
python -m reflex run
```

Open <http://localhost:3000>. **The first run compiles the frontend — give it about a minute.**

---

## 3. Installation — macOS

### Step 1 — Install Homebrew (if needed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2 — Install Python, Git and Nmap

```bash
brew install python git nmap
python3 --version   # expect 3.11+
nmap --version
```

### Step 3 — Clone the repository

```bash
git clone https://github.com/adityaa206/redflag.git
cd redflag
```

### Step 4 — Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 6 — Configure API keys (optional)

```bash
cp .env.example .env
nano .env          # or: open -e .env
```

### Step 7 — Launch

```bash
python -m reflex run
```

Open <http://localhost:3000>.

---

## 4. Running after the first install

**Windows**

```powershell
cd C:\Users\<you>\Redflag
.\venv\Scripts\Activate.ps1
python -m reflex run
```

**macOS**

```bash
cd ~/redflag
source venv/bin/activate
python -m reflex run
```

Subsequent launches skip the frontend compile and start in a few seconds.

---

## 5. Configuration

Edit `.env` in the repository root:

```env
# Optional — live Shodan lookups (1 credit per IP queried)
SHODAN_API_KEY=your_shodan_api_key_here

# Optional — per-CVE exploit confirmation via Vulners
VULNERS_API_KEY=your_vulners_api_key_here
```

- **Shodan** — [account.shodan.io](https://account.shodan.io) → API Key
- **Vulners** — [vulners.com/userinfo](https://vulners.com/userinfo) → API Keys

`.env` is git-ignored and must never be committed. There is one further, non-secret variable set
as a real environment variable rather than in `.env`:

| Variable | Purpose | Default |
|---|---|---|
| `REDFLAG_BRAIN_DIR` | Where the knowledge base is stored | `~/RedFlag-Brain` |

Everything else is configured through the YAML files in `config/` —
see [CONFIGURATION.md](../technical/CONFIGURATION.md).

---

## 6. Installing with no API keys

Skip step 6 entirely. RedFlag runs without a `.env` file at all.

| What you lose | Workaround |
|---|---|
| Live Shodan lookups | Upload a Shodan host JSON in the **Shodan JSON** slot |
| Vulners exploit confirmation | Findings still score; CISA KEV and EPSS still supply exploit intelligence with no key |
| Nothing else | NVD, KEV, EPSS, DNS, TLS, crt.sh and LeakIX all work keyless |

Ten of the fourteen integrations need no key. Full detail:
[INTEGRATIONS.md](../technical/INTEGRATIONS.md) §16.

---

## 7. Installing the optional extras

### Nuclei (template DAST)

```bash
# macOS
brew install nuclei

# Any platform, with Go installed
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

RedFlag finds it via `PATH` first, then `~/go/bin`, `C:\Program Files\Nuclei\`, `/usr/local/bin`
and `/opt/homebrew/bin`. If it is absent, live Nuclei scanning is skipped silently — you can still
upload `nuclei -jsonl` output produced anywhere.

### Vulners NSE script (CVE lookup during the Nmap scan)

Download `vulners.nse` from the
[vulscan/vulners project](https://github.com/vulnersCom/nmap-vulners) and place it in Nmap's
`scripts/` directory (`C:\Program Files (x86)\Nmap\scripts\` on Windows). RedFlag detects it
automatically and adds `--script vulners` to the scan.

### macOS without a Windows-path Nmap

`find_nmap()` only probes the two Windows paths, so a Homebrew Nmap will not be found and a live
scan will raise `FileNotFoundError`. Two options:

1. **Use upload-only mode.** Leave the target field empty, stage OpenVAS/ZAP/Nuclei/Shodan files,
   and click **Run scan**. The whole pipeline runs on the uploads.
2. **Patch the path list.** Add your Nmap location to `NMAP_PATHS` in `scanners/nmap_scan.py`:

   ```python
   NMAP_PATHS = [
       r"C:\Program Files (x86)\Nmap\nmap.exe",
       r"C:\Program Files\Nmap\nmap.exe",
       "/opt/homebrew/bin/nmap",     # Apple Silicon
       "/usr/local/bin/nmap",        # Intel
   ]
   ```

---

## 8. Verifying the installation

```bash
# 1. Dependencies resolve and the engines import
python -c "import reflex, pydantic, pandas, networkx, fpdf, nmap, shodan, dns, cryptography, yaml; print('ok')"

# 2. The engine test suite passes — expect "143 passed"
pytest tests/ -v

# 3. Nmap is reachable (Windows)
python -c "from scanners.nmap_scan import find_nmap; print(find_nmap())"

# 4. The app starts
python -m reflex run
```

A green test run is the strongest single signal that the installation is sound — it exercises the
scoring, maturity, cost, narrative, Day-1, EPSS, Nuclei, graph and integration engines without
needing a network or a target.

---

## 9. What gets created on first run

| Path | What | Committed? |
|---|---|---|
| `.web/` | The compiled Next.js frontend and `node_modules` | No (git-ignored) |
| `venv/` | The Python virtual environment | No |
| `.states/`, `reflex.lock/` | Reflex runtime state | No |
| `%TEMP%/redflag_scans/` | Nmap XML output | No — outside the repository |
| `~/RedFlag-Brain/` | The knowledge base, bootstrapped from the shipped seed | No — outside the repository |

The first launch is slow because `.web/` is being built. Later launches reuse it.

---

## Related documents

- [DEPLOYMENT_RUNBOOK.md](DEPLOYMENT_RUNBOOK.md) — day-to-day running and operational cautions
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — when a step above fails
- [DEVELOPER_ONBOARDING.md](DEVELOPER_ONBOARDING.md) — the next step for a developer
- [USER_GUIDE.md](../user/USER_GUIDE.md) — the next step for an analyst
- [CONFIGURATION.md](../technical/CONFIGURATION.md) — everything configurable
- [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) — **read before your first scan**
