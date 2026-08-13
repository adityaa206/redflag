# Security & Privacy

What RedFlag stores, what leaves your machine, and how secrets are handled.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Data handling posture

**RedFlag processes only the data you explicitly give it.** It has no telemetry, no analytics, no
crash reporting, no update check, and no account system. It never phones home.

| Aspect | Reality |
|---|---|
| Telemetry | **None** |
| Analytics | **None** |
| Cloud storage | **None** — everything is local |
| Database | **None** |
| Authentication | **None** — assumes a trusted local machine |
| Network binding | `localhost` only |
| Multi-user | Not supported |

### Where data is written

| Path | Contents | Sensitivity | Version-controlled |
|---|---|---|---|
| `%TEMP%/redflag_scans/` | Nmap XML — hosts, ports, service banners | **High** — a map of the target's attack surface | No — outside the repository |
| `~/RedFlag-Brain/brain.json` | Aggregate knowledge **plus a `targets` map naming every host assessed** | **High** | No — outside the repository |
| `~/RedFlag-Brain/vault/Scans/` | One Markdown note per scan, **named after the target** | **High** | No |
| `~/RedFlag-Brain/vault/{Techniques,CVEs}/` | Technique and CVE notes — no target identities | Low | No |
| `.env` | API keys | **Secret** | No — git-ignored |
| `.web/`, `.states/`, `uploaded_files/` | Reflex build output, runtime state, upload staging | Low–medium | No — git-ignored |
| Browser downloads | Exported CSV and PDF reports | **High** | No |
| `analysis/brain_seed/brain.json` | Aggregate knowledge, `targets` **stripped** | Low | **Yes — committed** |

**Both runtime paths sit outside the repository deliberately.** The brain is long-term memory that
must survive a `git clean`, and — for both paths — a write inside the worktree trips Reflex's dev
file-watcher, which hot-reloads the backend and destroys scan state mid-run.

---

## 2. Egress table — exactly what leaves the machine

| Destination | Data sent | When | Key required |
|---|---|---|---|
| **The target itself** | Nmap packets; Nuclei template requests; TLS handshakes; DNS queries | Live scan with a target | No |
| **Shodan** | The target **IP address** | Live lookup — *skipped entirely if a Shodan JSON is staged* | Yes (optional) |
| **LeakIX** | The target **domain** and up to **2 IPs** | Live scan with a target | No |
| **crt.sh** | The target **domain** | TLS scan | No |
| **NVD (NIST)** | **CVE IDs only** | CVSS enrichment | No |
| **CISA KEV** | **Nothing** — a public file download | KEV lookup, threat-intel refresh | No |
| **EPSS (FIRST.org)** | **CVE IDs only**, batched 100 per request | EPSS enrichment | No |
| **Vulners API** | **CVE IDs** and your API key | Exploit confirmation | Yes (optional) |
| **Vulners** (via the Nmap NSE script) | Service versions, from the NSE script during the scan | Only if `vulners.nse` is installed | Optional |

**Only three services ever receive target-identifying data: Shodan, LeakIX and crt.sh.** Everything
else receives CVE identifiers or nothing.

### Running with minimal egress

- **Do not supply a Shodan key** and upload a Shodan JSON instead — the upload takes priority and
  the API is never called.
- **Use upload-only mode.** Leave the target field blank and process staged OpenVAS/ZAP/Nuclei/
  Excel files. **Nothing leaves the machine at all** — those parsers are entirely local. The only
  network activity would be CVE-only enrichment (NVD, KEV, EPSS), which sends no
  target-identifying data.
- **Work offline entirely.** Every feed degrades silently, so the pipeline completes — but read
  [LIMITATIONS.md](../testing/LIMITATIONS.md) §4 first, because a report built with dead feeds
  looks identical to one built with live ones, only cleaner.

---

## 3. Secrets management

| Rule | Detail |
|---|---|
| Where secrets live | `.env` in the repository root, and nowhere else |
| Git status | `.env` is in `.gitignore`. Verify with `git check-ignore -v .env` |
| Committed template | `.env.example` — placeholders only, no real values |
| In documentation | Never. No document in this set contains a key, and none ever should |
| In logs | Keys are never printed. Note that `VULNERS_API_KEY` **is** passed on the Nmap command line as `--script-args ...,api_key=<key>`, so it may appear in process listings on a shared machine |

Provisioning:

```powershell
copy .env.example .env      # Windows
```

```bash
cp .env.example .env        # macOS / Linux
```

Both keys are optional — see [ACCESS_AND_CREDENTIALS.md](../handover/ACCESS_AND_CREDENTIALS.md)
for the inventory, rotation procedures, and the transfer checklist.

---

## 4. The exposed-key incident

> ⚠️ TODO(Adi): document this properly and close it out. A **Shodan API key was previously
> exposed** (in screenshots) and was flagged for rotation. Record:
>
> - the date the exposure was identified
> - how it was exposed and where the exposure may still be visible
> - **confirmation that the key was rotated and the old key revoked**, with the date
> - whether the old key's usage was reviewed for unauthorised activity
>
> Rotation steps are in
> [ACCESS_AND_CREDENTIALS.md](../handover/ACCESS_AND_CREDENTIALS.md) §4. **This should be closed
> before handover.** An exposed Shodan key lets a third party spend your credits and query the API
> under your identity.

**Verified as part of this documentation pass:** no API key, token or credential appears anywhere
in the repository's tracked files. `.env` is correctly git-ignored, and `.env.example` contains
only placeholders.

---

## 5. What is committed versus what stays local

### Committed to the repository

- All source code, configuration YAML, and this documentation set
- `.env.example` — placeholders only
- Test fixtures — synthetic data, no real target information
- **`analysis/brain_seed/brain.json`** — the only brain data in version control

### Never committed

- `.env` — real API keys
- `~/RedFlag-Brain/` — the local brain, including target identities
- `%TEMP%/redflag_scans/` — Nmap XML
- Exported CSV and PDF reports
- `.web/`, `.states/`, `venv/`, `uploaded_files/`

### How the shipped seed is made safe

`BrainMemory.export_seed()` strips **exactly one field** before writing the seed:

```python
data = json.loads(json.dumps(self.data))   # deep copy
data["targets"] = {}                        # drop who-was-scanned
```

`targets` is the only place in `brain.json` where a scanned host or IP is named. What remains is
aggregate pattern knowledge — technique, CVE, service, port, path and tier prevalence, plus the
KEV list — which reveals nothing about who was assessed.

> ⚠️ **This function is the entire boundary between "local memory" and "safe to publish".** If you
> add a field to `brain.json` that could identify a target, you must strip it here too. Six lines,
> high consequence, and currently **untested** — see [TEST_PLAN.md](../testing/TEST_PLAN.md) §7.

Note that the *local* brain is not sanitised. `~/RedFlag-Brain/brain.json` and the vault's
`Scans/` notes do name targets. They are outside version control, but they are real records.

### A note on `.gitignore`

The repository's `.gitignore` contains a blanket `*.md` rule, which historically ignored every
Markdown file. `README.md` predates the rule and so remained tracked, which masked the problem.
On 2026-07-27 explicit negations were added so this documentation set, `CONTRIBUTING.md`,
`SECURITY.md`, `CODE_OF_CONDUCT.md` and `CHANGELOG.md` are tracked, while local agent and scratch
notes stay ignored. Verify with:

```bash
git check-ignore -v docs/README.md
git status --short docs/
```

---

## 6. Data retention

| Data | Retention | How to delete |
|---|---|---|
| Nmap XML | Until the OS clears its temp directory | `Remove-Item -Recurse -Force $env:TEMP\redflag_scans` |
| The brain | **Indefinite — nothing expires or is pruned** | `Remove-Item -Recurse -Force $HOME\RedFlag-Brain` |
| Exported reports | Wherever the browser saved them | Delete manually |
| In-session findings | Lost on restart — nothing persists between sessions | Automatic |

**The brain is the retention risk worth understanding.** It accumulates a durable, permanent record
of every target you have assessed. If you assess third-party targets under an engagement agreement,
that agreement may govern how long you may retain such records — and that obligation covers
`~/RedFlag-Brain`. Deleting the directory removes it completely; the next run re-bootstraps from
the sanitised shipped seed.

---

## 7. Application security posture

RedFlag is a local single-user tool and is built accordingly. Be aware of the following.

| Consideration | Position |
|---|---|
| **No authentication** | Anyone who can reach the backend port can drive the application. **Never expose it to a network** — they could launch an active scan against an arbitrary target from your machine and your IP |
| **Uploaded file parsing** | XML is parsed with the standard library's `xml.etree.ElementTree`, which does **not** expand external entities by default; Excel via openpyxl; JSON via the standard library. All parse untrusted input, so only upload files from sources you trust |
| **Subprocess execution** | `run_nuclei_scan()` invokes an external binary. The target string is passed as an argument, not through a shell |
| **Broad exception handling** | `run_scan` wraps each scanner in `except Exception: pass`. This is deliberate resilience, but it means a genuine fault is swallowed silently |
| **Output sensitivity** | A RedFlag report is a map of a company's weaknesses — more sensitive than most data-room material. Distribute accordingly |
| **Dependency currency** | All dependencies are pinned. Pinning gives reproducibility but means security updates require an explicit bump. Review periodically (`pip list --outdated`) |

To report a vulnerability **in RedFlag itself**, see [SECURITY.md](../../SECURITY.md).

---

## 8. Privacy checklist for an engagement

| # | Check | ✓ |
|---|---|---|
| 1 | Written authorization obtained — see [AUTHORIZED_USE.md](AUTHORIZED_USE.md) | ☐ |
| 2 | You know which services will receive target-identifying data (§2) | ☐ |
| 3 | The engagement permits OSINT queries to Shodan, LeakIX and crt.sh | ☐ |
| 4 | Retention obligations for the results are understood | ☐ |
| 5 | Retention obligations for **the brain** are understood (§6) | ☐ |
| 6 | Exported reports will be stored and shared securely | ☐ |
| 7 | The brain will be cleared if the engagement requires it | ☐ |
| 8 | `.env` is confirmed git-ignored and contains no shared key | ☐ |

---

## Related documents

- [AUTHORIZED_USE.md](AUTHORIZED_USE.md) — the legal boundaries
- [ACCESS_AND_CREDENTIALS.md](../handover/ACCESS_AND_CREDENTIALS.md) — key inventory and rotation
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — per-service technical detail
- [BRAIN_KNOWLEDGE_BASE.md](../technical/BRAIN_KNOWLEDGE_BASE.md) — the store and its sanitisation
- [SECURITY.md](../../SECURITY.md) — reporting a vulnerability in RedFlag
