# Access & Credentials — Handover Template

An inventory of every account and key needed to own RedFlag, and how to transfer each one.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> **This document contains no secrets and must never contain any.** It is an inventory and a
> checklist. Actual key values live only in a local, git-ignored `.env` file, or in a password
> manager. If you find a real key in this file or anywhere else in the repository, treat it as
> compromised and rotate it immediately.

---

## 1. Repository ownership

| Item | Value |
|---|---|
| Repository | `github.com/adityaa206/redflag` |
| Remote name | `origin` |
| Default branch | `main` |
| Secondary remote | `upstream` → `quadindy/marisk` |

**To add a maintainer** (recommended for a supervisor who needs read/write but not ownership):
GitHub → repository → **Settings → Collaborators and teams → Add people** → grant `Write` or
`Maintain`.

**To transfer ownership outright:** GitHub → repository → **Settings → General → Danger Zone →
Transfer ownership**. Note that this moves issues, stars and the URL; the old URL will redirect.

> ⚠️ TODO(Adi): decide and record which of the two applies, and the GitHub username of the
> receiving owner.

> ⚠️ TODO(Adi): confirm what the `upstream` remote (`quadindy/marisk`) is and whether the
> receiver needs any access to it. Do not push to it without explicit instruction.

---

## 2. API key inventory

Both keys are **optional**. RedFlag runs a complete assessment with neither — see section 5.

| Service | Env variable | Used by | Free tier | Sign-up | Required? |
|---|---|---|---|---|---|
| Shodan | `SHODAN_API_KEY` | `scanners/shodan_scan.py` → `lookup_host()` | Yes (limited credits) | [account.shodan.io](https://account.shodan.io) | No |
| Vulners | `VULNERS_API_KEY` | `scanners/vulners_enrich.py`; also passed to the Nmap `vulners` NSE script | Yes | [vulners.com/userinfo](https://vulners.com/userinfo) | No |

There is also one **non-secret** environment variable:

| Variable | Purpose | Default |
|---|---|---|
| `REDFLAG_BRAIN_DIR` | Overrides where the knowledge base is stored | `~/RedFlag-Brain` |

Cost note: a live Shodan lookup consumes **1 credit per IP queried**. Uploading a Shodan host
JSON instead costs nothing and takes priority over the live call.

Full behavioural detail per integration: [INTEGRATIONS.md](../technical/INTEGRATIONS.md).

---

## 3. Secrets handling policy

1. Keys live **only** in `.env` in the repository root.
2. `.env` is listed in `.gitignore` and must never be committed. `.env.example` is the committed
   template and contains placeholders only.
3. To provision a fresh environment:

   ```powershell
   # Windows
   copy .env.example .env
   notepad .env
   ```

   ```bash
   # macOS / Linux
   cp .env.example .env
   nano .env
   ```

4. Never paste a key into a screenshot, a chat message, an issue, a commit message, or a
   documentation file.
5. If a key is exposed anywhere, rotate it first and investigate second.

---

## 4. Key rotation status

> ⚠️ TODO(Adi): confirm in writing whether the Shodan API key that was previously exposed has
> been **rotated and the old key revoked**. Record the date. If it has not been done, do it
> before handover — an exposed Shodan key allows a third party to spend your credits and to
> query the API under your identity.

**How to rotate a Shodan key**

1. Sign in at [account.shodan.io](https://account.shodan.io).
2. Open the **API Key** section — the key shown there is your active key.
3. Use the **Reset / regenerate** control to issue a new key. The previous key stops working
   immediately.
4. Update `SHODAN_API_KEY` in your local `.env`.
5. Confirm the old value appears nowhere in the repository history, in screenshots, or in shared
   documents.

**How to rotate a Vulners key**

1. Sign in at [vulners.com/userinfo](https://vulners.com/userinfo).
2. Open **API Keys**, revoke the existing key, and create a replacement scoped to `api`.
3. Update `VULNERS_API_KEY` in `.env`.

**If the key must not be reused by the receiver:** revoke it and let them create their own free
account. RedFlag needs no key to function.

---

## 5. Running with no keys at all

| What is lost | Workaround |
|---|---|
| Live Shodan host lookup | Upload a Shodan host JSON in the **Shodan JSON** slot — it takes priority over the live call anyway |
| Vulners exploit confirmation | Findings still score; `exploit_status` simply stays `UNKNOWN` unless KEV or EPSS supplies it |
| Nothing else | NVD, CISA KEV, EPSS, DNS, TLS, crt.sh and LeakIX all work with no key |

---

## 6. Other accounts and infrastructure

| Item | Status |
|---|---|
| Hosting / cloud deployment | **None.** RedFlag is a local desktop application. |
| Database | **None.** All state is in-memory or in local files. |
| CI/CD | **None configured.** |
| Container registry | **None.** |
| Monitoring / error tracking | **None.** |
| External binaries required | Nmap (required), Nuclei (optional), Node.js 18+ (installed by Reflex on first run) |

> ⚠️ TODO(Adi): confirm this is complete — in particular, that no cloud or hosted deployment
> exists anywhere.

---

## 7. Receiver checklist

| # | Step | Done |
|---|---|---|
| 1 | Repository access granted or ownership transferred | ☐ |
| 2 | Confirmed the exposed Shodan key was rotated and revoked | ☐ |
| 3 | Decided whether to reuse the existing keys or issue new ones | ☐ |
| 4 | Created a local `.env` from `.env.example` | ☐ |
| 5 | Verified `.env` is git-ignored (`git check-ignore -v .env`) | ☐ |
| 6 | Confirmed no secret appears in the repository or its history | ☐ |
| 7 | Read [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) before running any scan | ☐ |

---

## Related documents

- [HANDOVER.md](HANDOVER.md) — the transition cover document
- [SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) — what data leaves the machine
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — per-service auth and degradation behaviour
- [CONFIGURATION.md](../technical/CONFIGURATION.md) — every environment variable and config knob
