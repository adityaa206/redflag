# Access & Credentials

An inventory of every account and key needed to own RedFlag, and how to transfer each one.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> **This document contains no secrets and must never contain any.** It is an inventory. Actual
> key values live only in a local, git-ignored `.env` file, or in a password manager. If a real
> key is ever found in this file or anywhere else in the repository, treat it as compromised and
> rotate it immediately.

---

## 1. Repository ownership

| Item | Value |
|---|---|
| Repository | `github.com/adityaa206/redflag` |
| Remote name | `origin` |
| Default branch | `master` on GitHub; `main` and `master` are kept in sync |
| Secondary remote | `upstream` → `quadindy/marisk` (a separate account; RedFlag does not publish there) |

**To add a maintainer** (recommended for a supervisor who needs read/write but not ownership):
GitHub → repository → **Settings → Collaborators and teams → Add people** → grant `Write` or
`Maintain`.

**To transfer ownership outright:** GitHub → repository → **Settings → General → Danger Zone →
Transfer ownership**. Note that this moves issues, stars and the URL; the old URL will redirect.

Adding a maintainer is the lighter option and is sufficient for anyone who needs to read, clone
and contribute. Ownership transfer is only necessary if the repository is to leave the
`adityaa206` account entirely.

The `upstream` remote points at a different account's repository and exists only as a fetch
reference. RedFlag is published to `origin`; nothing in this project is pushed to `upstream`.

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

## 4. Key rotation

Both keys are personal to whoever holds the account, so the cleanest position for anyone taking
the project on is to issue their own rather than inherit these. RedFlag needs no key to function,
so a new holder can also simply run without them. The procedures below are recorded for either
case.

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

This inventory is complete. The repository contains no Dockerfile, no `.github/` workflows, no
infrastructure-as-code, and no deployment configuration of any kind; `rxconfig.py` declares no
remote API or deploy URL. RedFlag has only ever run on a local machine.

---

## 7. Setting up on a new machine

| # | Step |
|---|---|
| 1 | Clone the repository, or accept the collaborator invitation and then clone |
| 2 | Copy `.env.example` to `.env` — RedFlag runs fully without editing it |
| 3 | Add a Shodan or Vulners key to `.env` only if live enrichment from those services is wanted |
| 4 | Confirm `.env` is git-ignored: `git check-ignore -v .env` |
| 5 | Read [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) before running any scan against a host |

No secret appears in any tracked file in this repository. `.env` is git-ignored and
`.env.example` contains placeholders only.

---

## Related documents

- [HANDOVER.md](HANDOVER.md) — the transition cover document
- [SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) — what data leaves the machine
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — per-service auth and degradation behaviour
- [CONFIGURATION.md](../technical/CONFIGURATION.md) — every environment variable and config knob
