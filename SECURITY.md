# Security Policy

How to report a vulnerability **in RedFlag itself**.

---

## Scope

This policy covers security defects in the RedFlag codebase — for example:

- Code injection through an uploaded scanner file (XML, JSONL, JSON or XLSX)
- Command injection via the target input or a subprocess call
- Path traversal in file handling or export
- Leakage of API keys through logs, process listings, error messages or exports
- A flaw in `BrainMemory.export_seed()` that lets target-identifying data reach the committed seed
- Any way the local web interface could be reached or driven by a remote party

**Out of scope:**

- Vulnerabilities in the systems RedFlag scans. Report those to the system's owner.
- Vulnerabilities in third-party tools RedFlag integrates with (Nmap, Nuclei, OpenVAS, ZAP, Shodan,
  LeakIX and others). Report those to the respective projects.
- The absence of authentication on the local web interface. This is a **documented design
  decision** — RedFlag is a single-user local tool bound to `localhost` and must never be exposed
  to a network. See
  [docs/legal/SECURITY_AND_PRIVACY.md](docs/legal/SECURITY_AND_PRIVACY.md) §7.
- Reports that RedFlag "can be used to scan systems". That is what it is for; lawful use is the
  operator's responsibility under
  [docs/legal/AUTHORIZED_USE.md](docs/legal/AUTHORIZED_USE.md).

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately through **GitHub private vulnerability reporting** — the repository's
**Security** tab → *Report a vulnerability*. This is the only reporting channel, and it is the
right one: the disclosure, the discussion and the fix stay in one place, visible only to the
maintainers until a fix is published.

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- The affected file and, if you have it, a suggested fix
- Your commit or version, OS, and Python version

**Do not include** real API keys, real target data, or anything belonging to a third party.

---

## What to expect

RedFlag is a personal project maintained on a best-effort basis. There is no service-level
commitment, and no response time is guaranteed — a promise that cannot be kept is worse than none
at all.

What a reporter can expect in practice: an acknowledgement once the report has been read, an
assessment of whether the issue is in scope under the section above, and notification when a fix
or a documented mitigation lands. Credit in the commit or release notes is given unless the
reporter prefers otherwise.

Please give a reasonable opportunity to address the issue before disclosing it publicly.

---

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Anything earlier | ❌ |

The repository carries no git tags and has no released versions. **Only the current `main` branch
is supported.** Always update to latest before reporting.

---

## Security posture

RedFlag is a **local, single-user desktop application**. It has no server deployment, no database,
no authentication layer, and no multi-user support. It binds to `localhost` only.

The most important operational security control is one the user applies: **do not expose the
backend port to a network.** There is no authentication, so anyone who can reach it can launch an
active Nmap scan against an arbitrary target from your machine and your IP address.

Full detail — data handling, the egress table, secrets management, and what is committed versus
local — is in
[docs/legal/SECURITY_AND_PRIVACY.md](docs/legal/SECURITY_AND_PRIVACY.md).

---

## Secrets

API keys live only in `.env`, which is git-ignored. `.env.example` is the committed template and
contains placeholders only.

As of 2026-07-27, **no API key, token or credential appears in any tracked file** in this
repository.

If you find a real secret committed anywhere — including in the git history — please report it
privately using the process above and **do not** post the value in an issue.

Rotation procedures: [docs/handover/ACCESS_AND_CREDENTIALS.md](docs/handover/ACCESS_AND_CREDENTIALS.md) §4.

---

## Related documents

- [docs/legal/SECURITY_AND_PRIVACY.md](docs/legal/SECURITY_AND_PRIVACY.md) — data handling and egress
- [docs/legal/AUTHORIZED_USE.md](docs/legal/AUTHORIZED_USE.md) — lawful operation of the scanner
- [docs/handover/ACCESS_AND_CREDENTIALS.md](docs/handover/ACCESS_AND_CREDENTIALS.md) — key inventory and rotation
- [CONTRIBUTING.md](CONTRIBUTING.md) — reporting non-security bugs
