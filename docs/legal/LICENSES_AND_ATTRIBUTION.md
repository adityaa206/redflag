# Licenses & Attribution

The project's licensing position, a dependency inventory, and the terms attached to every external
service RedFlag contacts.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Project licence

> ⚠️ **DISCREPANCY — action required.** `README.md` states *"MIT — see [LICENSE](LICENSE) for
> details"* and links to a `LICENSE` file. **No such file exists in the repository.**
> `git ls-files` returns nothing for it, and there is no licence text anywhere in the tree.

**Why this matters.** Under copyright law the default position is **all rights reserved**.
Publishing source code with a licence *claim* but no licence *text* leaves anyone who forks,
reuses or contributes to the project without a grant they can rely on. It is ambiguous rather than
permissive.

**The fix** is one file. Create `LICENSE` in the repository root with the standard MIT text:

```
MIT License

Copyright (c) 2026 <copyright holder>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> ⚠️ TODO(Adi): supply the copyright holder's name for the `<copyright holder>` placeholder. The
> file has deliberately **not** been created automatically, because naming a copyright holder is a
> legal declaration only you can make. If the project should not be MIT-licensed, correct the
> README instead.

The MIT licence's warranty disclaimer would also reinforce
[AUTHORIZED_USE.md](AUTHORIZED_USE.md) §7, which currently stands alone.

**Assuming MIT is intended:** it is permissive. Anyone may use, modify, distribute and sell the
software, commercially, provided the copyright notice and licence text are preserved. There is no
copyleft obligation and no requirement to publish modifications.

---

## 2. Dependency inventory

From `requirements.txt`, all versions pinned exactly. Licences verified against each project's
published metadata.

| Package | Version | Purpose | Licence | Notes |
|---|---|---|---|---|
| `reflex` | 0.9.5.post2 | Web UI framework (compiles to Next.js/React) | Apache-2.0 | Pulls a large transitive tree — see §3 |
| `pydantic` | 2.13.4 | Data validation for `Finding` and the cost models | MIT | |
| `pandas` | 3.0.3 | DataFrames for CSV export | BSD-3-Clause | |
| `fpdf2` | 2.8.7 | PDF generation | LGPL-2.1-or-later | ⚠️ **See §4** |
| `openpyxl` | 3.1.5 | Excel read (asset inventory) and XLSX export | MIT | |
| `python-nmap` | 0.7.1 | Nmap wrapper | GPL-3.0-or-later | ⚠️ **See §4** |
| `shodan` | 1.31.0 | Shodan API client | BSD-3-Clause | |
| `dnspython` | 2.8.0 | DNS queries for SPF/DMARC/DKIM/DNSSEC | ISC | |
| `cryptography` | 48.0.0 | X.509 certificate parsing | Apache-2.0 **or** BSD-3-Clause (dual) | |
| `networkx` | 3.5 | Attack-graph analytics | BSD-3-Clause | |
| `PyYAML` | 6.0.3 | Config loading | MIT | |
| `python-dotenv` | 1.2.2 | `.env` loading | BSD-3-Clause | |
| `requests` | 2.34.2 | HTTP for NVD, KEV, Vulners, crt.sh, LeakIX | Apache-2.0 | |
| `pytest` | 9.0.3 | Test framework | MIT | Development only |

> ⚠️ TODO(Adi): licences above were determined from each project's published metadata. Before
> relying on this table commercially, verify against the installed distributions:
>
> ```bash
> pip install pip-licenses
> pip-licenses --format=markdown --with-urls
> ```
>
> That also enumerates the **transitive** dependencies, which this table does not.

---

## 3. Transitive dependencies

`requirements.txt` lists 14 direct dependencies. The installed environment contains many more,
mostly pulled in by Reflex (FastAPI, Starlette, Uvicorn, Pydantic-core, Rich, Typer, Alembic,
SQLModel and others) and by pandas (NumPy, python-dateutil, pytz).

Reflex additionally downloads **Node.js and an npm dependency tree** into `.web/` on first run,
including Next.js and React. Those are not Python packages and do not appear in any pip listing,
but they are third-party code executing on the developer's machine.

> ⚠️ TODO(Adi): if a full SBOM is required for the handover, generate one:
>
> ```bash
> pip install cyclonedx-bom
> cyclonedx-py environment -o sbom.json
> ```

---

## 4. Copyleft flags

Two direct dependencies carry copyleft terms. **Neither is a problem for RedFlag as it stands**,
but both matter if the project is ever distributed as a binary or bundled into a proprietary
product.

### `python-nmap` — GPL-3.0-or-later ⚠️

The strongest obligation in the tree. GPL-3.0 requires that derivative works, when distributed, be
licensed under GPL-3.0 and their source made available.

**Current position:** RedFlag is distributed as source under a permissive licence, and users
install `python-nmap` themselves via pip. This is the ordinary "aggregation with an interpreted
dependency" arrangement and does not trigger the copyleft obligation.

**When it would matter:** bundling `python-nmap` into a distributed binary, container image, or
closed-source product would raise a genuine question about whether the combined work must be
GPL-3.0. Take advice before doing that.

**Note also:** the **Nmap binary itself** is not a pip dependency — the user installs it
separately. Nmap is distributed under the [Nmap Public Source License](https://nmap.org/npsl/),
which is GPL-derived and **explicitly restricts redistribution and commercial embedding**. Nmap's
own FAQ is clear that commercial redistribution requires a separate licence from Nmap Software LLC.
Do not bundle the Nmap binary with RedFlag.

### `fpdf2` — LGPL-2.1-or-later ⚠️

Weaker copyleft. The LGPL permits use in a work under a different licence provided the library
itself remains replaceable and its own source is available.

**Current position:** installed via pip and imported at runtime. Fine.

**When it would matter:** static bundling into a distributed binary would require preserving the
user's ability to replace the library. Alternatives with permissive licences exist
(`reportlab` — BSD) if this ever becomes a constraint.

---

## 5. External services

Every service RedFlag contacts, what it sends, and the terms attached.

| Service | What is sent | Attribution / terms |
|---|---|---|
| **Nmap** (local binary) | Packets to the target | [Nmap Public Source License](https://nmap.org/npsl/). Free for internal use; commercial redistribution requires a licence |
| **Nuclei** (local binary) | Requests to the target | MIT (ProjectDiscovery) |
| **Shodan** | Target IP | Commercial API. Governed by [Shodan's Terms of Service](https://www.shodan.io/legal/tos). Free tier available; **1 credit per IP** |
| **NVD (NIST)** | CVE IDs | Public US government data, no licence restriction. Rate-limited to 5 req/30 s unauthenticated. [NVD terms](https://nvd.nist.gov/general/terms-of-use) |
| **CISA KEV** | Nothing — file download | US government public data, free to use and redistribute |
| **EPSS (FIRST.org)** | CVE IDs | Free. FIRST asks that EPSS be **cited by name** when scores are published — RedFlag does this in the UI and this documentation |
| **Vulners** | CVE IDs + API key | Commercial API with a free tier. [Vulners terms](https://vulners.com/) |
| **crt.sh** | Target domain | Free public certificate-transparency service operated by Sectigo. No formal terms; use courteously |
| **LeakIX** | Target domain and up to 2 IPs | Free API. [LeakIX terms](https://leakix.net/) |
| **MITRE ATT&CK** | Nothing — knowledge encoded locally | ATT&CK® is a registered trademark of The MITRE Corporation. Used under MITRE's [terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), which permit reuse with attribution. RedFlag links every technique to its attack.mitre.org page |
| **Obsidian** | Nothing | The brain writes a plain-Markdown vault. Obsidian itself is not a dependency and is not bundled |

**Privacy summary.** Only three services ever receive target-identifying data: Shodan (the IP),
LeakIX (the domain and IPs), and crt.sh (the domain). Everything else receives only CVE
identifiers or nothing at all. Consolidated view:
[SECURITY_AND_PRIVACY.md](SECURITY_AND_PRIVACY.md) §2.

---

## 6. Attributions

RedFlag builds on public security data and frameworks. Attribution where it is due:

- **MITRE ATT&CK®** — the technique taxonomy underpinning the attacker-brain. ATT&CK is a
  registered trademark of The MITRE Corporation. RedFlag encodes technique mappings locally and
  links each one to its canonical page.
- **CISA Known Exploited Vulnerabilities catalog** — the authoritative source for
  `ACTIVE_EXPLOITATION` status, published free by the US Cybersecurity and Infrastructure Security
  Agency.
- **EPSS**, by the FIRST.org EPSS Special Interest Group — the exploitation-probability model
  behind RedFlag's forward-looking scoring.
- **SSVC** (Stakeholder-Specific Vulnerability Categorization), CISA and Carnegie Mellon SEI — the
  methodology the weighting scheme is aligned with.
- **NVD**, NIST — CVSS base scores.
- **Nmap**, by Gordon Lyon and the Nmap Project.
- **Nuclei**, by ProjectDiscovery.
- **OWASP ZAP** and **OpenVAS/Greenbone** — supported through their report formats.
- **Reflex** — the UI framework.

Industry sources cited in `config/day1_blueprint.yaml` for the connectivity models: EY and
Deloitte (M&A clean rooms), VMware (Day-0 VDI productivity), Microsoft Entra (identity federation
and B2B trust options), and Cybersecurity Insiders (ZTNA in M&A). Pricing sources for
`config/day1_cost_catalog.yaml` are cited per line item in that file.

---

## 7. Licence compliance checklist

| # | Item | Status |
|---|---|---|
| 1 | A `LICENSE` file exists in the repository root | ❌ **Missing — §1** |
| 2 | The README's licence claim matches the actual licence | ❌ Blocked by (1) |
| 3 | Copyleft dependencies identified | ✅ `python-nmap` GPL-3.0, `fpdf2` LGPL-2.1 |
| 4 | No copyleft code is statically bundled or redistributed | ✅ pip-installed at runtime |
| 5 | The Nmap binary is not redistributed | ✅ Installed separately by the user |
| 6 | EPSS is cited by name where scores are shown | ✅ |
| 7 | MITRE ATT&CK is attributed and linked | ✅ |
| 8 | No API key or secret is committed | ✅ `.env` is git-ignored |
| 9 | Full transitive SBOM generated | ⚠️ Not yet — §3 |
| 10 | Dependency licences verified against installed distributions | ⚠️ Not yet — §2 |

---

## Related documents

- [AUTHORIZED_USE.md](AUTHORIZED_USE.md) — the legal boundaries of operating the tool
- [SECURITY_AND_PRIVACY.md](SECURITY_AND_PRIVACY.md) — the data-egress view
- [INTEGRATIONS.md](../technical/INTEGRATIONS.md) — technical detail per service
- [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §1.1 — the missing LICENSE
