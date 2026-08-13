# Integrations

Every external tool, binary and API RedFlag touches: what it is used for, what leaves your
machine, what it costs, and exactly how it behaves when it is unavailable.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Summary table

| # | Integration | Type | Mode | Key needed | Cost | Data sent |
|---|---|---|---|---|---|---|
| 1 | **Nmap** | Local binary | Live | No | Free | Packets to the target |
| 2 | **Shodan** | REST API | Live **or** upload | Optional | 1 credit / IP | Target IP |
| 3 | **Nuclei** | Local binary | Live **or** upload | No | Free | Requests to the target |
| 4 | **OpenVAS / GVM** | XML upload | Upload only | No | Free | Nothing |
| 5 | **OWASP ZAP** | XML upload | Upload only | No | Free | Nothing |
| 6 | **Vulners NSE** | Nmap script | Live (in-scan) | Optional | Free | CVE lookups from the NSE script |
| 7 | **Vulners API** | REST API | Live | Optional | Free tier | CVE IDs |
| 8 | **CISA KEV** | Public JSON feed | Live | No | Free | Nothing (download only) |
| 9 | **EPSS (FIRST.org)** | REST API | Live | No | Free | CVE IDs |
| 10 | **NVD (NIST)** | REST API | Live | No | Free | CVE IDs |
| 11 | **DNS** | DNS resolver | Live | No | Free | DNS queries for the target domain |
| 12 | **TLS + crt.sh** | Socket + REST | Live | No | Free | TLS handshake to the target; domain to crt.sh |
| 13 | **LeakIX** | REST API | Live | No | Free | Target domain and IPs |
| 14 | **Asset inventory** | Excel upload | Upload only | No | Free | Nothing |

A consolidated view of what leaves the machine is in
[SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) §2.

---

## 2. Nmap

- **Module:** `scanners/nmap_scan.py` · **Library:** `python-nmap 0.7.1`
- **Purpose:** the base layer. Open ports, service names, product/version banners. Every other
  scanner either enriches these findings or adds to them.
- **Mode:** active scan against the target. This is the one integration that **touches the target
  directly and at volume** — see [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md).
- **Arguments:** `-sV --open -T4 --max-retries 2`; fast mode adds
  `--top-ports 200 --version-intensity 3 --max-retries 1`.
- **Output:** `{output_dir}/nmap_{target}_{YYYYMMDD_HHMMSS}.xml`, written to
  `%TEMP%/redflag_scans` at runtime.
- **Binary discovery:** two hard-coded Windows paths only —
  `C:\Program Files (x86)\Nmap\nmap.exe`, then `C:\Program Files\Nmap\nmap.exe`.
  It does **not** consult `PATH`, so a non-standard Windows install or a macOS/Linux install
  (`/usr/local/bin/nmap`) will not be found by `find_nmap()`.
- **Degradation:** **this is the one integration that raises.** `run_nmap_scan()` throws
  `FileNotFoundError` if the binary is missing, and `run_scan` surfaces it as
  *"Scan failed: Could not find nmap.exe"*. Everything else in the pipeline degrades silently.
- **Evidence strength produced:** `CONFIRMED` — the port genuinely is open. CVSS is a flat **3.5**,
  because an open port is not itself a vulnerability.

---

## 3. Shodan

- **Module:** `scanners/shodan_scan.py` · **Library:** `shodan 1.31.0`
- **Endpoint:** the Shodan host API, via the official client.
- **Purpose:** confirm which ports are visible **from the internet**, and pull organisation, ASN,
  ISP, geography, hostnames and known CVEs.
- **Key:** `SHODAN_API_KEY`. **Cost: 1 credit per IP queried.**
- **Data sent:** the target IP address, nothing else.
- **Two modes:**
  - *Live* — `lookup_host(ip)`. Requires a resolved IPv4 address, so `run_scan` calls
    `socket.gethostbyname()` first.
  - *Upload* — `parse_shodan_json(data)` reads a Shodan host record from the **Shodan JSON**
    upload slot. **The upload takes priority: if one is staged, the live API is never called.**
    Useful when the target supplies its own export, and it costs nothing.
- **What it changes:** for findings whose port Shodan also observed, `exposure` becomes
  `INTERNET_FACING` and `evidence_strength` becomes `CORRELATED`. This is the single biggest
  score mover in the product — exposure is worth 25% of the weighting, and the jump from
  `INTERNAL` (30) to `INTERNET_FACING` (100) is large.
- **It also creates standalone findings:** up to `SHODAN_MAX_CVES` (10) CVE findings plus one per
  risky observed port, from a 12-port table (21, 23, 25, 3389, 445, 5900, 6379, 9200, 27017,
  5000, 8080, 2375). These carry `EXTERNAL` evidence (×0.80).
- **Degradation:** no key, or an API error, or an unresolvable hostname → the enrichment step is
  skipped entirely. Findings keep the `PARTNER`/`INTERNAL` exposure that `analysis/parser.py`
  assigned, and score correspondingly lower.

---

## 4. Nuclei

- **Module:** `scanners/nuclei_scan.py` · **Binary:** ProjectDiscovery Nuclei (optional)
- **Purpose:** template-based DAST. Confirms **actual** vulnerabilities — CVEs, exposed admin
  panels, default credentials, misconfigurations — rather than just open ports.
- **Mode:** live subprocess (300 s default timeout) **or** an uploaded `nuclei -jsonl` file.
- **Binary discovery:** `shutil.which("nuclei")` first — genuinely cross-platform — then
  `~/go/bin/nuclei[.exe]`, `C:\Program Files\Nuclei\nuclei.exe`, `/usr/local/bin/nuclei`,
  `/opt/homebrew/bin/nuclei`.
- **Severity → CVSS:** `critical 9.5 · high 7.5 · medium 5.5 · low 3.0 · info 0.0`.
- **Cross-references CISA KEV** for each CVE it reports.
- **Merge:** `merge_nuclei_with_nmap()` correlates by `(host, port)` and upgrades the matched Nmap
  finding to `CONFIRMED` with the higher CVSS and exploit status.
- **Degradation:** binary absent → `run_nuclei_scan()` returns `[]` silently. You can still upload
  JSONL produced on any other machine, so no local install is ever required.

---

## 5. OpenVAS / GVM

- **Module:** `scanners/openvas_parse.py` · **Mode:** XML upload only
- **Purpose:** verified CVEs and configuration flaws from an authenticated or credentialed scan —
  the depth RedFlag cannot reach on its own.
- **Data sent:** none. Parsing is entirely local.
- **Format:** handles both `<report><results>` and bare `<results>` document shapes. Extracts CVE
  references and CVSS from either the `<result>` or its `<nvt>` element, and derives exploit
  status from CVSS combined with the GVM threat level.
- **Merge:** correlates by `host:port`, upgrading matched Nmap findings. Unmatched OpenVAS
  findings are added on their own.
- **Fixture:** `tests/fixtures/mock_openvas.xml` contains EternalBlue, PrintNightmare, Log4Shell,
  default credentials, Telnet, Redis exposure, TLS misconfiguration and missing security headers.
- **Degradation:** not applicable — nothing runs unless a file is uploaded.

---

## 6. OWASP ZAP

- **Module:** `scanners/zap_scan.py` · **Mode:** XML upload only
- **Purpose:** web-application-layer findings — SQL injection, XSS, IDOR, missing CSRF protection,
  directory listing, cookie flags, vulnerable libraries, exposed actuator endpoints.
- **Data sent:** none. Local parsing.
- **Exposure derivation:** from the port and whether the site was HTTPS.
- **Merge:** correlates by `host:port` into the Nmap layer.
- **Fixture:** `tests/fixtures/mock_zap.xml`.
- **Degradation:** not applicable — upload only.

---

## 7. Vulners NSE script

- **Module:** `scanners/vulners_parse.py` (parsing); `scanners/nmap_scan.py` (invocation)
- **Purpose:** CVE-to-service mapping produced **during** the Nmap scan.
- **How it runs:** if `vulners.nse` is present in Nmap's `scripts/` directory, `run_nmap_scan()`
  appends `--script vulners --script-args vulners.mincvss=5.0`, plus `,api_key=<key>` when
  `VULNERS_API_KEY` is set.
- **Parsing:** `parse_vulners_from_nmap_xml()` reads the script output already embedded in the
  XML — **no additional network call from RedFlag**. The NSE script itself contacts Vulners
  during the scan.
- **Thresholds:** `VULNERS_MIN_CVSS = 5.0`; `VULNERS_STANDALONE_MIN_CVSS = 7.0` for secondary CVEs
  on an already-matched port.
- **Degradation:** script not installed → the argument is omitted, a `[INFO]` line is printed, and
  no Vulners findings are produced. Nothing fails.

---

## 8. Vulners API

- **Module:** `scanners/vulners_enrich.py`
- **Endpoint:** `https://vulners.com/api/v3/search/lucene/` (POST), 6 s timeout
- **Query:** `cvelist:{CVE} AND type:exploit`, size 1 — RedFlag only asks *whether* an exploit
  exists, not for its content.
- **Data sent:** the CVE ID and your API key.
- **Key:** `VULNERS_API_KEY`. Free tier available.
- **Caching:** per-CVE, in-process, for the session.
- **Upgrade only:** `get_exploit_status_from_vulners()` never downgrades `ACTIVE_EXPLOITATION` and
  only ever raises `UNKNOWN` → `PUBLIC_EXPLOIT`.
- **Degradation:** no key → returns the current status unchanged, silently. `exploit_status`
  simply stays `UNKNOWN` (which still scores 30) unless KEV or EPSS supplies it.

---

## 9. CISA KEV

- **Modules:** `scanners/kev_lookup.py`; `analysis/brain_memory.py:ingest_kev()`
- **Endpoint:**
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Purpose:** the authoritative list of vulnerabilities **confirmed exploited in the wild**. A
  KEV hit sets `ACTIVE_EXPLOITATION`, which is a deal-killer override — score forced to 100.
- **Data sent:** none. It is a public file download.
- **Key:** none required.
- **Caching:** the whole catalogue is fetched once per process and held in `_kev_cache`.
- **Also used by the brain:** the **Refresh threat intel** button on the Attack path tab calls
  `BrainMemory.ingest_kev()`, which stores the full CVE list in `brain.json` and back-fills the
  `kev` flag on every CVE the brain already knows.
- **Degradation:** unreachable → the cache becomes `{}`, and every `is_kev()` returns `False`.
  **This is the most consequential silent degradation in the product**: with no KEV feed, an
  actively-exploited CVE will not be flagged as a deal killer. EPSS provides partial cover.

---

## 10. EPSS (FIRST.org)

- **Module:** `scanners/epss_scan.py`
- **Endpoint:** `https://api.first.org/data/v1/epss`, 15 s timeout, **batched 100 CVEs per
  request**
- **Purpose:** the probability that a CVE will be exploited **in the next 30 days**. This is what
  makes the risk model forward-looking rather than purely retrospective.
- **Data sent:** CVE IDs only.
- **Key:** none required.
- **Promotion rule:** `EPSS ≥ 0.50` on a finding whose status is `UNKNOWN` or `NO_EXPLOIT`
  promotes it to `PUBLIC_EXPLOIT` and sets `raw_data["epss_promoted"] = True`. It never
  downgrades. Rationale: [ADR-0007](../process/adr/0007-epss-exploit-promotion.md).
- **Position in the pipeline:** runs **last before triage**, because promotion changes the score.
- **Degradation:** unreachable → findings pass through untouched; `epss_score` stays `None` and no
  promotion occurs. Tests inject a `scores` dict to bypass the network entirely.

---

## 11. NVD (NIST)

- **Module:** `scanners/shodan_scan.py` → `fetch_cvss_from_nvd()` / `fetch_cvss_batch()`
- **Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`, 8 s timeout
- **Purpose:** real CVSS base scores for CVEs that Shodan reports without one.
- **Data sent:** CVE IDs only.
- **Key:** none used. **Rate limit: 5 requests / 30 s unauthenticated**, which is why
  `fetch_cvss_batch()` caps its thread pool at 5 workers and skips anything already cached.
- **Score preference:** CVSS v3.1 → v3.0 → v2.
- **Degradation:** any failure falls back to a **default CVSS of 6.5**. Note this is a *silent
  substitution of a plausible number*, not an error — if NVD is unreachable, a batch of CVEs will
  all score 6.5.

---

## 12. DNS

- **Module:** `scanners/dns_scan.py` · **Library:** `dnspython 2.8.0`
- **Purpose:** email-security posture, which becomes the acquirer's liability on day one.
- **Queries sent:** `TXT` on the domain (SPF), `TXT` on `_dmarc.{domain}`, `TXT` on
  `{selector}._domainkey.{domain}` for **12 common selectors** (`default`, `google`, `mail`,
  `selector1`, `selector2`, `dkim`, `k1`, `s1`, `s2`, `email`, `mandrill`, `protonmail`), and
  `DNSKEY` (DNSSEC). 8 s lifetime per query.
- **Key:** none. Uses the system resolver.
- **Findings produced:** missing SPF (5.3) · multiple SPF records (4.0) · `+all` (6.0) · `~all`
  (3.5) · missing DMARC (6.5) · `p=none` (4.5) · no DKIM found (4.0, `INFERRED`) · no DNSSEC (3.0).
- **Known limitation:** DKIM selectors are arbitrary names. A domain using a custom selector will
  produce a false "No DKIM Selector Found" — which is why that finding alone is marked `INFERRED`
  (×0.85) rather than `CONFIRMED`.
- **Degradation:** returns `[]` immediately for a bare IP address. Any resolver failure returns an
  empty record list, which reads as "not configured" — a resolver outage can therefore produce
  false positives.

---

## 13. TLS and crt.sh

- **Module:** `scanners/tls_scan.py` · **Library:** `cryptography 48.0.0`
- **Two parts:**
  1. **Direct TLS connection** to each HTTPS port Nmap found (443 always included), 8 s timeout.
     Reads certificate expiry, issuer, subject, SANs, negotiated TLS version and cipher.
     **Certificate verification is deliberately disabled** (`CERT_NONE`) so that an expired or
     self-signed certificate can still be inspected — the point is to *report* the problem.
  2. **crt.sh certificate-transparency query** — `https://crt.sh/?q=%.{domain}&output=json`,
     12 s timeout. Returns every subdomain that has ever had a certificate issued, revealing
     forgotten and unmonitored hosts.
- **Data sent:** a TLS handshake to the target; the bare domain name to crt.sh.
- **Key:** none.
- **Weak versions flagged:** TLS 1.0, TLS 1.1, SSLv2, SSLv3 — deprecated and a PCI-DSS violation.
- **Degradation:** returns `([], {"skipped": ...})` for a bare IP. crt.sh is frequently slow or
  rate-limited; a failure returns an empty subdomain list, and the certificate checks still run.

---

## 14. LeakIX

- **Module:** `scanners/breach_scan.py`
- **Endpoints:** `https://leakix.net/domain/{domain}` and `https://leakix.net/host/{ip}`,
  12 s timeout
- **Purpose:** answers the single most important acquisition question — *has this company already
  been compromised?* LeakIX indexes live exposures: unauthenticated MongoDB/Elasticsearch/Redis,
  leaked configuration and credential dumps, exposed `.git` directories and backups.
- **Data sent:** the target domain and up to **2 IP addresses** (capped to avoid rate limiting).
- **Key:** none required for basic queries.
- **Classification:** credential/secret leak → CVSS 9.5 + `ACTIVE_EXPLOITATION` · exposed
  database → 8.5 + `ACTIVE_EXPLOITATION` · exposed `.git` → 7.5 + `PUBLIC_EXPLOIT` · exposed
  backup → 7.0 · generic exposure → 6.0. The first two therefore trigger the deal-killer override.
- **Evidence strength:** `CONFIRMED` — the exposure has been *observed* by a public scanner, not
  inferred.
- **Degradation:** any error is captured into the returned summary dict and the findings list is
  simply shorter. Never raises.

---

## 15. Asset inventory (Excel)

- **Module:** `analysis/parsers/excel_assets.py` · **Library:** `openpyxl 3.1.5` via pandas
- **Purpose:** the only source of `data_sensitivity`. Without it, every finding stays `UNKNOWN`
  and scores the neutral 50 on the dimension worth 20% of the weighting — **and two of the three
  deal-killer override rules can never fire**, because both require `CROWN_JEWEL` or `REGULATED`.
- **Format:** any `.xlsx` with a host column (`ip`, `host`, `ip_address`, `hostname`, `address`)
  and a sensitivity column (any header containing `sensitiv` or `classif`, or exactly `tier`).
  Matching is case-insensitive and space-tolerant.
- **Accepted values:** `crown_jewel` / `crown jewel` / `crownjewel`, `regulated`, `sensitive`,
  `low`, `unknown`. Anything unrecognised becomes `UNKNOWN`.
- **Upgrade only:** a finding is stamped **only if its sensitivity is currently `UNKNOWN`**.
- **Degradation:** **raises `ValueError`** if a required column is missing — surfaced as an upload
  error in the UI. Not uploading a file is fine; uploading a malformed one tells you so.

---

## 16. Running with no API keys at all

RedFlag is designed to produce a complete assessment with zero keys. This is a deliberate
constraint, not a fallback — see [ADR-0003](../process/adr/0003-free-no-paid-api.md).

| What you lose | What still works |
|---|---|
| Live Shodan lookup | Upload a Shodan host JSON instead — it takes priority over the live call anyway |
| Vulners API exploit confirmation | KEV and EPSS both supply exploit intelligence with no key |
| *(nothing else)* | Nmap, Nuclei, OpenVAS, ZAP, CISA KEV, EPSS, NVD, DNS, TLS, crt.sh, LeakIX, Excel |

**Ten of the fourteen integrations require no key at all.** The two optional keys only sharpen
enrichment; neither gates any feature.

---

## 17. Failure-mode reference

| Integration | If unavailable | Visible symptom | Risk to the assessment |
|---|---|---|---|
| Nmap | **Raises** | *"Scan failed: Could not find nmap.exe"* | Total — no base findings |
| Shodan | Silent skip | Exposure stays `PARTNER`/`INTERNAL` | **High** — scores materially understate risk |
| Nuclei | Silent `[]` | Fewer `CONFIRMED` findings | Medium |
| CISA KEV | Silent `{}` | No deal-killer overrides fire | **High** — an exploited CVE goes unflagged |
| EPSS | Silent skip | No `epss_score`, no promotion | Medium |
| NVD | Falls back to **6.5** | Plausible but wrong CVSS | Medium — *silent substitution* |
| Vulners | Silent no-op | `exploit_status` stays `UNKNOWN` | Low — KEV/EPSS cover most of it |
| DNS | Empty records | Reads as "not configured" | Low — but can cause **false positives** |
| TLS / crt.sh | Empty list | No subdomain discovery | Low |
| LeakIX | Error into summary | No breach findings | Medium |
| Excel | **Raises `ValueError`** | Upload error shown | None — it tells you |

> **Consequence.** A scan that produces a clean report is not evidence that the target is clean;
> it may instead reflect an unreachable KEV feed. The feeds should be confirmed live before an
> assessment is relied upon. See [LIMITATIONS.md](../testing/LIMITATIONS.md).

---

## Related documents

- [SECURITY_AND_PRIVACY.md](../legal/SECURITY_AND_PRIVACY.md) — the consolidated egress view
- [AUTHORIZED_USE.md](../legal/AUTHORIZED_USE.md) — which of these touch the target directly
- [LICENSES_AND_ATTRIBUTION.md](../legal/LICENSES_AND_ATTRIBUTION.md) — service terms and attribution
- [MODULE_REFERENCE.md](MODULE_REFERENCE.md) — the functions behind each integration
- [TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md) — what to do when one of these fails
