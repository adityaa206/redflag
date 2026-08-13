# Configuration

Every tunable knob in RedFlag: environment variables, the constants module, and all seven YAML
files. Values shown are the real ones in the repository on 2026-07-27.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

> **All YAML is cached for the life of the process.** `config/loader.py` loads each file once.
> After editing any YAML you must **restart the app** for the change to take effect. In tests,
> call `config.loader.reload_all()`.

---

## 1. Environment variables (`.env`)

`.env` lives in the repository root and is **git-ignored**. Copy `.env.example` to create it.

| Variable | Purpose | Required | Behaviour if unset |
|---|---|---|---|
| `SHODAN_API_KEY` | Live Shodan host lookups (1 credit per IP) | No | `lookup_host()` returns `{"success": False, "error": ...}`; the pipeline continues. Upload a Shodan JSON instead |
| `VULNERS_API_KEY` | Vulners exploit confirmation; also passed to the Nmap `vulners` NSE script | No | `get_exploit_status_from_vulners()` no-ops; the NSE script still runs unauthenticated if installed |
| `REDFLAG_BRAIN_DIR` | Overrides the knowledge-base location | No | Defaults to `~/RedFlag-Brain` |

`.env.example` (committed, placeholders only):

```env
SHODAN_API_KEY=your_shodan_api_key_here
VULNERS_API_KEY=your_vulners_api_key_here
```

> `REDFLAG_BRAIN_DIR` is read directly from `os.environ` in `analysis/brain_memory.py`, not from
> `.env`. Set it as a real environment variable if you need it.

---

## 2. `config/__init__.py` — scoring constants

The only tunables that are **not** YAML. Changing any of these changes every score RedFlag has
ever produced, so treat them as a versioned decision.

```python
# ── Scoring weights — MUST sum to 1.0 ──
WEIGHT_EXPLOIT     = 0.30   # highest: active/public exploitation is the primary triage signal
WEIGHT_EXPOSURE    = 0.25   # reachability; mirrors the CVSS Attack Vector dimension
WEIGHT_CVSS        = 0.25   # technical severity baseline
WEIGHT_SENSITIVITY = 0.20   # business / regulatory impact

# ── Score → tier thresholds ──
TIER_THRESHOLD_CRITICAL = 75   # >= 75 → CRITICAL
TIER_THRESHOLD_MODERATE = 50   # >= 50 → MODERATE, else MANAGEABLE

# ── Shodan ──
SHODAN_MAX_CVES = 10   # cap on standalone CVE findings created from a Shodan record

# ── Vulners NSE ──
VULNERS_MIN_CVSS            = 5.0   # ignore NSE CVEs below this
VULNERS_STANDALONE_MIN_CVSS = 7.0   # min CVSS for secondary CVEs on an already-matched port

# ── Nmap ──
NMAP_SCAN_ARGS = "-sV --open -T4 --max-retries 2"
NMAP_FAST_ARGS = "-sV --open -T4 --top-ports 200 --version-intensity 3 --max-retries 1"
```

`-T4` is aggressive timing (the `-T3` default is roughly twice as slow; `-T5` starts missing
ports). Fast mode cuts a typical scan from 40–70 s to 15–25 s.

The **lookup tables** that these weights multiply live in `analysis/triage.py`, not in config —
`EXPOSURE_SCORES`, `SENSITIVITY_SCORES`, `EXPLOIT_SCORES`, `EVIDENCE_MULTIPLIERS`. They are
documented in [DATA_MODEL.md](DATA_MODEL.md) §2.

> A root-level `config.py` also exists with the same values plus a longer rationale comment.
> Python resolves the `config/` **package** first, so that file is dead code. See
> [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) §3.

---

## 3. `config/maturity_questions.yaml`

Defines the questionnaire. **One top-level key: `domains`.** 7 domains, **23 questions**.

| Domain key | Label | Questions |
|---|---|---|
| `identity_access` | Identity & Access Management | 4 |
| `network_security` | Network Security | 4 |
| `endpoint_security` | Endpoint Security | 3 |
| `application_security` | Application Security | 3 |
| `data_protection` | Data Protection | 3 |
| `incident_response` | Incident Response | 3 |
| `third_party_risk` | Third-Party & Supply Chain Risk | 3 |

Each question has `id`, `text`, `weight` and six `options` — **the option index is the maturity
level**, 0 to 5.

```yaml
domains:
  identity_access:
    label: "Identity & Access Management"
    description: "Controls over who can access what, with what privileges."
    questions:
      - id: iam_mfa
        text: "Is multi-factor authentication (MFA) enforced for all privileged and remote access?"
        weight: 2.0          # MFA counts double within the domain
        options:
          - "No MFA in place"                                    # level 0
          - "MFA available but optional"                         # level 1
          - "MFA required for admin accounts only"               # level 2
          - "MFA required for all remote access"                 # level 3
          - "MFA enforced everywhere with phishing-resistant methods (FIDO2/hardware)"
          - "Continuous authentication with risk-based step-up enforced"   # level 5
```

**Effect of editing:** the domain score is the weighted mean of *answered* questions only, so
raising a `weight` increases that question's pull on the domain score. Adding a question changes
the denominator and therefore every historical comparison. Question `id`s are used as form field
keys — renaming one silently discards any saved answer.

---

## 4. `config/corporate_standard.yaml`

The acquirer's bar. Three thresholds per domain on the same 0–5 scale, plus one global value.

| Domain | `acceptable_min` | `recommended` | `deal_blocker` |
|---|---|---|---|
| `identity_access` | 2 | 4 | 1 |
| `network_security` | 2 | 4 | 1 |
| `endpoint_security` | 2 | 4 | 1 |
| `application_security` | 2 | 3 | 1 |
| `data_protection` | 2 | 4 | 1 |
| `incident_response` | 2 | 3 | **0** |
| `third_party_risk` | 2 | 3 | 1 |

```yaml
overall_deal_blocker_threshold: 1.5   # mean across all domains
```

Severity is assigned in `analysis/maturity.py:score_domain()`:

- `score <= deal_blocker` (and at least one answer) → **`DEAL_BLOCKER`**
- `score < acceptable_min` → **`BELOW_MIN`**
- `score < recommended` → **`ACCEPTABLE`**
- otherwise → **`AT_TARGET`** (excluded from the gap report entirely)

Note `incident_response` has `deal_blocker: 0` — a missing IR plan is a gap but never on its own
a reason to walk away. Each domain also carries a `rationale` string, which is surfaced verbatim
in the Day-1 roadmap and the narrative.

**How to retune a deal-blocker threshold:** edit the domain's `deal_blocker` value, restart the
app, and re-run the assessment. Nothing else changes — the value flows to the maturity engine,
the gap report, the Day-1 tier gates and the cost engine automatically.

---

## 5. `config/pricing_benchmarks.yaml`

Three sections, all in USD, each entry a `low`/`base`/`high` triple.

| Section | Entries | Unit |
|---|---|---|
| `labour_rates` | 8 roles | USD per hour |
| `tool_costs` | 12 tools | per year, per endpoint, per user/month, or per engagement (each entry declares its `unit`) |
| `effort_hours` | 12 tasks | hours |

Representative values:

```yaml
labour_rates:
  security_engineer: {low: 85,  base: 150, high: 250}
  security_architect: {low: 120, base: 200, high: 350}
  incident_responder: {low: 150, base: 250, high: 400}

tool_costs:
  edr_per_endpoint: {low: 30,    base: 60,    high: 120,    unit: "per endpoint per year"}
  siem_annual:      {low: 15000, base: 50000, high: 200000, unit: "per year"}
  mfa_per_user:     {low: 3,     base: 6,     high: 15,     unit: "per user per month"}

effort_hours:
  patch_single_system:      {low: 1,  base: 3,   high: 8}
  network_segmentation:     {low: 40, base: 120, high: 300}
  mfa_rollout_100_users:    {low: 8,  base: 20,  high: 40}
```

Accessed through `get_labour_rate(role, scenario)`, `get_tool_cost(tool_key, scenario)` and
`get_effort_hours(task_key, scenario)`. All three fall back to `base`, then to a hard default
(150 / 0 / 8) if the key is missing — so a typo produces a plausible-looking wrong number rather
than an error. Check your key names.

**How to retune for a different market:** scale `labour_rates` and re-run. Everything downstream
— line items, scenarios, the CapEx/OpEx split, the confidence interval — recomputes.

---

## 6. `config/remediation_catalog.yaml`

Maps a finding or maturity gap to a costed line item. Five top-level keys, resolved in this
order by `cost/catalog.py:lookup_finding()`:

| Key | Entries | Matched on |
|---|---|---|
| `cve_overrides` | 5 | Exact `finding.cve_id` |
| `service_entries` | 13 | `finding.service` |
| `tier_entries` | 4 | `finding.deal_tier` |
| `maturity_entries` | 7 | `GapItem.catalog_key` (`{domain}_gap`) |
| `default` | 1 | Fallback — **flags the item `ZERO_ESTIMATE` for human review** |

Shipped `cve_overrides`: `CVE-2017-0144` (EternalBlue), `CVE-2021-44228` (Log4Shell),
`CVE-2023-44487` (HTTP/2 Rapid Reset), `CVE-2021-34527` (PrintNightmare), `CVE-2022-30190`
(Follina).

Shipped `service_entries`: `ftp`, `telnet`, `rdp`, `smb`, `vnc`, `redis`, `elasticsearch`,
`mongodb`, `docker`, `http`, `https`, `ssh`, `smtp`.

```yaml
cve_overrides:
  CVE-2017-0144:
    title: "Patch MS17-010 (EternalBlue / WannaCry)"
    description: "Critical SMB RCE used by WannaCry and NotPetya ransomware campaigns."
    category: patching              # RemediationCategory enum value
    capex_opex: opex                # capex | opex | mixed
    labour_role: security_engineer  # key in pricing_benchmarks.labour_rates
    labour_hours_key: patch_single_system   # key in pricing_benchmarks.effort_hours
    confidence: high                # high | medium | low
    notes: "MS17-010 patch is available for all affected Windows versions."
```

**How to add a pricing line item:** add an entry under the appropriate section. `labour_role` and
`labour_hours_key` must name existing keys in `pricing_benchmarks.yaml`; `category` must be a
valid `RemediationCategory` value; `capex_opex` and `confidence` must be valid enum values. No
code change is needed. Restart the app.

Note that dedup buckets on `catalog_key::category`, so ten findings resolving to the same
`service_entries` key collapse into one line item — with `min(low)`, `max(base)`, `max(high)`.

---

## 7. `config/narrative_blocks.yaml`

Every sentence the tool writes. Six sections; blocks within a section are sorted by `priority`
ascending and **the first whose `when` conditions all match wins**.

| Section | Blocks |
|---|---|
| `executive_summary` | 4 |
| `maturity_summary` | 3 |
| `cost_summary` | 4 |
| `day1_summary` | 4 |
| `finding_detail` | 6 |
| `remediation_priority` | 4 |

```yaml
executive_summary:
  - id: ex_deal_killer_present
    priority: 1
    when: {has_deal_killers: true}
    text: >
      This assessment identified {deal_killer_count} deal-killer finding(s) that
      present unacceptable risk to the proposed acquisition of {target}.
```

`{variable}` placeholders are substituted from a context dict built by `narrative/engine.py`.
Unknown placeholders are **left in place unchanged**, which is the visible symptom of a typo.
Floats ≥ 1000 render with thousands separators; smaller floats render to one decimal place.

**How to edit report wording:** change the `text` of the relevant block. To add a new case,
insert a block with a **lower** `priority` than the general one it should pre-empt, and a `when`
condition specific enough not to fire otherwise. Keep the most general block at the highest
priority number so it acts as the catch-all.

---

## 8. `config/day1_blueprint.yaml`

Drives the entire Day-1 tab. Seven top-level keys.

| Key | What it controls |
|---|---|
| `remote_access_services` | What counts as a remote-access pathway — 16 service names and 15 ports (3389, 22, 23, 5900/5901, 21, 445, 139, 5985/5986, 1723, 1194, 500, 4500, 1701) |
| `phases` | The four timeline phases with `label`, `window` and `description` |
| `phase_rules` | Ordered finding-attribute → phase mapping; **first match wins** |
| `maturity_gap_phase` | Gap severity → phase |
| `pillars` | The three review pillars and their four status-keyed recommendation strings |
| `connectivity_models` | The four-rung ladder with `summary`, `controls` and cited `sources` |
| `tier_gates` | Entry criteria per tier |

**The phase rules, in evaluation order:**

| # | Condition | Phase |
|---|---|---|
| 1 | `exploit_status: active_exploitation` | **P0** Pre-Connection Blocker |
| 2 | `deal_tier: deal_killer` | **P0** |
| 3 | `exposure: internet_facing` **and** `remote_access: true` | **P0** |
| 4 | `exposure: internet_facing` **and** `exploit_status: public_exploit` | **P0** |
| 5 | `exposure: internet_facing` | **P1** Day-1 Containment |
| 6 | `exposure: partner` **and** `remote_access: true` | **P1** |
| 7 | `deal_tier: critical` | **P2** Day 1–30 Stabilise |
| 8 | `exposure: partner` | **P2** |
| 9 | *(empty condition — always matches)* | **P3** Day 30–100 Integration-Ready |

Maturity gaps map separately: `deal_blocker → P0`, `below_min → P2`, `acceptable → P3`.

**Tier gate criteria.** Two criterion types:

- `no_finding` — passes when **no** finding matches the `when` clause.
- `maturity_min` — passes when the named domain's score ≥ the named `level`
  (`acceptable_min` or `recommended`) from `corporate_standard.yaml`. **Fails if the domain was
  never assessed** — you cannot prove a posture you did not measure.

| Tier | Criteria |
|---|---|
| `isolate` | *(none — always available; the floor)* |
| `broker` | No actively-exploited vulnerabilities |
| `federate` | The above, plus: no internet-facing remote access; `identity_access` ≥ acceptable_min; `network_security` ≥ acceptable_min |
| `integrate` | The above, plus: no internet-facing deal-killers; `identity_access` ≥ recommended; `network_security` ≥ recommended |

**How to retune:** to make the tool more conservative about federating, add a criterion to
`tier_gates.federate.criteria` or raise the `level` from `acceptable_min` to `recommended`. To
change what counts as remote access, edit the `services` and `ports` lists — this affects both
phase assignment and the gates.

---

## 9. `config/day1_cost_catalog.yaml`

Prices the connectivity ladder. Four top-level keys. Every item cites a real 2026 source in a
`source` field.

```yaml
assumptions:
  default_headcount: 250        # acquired-company users, if none is supplied
  opex_months: 12               # year-1 window for recurring items
  tsa_months: 12                # default TSA duration for the Isolate run-rate
  privileged_user_ratio: 0.05   # ~5% of users need PAM access

accuracy_bands: {high: 15, medium: 30, low: 50}   # confidence → ±% band
assumed_headcount_penalty: 8                       # extra ± when headcount is a guess
```

`models` holds one entry per rung, each a list of items:

| Model | Items |
|---|---|
| `isolate` | `cleanroom_setup`, `perimeter_ngfw`, `tsa_it_runrate` |
| `broker` | `perimeter_ngfw`, `vdi_daas`, `ztna`, `pam`, `siem_day1`, `broker_services` |
| `federate` | `ztna`, `identity_federation`, `edr_standardize`, `pam`, `siem_day1`, `federation_services` |
| `integrate` | `identity_federation`, `edr_standardize`, `tenant_migration`, `network_rearch`, `siem_unified`, `integration_pmo` |

Each item declares `key`, `title`, `category`, `capex_opex`, `scale`, `low`/`base`/`high`,
`confidence` and `source`. Six scale modes:

| `scale` | Multiplier applied to low/base/high |
|---|---|
| `fixed` | 1 |
| `per_user` | headcount |
| `per_user_year` | headcount |
| `per_user_month` | headcount × `opex_months` |
| `per_priv_user_year` | `round(headcount × privileged_user_ratio)`, minimum 1 |
| `tsa_runrate` | headcount × `tsa_months` |

**How to tighten the accuracy readout:** replace a `base` with a real vendor quote and set
`confidence: high`. Better still, enter the quote in the UI's vendor-quote field — that collapses
the item's triple to a single figure, pins it to `HIGH`, and clears its high-variance flag,
without editing YAML.

---

## 10. Retuning recipes

| Goal | Change | File |
|---|---|---|
| Make exploitability matter more than severity | Raise `WEIGHT_EXPLOIT`, lower `WEIGHT_CVSS` (keep the four summing to 1.0) | `config/__init__.py` |
| Classify more findings as Critical | Lower `TIER_THRESHOLD_CRITICAL` from 75 | `config/__init__.py` |
| Raise the bar for a maturity deal-blocker | Raise a domain's `deal_blocker` value | `corporate_standard.yaml` |
| Price for a different labour market | Scale `labour_rates` | `pricing_benchmarks.yaml` |
| Add a cost for a new CVE or service | Add a `cve_overrides` / `service_entries` entry | `remediation_catalog.yaml` |
| Change report wording | Edit a block's `text` | `narrative_blocks.yaml` |
| Treat a new port as remote access | Add it to `remote_access_services.ports` | `day1_blueprint.yaml` |
| Be stricter about federating identity | Add a criterion, or raise `level` to `recommended` | `day1_blueprint.yaml` |
| Use a real vendor quote in the budget | Enter it in the UI, or set `base` + `confidence: high` | `day1_cost_catalog.yaml` |
| Scan faster | Toggle **Fast mode** in the UI, or edit `NMAP_FAST_ARGS` | `config/__init__.py` |
| Store the brain elsewhere | Set `REDFLAG_BRAIN_DIR` | environment |

**After any YAML edit, restart the app.** The loader cache is per-process.

---

## Related documents

- [DATA_MODEL.md](DATA_MODEL.md) — the lookup tables these weights multiply
- [RESULTS_INTERPRETATION.md](../user/RESULTS_INTERPRETATION.md) — the effect of these values on output
- [MODULE_REFERENCE.md](MODULE_REFERENCE.md) — the loader accessors
- [ACCESS_AND_CREDENTIALS.md](../handover/ACCESS_AND_CREDENTIALS.md) — key provisioning
