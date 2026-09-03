# Test Plan

What is tested, how to run it, and — just as importantly — what is not covered.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Summary

| | |
|---|---|
| Framework | pytest 9.0.3 |
| Test files | 11 |
| **Test cases** | **143** |
| Status | **143 passed** (verified 2026-07-27) |
| Runtime | ~9 seconds |
| Network required | **No** |
| Target required | **No** |
| External binaries required | **No** |

The suite is a pure **engine** suite. It exercises the deterministic layers — scoring, maturity,
Day-1, cost, narrative, EPSS, Nuclei parsing and graph analytics — and deliberately excludes the
Reflex UI and all live network behaviour. That is why it runs in nine seconds on a plane.

---

## 2. How to run it

```bash
# Everything
pytest tests/ -v

# One module
pytest tests/test_triage.py -v
pytest tests/test_day1.py -v
pytest tests/test_estimator.py -v

# By keyword across the suite
pytest tests/ -k "day1"
pytest tests/ -k "epss or nuclei"

# Stop at the first failure
pytest tests/ -x

# Quiet — just the count
pytest tests/ -q
```

Activate the virtual environment first, or the imports will fail.

---

## 3. Coverage map

| File | Tests | Covers |
|---|---|---|
| `test_triage.py` | **24** | The scoring model: lookup tables, the weighted formula, the evidence multiplier, all deal-killer overrides, tier thresholds, and `triage_all` sort order |
| `test_day1.py` | **26** | The Day-1 engine end to end: remote-access detection by service and by port, all nine phase rules, roadmap construction with maturity gaps, tier-gate evaluation, connectivity recommendation, review pillars, and graceful degradation without a questionnaire |
| `test_estimator.py` | **23** | The cost engine: `CostTriple` arithmetic, catalogue lookup (CVE override → service → tier → default), deal-killer flagging, deduplication and its conservative merge, rollup totals, CapEx/OpEx split, scenarios, and the review gate |
| `test_maturity.py` | **17** | Domain scoring including weighting, partial answers and clamping; severity classification; overall assessment; and gap-report comparison against the corporate standard |
| `test_narrative_engine.py` | **15** | Block selection, priority ordering, condition matching, variable substitution, and each narrative builder |
| `test_day1_cost.py` | **10** | The integration budget: catalogue completeness, per-user scaling, ladder costing for all four tiers, pipeline wiring, accuracy readout, headcount-assumed penalty, and vendor-quote overrides |
| `test_integration.py` | **7** | End to end from a fixture through maturity → cost → narrative → CSV export |
| `test_epss.py` | **6** | EPSS attachment, promotion at threshold, non-promotion below it, never downgrading `ACTIVE_EXPLOITATION`, and no-op cases |
| `test_attack_graph.py` | **5** | Blast radius, chokepoint ranking, crown-jewel path discovery, no-internet and empty cases |
| `test_nuclei.py` | **5** | JSONL parsing, host/port/CVE extraction, severity→CVSS baseline, info-level filtering, and the correlation merge |
| `test_simulation.py` | **5** | The variance-based confidence interval and accuracy percentage |

---

## 4. What each module proves

**`test_triage.py`** — the most important file in the suite. It pins the exact numbers in
`EXPOSURE_SCORES`, `SENSITIVITY_SCORES`, `EXPLOIT_SCORES` and `EVIDENCE_MULTIPLIERS`, verifies the
weighted formula, and checks every deal-killer override independently. It constitutes the executable specification
for the scoring model and constrains any change to `analysis/triage.py`.

**`test_day1.py`** — the largest file. It walks every phase rule in order (`active_exploitation`
→ P0, `internet + remote_access` → P0, `partner + remote_access` → P1, plain internal → P3…) and
asserts the recommendation logic in both directions: `test_recommend_integrate_when_clean_and_mature`
proves the ladder climbs when the evidence allows it, and
`test_internet_rdp_blocks_federate_even_with_max_maturity` proves that a single internet-facing
RDP service pins you below Federate *no matter how good the questionnaire looks*. There are
explicit tests for degradation without a questionnaire and with no findings at all.

**`test_estimator.py`** — proves the catalogue resolution order and, importantly, that
deduplication is **conservative**: merged items take `min(low)`, `max(base)`, `max(high)`, so
collapsing ten identical findings never understates the fix.

**`test_epss.py`** — runs entirely offline by injecting a `scores` dict, which is the pattern the
whole suite follows for external data. It proves promotion fires at the threshold, does not fire
below it, and **never downgrades** an actively-exploited finding.

**`test_day1_cost.py`** — proves the integration budget scales with headcount, that all four
ladder rungs price above zero, that the accuracy band widens when headcount is assumed, and that a
vendor quote pins its item to high confidence and tightens the overall accuracy.

**`test_integration.py`** — the only test that runs several engines in sequence, driven by
`tests/fixtures/sample_assessment.json`. It also asserts the fixture exists and has the required
keys, so a missing fixture fails loudly rather than skipping silently.

---

## 5. Fixtures

| File | Size | Purpose | Committed |
|---|---|---|---|
| `tests/fixtures/mock_openvas.xml` | 9.8 KB | OpenVAS/GVM report for upload testing and manual demos | ✅ |
| `tests/fixtures/mock_zap.xml` | 14.2 KB | OWASP ZAP report | ✅ |
| `tests/fixtures/sample_assessment.json` | 4.1 KB | Drives `test_integration.py` | ✅ |
| `tests/fixtures/mock_nuclei.jsonl` | 4.2 KB | Nuclei JSONL for upload testing | ✅ |

**Contents of the mocks** — `mock_openvas.xml` contains EternalBlue, PrintNightmare, Log4Shell,
default credentials, Telnet, Redis exposure, TLS misconfiguration and missing security headers.
`mock_zap.xml` contains SQL injection, reflected XSS, IDOR, missing CSRF protection, directory
listing, insecure cookie flags, a vulnerable jQuery and an exposed Spring Actuator endpoint.

All four fixtures are committed, so a fresh clone can reproduce every upload workflow described
in [USER_GUIDE.md](../user/USER_GUIDE.md). Note that `test_nuclei.py` does **not** read
`mock_nuclei.jsonl` — it injects its JSONL inline — so the fixture serves the manual upload
walkthrough rather than the suite.

---

## 6. Testing philosophy

Three rules, visible throughout the suite:

1. **No network, ever.** External data is injected — EPSS takes an explicit `scores` dict; Nuclei
   takes inline JSONL; OpenVAS and ZAP take fixture files. A test that reaches the internet is a
   test that fails on a plane and lies in CI.
2. **No mocking framework.** The engines are pure functions over plain objects, so tests construct
   real `Finding` objects and assert on real output. If a module needs heavy mocking to test, that
   is a signal it has the wrong dependencies.
3. **Test the contract, not the implementation.** Tests assert scores, tiers, phases and totals —
   the things a user sees — rather than internal call sequences. This is what let the Streamlit →
   Reflex migration happen without touching a single test.

---

## 7. What is NOT covered

Stated plainly, because it matters more than the coverage that exists.

### The Reflex UI layer — untested

`redflag_ui/` has **no test coverage at all**. That includes:

- `RedFlagState.run_scan` — the entire pipeline orchestration
- All upload handlers and staging logic
- Every view-model flattening function
- All page components and rendering

`build_view()` is written as a module-level pure function specifically so it *could* be tested
without Reflex. It currently is not. This is the largest single coverage gap.

Note that the earlier Streamlit app *did* have UI tests; they were removed during the Reflex
migration and never replaced.

### Live network behaviour — untested

No test exercises a real Nmap scan, a real Shodan lookup, a live KEV or EPSS fetch, a DNS query, a
TLS handshake, a crt.sh query, or a LeakIX call. The scanners' **parsers** are tested against
fixtures; their **network paths and failure modes** are not.

That matters because the failure modes are silent — for example, `fetch_cvss_from_nvd()` returning
6.5 on any error. Nothing verifies that behaviour.

### Also untested

| Area | Note |
|---|---|
| PDF generation (`reports/pdf_report.py`) | 440 lines, entirely uncovered. The `_safe()` character-stripping path is a known source of runtime errors |
| The brain (`analysis/brain_memory.py`) | Recall, learn, vault writing and `export_seed()` are all uncovered — including the sanitisation that decides what is safe to commit |
| `analysis/parser.py` | Nmap XML parsing has no direct test; it is only exercised indirectly |
| The Shodan enrichment path | `enrich_findings_with_shodan()` and `create_shodan_findings()` are uncovered |
| DNS / TLS / breach scanners | No fixture-driven tests |
| XLSX export (`cost/exporters.py`) | CSV export is covered by `test_integration.py`; XLSX is not |
| `analysis/parsers/excel_assets.py` | Column detection and the upgrade-only rule are uncovered |

### Highest-value tests to add

1. **`export_seed()` sanitisation** — assert that `targets` is stripped and that no other field
   contains a hostname. This is the boundary between local memory and published data, and it is
   currently unguarded.
2. **`build_view()`** — pure and already isolated; a handful of tests would cover a large surface.
3. **`apply_sensitivity_to_findings()`** — assert it upgrades `UNKNOWN` and never downgrades.
4. **`reports/pdf_report.py` smoke test** — generate a PDF from fixture findings and assert it is
   non-empty. Would catch the encoding failures.
5. **Scanner degradation** — assert each scanner returns `[]` (rather than raising) when its
   dependency is missing.

---

## 8. Coverage measurement

Coverage is not currently measured. To generate a report:

```bash
pip install pytest-cov
pytest tests/ --cov=analysis --cov=cost --cov=narrative --cov=scanners --cov-report=term-missing
```

Expect high coverage on `analysis/triage.py`, `analysis/day1.py`, `analysis/maturity.py` and the
`cost/` package, and near-zero on `redflag_ui/`, `reports/pdf_report.py` and the network paths in
`scanners/`.

`pytest-cov` is not in `requirements.txt` — it is a development-only tool.

---

## 9. Continuous integration

**None configured.** There is no GitHub Actions workflow, no pre-commit hook, and no automated
gate. Tests are run manually.

Adding a workflow that runs `pytest tests/ -v` on push would be a small, high-value change: the
suite needs no network, no secrets and no binaries, so it would work in a stock runner with only
`pip install -r requirements.txt`.

---

## Related documents

- [LIMITATIONS.md](LIMITATIONS.md) — accuracy caveats that are by design, not gaps in testing
- [DEVELOPER_ONBOARDING.md](../operations/DEVELOPER_ONBOARDING.md) — running tests while developing
- [KNOWN_ISSUES_AND_BACKLOG.md](../handover/KNOWN_ISSUES_AND_BACKLOG.md) — the fixture and count defects
- [MODULE_REFERENCE.md](../technical/MODULE_REFERENCE.md) — what each tested function does
