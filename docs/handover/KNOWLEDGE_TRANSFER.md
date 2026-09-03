# Knowledge Transfer

Design rationale and non-obvious behaviour that are not apparent from the source alone.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## 1. Design principles

Three principles govern the structure of the codebase.

### 1.1 There is exactly one finding set

Every scanner, feed and uploaded file exists to produce or improve `Finding` objects
(`analysis/schema.py`). Nothing renders its own results. A Nuclei hit does not appear in a
"Nuclei section" — it merges into the finding that Nmap already created for that `host:port`,
raising its evidence strength from `CONFIRMED`-by-banner to a verified vulnerability, its CVSS,
and its exploit status. The output is one ranked list, not twelve lists.

This is why the merge functions are named `merge_*_with_nmap` rather than `add_*_findings`.

### 1.2 Scanners perform network I/O; analysis does not

`scanners/` is the only layer permitted to make a network call. Everything in `analysis/`,
`cost/` and `narrative/` is a pure function of its inputs: identical findings produce an identical
score, sentence and price, offline, on every run. This property is what makes the reports
defensible in a deal room, and what makes the engines testable without network mocking.

`analysis/brain_memory.py` is the sole exception, and only for its optional `ingest_kev()` call.

### 1.3 The interface is a projection

`redflag_ui/state.py` implements no business logic. It calls the engines, then flattens their
rich objects into flat dataclass "view-models" (`FindingRow`, `LadderStep`, `GateRow`,
`CostLadderRow`…) whose fields are already strings, integers and CSS class names. The Reflex
components bind to those fields directly.

This boundary was validated in practice: the interface was migrated from Streamlit to Reflex in
June 2026 with **no changes to any engine**.

### 1.4 The pipeline, end to end

`RedFlagState.run_scan` (`redflag_ui/state.py:958`) is the spine. In order:

1. Nmap → XML → `analyze_nmap_file()` → base findings
2. Vulners NSE block parsed from the same XML → merged in
3. Shodan: a **staged upload beats the live API call**; enrich matched ports, plus standalone
   CVE/port findings
4. OpenVAS → ZAP → Nuclei, each correlation-merged by `host:port`
5. DNS, TLS and breach scans (live target only) append their own findings
6. Asset-inventory Excel stamps `data_sensitivity` onto matching hosts
7. EPSS attaches exploitation probability and may **promote** exploit status
8. `triage_all()` scores and sorts everything
9. `build_view()` runs the Day-1, attack-brain, attack-graph and narrative engines and flattens
   the lot into view-models
10. `_learn_and_recall()` reads the brain's prior knowledge, then folds this scan into it

---

## 2. Non-obvious behaviour

Each of the following is a constraint discovered in development and not evident from the source.

### 2.1 Nothing may be written inside the repository at runtime

Nmap XML goes to `%TEMP%/redflag_scans` (`_SCAN_DIR` in `state.py`); the brain goes to
`~/RedFlag-Brain`. This is not tidiness — it is load-bearing. Reflex's development server watches
the worktree, and a write inside it triggers a hot reload that **resets backend state mid-scan**.
The scan completes and the findings vanish. The tell-tale is `Compiling…` appearing in the
terminal during a scan.

### 2.2 The project must not reside in OneDrive

The working checkout was moved from `OneDrive\Desktop\Redflag` to `C:\Users\Adityaa\Redflag`
because OneDrive's sync engine fights Reflex's Node/Vite build: `EBUSY` errors, npm prune churn,
and a blank page with "cannot resolve react". `.web/` and `node_modules/` must not reside in a
synchronised folder.

### 2.3 Hostnames must be resolved before a Shodan lookup

Shodan's host API takes an IP. `run_scan` calls `socket.gethostbyname(tgt)` first and passes
`resolved_ip` onward. If resolution fails, the Shodan step is skipped silently rather than
erroring.

### 2.4 The knowledge base bootstraps from a seed on first run

A fresh clone does **not** start with an empty brain. `BrainMemory._load()` sees no
`~/RedFlag-Brain/brain.json` and copies `analysis/brain_seed/brain.json` in. `export_seed()` goes
the other way and **strips the `targets` map** — the only field naming a scanned host — so
committing a refreshed seed never reveals who was assessed. See
[BRAIN_KNOWLEDGE_BASE.md](../technical/BRAIN_KNOWLEDGE_BASE.md).

### 2.5 First launch compiles a frontend and requires Node.js

Reflex builds a Next.js bundle on first run. This takes approximately one minute and will offer
to install Node.js 18+ if it is absent. The delay is expected and occurs only once.

### 2.6 Enum values, not enum objects

`Finding` sets `model_config = ConfigDict(use_enum_values=True)`, so a `Finding` field holds the
**string** `"internet_facing"`, not `ExposureLevel.INTERNET_FACING`. But `triage_all()` assigns
enum *objects* to `deal_tier`. The codebase therefore normalises everywhere with

```python
def _v(x) -> str:
    return str(getattr(x, "value", x))
```

This helper must be used in preference to `str(x)`, which on an enum member yields
`"DealTier.CRITICAL"` and silently fails every comparison and dictionary lookup.

### 2.7 Uploads take priority over live API calls

If a Shodan JSON is staged, `lookup_host()` is never called. This is deliberate: it saves an API
credit and lets a target supply its own export.

### 2.8 Scanners degrade to an empty result, never to an exception

Missing Nuclei binary → `[]`. No Vulners key → status unchanged. Network down → EPSS enrichment
skipped. This is why a scan with no keys and no optional binaries still produces a full report.
The cost is that a genuine bug inside a scanner is swallowed by `except Exception: pass` in
`run_scan`. A scanner that appears to produce nothing should therefore be invoked directly from a
Python shell rather than diagnosed through the interface.

### 2.9 Reflex-specific constraints

- `rx.upload` cannot take a `Var` for `class_name` ("Cannot iterate over Var"). Keep it static
  and put conditional classes on a wrapping `rx.el.div`.
- Dynamic widths and gradients must be **precomputed string Vars** (`bar_w="60%"`,
  `donut_gradient="conic-gradient(...)"`), never f-strings built over a Var in a component.
- Backend-only state vars use a leading underscore (`_findings`, `_assessment`, `_gap_report`,
  `_staged`) so Reflex does not serialise the raw engine objects to the browser.
- A compile error on hot reload **terminates the development server**. Component edits should be
  validated by building the page component and calling `.render()` in the virtual environment,
  which surfaces binding errors without involving the running server.

---

## 3. Areas requiring particular care

| Area | Consideration |
|---|---|
| **Scoring arithmetic** (`analysis/triage.py`) | The weights must sum to 1.0 or the score ceases to be a 0–100 scale. The evidence multiplier is applied *after* the weighted sum. Deal-killer overrides are evaluated *before* any scoring and force the score to 100; altering their order alters verdicts. 24 tests constrain this file. |
| **Knowledge-base write path** (`analysis/brain_memory.py`) | Writes to the operator's home directory. `_save()` and `_write_vault()` are wrapped in bare `except: pass` so that a disk fault cannot interrupt a scan; consequently a failure produces no diagnostic. Where the knowledge base does not update, verify that the directory exists and is writable. |
| **`export_seed()`** | Determines what is safe to publish. It strips `targets` and nothing else. Any new field added to `brain.json` that could identify a target must be stripped here as well. |
| **Silent degradation without keys** | A report produced without a Vulners key is indistinguishable from one produced with it, save for weaker exploit statuses. The recipient of a report should be told which enrichments were live. |
| **`config/` YAML edits** | The loader caches every file for the lifetime of the process. A YAML change requires an application restart, or `reload_all()` under test, before taking effect. |
| **Correlation-merge functions** | These mutate and upgrade existing findings in place. An upgrade that inadvertently *downgraded* CVSS or exploit status would understate a genuine risk; the `_higher_exploit()` helpers exist to prevent this and should be retained. |
| **PDF generation** | fpdf2 raises on characters outside the embedded font. PDF text passes through `_safe()` in `reports/pdf_report.py`. A new glyph introduced without verification raises at export time rather than at authoring time. |

---

## 4. My assessment

**What I would keep unchanged.** The scoring model and the layering around it. Four weighted
factors, an evidence multiplier and a small set of categorical overrides is enough to rank
findings the way a deal team actually thinks, and it is simple enough to explain in a meeting
without a slide. Keeping every one of those numbers in configuration rather than in code is what
makes the model arguable instead of authoritative, which for a risk score is the more useful
property. The scanner contract — every scanner returns `Finding` objects or an empty list, never
an exception — is the other part I would not change; it is why fourteen integrations coexist
without any one of them being able to end a scan.

**Where the design is honestly weaker than it looks.** The cost engine applies a genuinely
careful uncertainty model — triangular distributions widened by confidence, aggregated with
partial correlation, producing an 80% interval — to inputs that ultimately come from a catalogue
lookup and a headcount. The statistics are sound; the precision they imply exceeds the quality of
what feeds them. The confidence interval should be read as a statement about spread in the
benchmark data, not as a claim to know the true cost to within a band. Anyone extending this
should invest in the input catalogue before refining the mathematics further.

**The knowledge base weights by prevalence only.** A technique seen in twenty scans two months ago
counts the same as one seen yesterday. For a corpus of this size that is the right simplification —
recency weighting on sparse data mostly amplifies noise — but it will not stay right. Once the
brain holds a few hundred scans, something in the finding will need to decay, or old estate
patterns will quietly dominate the recall panel. That is the first change I would make as the
corpus grows.

**The largest structural gap is the interface layer's test coverage.** The engines carry 143
tests; `redflag_ui/` carries none, because the Streamlit suite was retired in the migration and
never replaced. The view-model flattening in `state.py` is real logic — it normalises enums,
precomputes gradients and widths, and decides what each page can display — and it is currently
verified only by running the application. That is the piece of this project I would fix first.

**On the migration.** Replacing the entire UI without touching a single engine confirmed the
boundary was drawn in the right place. The lesson I take from it is narrower than "keep layers
separate": it is that the boundary has to be *enforced while it is inconvenient*. Every time it
would have been quicker to compute something in a page, doing it in the engine instead is what
made the eventual rewrite a two-day job rather than a rebuild.

Concrete follow-on work derived from the code is recorded in
[KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md) §5.

---

## Related documents

- [ARCHITECTURE.md](../technical/ARCHITECTURE.md) — the structural view of section 1
- [MODULE_REFERENCE.md](../technical/MODULE_REFERENCE.md) — signatures and side effects
- [TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md) — diagnostics for section 2
- [KNOWN_ISSUES_AND_BACKLOG.md](KNOWN_ISSUES_AND_BACKLOG.md) — outstanding work
