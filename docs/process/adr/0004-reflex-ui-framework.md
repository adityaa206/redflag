# ADR-0004 — Reflex as the UI framework

**Status:** Accepted (superseded Streamlit, 2026-06-29)

---

## Context

RedFlag's first UI was **Streamlit**, chosen for the reason everyone chooses it: an analytical
Python tool gets a working interface in an afternoon with no frontend code.

It carried the project from the initial commit (2026-05-25) through the Maturity, Cost and
Narrative engines, the DNS/TLS/breach scanners, and the Attack Path tab. Roughly a month of
development.

By June the product had outgrown it. Three specific pressures:

1. **Seven tabs, each with real state.** Streamlit re-runs the entire script on every widget
   interaction. Keeping findings, a maturity assessment, a gap report, staged uploads and a cost
   rollup alive across that model meant increasingly elaborate `st.session_state` management, and
   the risk of losing a scan to an unrelated interaction.
2. **The interface had become the product's face.** RedFlag produces documents that go to deal
   teams. Streamlit's default aesthetic is unmistakably Streamlit, and fighting it — an
   "Executive Editorial / emerald" design direction was already defined — meant increasing amounts
   of injected CSS working against the framework.
3. **No real routing.** Streamlit's tab and multipage models do not give addressable URLs with
   independent lifecycles. `/day1` should be a link someone can send.

The scan pipeline in particular was uncomfortable: a long-running operation with staged file
uploads, in a framework whose central abstraction is "re-run everything on every interaction".

Rewriting the UI in React with a Python API was the conventional answer, and was rejected: it
doubles the language surface for a solo project and puts the presentation layer out of reach of
the person who understands the domain.

## Decision

**Migrate to [Reflex](https://reflex.dev): pure-Python components that compile to a Next.js/React
frontend with a WebSocket-backed Python state server.**

The migration completed on 2026-06-29 (`bf0d606`, "Migrate to Reflex UI; retire Streamlit
app.py").

Key constraints adopted with it:

- `redflag_ui/` is **presentation only.** All state lives in one `RedFlagState` class, which calls
  the engines and flattens their output into flat dataclass view-models.
- Raw engine objects live in **backend-only vars** (leading underscore) so they are not serialised
  to the browser.
- Tailwind's preflight reset is deliberately omitted in `rxconfig.py` — `assets/redflag.css` owns
  the design and a utility reset would fight it.

**The migration required zero changes to any engine.** `analysis/`, `cost/`, `narrative/`,
`reports/` and `scanners/` were untouched. That is the strongest available evidence that the
layering described in [ARCHITECTURE.md](../../technical/ARCHITECTURE.md) is real rather than
aspirational.

## Consequences

**Costs**

- **Node.js is now a dependency.** The first launch compiles a Next.js frontend — roughly a
  minute, and Reflex offers to install Node if absent. A genuine regression against Streamlit's
  pure-Python install.
- **The build is fragile in synced folders.** OneDrive and Dropbox fight the Vite build, producing
  `EBUSY` errors and a blank page. The working checkout had to be moved out of OneDrive entirely.
- **The dev file-watcher resets backend state on any write inside the worktree.** This is why Nmap
  output goes to `%TEMP%/redflag_scans` and the brain to `~/RedFlag-Brain` — a constraint that
  must be understood before touching either path.
- **A compile error crashes the dev server.** Risky component edits need a `.render()` check in
  the venv first.
- Reflex-specific traps: `rx.upload` cannot take a `Var` `class_name`; dynamic widths and
  gradients must be precomputed string Vars, not f-strings over a Var.
- Reflex is a younger framework with a smaller community than Streamlit.
- **The Streamlit UI tests were removed and never replaced.** `redflag_ui/` currently has **no
  test coverage** — the largest gap in the suite.

**Benefits**

- **Nine real routes** with addressable URLs: `/`, `/findings`, `/attack`, `/maturity`, `/day1`,
  `/cost`, `/export`, `/privacy`, `/contact`.
- **Persistent server-side state.** No re-run model, so a long scan is not at risk from an
  unrelated widget interaction.
- **Full design control.** `assets/redflag.css` implements the intended aesthetic without fighting
  a framework. The risk donut is a CSS conic-gradient and the attack mind-map is precomputed SVG —
  no chart library, no JS graph library.
- Still pure Python. One language, one mental model, one debugger.
- The migration itself proved the architecture — and that proof is worth more than the framework.

## Alternatives considered

**Stay on Streamlit and work around it.** Cheapest option. Rejected because the workarounds were
already accumulating and the state-management pressure would grow with every new tab. The design
ceiling was the deciding factor.

**A React/Next.js frontend with a FastAPI backend.** The conventional and most powerful answer.
Rejected for a solo project: it doubles the language surface, splits the codebase, and requires
maintaining an API contract between two halves. Worth revisiting only if a team forms.

**Dash / Plotly.** Mature, Python-native, good routing. Rejected on aesthetics — Dash's idiom is
dashboards and charts, while RedFlag's output is closer to an editorial document. The
"Executive Editorial" direction would have fought it much as it fought Streamlit.

**Gradio.** Optimised for ML demos and single-input/single-output flows. Wrong shape for a
seven-tab stateful application.

**A static report generator — no web UI at all.** Genuinely attractive, and the closest thing to a
real alternative: the PDF and CSV exports are arguably the product. Rejected because the maturity
questionnaire, the What-If cost controls and the vendor-quote overrides are all interactive by
nature.

---

## Related

- [ARCHITECTURE.md](../../technical/ARCHITECTURE.md) — the layering this migration validated
- [KNOWLEDGE_TRANSFER.md](../../handover/KNOWLEDGE_TRANSFER.md) §2 — the Reflex traps in full
- [TROUBLESHOOTING.md](../../operations/TROUBLESHOOTING.md) §2.7 — the OneDrive build failure
- [TEST_PLAN.md](../../testing/TEST_PLAN.md) §7 — the UI coverage gap this created
- [CHANGELOG.md](../CHANGELOG.md) — the migration in context
