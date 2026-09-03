# RedFlag Documentation

The complete documentation set for RedFlag, the M&A cybersecurity due-diligence platform.

The whole set is also available as a single bookmarked PDF —
**[RedFlag_Documentation.pdf](RedFlag_Documentation.pdf)** (201 pages) — regenerated from these
Markdown sources with `python tools/build_docs_pdf.py . <output-dir>`.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## What RedFlag is

RedFlag is an end-to-end **M&A cybersecurity due-diligence platform**. Given a target company,
it maps the internet-facing attack surface, scores every finding with an SSVC/EPSS-aligned risk
model, checks DNS/email security, TLS health and breach exposure, assesses internal security
maturity, plans Day-1 connectivity, estimates remediation and integration cost, and reasons about
attack paths — all inside a single [Reflex](https://reflex.dev) web application. Its core is
deliberately **offline, free, and LLM-free**: same input, same output, no paid API, no GPU.

---

## Handover

| Document | What it covers |
|---|---|
| [HANDOVER.md](handover/HANDOVER.md) | Project status, what shipped, where everything lives, sign-off checklist |
| [PROJECT_REPORT.md](handover/PROJECT_REPORT.md) | Problem, objectives, scope, solution, outcomes |
| [ACCESS_AND_CREDENTIALS.md](handover/ACCESS_AND_CREDENTIALS.md) | Account/key inventory and transfer checklist (no secrets) |
| [KNOWN_ISSUES_AND_BACKLOG.md](handover/KNOWN_ISSUES_AND_BACKLOG.md) | Known bugs, incomplete features, tech debt, next steps |
| [KNOWLEDGE_TRANSFER.md](handover/KNOWLEDGE_TRANSFER.md) | Tacit knowledge, gotchas, "why it's like this" |

## Technical

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](technical/ARCHITECTURE.md) | Layering, component and data-flow diagrams, module responsibilities |
| [DATA_MODEL.md](technical/DATA_MODEL.md) | The `Finding` model and every enum, verified from `analysis/schema.py` |
| [MODULE_REFERENCE.md](technical/MODULE_REFERENCE.md) | Public function signatures per package, with side effects |
| [CONFIGURATION.md](technical/CONFIGURATION.md) | Every `.env` variable, constant and YAML knob, with retuning recipes |
| [INTEGRATIONS.md](technical/INTEGRATIONS.md) | Each external tool/API: endpoints, keys, limits, degradation |
| [BRAIN_KNOWLEDGE_BASE.md](technical/BRAIN_KNOWLEDGE_BASE.md) | The self-improving offline knowledge base |

## Operations

| Document | What it covers |
|---|---|
| [INSTALLATION.md](operations/INSTALLATION.md) | Prerequisites and step-by-step install (Windows + macOS) |
| [DEVELOPER_ONBOARDING.md](operations/DEVELOPER_ONBOARDING.md) | Get productive: layout tour, tests, conventions, extension points |
| [DEPLOYMENT_RUNBOOK.md](operations/DEPLOYMENT_RUNBOOK.md) | Running and operating the app; ports, outputs, cautions |
| [TROUBLESHOOTING.md](operations/TROUBLESHOOTING.md) | Symptom → cause → fix reference |

## User

| Document | What it covers |
|---|---|
| [USER_GUIDE.md](user/USER_GUIDE.md) | Running a scan and a walkthrough of all seven tabs |
| [RESULTS_INTERPRETATION.md](user/RESULTS_INTERPRETATION.md) | How to read and trust every number RedFlag prints |

## Testing

| Document | What it covers |
|---|---|
| [TEST_PLAN.md](testing/TEST_PLAN.md) | How to run the suite, per-file coverage map, what is *not* covered |
| [LIMITATIONS.md](testing/LIMITATIONS.md) | Honest accuracy caveats and scope boundaries |

## Legal & security

| Document | What it covers |
|---|---|
| [AUTHORIZED_USE.md](legal/AUTHORIZED_USE.md) | Legal and ethical boundaries of running an active scanner |
| [LICENSES_AND_ATTRIBUTION.md](legal/LICENSES_AND_ATTRIBUTION.md) | Project licence, dependency SBOM, external-service terms |
| [SECURITY_AND_PRIVACY.md](legal/SECURITY_AND_PRIVACY.md) | Data handling, the egress table, secrets management |

## Process

| Document | What it covers |
|---|---|
| [CHANGELOG.md](process/CHANGELOG.md) | Version and milestone history (canonical copy at repo root) |
| [ROADMAP.md](process/ROADMAP.md) | Forward direction if the project continues |
| [adr/](process/adr/README.md) | Eight Architecture Decision Records with rationale |

## Conventions

Each fact is recorded in exactly one canonical document; other documents cross-reference it
rather than repeating it. Directories are organised by audience: `handover/` addresses the
receiving supervisor, `technical/` the maintaining engineer, `operations/` the operator, and
`user/` the analyst. `testing/`, `legal/` and `process/` hold the assurance, compliance and
history material.

Every figure, signature, threshold and configuration key in this set was read from the source
rather than from the README. Where the two disagreed, the code was treated as the truth and the
README was corrected to match.

---

## Related documents

- Repository front page: [../README.md](../README.md)
- Licence: [../LICENSE](../LICENSE)
- Contribution guide: [../CONTRIBUTING.md](../CONTRIBUTING.md)
- Vulnerability reporting: [../SECURITY.md](../SECURITY.md)
