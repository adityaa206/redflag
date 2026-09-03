# tools/

Utilities that are not part of the RedFlag application.

_Last updated: 2026-07-27 · Owner: Adi · Status: Handover_

---

## Rendering the documentation as PDF

The Markdown under `docs/` is the **source of truth**. These scripts typeset it into PDFs for
people who would rather not read raw Markdown.

```bash
python tools/build_docs_pdf.py . ../pdf-out
```

Two arguments: the repository root, and an output directory. It produces:

| Output | What it is |
|---|---|
| `RedFlag_Documentation.pdf` | The whole set as one book — cover, contents with page numbers, part dividers, and PDF bookmarks for navigation (~211 pages) |
| `RedFlag_Docs_PDF/NN_Title.pdf` | One PDF per document, numbered so the folder sorts in reading order (38 files) |

**Re-run it after editing any document** so the PDFs do not drift from the Markdown.

### Files

| File | Purpose |
|---|---|
| `mdpdf.py` | The Markdown renderer: parser plus an fpdf2 layout engine |
| `build_docs_pdf.py` | The book's structure (`PARTS`), cover, contents, dividers, and the driver |

### What it handles

Headings, paragraphs with inline `**bold**` / `*italic*` / `` `code` `` / `[links](url)`, bullet
and numbered lists, task list checkboxes, GitHub tables (including `\|` escaped pipes), fenced
code, horizontal rules, and blockquote callouts, which are tinted by their leading label.

**Mermaid diagrams** are parsed and laid out natively: `subgraph` blocks become titled groups and
the edges become a flow list. A page of Mermaid source is useless on paper.

### Design

Matches `RedFlag_Handover_Pack.pdf`: warm off-white paper, near-black ink, a single sage accent,
muted clay and sand for warnings. Light backgrounds only — dark page fills are dropped when
someone opens a PDF in Word, which converts rather than renders.

Fonts are Windows system fonts (Georgia, Segoe UI, Consolas). On a machine without them the
renderer falls back to the PDF core fonts and still produces valid output.

### Characters

The embedded fonts have no emoji, so `sanitize()` substitutes them (`⚠️` is dropped in favour of
the callout styling, `✅`/`❌` become Yes/No, the `MODULE_REFERENCE` legend markers become
`[net]` / `[disk]` / `[cfg]` / `[key]`). Box-drawing characters survive because they exist in
Consolas and only ever appear inside code fences; arrows are replaced only in the serif face,
which lacks them.

Verify the character inventory after adding new docs:

```bash
python -c "import glob,collections;print(collections.Counter(c for f in glob.glob('docs/**/*.md',recursive=True) for c in open(f,encoding='utf-8').read() if ord(c)>127).most_common())"
```

### Requirements

`fpdf2`, already pinned in `requirements.txt`. Nothing else.

---

## Related documents

- [../docs/README.md](../docs/README.md) — the documentation index
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — keeping code and docs in step
