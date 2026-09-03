"""
Build the RedFlag documentation as PDFs.

  RedFlag_Documentation.pdf   one book: cover, contents, part dividers, all docs
  RedFlag_Docs_PDF/*.pdf      one file per document

Usage:  python build_docs_pdf.py <repo_root> <output_dir>
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mdpdf import (  # noqa: E402
    Book, parse_md, sanitize, ML, MR, MT, MB, W, H, CW, RIGHT,
    PAPER, INK, BODY, SOFT, FAINT, RULE, WASH, SAGE, SAGE_BG,
)

# ── the book's structure ──────────────────────────────────────────────────────
PARTS = [
    ("Front matter", "Index and documentation conventions", [
        ("docs/README.md", "Documentation Index"),
    ]),
    ("Part I — Handover", "Project status, transition and outstanding items", [
        ("docs/handover/HANDOVER.md", "Handover"),
        ("docs/handover/PROJECT_REPORT.md", "Project Report"),
        ("docs/handover/ACCESS_AND_CREDENTIALS.md", "Access & Credentials"),
        ("docs/handover/KNOWN_ISSUES_AND_BACKLOG.md", "Known Issues & Backlog"),
        ("docs/handover/KNOWLEDGE_TRANSFER.md", "Knowledge Transfer"),
    ]),
    ("Part II — Technical", "Architecture, data model, interfaces and configuration", [
        ("docs/technical/ARCHITECTURE.md", "Architecture"),
        ("docs/technical/DATA_MODEL.md", "Data Model"),
        ("docs/technical/MODULE_REFERENCE.md", "Module Reference"),
        ("docs/technical/CONFIGURATION.md", "Configuration"),
        ("docs/technical/INTEGRATIONS.md", "Integrations"),
        ("docs/technical/BRAIN_KNOWLEDGE_BASE.md", "Brain Knowledge Base"),
    ]),
    ("Part III — Operations", "Installation, operation and diagnostics", [
        ("docs/operations/INSTALLATION.md", "Installation"),
        ("docs/operations/DEVELOPER_ONBOARDING.md", "Developer Onboarding"),
        ("docs/operations/DEPLOYMENT_RUNBOOK.md", "Deployment Runbook"),
        ("docs/operations/TROUBLESHOOTING.md", "Troubleshooting"),
    ]),
    ("Part IV — User", "Operating the application and interpreting its output", [
        ("docs/user/USER_GUIDE.md", "User Guide"),
        ("docs/user/RESULTS_INTERPRETATION.md", "Interpreting the Results"),
    ]),
    ("Part V — Testing", "Verification coverage and accuracy caveats", [
        ("docs/testing/TEST_PLAN.md", "Test Plan"),
        ("docs/testing/LIMITATIONS.md", "Limitations"),
    ]),
    ("Part VI — Legal & Security", "Authorised use, licensing and data handling", [
        ("docs/legal/AUTHORIZED_USE.md", "Authorized Use"),
        ("docs/legal/LICENSES_AND_ATTRIBUTION.md", "Licenses & Attribution"),
        ("docs/legal/SECURITY_AND_PRIVACY.md", "Security & Privacy"),
    ]),
    ("Part VII — Process & History", "Version history, forward plan and decision records", [
        ("CHANGELOG.md", "Changelog"),
        ("docs/process/ROADMAP.md", "Roadmap"),
        ("docs/process/adr/README.md", "Architecture Decision Records"),
        ("docs/process/adr/0001-no-llm.md", "ADR-0001 — No LLM in the core"),
        ("docs/process/adr/0002-deterministic-yaml-narrative.md",
         "ADR-0002 — Deterministic YAML narrative engine"),
        ("docs/process/adr/0003-free-no-paid-api.md",
         "ADR-0003 — Entirely free, no paid API"),
        ("docs/process/adr/0004-reflex-ui-framework.md",
         "ADR-0004 — Reflex as the UI framework"),
        ("docs/process/adr/0005-offline-brain-learn-by-remembering.md",
         "ADR-0005 — The brain accumulates, it never trains"),
        ("docs/process/adr/0006-evidence-strength-multiplier.md",
         "ADR-0006 — Evidence-strength multiplier"),
        ("docs/process/adr/0007-epss-exploit-promotion.md",
         "ADR-0007 — EPSS can promote exploit status"),
        ("docs/process/adr/0008-uploads-correlate-not-replace.md",
         "ADR-0008 — Uploads correlate into the Nmap layer"),
    ]),
    ("Part VIII — Contributing", "Contribution, security-reporting and conduct policies", [
        ("CONTRIBUTING.md", "Contributing"),
        ("SECURITY.md", "Security Policy"),
        ("CODE_OF_CONDUCT.md", "Code of Conduct"),
    ]),
]


def load(root, rel):
    path = os.path.join(root, rel.replace("/", os.sep))
    if not os.path.exists(path):
        return None
    return open(path, encoding="utf-8").read()


def split_front(blocks):
    """Peel the H1, the purpose line and the metadata line off the top."""
    title = None
    purpose = None
    meta = None
    rest = list(blocks)
    if rest and rest[0]["t"] == "h" and rest[0]["level"] == 1:
        title = rest.pop(0)["text"]
    if rest and rest[0]["t"] == "para" and not rest[0]["text"].startswith("_"):
        purpose = rest.pop(0)["text"]
    if rest and rest[0]["t"] == "para" and rest[0]["text"].startswith("_"):
        meta = rest.pop(0)["text"].strip("_")
    elif rest and rest[0]["t"] == "para" and "Last updated" in rest[0]["text"]:
        meta = rest.pop(0)["text"].strip("_")
    while rest and rest[0]["t"] == "hr":
        rest.pop(0)
    return title, purpose, meta, rest


# ── page furniture ────────────────────────────────────────────────────────────
def cover(bk, subtitle, note):
    bk.new_page(chrome=False)
    p = bk.pdf
    p.set_fill_color(*SAGE)
    p.rect(ML, 150, 2.6, 54, style="F")
    p.set_fill_color(*(214, 224, 217))
    p.rect(ML + 2.6, 150, 40, 26, style="F")

    bk.F("SansSB", "", 7.6)
    p.set_text_color(*SOFT)
    p.set_char_spacing(2.0)
    p.set_xy(ML, 232)
    p.cell(CW, 12, "M&A CYBERSECURITY DUE DILIGENCE")
    p.set_char_spacing(0)

    bk.F("Serif", "", 60)
    p.set_text_color(*INK)
    p.set_xy(ML, 254)
    p.cell(CW, 72, "RedFlag")

    bk.F("Serif", "I", 17)
    p.set_text_color(*SOFT)
    p.set_xy(ML, 334)
    p.cell(CW, 26, subtitle)

    p.set_draw_color(*RULE)
    p.set_line_width(0.7)
    p.line(ML, 382, RIGHT, 382)

    bk.y = 402
    bk.rich(note, size=11.0, lead=18.0, width=CW - 30, base_color=BODY)

    y0 = H - 176
    p.set_draw_color(*RULE)
    p.line(ML, y0 - 22, RIGHT, y0 - 22)
    for i, (k, v) in enumerate([
        ("Repository", "github.com/adityaa206/redflag"),
        ("Status", "Complete — documented for handover"),
        ("Compiled", "27 July 2026"),
        ("Source", "Markdown in docs/ — this PDF is generated from it"),
    ]):
        yy = y0 + i * 22
        bk.F("SansSB", "", 7.6)
        p.set_text_color(*FAINT)
        p.set_char_spacing(1.0)
        p.set_xy(ML, yy)
        p.cell(150, 14, k.upper())
        p.set_char_spacing(0)
        bk.F("Sans", "", 9.4)
        p.set_text_color(*BODY)
        p.set_xy(ML + 150, yy)
        p.cell(CW - 150, 14, v)


def divider(bk, part_title, part_sub, docs):
    bk.new_page(chrome=False)
    p = bk.pdf
    p.set_fill_color(*WASH)
    p.rect(0, 0, W, H, style="F")

    label, _, name = part_title.partition(" — ")
    bk.F("SansSB", "", 8.0)
    p.set_text_color(*SAGE)
    p.set_char_spacing(2.0)
    p.set_xy(ML, 250)
    p.cell(CW, 14, sanitize(label, serif=True).upper())
    p.set_char_spacing(0)

    p.set_draw_color(*INK)
    p.set_line_width(1.6)
    p.line(ML, 276, ML + 46, 276)

    bk.F("Serif", "", 34)
    p.set_text_color(*INK)
    p.set_xy(ML, 296)
    p.cell(CW, 44, sanitize(name or label, serif=True))

    bk.F("Serif", "I", 12.5)
    p.set_text_color(*SOFT)
    p.set_xy(ML, 348)
    p.cell(CW, 20, sanitize(part_sub, serif=True))

    y = 404
    for _rel, title in docs:
        bk.F("Sans", "", 10.0)
        p.set_text_color(*BODY)
        p.set_xy(ML, y)
        p.cell(CW, 17, sanitize(title, serif=True))
        y += 19
    bk.head_left = "RedFlag  ·  Documentation"
    bk.head_right = part_title


def toc(bk, entries):
    """entries: (kind, text, page) where kind in {part, doc}."""
    first = True
    for kind, text, page in entries:
        if first:
            bk.new_page(chrome=False)
            p = bk.pdf
            p.set_draw_color(*INK)
            p.set_line_width(1.6)
            p.line(ML, MT, ML + 46, MT)
            bk.y = MT + 18
            bk.F("Serif", "", 25)
            p.set_text_color(*INK)
            p.set_xy(ML, bk.y)
            p.cell(CW, 31, "Contents")
            bk.y += 46
            first = False
        p = bk.pdf
        if bk.y > H - MB - 20:
            bk.new_page(chrome=False)
            bk.y = MT + 8
        if kind == "part":
            bk.y += 14
            if bk.y > H - MB - 30:
                bk.new_page(chrome=False)
                bk.y = MT + 8
            bk.F("SansSB", "", 8.0)
            p.set_text_color(*SAGE)
            p.set_char_spacing(1.4)
            p.set_xy(ML, bk.y)
            p.cell(CW - 40, 14, sanitize(text, serif=True).upper())
            p.set_char_spacing(0)
            bk.F("Mono", "", 8.0)
            p.set_text_color(*FAINT)
            p.set_xy(RIGHT - 40, bk.y)
            p.cell(40, 14, str(page), align="R")
            bk.y += 17
            p.set_draw_color(*RULE)
            p.set_line_width(0.5)
            p.line(ML, bk.y - 2, RIGHT, bk.y - 2)
            bk.y += 4
        else:
            bk.F("Sans", "", 9.4)
            p.set_text_color(*BODY)
            label = sanitize(text, serif=True)
            p.set_xy(ML + 14, bk.y)
            p.cell(CW - 60, 14, label)
            lw = p.get_string_width(label)
            bk.F("Mono", "", 8.2)
            p.set_text_color(*FAINT)
            p.set_xy(RIGHT - 40, bk.y)
            p.cell(40, 14, str(page), align="R")
            # leader dots
            x0 = ML + 18 + lw
            x1 = RIGHT - 46
            if x1 - x0 > 12:
                p.set_draw_color(*(214, 219, 214))
                p.set_line_width(0.5)
                p.set_dash_pattern(dash=0.7, gap=3.2)
                p.line(x0, bk.y + 9.5, x1, bk.y + 9.5)
                p.set_dash_pattern()
            bk.y += 15.5


def doc_opener(bk, title, purpose, meta, part_title):
    bk.head_left = "RedFlag  ·  Documentation"
    bk.head_right = title
    bk.new_page()
    p = bk.pdf
    p.set_draw_color(*INK)
    p.set_line_width(1.6)
    p.line(ML, bk.y, ML + 46, bk.y)
    bk.y += 18
    lines = bk._wrap_plain(sanitize(bk._plain(title), serif=True), CW, "Serif", "", 25)
    bk.F("Serif", "", 25)
    p.set_text_color(*INK)
    for ln in lines:
        p.set_xy(ML, bk.y)
        p.cell(CW, 31, ln)
        bk.y += 31
    bk.y += 4
    if purpose:
        txt = sanitize(bk._plain(purpose), serif=True)
        for ln in bk._wrap_plain(txt, CW, "Serif", "I", 10.6):
            bk.F("Serif", "I", 10.6)
            p.set_text_color(*SOFT)
            p.set_xy(ML, bk.y)
            p.cell(CW, 16, ln)
            bk.y += 16
    if meta:
        bk.y += 6
        bk.F("Sans", "", 8.0)
        p.set_text_color(*FAINT)
        p.set_xy(ML, bk.y)
        p.cell(CW, 12, sanitize(bk._plain(meta), serif=True))
        bk.y += 14
    bk.y += 12


# ── passes ────────────────────────────────────────────────────────────────────
def render_body(bk, root, offset, record=None, outline=False):
    """Render every part and document. `record` collects (kind, title, page)."""
    for part_title, part_sub, docs in PARTS:
        present = [(rel, t) for rel, t in docs if load(root, rel) is not None]
        if not present:
            continue
        divider(bk, part_title, part_sub, present)
        if record is not None:
            record.append(("part", part_title, bk.page_no + offset))
        if outline:
            try:
                bk.pdf.start_section(sanitize(part_title, serif=True), level=0)
            except Exception:
                pass
        for rel, title in present:
            src = load(root, rel)
            blocks = parse_md(src)
            h1, purpose, meta, rest = split_front(blocks)
            doc_opener(bk, title, purpose, meta, part_title)
            if record is not None:
                record.append(("doc", title, bk.page_no + offset))
            if outline:
                try:
                    bk.pdf.start_section(sanitize(title, serif=True), level=1)
                except Exception:
                    pass
            bk.render_blocks(rest)


def build_book(root, out_path):
    # ── pass A: content only, to learn each document's page number ───────────
    probe = Book()
    probe.show_chrome = True
    rec: list[tuple[str, str, int]] = []
    render_body(probe, root, offset=0, record=rec, outline=False)

    # front matter = cover (1) + however many contents pages the entries need
    tmp = Book()
    tmp.show_chrome = False
    toc(tmp, rec)
    front = 1 + tmp.page_no

    # ── pass B: the real thing ───────────────────────────────────────────────
    bk = Book()
    cover(bk, "Documentation",
          "The complete documentation set for the RedFlag platform, comprising the "
          "handover, technical, operational, user, testing, legal and process "
          "material, together with the architecture decision records. Generated "
          "from the Markdown sources under docs/.")
    toc(bk, [(k, t, pg + front) for k, t, pg in rec])
    render_body(bk, root, offset=front, record=None, outline=True)

    bk.pdf.output(out_path)
    return out_path, bk.page_no


def _slug(title):
    s = sanitize(title, serif=True)
    s = s.replace("—", "-").replace("&", "and")
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")
    return re.sub(r"-{2,}", "-", s)


def build_singles(root, out_dir):
    """One PDF per document, numbered so the folder sorts in reading order."""
    os.makedirs(out_dir, exist_ok=True)
    made = []
    idx = 0
    for part_title, _sub, docs in PARTS:
        for rel, title in docs:
            src = load(root, rel)
            if src is None:
                continue
            idx += 1
            bk = Book(title=f"RedFlag — {title}")
            blocks = parse_md(src)
            h1, purpose, meta, rest = split_front(blocks)
            doc_opener(bk, title, purpose, meta, part_title)
            bk.render_blocks(rest)
            path = os.path.join(out_dir, f"{idx:02d}_{_slug(title)}.pdf")
            bk.pdf.output(path)
            made.append((path, bk.page_no))
    return made


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Adityaa\Redflag"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "."
    os.makedirs(outdir, exist_ok=True)

    book_path = os.path.join(outdir, "RedFlag_Documentation.pdf")
    path, pages = build_book(root, book_path)
    print(f"BOOK  {path}  {pages} pages  {os.path.getsize(path):,} bytes")

    singles_dir = os.path.join(outdir, "RedFlag_Docs_PDF")
    made = build_singles(root, singles_dir)
    total = sum(p for _f, p in made)
    print(f"SINGLES  {len(made)} files, {total} pages -> {singles_dir}")
    for f, pg in made:
        print(f"   {os.path.basename(f):<46} {pg:>3}p")
