"""
mdpdf.py — render the RedFlag Markdown documentation set as typeset PDFs.

Same design language as the Handover Pack: warm paper, near-black ink, a single
sage accent, muted clay/sand for warnings. Light backgrounds only, so the result
survives conversion in Word and prints cleanly in greyscale.

Handles: ATX headings, paragraphs with inline **bold** / *italic* / `code` /
[links](url), bullet and numbered lists, GitHub tables, fenced code, blockquote
callouts, horizontal rules, and Mermaid blocks (shown as labelled source).
"""
from __future__ import annotations

import os
import re

from fpdf import FPDF

# ── page geometry (A4 portrait) ───────────────────────────────────────────────
W, H = 595.0, 842.0
ML, MR = 62.0, 62.0
MT, MB = 74.0, 62.0
CW = W - ML - MR
RIGHT = W - MR

# ── muted palette (identical to the Handover Pack) ────────────────────────────
PAPER = (252, 252, 250)
INK = (31, 36, 33)
BODY = (74, 84, 78)
SOFT = (124, 134, 127)
FAINT = (162, 170, 164)
RULE = (226, 228, 223)
WASH = (245, 246, 243)
CODEBG = (243, 245, 242)
SAGE = (92, 122, 107)
SAGE_BG = (237, 241, 238)
CLAY = (140, 79, 69)
CLAY_BG = (246, 236, 234)
SAND = (138, 109, 59)
SAND_BG = (245, 239, 228)

FONTS = r"C:\Windows\Fonts"

# ── character handling ────────────────────────────────────────────────────────
# Verified against each font's cmap:
#   box drawing + arrows  -> present in Consolas (mono) and Segoe UI (sans)
#   arrows                -> absent from Georgia (serif)
#   all emoji, plus the warning sign, ballot box, check/cross, gear and star
#                         -> absent from every embedded font
_EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
    "\U00002B00-\U00002BFF\U0000FE00-\U0000FE0F\U00002190-\U000021FF"
    "\U00002500-\U000025FF]"
)

# Chars in NO font — must be substituted before they reach the PDF.
HARD_MAP = {
    "⚠": "",        # warning sign (callouts carry their own styling)
    "️": "",        # variation selector-16
    "☐": "[ ]",     # ballot box
    "✅": "Yes",     # white heavy check mark
    "❌": "No",      # cross mark
    "✓": "Yes",     # check mark
    "★": "*",       # black star
    "\U0001F310": "[net]",   # globe   — MODULE_REFERENCE legend
    "\U0001F4BE": "[disk]",  # floppy
    "⚙": "[cfg]",       # gear
    "\U0001F511": "[key]",   # key
}
# Arrows and box drawing survive in sans/mono but not serif.
SERIF_MAP = {"→": "->", "←": "<-", "▼": "v"}


def sanitize(text: str, serif: bool = False, mono: bool = False) -> str:
    """Replace characters the embedded fonts cannot encode."""
    for k, v in HARD_MAP.items():
        if k in text:
            text = text.replace(k, v)
    if serif:
        for k, v in SERIF_MAP.items():
            text = text.replace(k, v)
    if not mono:
        # Box drawing exists only in Consolas; outside code it would be dropped.
        text = re.sub("[─-╿]", "-", text)
    # Final net: strip any remaining pictograph.
    text = _EMOJI.sub(lambda m: "" if ord(m.group()) > 0x2500 else m.group(), text)
    return text


# ═══════════════════════════════════════════════════════════════════════════
# Markdown parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_md(src: str) -> list[dict]:
    """Turn Markdown into a flat list of block dicts."""
    lines = src.replace("\r\n", "\n").split("\n")
    blocks: list[dict] = []
    i, n = 0, len(lines)

    def flush(buf):
        if buf:
            blocks.append({"t": "para", "text": " ".join(buf).strip()})
            buf.clear()

    buf: list[str] = []
    while i < n:
        ln = lines[i]
        s = ln.strip()

        # fenced code
        if s.startswith("```"):
            flush(buf)
            lang = s[3:].strip().lower()
            i += 1
            body = []
            while i < n and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            while body and not body[0].strip():
                body.pop(0)
            while body and not body[-1].strip():
                body.pop()
            blocks.append({"t": "mermaid" if lang == "mermaid" else "code",
                           "lines": body, "lang": lang})
            continue

        # blank
        if not s:
            flush(buf)
            i += 1
            continue

        # horizontal rule
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", s):
            flush(buf)
            blocks.append({"t": "hr"})
            i += 1
            continue

        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            flush(buf)
            blocks.append({"t": "h", "level": len(m.group(1)),
                           "text": m.group(2).strip()})
            i += 1
            continue

        # table (a header row followed by a separator row)
        if s.startswith("|") and i + 1 < n and re.match(
                r"^\|?[\s:\-|]+\|[\s:\-|]*$", lines[i + 1].strip()):
            flush(buf)

            def cells(row):
                # Split on UNESCAPED pipes only. Markdown escapes a literal pipe
                # inside a cell as \| — e.g. `str \| None` — and splitting on it
                # would shred the row into extra columns.
                row = row.strip()
                if row.startswith("|"):
                    row = row[1:]
                if row.endswith("|") and not row.endswith(r"\|"):
                    row = row[:-1]
                parts = re.split(r"(?<!\\)\|", row)
                return [c.strip().replace(r"\|", "|") for c in parts]

            header = cells(lines[i])
            spec = cells(lines[i + 1])
            aligns = []
            for sp in spec:
                sp = sp.strip()
                if sp.startswith(":") and sp.endswith(":"):
                    aligns.append("C")
                elif sp.endswith(":"):
                    aligns.append("R")
                else:
                    aligns.append("L")
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                r = cells(lines[i])
                r = (r + [""] * len(header))[:len(header)]
                rows.append(r)
                i += 1
            blocks.append({"t": "table", "head": header, "rows": rows,
                           "align": aligns})
            continue

        # blockquote (callout)
        if s.startswith(">"):
            flush(buf)
            q = []
            while i < n and lines[i].strip().startswith(">"):
                q.append(lines[i].strip()[1:].strip())
                i += 1
            # split the quote into paragraphs / code-ish lines
            text = " ".join(x for x in q if x).strip()
            blocks.append({"t": "quote", "text": text, "raw": q})
            continue

        # bullet list
        if re.match(r"^[-*+]\s+", s):
            flush(buf)
            items = []
            while i < n:
                raw = lines[i]
                st = raw.strip()
                m2 = re.match(r"^[-*+]\s+(.*)$", st)
                if m2:
                    indent = len(raw) - len(raw.lstrip())
                    items.append({"depth": 1 if indent >= 2 else 0,
                                  "text": m2.group(1).strip()})
                    i += 1
                elif st and not re.match(r"^(\d+\.|[-*+#>|])", st) and items:
                    items[-1]["text"] += " " + st          # continuation line
                    i += 1
                else:
                    break
            blocks.append({"t": "ul", "items": items})
            continue

        # numbered list
        if re.match(r"^\d+[.)]\s+", s):
            flush(buf)
            items = []
            while i < n:
                st = lines[i].strip()
                m2 = re.match(r"^(\d+)[.)]\s+(.*)$", st)
                if m2:
                    items.append({"num": m2.group(1), "text": m2.group(2).strip()})
                    i += 1
                elif st and not re.match(r"^(\d+[.)]|[-*+#>|])", st) and items:
                    items[-1]["text"] += " " + st
                    i += 1
                else:
                    break
            blocks.append({"t": "ol", "items": items})
            continue

        buf.append(s)
        i += 1

    flush(buf)
    return blocks


# ── inline formatting ────────────────────────────────────────────────────────
_INLINE = re.compile(
    r"(`[^`]+`)"                       # code
    r"|(\*\*[^*]+\*\*)"                # bold
    r"|(__[^_]+__)"                    # bold
    r"|(\*[^*\n]+\*)"                  # italic
    r"|(\[[^\]]+\]\([^)]+\))"          # link
)


def runs(text: str) -> list[tuple[str, str, str]]:
    """Split inline Markdown into (text, style, href) runs."""
    out: list[tuple[str, str, str]] = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], "n", ""))
        tok = m.group(0)
        if tok.startswith("`"):
            out.append((tok[1:-1], "c", ""))
        elif tok.startswith("**") or tok.startswith("__"):
            out.append((tok[2:-2], "b", ""))
        elif tok.startswith("*"):
            out.append((tok[1:-1], "i", ""))
        else:
            lm = re.match(r"\[([^\]]+)\]\(([^)]+)\)", tok)
            label, href = lm.group(1), lm.group(2)
            # nested emphasis inside a link label
            label = re.sub(r"\*\*([^*]+)\*\*", r"\1", label)
            out.append((label, "l", href if href.startswith("http") else ""))
        pos = m.end()
    if pos < len(text):
        out.append((text[pos:], "n", ""))
    return [(t, s, h) for t, s, h in out if t]


# ═══════════════════════════════════════════════════════════════════════════
# Renderer
# ═══════════════════════════════════════════════════════════════════════════
class Book:
    def __init__(self, title="RedFlag Documentation"):
        self.pdf = FPDF(unit="pt", format=(W, H))
        self.pdf.set_auto_page_break(False)
        self.pdf.set_margins(0, 0, 0)
        self.pdf.set_title(title)
        self.pdf.set_creator("RedFlag")
        self.nice = True
        try:
            for fam, style, fn in [
                ("Serif", "", "georgia.ttf"), ("Serif", "B", "georgiab.ttf"),
                ("Serif", "I", "georgiai.ttf"),
                ("Sans", "", "segoeui.ttf"), ("Sans", "B", "segoeuib.ttf"),
                ("Sans", "I", "segoeuii.ttf"),
                ("SansSB", "", "seguisb.ttf"),
                ("Mono", "", "consola.ttf"), ("Mono", "B", "consolab.ttf"),
            ]:
                self.pdf.add_font(fam, style, os.path.join(FONTS, fn))
        except Exception:
            self.nice = False
        self.y = MT
        self.page_no = 0
        self.head_left = ""
        self.head_right = ""
        self.show_chrome = True
        self._bold_plain = False
        self._lead = 14.0

    # ── fonts ────────────────────────────────────────────────────────────────
    def F(self, fam, style="", size=10):
        if self.nice:
            self.pdf.set_font(fam, style, size)
        else:
            core = {"Serif": "Times", "Sans": "Helvetica",
                    "SansSB": "Helvetica", "Mono": "Courier"}[fam]
            self.pdf.set_font(core, style if style in ("", "B", "I") else "", size)

    def _style_font(self, style, size):
        if style == "c":
            self.F("Mono", "", size - 0.6)
        elif style == "b":
            self.F("Sans", "B", size)
        elif style == "i":
            self.F("Sans", "I", size)
        elif style == "l":
            self.F("Sans", "", size)
        elif self._bold_plain:
            # A table's first column is drawn bold; it must be MEASURED bold
            # too, or every bold glyph overruns its advance and swallows the
            # following space ("Network binding" -> "Networkbinding").
            self.F("Sans", "B", size)
        else:
            self.F("Sans", "", size)

    def _style_color(self, style):
        if style == "c":
            return (58, 74, 64)
        if style == "b":
            return INK
        if style == "l":
            return SAGE
        return BODY

    # ── shared inline layout (used by rich text AND table cells) ─────────────
    # Inline code gets a little breathing room on each side so its tinted chip
    # never paints over the neighbouring glyph.
    CODE_PAD = 1.6

    def _words(self, text, size):
        """(word, style, href, width) tuples, whitespace preserved as words."""
        p = self.pdf
        out = []
        for t, st, href in runs(text):
            t = sanitize(t, mono=(st == "c"))
            if not t:
                continue
            for w in re.split(r"(\s+)", t):
                if w == "":
                    continue
                self._style_font(st, size)
                ww = p.get_string_width(w)
                if st == "c" and not w.isspace():
                    ww += self.CODE_PAD * 2
                out.append((w, st, href, ww))
        return out

    # A long identifier reads far better broken after a separator
    # (BRAIN_KNOWLEDGE_/BASE.md) than mid-word (BRAIN_KNOWLEDGE_BASE.m/d).
    _BREAK_AFTER = "_./\\-:,+"

    def _break_token(self, word, style, href, width, size):
        """Split a token too wide for its column, preferring separators."""
        p = self.pdf
        self._style_font(style, size)
        pad = self.CODE_PAD * 2 if style == "c" else 0.0
        pieces = []
        rest = word
        while rest:
            fit = 0
            for i in range(1, len(rest) + 1):
                if p.get_string_width(rest[:i]) + pad <= width:
                    fit = i
                else:
                    break
            if fit == 0:
                fit = 1                        # column narrower than one glyph
            if fit < len(rest):
                # back up to just after the last separator inside the fit
                cut = max((j + 1 for j in range(fit)
                           if rest[j] in self._BREAK_AFTER), default=0)
                if cut >= max(3, fit // 3):    # only if it isn't a silly stub
                    fit = cut
            chunk, rest = rest[:fit], rest[fit:]
            pieces.append((chunk, style, href,
                           p.get_string_width(chunk) + pad))
        return pieces

    def _seg_width(self, word, style, size):
        """Width of the widest piece a token can be broken into."""
        p = self.pdf
        self._style_font(style, size)
        segs, cur = [], ""
        for ch in word:
            cur += ch
            if ch in self._BREAK_AFTER:
                segs.append(cur)
                cur = ""
        if cur:
            segs.append(cur)
        pad = self.CODE_PAD * 2 if style == "c" else 0.0
        return max((p.get_string_width(s) for s in segs), default=0.0) + pad

    def _layout(self, words, width, size):
        """Greedy wrap into lines, breaking over-long tokens if forced."""
        lines: list[list] = [[]]
        wsum = 0.0
        for w, st, href, ww in words:
            if w.isspace():
                if lines[-1]:
                    lines[-1].append((w, st, href, ww))
                    wsum += ww
                continue
            if ww > width:                      # unbreakable token, e.g. a path
                for piece in self._break_token(w, st, href, width, size):
                    if wsum + piece[3] > width and lines[-1]:
                        lines.append([])
                        wsum = 0.0
                    lines[-1].append(piece)
                    wsum += piece[3]
                continue
            if wsum + ww > width and lines[-1]:
                while lines[-1] and lines[-1][-1][0].isspace():
                    lines[-1].pop()
                lines.append([])
                wsum = 0.0
            lines[-1].append((w, st, href, ww))
            wsum += ww
        return [ln for ln in lines if ln]

    def _draw_line(self, line, cx, size, first_col_bold=False, base_color=None):
        """Draw one laid-out line of runs starting at cx."""
        p = self.pdf
        for w, st, href, ww in line:
            if first_col_bold and st == "n":
                self.F("Sans", "B", size)
                p.set_text_color(*INK)
            else:
                self._style_font(st, size)
                p.set_text_color(*(base_color or self._style_color(st)))
            if st == "c" and not w.isspace():
                p.set_fill_color(*CODEBG)
                p.rect(cx, self.y + 2.2, ww, self._lead - 4.4, style="F")
                p.set_xy(cx + self.CODE_PAD, self.y)
                p.cell(ww, self._lead, w, link=href or None)
            else:
                p.set_xy(cx, self.y)
                p.cell(ww + 0.6, self._lead, w, link=href or None)
                if st == "l" and href and not w.isspace():
                    p.set_draw_color(*(176, 196, 184))
                    p.set_line_width(0.4)
                    p.line(cx, self.y + self._lead - 3.2,
                           cx + ww, self.y + self._lead - 3.2)
            cx += ww

    # ── page management ──────────────────────────────────────────────────────
    def new_page(self, chrome=True):
        p = self.pdf
        p.add_page()
        self.page_no += 1
        p.set_fill_color(*PAPER)
        p.rect(0, 0, W, H, style="F")
        self.y = MT
        if chrome and self.show_chrome:
            self.chrome()

    def chrome(self):
        p = self.pdf
        self.F("SansSB", "", 7.0)
        p.set_text_color(*FAINT)
        p.set_char_spacing(1.0)
        p.set_xy(ML, 40)
        p.cell(CW * 0.5, 10, sanitize(self.head_left, serif=True)[:60].upper(), align="L")
        p.set_xy(ML + CW * 0.5, 40)
        p.cell(CW * 0.5, 10, sanitize(self.head_right, serif=True)[:60].upper(), align="R")
        p.set_char_spacing(0)
        p.set_draw_color(*RULE)
        p.set_line_width(0.5)
        p.line(ML, 54, RIGHT, 54)
        p.line(ML, H - 48, RIGHT, H - 48)
        self.F("Mono", "", 7.5)
        p.set_text_color(*FAINT)
        p.set_xy(ML, H - 42)
        p.cell(CW, 10, f"{self.page_no}", align="R")

    def need(self, h):
        if self.y + h > H - MB:
            self.new_page()
            return True
        return False

    # ── rich text ────────────────────────────────────────────────────────────
    def rich(self, text, size=9.4, lead=14.0, x=ML, width=None,
             base_color=None, indent=0.0):
        """Wrap and draw a string containing inline Markdown."""
        width = width or (CW - indent)
        words = self._words(text, size)
        lines = self._layout(words, width, size)
        self._lead = lead
        for ln in lines:
            self.need(lead)
            self._draw_line(ln, x + indent, size, base_color=base_color)
            self.y += lead
        return len(lines)

    def _plain(self, text):
        return re.sub(r"[*`_]", "", re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text))

    def _wrap_plain(self, text, width, fam, style, size):
        """Greedy word wrap. A single word wider than `width` is broken at a
        separator (or, failing that, mid-word) so it cannot run past the margin.
        """
        p = self.pdf
        self.F(fam, style, size)

        def chop(word):
            out, rest = [], word
            while p.get_string_width(rest) > width and rest:
                fit = 1
                for i in range(1, len(rest) + 1):
                    if p.get_string_width(rest[:i]) <= width:
                        fit = i
                    else:
                        break
                cut = max((j + 1 for j in range(fit)
                           if rest[j] in self._BREAK_AFTER), default=0)
                if cut >= max(3, fit // 3):
                    fit = cut
                out.append(rest[:fit])
                rest = rest[fit:]
            if rest:
                out.append(rest)
            return out

        lines, cur = [], ""
        for w in str(text).split():
            for piece in (chop(w) if p.get_string_width(w) > width else [w]):
                t = (cur + " " + piece).strip()
                if p.get_string_width(t) <= width or not cur:
                    cur = t
                else:
                    lines.append(cur)
                    cur = piece
        if cur:
            lines.append(cur)
        return lines

    # ── blocks ───────────────────────────────────────────────────────────────
    def heading(self, level, text):
        p = self.pdf
        txt = sanitize(self._plain(text), serif=True)
        if level <= 1:
            return                       # doc title is drawn by the doc opener
        if level == 2:
            self.y += 20
            lines = self._wrap_plain(txt, CW, "Serif", "B", 13.2)
            self.need(len(lines) * 19 + 20)
            self.F("Serif", "B", 13.2)
            p.set_text_color(*INK)
            for ln in lines:
                p.set_xy(ML, self.y)
                p.cell(CW, 19, ln)
                self.y += 19
            self.y += 3
            p.set_draw_color(*RULE)
            p.set_line_width(0.6)
            p.line(ML, self.y, RIGHT, self.y)
            self.y += 11
        elif level == 3:
            self.y += 15
            lines = self._wrap_plain(txt, CW, "SansSB", "", 10.4)
            self.need(len(lines) * 16 + 12)
            self.F("SansSB", "", 10.4)
            p.set_text_color(*INK)
            for ln in lines:
                p.set_xy(ML, self.y)
                p.cell(CW, 16, ln)
                self.y += 16
            self.y += 5
        else:
            self.y += 11
            lines = self._wrap_plain(txt, CW, "Sans", "B", 9.4)
            self.need(len(lines) * 14 + 8)
            self.F("Sans", "B", 9.4)
            p.set_text_color(*(58, 68, 62))
            for ln in lines:
                p.set_xy(ML, self.y)
                p.cell(CW, 14, ln)
                self.y += 14
            self.y += 3

    def para(self, text):
        self.rich(text, size=9.4, lead=14.2)
        self.y += 7

    def hr(self):
        self.y += 6
        self.need(16)
        p = self.pdf
        p.set_draw_color(*RULE)
        p.set_line_width(0.6)
        p.line(ML, self.y, RIGHT, self.y)
        self.y += 12

    def ul(self, items):
        p = self.pdf
        for it in items:
            ind = 14 + it.get("depth", 0) * 16
            txt = it["text"]
            # a "- [ ]" task item
            m = re.match(r"^\[([ xX])\]\s*(.*)$", txt)
            self.need(16)
            top = self.y
            if m:
                done = m.group(1).lower() == "x"
                txt = m.group(2)
                p.set_draw_color(*(190, 196, 190))
                p.set_line_width(0.8)
                p.rect(ML + ind - 12, top + 3.4, 8, 8, style="D",
                       round_corners=True, corner_radius=1.2)
                if done:
                    p.set_fill_color(*SAGE)
                    p.rect(ML + ind - 10, top + 5.4, 4, 4, style="F")
            else:
                p.set_fill_color(*(150, 172, 158) if it.get("depth") else SAGE)
                p.rect(ML + ind - 10, top + 5.6, 3.0, 3.0, style="F")
            self.rich(txt, size=9.4, lead=14.0, x=ML, width=CW - ind, indent=ind)
            self.y += 4
        self.y += 5

    def ol(self, items):
        p = self.pdf
        for it in items:
            self.need(16)
            top = self.y
            self.F("Mono", "B", 8.6)
            p.set_text_color(*SAGE)
            p.set_xy(ML, top + 0.6)
            p.cell(20, 13, f"{it['num']}.")
            self.rich(it["text"], size=9.4, lead=14.0, x=ML, width=CW - 24, indent=24)
            self.y += 4
        self.y += 5

    def code(self, lines, lang=""):
        p = self.pdf
        size = 8.0
        lead = 11.6
        self.F("Mono", "", size)
        # wrap over-long lines at character level so nothing is clipped
        maxw = CW - 36
        out: list[str] = []
        for ln in lines:
            ln = sanitize(ln.rstrip("\n"), mono=True).replace("\t", "    ")
            if p.get_string_width(ln) <= maxw or not ln:
                out.append(ln)
                continue
            cur = ""
            for ch in ln:
                if p.get_string_width(cur + ch) > maxw:
                    out.append(cur)
                    cur = "    " + ch.lstrip()
                else:
                    cur += ch
            if cur:
                out.append(cur)

        # Paginate: decide how many lines fit AFTER any page break, never
        # before it, or a chunk sized for the old cursor gets stranded.
        idx = 0
        while idx < len(out):
            fit = int(((H - MB) - self.y - 22) // lead)
            if fit < 2:                       # no useful room left on this page
                self.new_page()
                fit = int(((H - MB) - self.y - 22) // lead)
            fit = max(1, fit)
            # widow control: never carry a single line onto the next page
            if 0 < len(out) - (idx + fit) < 2 and fit > 2:
                fit -= 1
            chunk = out[idx:idx + fit]
            h = len(chunk) * lead + 20
            p.set_fill_color(*CODEBG)
            p.rect(ML, self.y, CW, h, style="F", round_corners=True, corner_radius=3)
            p.set_fill_color(*(214, 224, 217))
            p.rect(ML, self.y, 2.0, h, style="F")
            self.F("Mono", "", size)
            p.set_text_color(*(56, 66, 60))
            yy = self.y + 10
            for ln in chunk:
                p.set_xy(ML + 18, yy)
                p.cell(CW - 30, lead, ln)
                yy += lead
            self.y += h + 10
            idx += fit
        self.y += 2

    # ── Mermaid ─────────────────────────────────────────────────────────────
    # A page of Mermaid source is useless on paper, so parse the graph and lay
    # it out natively: subgraphs become titled groups, edges become a flow list.
    @staticmethod
    def _mermaid_parse(lines):
        node_re = re.compile(
            r'([A-Za-z_][\w]*)\s*(?:\[\("([^"]*)"\)\]|\{\{"?([^"}]*)"?\}\}'
            r'|\["([^"]*)"\]|\("([^"]*)"\)|\{"?([^"}]*)"?\}|\[([^\]"]+)\])')
        labels: dict[str, str] = {}
        groups: list[dict] = []
        edges: list[tuple[str, str, str]] = []
        stack: list[dict] = []
        loose: list[str] = []

        def clean(s):
            s = re.sub(r"<br\s*/?>", " — ", s or "")
            return re.sub(r"\s+", " ", s).strip()

        def note(m):
            gid = m.group(1)
            lab = next((g for g in m.groups()[1:] if g), gid)
            labels.setdefault(gid, clean(lab))
            return gid

        for raw in lines:
            s = raw.strip()
            if not s or s.startswith("%%"):
                continue
            if re.match(r"^(graph|flowchart|stateDiagram|classDiagram)", s):
                continue
            if s.startswith("subgraph"):
                m = re.match(r'subgraph\s+(\w+)?\s*\["?([^"\]]*)"?\]|subgraph\s+(.+)', s)
                title, sid = "", None
                if m:
                    sid = m.group(1)
                    title = clean(m.group(2) or m.group(3) or m.group(1) or "")
                # an edge may target the subgraph itself — give its id the title
                if sid and title:
                    labels[sid] = title
                g = {"title": title, "nodes": []}
                groups.append(g)
                stack.append(g)
                continue
            if s == "end":
                if stack:
                    stack.pop()
                continue
            if s.startswith(("style ", "classDef", "class ", "linkStyle")):
                continue
            if s.startswith("note "):
                continue

            # edges (possibly chained)
            if "--" in s or "==" in s or "-." in s:
                parts = re.split(r"\s*(?:-{2,}>|-\.->|={2,}>|-{3,}|-\.-)\s*", s)
                elabels = re.findall(r"\|([^|]*)\|", s)
                ids = []
                for seg in parts:
                    seg = seg.strip()
                    seg = re.sub(r"^\|[^|]*\|\s*", "", seg)
                    if not seg:
                        continue
                    mm = node_re.match(seg)
                    if mm:
                        ids.append(note(mm))
                    else:
                        w = re.match(r"^([A-Za-z_][\w]*)", seg)
                        if w:
                            labels.setdefault(w.group(1), w.group(1))
                            ids.append(w.group(1))
                for k in range(len(ids) - 1):
                    lab = elabels[k] if k < len(elabels) else ""
                    edges.append((ids[k], ids[k + 1], clean(lab)))
                continue

            mm = node_re.match(s)
            if mm:
                gid = note(mm)
                if stack:
                    if gid not in stack[-1]["nodes"]:
                        stack[-1]["nodes"].append(gid)
                elif gid not in loose:
                    loose.append(gid)
        return labels, groups, edges, loose

    def mermaid(self, lines):
        p = self.pdf
        try:
            labels, groups, edges, loose = self._mermaid_parse(lines)
        except Exception:
            labels, groups, edges, loose = {}, [], [], []

        if not labels or (not groups and len(edges) < 2):
            self.need(30)
            self.F("SansSB", "", 7.2)
            p.set_text_color(*SOFT)
            p.set_char_spacing(1.2)
            p.set_xy(ML, self.y)
            p.cell(CW, 12, "DIAGRAM  ·  MERMAID SOURCE")
            p.set_char_spacing(0)
            self.y += 15
            self.code(lines)
            return

        self.need(26)
        self.F("SansSB", "", 7.2)
        p.set_text_color(*SOFT)
        p.set_char_spacing(1.2)
        p.set_xy(ML, self.y)
        p.cell(CW, 12, "DIAGRAM")
        p.set_char_spacing(0)
        self.y += 16

        # grouped nodes
        for g in groups:
            names = [labels.get(n, n) for n in g["nodes"]]
            if not names:
                continue
            body = self._wrap_plain(sanitize("  ·  ".join(names)), CW - 34,
                                    "Sans", "", 8.6)
            h = 16 + 12 + len(body) * 12.4 + 12
            self.need(h + 8)
            top = self.y
            p.set_fill_color(*WASH)
            p.rect(ML, top, CW, h, style="F", round_corners=True, corner_radius=3)
            p.set_fill_color(*SAGE)
            p.rect(ML, top, 2.2, h, style="F")
            self.F("SansSB", "", 8.4)
            p.set_text_color(*INK)
            p.set_xy(ML + 18, top + 11)
            p.cell(CW - 30, 13, sanitize(g["title"], serif=True))
            self.F("Sans", "", 8.6)
            p.set_text_color(*BODY)
            yy = top + 27
            for ln in body:
                p.set_xy(ML + 18, yy)
                p.cell(CW - 34, 12.4, ln)
                yy += 12.4
            self.y = top + h + 8

        if loose:
            names = [labels.get(n, n) for n in loose]
            self.y += 2
            self.rich("**Also:** " + "  ·  ".join(names), size=8.8, lead=12.6)
            self.y += 4

        # flow
        if edges:
            self.y += 6
            self.need(24)
            self.F("SansSB", "", 7.2)
            p.set_text_color(*SOFT)
            p.set_char_spacing(1.2)
            p.set_xy(ML, self.y)
            p.cell(CW, 12, "FLOW")
            p.set_char_spacing(0)
            self.y += 15
            seen = set()
            for a, b, lab in edges:
                key = (a, b, lab)
                if key in seen:
                    continue
                seen.add(key)
                la = sanitize(labels.get(a, a)).split(" — ")[0]
                lb = sanitize(labels.get(b, b)).split(" — ")[0]
                txt = f"{la}   ->   {lb}"
                if lab:
                    txt += f"   ({sanitize(lab)})"
                self.need(12.8)
                self.F("Mono", "", 7.8)
                p.set_text_color(*(70, 82, 74))
                for ln in self._wrap_plain(txt, CW - 16, "Mono", "", 7.8):
                    p.set_xy(ML + 10, self.y)
                    p.cell(CW - 16, 12.4, ln)
                    self.y += 12.4
            self.y += 8

    def quote(self, text, raw):
        """Blockquotes become callouts: a sage rule, a NOTE chip, and a tinted panel."""
        p = self.pdf
        accent, bg, label = SAGE, SAGE_BG, "NOTE"

        # Strip the warning sign; the label chip already carries that meaning,
        # and the glyph is absent from every embedded font.
        body = text.replace("⚠", "").replace("️", "").strip()
        body = re.sub(r"^\*{0,2}\s*[-—:]\s*", "", body).strip()
        if not body:
            body = text

        # measure
        inner = CW - 40
        tmp_y = self.y
        self.F("Sans", "", 9.2)
        est = self._wrap_plain(self._plain(body), inner, "Sans", "", 9.2)
        h = 16 + 12 + 4 + len(est) * 13.8 + 14
        if self.y + h > H - MB and h < (H - MB - MT):
            self.new_page()
        top = self.y
        p.set_fill_color(*bg)
        p.rect(ML, top, CW, h, style="F", round_corners=True, corner_radius=3)
        p.set_fill_color(*accent)
        p.rect(ML, top, 2.4, h, style="F")
        self.F("SansSB", "", 7.4)
        p.set_text_color(*accent)
        p.set_char_spacing(1.1)
        p.set_xy(ML + 20, top + 12)
        p.cell(inner, 12, label)
        p.set_char_spacing(0)
        self.y = top + 30
        self.rich(body, size=9.2, lead=13.8, x=ML + 20, width=inner,
                  base_color=(62, 72, 66))
        self.y = max(self.y, top + h) + 12
        _ = tmp_y

    def table(self, head, rows, aligns):
        p = self.pdf
        ncol = len(head)
        size = 8.2
        lead = 11.8
        pad = 6.0

        # ── column widths ───────────────────────────────────────────────────
        # Two competing needs: proportional to content volume, but never
        # narrower than the widest UNBREAKABLE token (file paths and
        # identifiers have no spaces to wrap at, so a too-narrow column would
        # spill into its neighbour).
        GAP = 10.0
        weights, mins = [], []
        for c in range(ncol):
            texts = [head[c]] + [r[c] for r in rows]
            longest = max((len(self._plain(x)) for x in texts), default=1)
            avg = sum(len(self._plain(x)) for x in texts) / max(1, len(texts))
            weights.append(max(4.0, 0.45 * longest + 0.55 * avg))
            # the minimum is the widest piece that CANNOT be broken further,
            # not the whole token — long identifiers split at their separators
            widest = 0.0
            for x in texts:
                for w_, st_, _h, _ww in self._words(x, size):
                    if not w_.isspace():
                        widest = max(widest, self._seg_width(w_, st_, size))
            mins.append(min(widest + GAP, CW * 0.40))

        tot = sum(weights) or 1
        ws = [w / tot * CW for w in weights]
        # lift any column that is under its unbreakable minimum, then take the
        # difference back from the columns that have slack
        for _ in range(6):
            deficit = sum(max(0.0, mins[c] - ws[c]) for c in range(ncol))
            if deficit < 0.5:
                break
            slack = [max(0.0, ws[c] - mins[c]) for c in range(ncol)]
            total_slack = sum(slack)
            if total_slack < 0.5:
                break
            take = min(deficit, total_slack)
            for c in range(ncol):
                if slack[c] > 0:
                    ws[c] -= take * (slack[c] / total_slack)
                if ws[c] < mins[c]:
                    ws[c] = mins[c]
        scale = CW / sum(ws)
        ws = [w * scale for w in ws]

        def draw_head():
            self.F("SansSB", "", 7.2)
            p.set_text_color(*SOFT)
            p.set_char_spacing(0.7)
            hh = 0
            # letter-spacing (0.7pt/char) is not counted by get_string_width,
            # so budget a little less width than the column actually has
            cells = [self._wrap_plain(sanitize(self._plain(h)), (w - GAP) * 0.86,
                                      "SansSB", "", 7.2) for h, w in zip(head, ws)]
            hh = max(len(c) for c in cells) * 10 + 4
            x = ML
            for cell, w, a in zip(cells, ws, aligns):
                yy = self.y
                for ln in cell:
                    p.set_xy(x, yy)
                    p.cell(w - 10, 10, ln.upper(), align=a)
                    yy += 10
                x += w
            p.set_char_spacing(0)
            self.y += hh
            p.set_draw_color(*INK)
            p.set_line_width(0.8)
            p.line(ML, self.y, RIGHT, self.y)
            self.y += 5

        self.need(64)
        draw_head()

        for idx, row in enumerate(rows):
            cells = []
            for ci, (val, w) in enumerate(zip(row, ws)):
                self._bold_plain = (ci == 0)
                lines = self._layout(self._words(val, size), w - GAP, size)
                self._bold_plain = False
                cells.append(lines or [[]])
            nlines = max(len(c) for c in cells)
            h = nlines * lead + pad * 2 - 3

            if self.y + h > H - MB:
                self.new_page()
                draw_head()
            if idx % 2 == 1:
                p.set_fill_color(*WASH)
                p.rect(ML, self.y - 2, CW, h, style="F")

            self._lead = lead
            saved_y = self.y
            x = ML
            for ci, (cell, w, a) in enumerate(zip(cells, ws, aligns)):
                self.y = saved_y + pad - 4
                for ln in cell:
                    lw = sum(t[3] for t in ln)
                    if a == "R":
                        cx = x + (w - GAP) - lw
                    elif a == "C":
                        cx = x + ((w - GAP) - lw) / 2
                    else:
                        cx = x
                    self._bold_plain = (ci == 0)
                    self._draw_line(ln, cx, size, first_col_bold=(ci == 0))
                    self._bold_plain = False
                    self.y += lead
                x += w
            self.y = saved_y + h
            p.set_draw_color(*RULE)
            p.set_line_width(0.5)
            p.line(ML, self.y - 2, RIGHT, self.y - 2)
        self.y += 10

    # ── document driver ──────────────────────────────────────────────────────
    def render_blocks(self, blocks):
        for b in blocks:
            t = b["t"]
            if t == "h":
                self.heading(b["level"], b["text"])
            elif t == "para":
                self.para(b["text"])
            elif t == "ul":
                self.ul(b["items"])
            elif t == "ol":
                self.ol(b["items"])
            elif t == "code":
                self.code(b["lines"], b.get("lang", ""))
            elif t == "mermaid":
                self.mermaid(b["lines"])
            elif t == "quote":
                self.quote(b["text"], b.get("raw", []))
            elif t == "table":
                self.table(b["head"], b["rows"], b["align"])
            elif t == "hr":
                self.hr()
