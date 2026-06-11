"""
Static guard against a Streamlit markdown rendering bug.

`st.markdown(\"\"\"<div>...\"\"\", unsafe_allow_html=True)` blocks that are
(a) indented >= 4 spaces in the source AND (b) contain a blank line inside the
HTML will render as raw text instead of HTML. Reason: per CommonMark, an HTML
block started by <div> is terminated by a blank line, and the deeply-indented
lines that follow become an indented code block (rendered literally).

This test scans app.py and fails if any such block exists, so the What-If
"Simulated Risk Profile" regression (raw HTML dumped on screen) cannot return.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app.py"

# HTML block-level tags that CommonMark terminates on a blank line (type 6).
_BLOCK_TAG = re.compile(r'^\s*</?(div|span|p|table|section|ul|ol|li|h[1-6])\b')


# A line that is ONLY a conditional rendering empty -> "" (or '') becomes a
# whitespace-only (i.e. blank) line at runtime, which also terminates the HTML
# block. This is the runtime variant that the static blank-line check misses.
_EMPTY_CONDITIONAL = re.compile(r'''^\s*\{.*\bif\b.*\belse\s*(""|'')\s*\)?\}\s*$''')


def _find_broken_blocks(source: str):
    lines = source.split("\n")
    broken = []
    i = 0
    while i < len(lines):
        m = re.match(r'^(\s*)st\.markdown\(f?"""', lines[i])
        if m:
            indent = len(m.group(1))
            k = i + 1
            block = []
            while k < len(lines) and '"""' not in lines[k]:
                block.append(lines[k])
                k += 1
            has_blank = any(ln.strip() == "" for ln in block)
            has_empty_cond = any(_EMPTY_CONDITIONAL.match(ln) for ln in block)
            has_block_tag = any(_BLOCK_TAG.match(ln) for ln in block)
            # Module-level blocks (indent < 4) re-parse as HTML after a blank
            # line; only deeply-indented blocks turn into code blocks. Both a
            # literal blank line and a runtime-empty conditional break it — use
            # st.html for such panels instead of st.markdown.
            if indent >= 4 and has_block_tag and (has_blank or has_empty_cond):
                broken.append(i + 1)  # 1-based line of the st.markdown call
            i = k
        else:
            i += 1
    return broken


def test_no_indented_html_markdown_with_blank_lines():
    source = APP.read_text(encoding="utf-8")
    broken = _find_broken_blocks(source)
    assert not broken, (
        "Deeply-indented st.markdown HTML blocks with internal blank lines "
        f"render as raw text. Offending st.markdown calls at app.py lines: {broken}. "
        "Remove the blank lines inside the HTML string (or use st.html)."
    )
