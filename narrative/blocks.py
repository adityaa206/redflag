"""
narrative/blocks.py — Deterministic narrative block selector.

Loads narrative_blocks.yaml and selects the first matching block for a given
context dict, then renders the text with variable substitution.

No LLM, no randomness — same context always produces same text.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from config.loader import get_narrative_blocks


def _matches(condition: dict, context: dict) -> bool:
    """
    Return True if all keys in condition match the context.

    Comparison rules:
    - bool: exact match
    - str:  exact match (case-insensitive)
    - int/float: exact match
    """
    for key, expected in condition.items():
        actual = context.get(key)
        if isinstance(expected, bool):
            if bool(actual) != expected:
                return False
        elif isinstance(expected, str):
            if str(actual).lower() != expected.lower():
                return False
        elif isinstance(expected, (int, float)):
            if actual != expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def _render(template: str, context: dict) -> str:
    """
    Substitute {variable} placeholders in template with context values.
    Unknown placeholders are left as-is.
    """
    def replace(match):
        key = match.group(1)
        val = context.get(key)
        if val is None:
            return match.group(0)  # leave unchanged
        # Format numbers
        if isinstance(val, float):
            if val >= 1000:
                return f"{val:,.0f}"
            return f"{val:.1f}"
        if isinstance(val, int):
            return f"{val:,}"
        return str(val)

    return re.sub(r"\{(\w+)\}", replace, template)


def select_block(section: str, context: dict) -> Optional[str]:
    """
    Select and render the first matching narrative block for a section.

    Args:
        section: one of the top-level keys in narrative_blocks.yaml
                 (e.g. "executive_summary", "maturity_summary", "cost_summary",
                  "finding_detail", "remediation_priority")
        context: dict of variables for condition matching and text substitution

    Returns:
        Rendered text string, or None if no block matched.
    """
    blocks_cfg = get_narrative_blocks()
    blocks     = blocks_cfg.get(section, [])

    # Sort by priority ascending (lower = evaluated first)
    sorted_blocks = sorted(blocks, key=lambda b: b.get("priority", 99))

    for block in sorted_blocks:
        condition = block.get("when", {})
        if _matches(condition, context):
            raw_text = block.get("text", "")
            # Normalise whitespace from YAML block scalars
            clean_text = " ".join(raw_text.split())
            return _render(clean_text, context)

    return None


def select_all_blocks(section: str, context: dict) -> list[str]:
    """
    Return rendered text for ALL matching blocks in a section (for sections
    where multiple blocks may apply, e.g. finding_detail).
    """
    blocks_cfg = get_narrative_blocks()
    blocks     = blocks_cfg.get(section, [])

    sorted_blocks = sorted(blocks, key=lambda b: b.get("priority", 99))
    results = []

    for block in sorted_blocks:
        condition = block.get("when", {})
        if _matches(condition, context):
            raw_text = block.get("text", "")
            clean_text = " ".join(raw_text.split())
            results.append(_render(clean_text, context))

    return results


def list_sections() -> list[str]:
    """Return all section names defined in narrative_blocks.yaml."""
    return list(get_narrative_blocks().keys())
