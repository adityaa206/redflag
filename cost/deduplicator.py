"""
cost/deduplicator.py — Merge duplicate CostLineItems.

Deduplication rules:
  1. Items with the same catalog_key AND the same category are considered
     duplicates (e.g. five findings all mapping to "service:ssh" → one item).
  2. Merged items combine their finding_ids lists.
  3. The merged cost uses the highest base estimate (conservative).
  4. The merged item inherits ALL review_flags from the constituent items.
  5. is_merged = True and merged_from contains the original IDs.

This prevents double-counting when multiple findings require the same fix
(e.g. patching the same OS vulnerability across several ports).
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy

from cost.schema import CostLineItem, CostTriple, ReviewFlag


def _deduplicate_key(item: CostLineItem) -> str:
    """
    Derive the deduplication bucket key for an item.
    Items with the same key are candidates for merging.
    """
    # catalog_key + category is the primary dedup key
    return f"{item.catalog_key}::{item.category}"


def deduplicate(items: list[CostLineItem]) -> list[CostLineItem]:
    """
    Merge duplicate line items.  Returns a new list (inputs unchanged).

    Items that cannot be deduplicated (different catalog_key or category) pass
    through unchanged.  Items with catalog_key starting with "default" are NOT
    merged (each one may represent a unique finding needing manual scoping).
    """
    if not items:
        return []

    # Group by dedup key
    buckets: dict[str, list[CostLineItem]] = defaultdict(list)
    non_merge: list[CostLineItem] = []

    for item in items:
        # Don't merge default/zero-estimate items — each needs individual review
        if item.catalog_key == "default" or ReviewFlag.ZERO_ESTIMATE in item.review_flags:
            non_merge.append(item)
        else:
            buckets[_deduplicate_key(item)].append(item)

    result: list[CostLineItem] = []

    for key, group in buckets.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Merge the group
        base_item = deepcopy(group[0])

        # Combine finding_ids (deduplicated)
        all_finding_ids: list[str] = []
        seen_fids: set[str] = set()
        for g in group:
            for fid in g.finding_ids:
                if fid not in seen_fids:
                    all_finding_ids.append(fid)
                    seen_fids.add(fid)

        # Conservative cost: use the maximum base estimate among the group
        max_base = max(g.cost.base for g in group)
        max_high = max(g.cost.high for g in group)
        min_low  = min(g.cost.low  for g in group)

        merged_cost = CostTriple(low=min_low, base=max_base, high=max_high)

        # Accumulate review flags
        all_flags: list[ReviewFlag] = []
        seen_flags: set[str] = set()
        for g in group:
            for f in g.review_flags:
                if f not in seen_flags:
                    all_flags.append(f)
                    seen_flags.add(str(f))

        # Flag high-variance if spread > 3×
        if merged_cost.spread_ratio() > 3.0 and ReviewFlag.HIGH_VARIANCE not in all_flags:
            all_flags.append(ReviewFlag.HIGH_VARIANCE)

        # Add DUPLICATE flag
        if ReviewFlag.DUPLICATE not in all_flags:
            all_flags.append(ReviewFlag.DUPLICATE)

        merged = CostLineItem(
            title=base_item.title,
            description=base_item.description + f" (merged from {len(group)} similar findings)",
            category=base_item.category,
            capex_opex=base_item.capex_opex,
            finding_ids=all_finding_ids,
            cost=merged_cost,
            confidence=base_item.confidence,
            catalog_key=base_item.catalog_key,
            notes=base_item.notes,
            review_flags=all_flags,
            is_merged=True,
            merged_from=[g.id for g in group],
        )
        result.append(merged)

    # Append non-merged items
    result.extend(non_merge)

    return result
