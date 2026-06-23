"""
config/loader.py — Cached YAML config loader for all RedFlag config files.

All files are loaded once per process and cached in-memory.
Call reload_all() in tests to reset the cache.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# ── Path resolution ───────────────────────────────────────────────────────────
_CONFIG_DIR = Path(__file__).parent


def _config_path(filename: str) -> Path:
    return _CONFIG_DIR / filename


# ── In-process cache ──────────────────────────────────────────────────────────
_CACHE: dict[str, Any] = {}


def _load(filename: str) -> Any:
    if filename not in _CACHE:
        path = _config_path(filename)
        with open(path, "r", encoding="utf-8") as f:
            _CACHE[filename] = yaml.safe_load(f)
    return _CACHE[filename]


def reload_all() -> None:
    """Clear the in-process cache (useful in tests)."""
    _CACHE.clear()


# ── Public accessors ──────────────────────────────────────────────────────────

def get_maturity_questions() -> dict:
    """Return the parsed maturity_questions.yaml content."""
    return _load("maturity_questions.yaml")


def get_corporate_standard() -> dict:
    """Return the parsed corporate_standard.yaml content."""
    return _load("corporate_standard.yaml")


def get_pricing_benchmarks() -> dict:
    """Return the parsed pricing_benchmarks.yaml content."""
    return _load("pricing_benchmarks.yaml")


def get_remediation_catalog() -> dict:
    """Return the parsed remediation_catalog.yaml content."""
    return _load("remediation_catalog.yaml")


def get_narrative_blocks() -> dict:
    """Return the parsed narrative_blocks.yaml content."""
    return _load("narrative_blocks.yaml")


def get_day1_blueprint() -> dict:
    """Return the parsed day1_blueprint.yaml content."""
    return _load("day1_blueprint.yaml")


# ── Convenience helpers ───────────────────────────────────────────────────────

def get_labour_rate(role: str, scenario: str = "base") -> float:
    """
    Return the labour rate (USD/hr) for a given role and scenario.

    Args:
        role: key in pricing_benchmarks.labour_rates
        scenario: "low" | "base" | "high"
    """
    benchmarks = get_pricing_benchmarks()
    rates = benchmarks.get("labour_rates", {})
    role_rates = rates.get(role, {})
    return float(role_rates.get(scenario, role_rates.get("base", 150)))


def get_effort_hours(task_key: str, scenario: str = "base") -> float:
    """
    Return effort hours for a given task key and scenario.

    Args:
        task_key: key in pricing_benchmarks.effort_hours
        scenario: "low" | "base" | "high"
    """
    benchmarks = get_pricing_benchmarks()
    efforts = benchmarks.get("effort_hours", {})
    task = efforts.get(task_key, {})
    return float(task.get(scenario, task.get("base", 8)))


def get_tool_cost(tool_key: str, scenario: str = "base") -> float:
    """
    Return tool/licence cost (USD/yr) for a given tool key and scenario.

    Args:
        tool_key: key in pricing_benchmarks.tool_costs
        scenario: "low" | "base" | "high"
    """
    benchmarks = get_pricing_benchmarks()
    tools = benchmarks.get("tool_costs", {})
    tool = tools.get(tool_key, {})
    return float(tool.get(scenario, tool.get("base", 0)))


def get_domain_standard(domain: str) -> dict:
    """
    Return the corporate standard thresholds for a maturity domain.

    Returns dict with keys: acceptable_min, recommended, deal_blocker, rationale
    """
    standard = get_corporate_standard()
    domains = standard.get("domains", {})
    return domains.get(domain, {"acceptable_min": 2, "recommended": 3, "deal_blocker": 1})


def get_overall_deal_blocker_threshold() -> float:
    """Return the overall maturity deal-blocker threshold."""
    standard = get_corporate_standard()
    return float(standard.get("overall_deal_blocker_threshold", 1.5))
