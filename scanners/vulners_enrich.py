import os
import requests
from dotenv import load_dotenv

from analysis.schema import ExploitStatus

load_dotenv()

_exploit_cache: dict[str, bool] = {}


def _api_key() -> str:
    return os.getenv("VULNERS_API_KEY", "")


def has_public_exploit(cve_id: str) -> bool:
    """
    Query Vulners to check whether a public exploit exists for a CVE.
    Cached in-process. Returns False if no API key or request fails.
    """
    if cve_id in _exploit_cache:
        return _exploit_cache[cve_id]

    key = _api_key()
    if not key:
        _exploit_cache[cve_id] = False
        return False

    result = False
    try:
        resp = requests.post(
            "https://vulners.com/api/v3/search/lucene/",
            json={
                "query": f"cvelist:{cve_id} AND type:exploit",
                "size": 1,
                "apiKey": key,
            },
            timeout=6,
        )
        if resp.status_code == 200:
            result = resp.json().get("data", {}).get("total", 0) > 0
    except Exception:
        pass

    _exploit_cache[cve_id] = result
    return result


def get_exploit_status_from_vulners(cve_id: str, current_status: ExploitStatus) -> ExploitStatus:
    """
    Upgrade exploit_status if Vulners confirms a public exploit exists for the CVE.
    Only upgrades UNKNOWN → PUBLIC_EXPLOIT. Never downgrades ACTIVE_EXPLOITATION.
    No-ops silently if VULNERS_API_KEY is not set.
    """
    if current_status == ExploitStatus.ACTIVE_EXPLOITATION:
        return current_status
    if not _api_key():
        return current_status
    if current_status == ExploitStatus.PUBLIC_EXPLOIT:
        return current_status
    if has_public_exploit(cve_id):
        return ExploitStatus.PUBLIC_EXPLOIT
    return current_status
