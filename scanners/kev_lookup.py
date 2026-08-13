"""
scanners/kev_lookup.py — CISA Known Exploited Vulnerabilities cross-reference.

The authoritative list of CVEs CONFIRMED exploited in the wild. A KEV hit sets
ExploitStatus.ACTIVE_EXPLOITATION, which is a deal-killer override — the score
is forced to 100 and the tier to DEAL_KILLER.

Free public feed, no API key. The whole catalogue is fetched once per process
and held in memory.

!! Degradation matters here more than anywhere else in the pipeline. If the
feed is unreachable the cache becomes {} and every is_kev() returns False — so
NO deal-killer override fires for an actively-exploited CVE, and the report
looks REASSURING rather than broken. Diagnose with:

    from scanners.kev_lookup import fetch_kev_catalog
    print(len(fetch_kev_catalog()))     # 0 means the feed failed

Note the feed is retrospective: a CVE enters KEV after exploitation is observed.
scanners/epss_scan.py covers the window before that (see ADR-0007).
"""
import requests

_kev_cache: dict[str, dict] | None = None

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog() -> dict[str, dict]:
    """
    Download the CISA Known Exploited Vulnerabilities catalog.
    Cached in-process for the lifetime of the app session.
    Returns a dict keyed by CVE ID.
    """
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        resp = requests.get(CISA_KEV_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {
            v["cveID"]: v
            for v in data.get("vulnerabilities", [])
        }
    except Exception:
        _kev_cache = {}

    return _kev_cache


def is_kev(cve_id: str) -> bool:
    return cve_id in fetch_kev_catalog()


def get_kev_entry(cve_id: str) -> dict | None:
    return fetch_kev_catalog().get(cve_id)
