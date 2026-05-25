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
