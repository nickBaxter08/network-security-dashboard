"""
Looks up known CVEs for a given product/version against the public
NVD (National Vulnerability Database) API. Read-only, public data —
safe to call in demo mode too.
"""

import requests

from config import config

# Small local cache so repeated scans don't hammer the NVD API
_cache = {}


def lookup_cves(product, version, max_results=5):
    if not product:
        return []

    query = f"{product} {version}" if version else product
    cache_key = query.lower().strip()
    if cache_key in _cache:
        return _cache[cache_key]

    params = {"keywordSearch": query, "resultsPerPage": max_results}
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}

    try:
        resp = requests.get(config.NVD_API_BASE, params=params, headers=headers, timeout=5)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severity = _extract_severity(metrics)
        if cve_id:
            results.append({
                "id": cve_id,
                "summary": summary[:200],
                "severity": severity,
            })

    _cache[cache_key] = results
    return results


def _extract_severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    return "UNKNOWN"
