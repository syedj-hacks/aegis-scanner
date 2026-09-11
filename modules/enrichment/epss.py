"""
modules/enrichment/epss.py
FIRST.org EPSS (Exploit Prediction Scoring System) client.

WHAT EPSS ADDS OVER CVSS
------------------------
CVSS says how bad a vulnerability WOULD be if exploited; EPSS says how
LIKELY it is to be exploited in the next 30 days, as a probability 0-1,
updated daily from real-world exploitation telemetry. A CVSS 9.8 that
nobody is exploiting (EPSS 0.01) and a CVSS 6.5 under active mass
exploitation (EPSS 0.95) are very different remediation priorities, and
CVSS alone cannot tell them apart. This is exactly the signal a
professional scanner uses to rank findings, and the thing the Phase 3
"combined risk score" is built from.

THE API
-------
GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2019-0708
returns {"data": [{"cve", "epss", "percentile", "date"}, ...]}. Free, no
key, courteous-use. Batched (many CVEs per request) and cached for a day
(EPSS republishes daily, so a shorter TTL would just re-fetch unchanged
numbers and a longer one would serve yesterday's after a refresh).

HONESTY
-------
EPSS is defined ONLY for published CVEs. A finding with no CVE (a missing
header, a discovered path, a weak-TLS cipher) has no EPSS score and this
module returns None for it — it does not invent a 0.0, because "no data"
and "certainly-not-exploited" are different claims and only one of them is
true here. Never raises: any network/parse failure returns {} and the
finding keeps its CVSS-only risk score.
"""

from __future__ import annotations

import re

import requests

from modules.enrichment import enrich_cache
from modules.utils.error_handler import safe_call
from modules.utils.logger import log_tool_start, log_tool_success, log_tool_failure
from modules.utils.display import print_info, print_warning

_EPSS_URL = "https://api.first.org/data/v1/epss"
_USER_AGENT = "AegisScanner/1.0 (+https://github.com/syedj-hacks/aegis-scanner)"
_REQUEST_TIMEOUT = 20.0
_CACHE_NAMESPACE = "epss"
# EPSS republishes once a day; a day-long TTL is the natural fit.
_CACHE_TTL = 24 * 3600
# API accepts many CVEs at once; keep batches reasonable so one giant URL
# doesn't trip a server-side limit.
_BATCH = 80

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _valid_cves(cve_ids) -> list:
    """Uppercased, de-duplicated, well-formed CVE ids only."""
    seen, out = set(), []
    for cve in cve_ids or []:
        if not cve:
            continue
        c = str(cve).strip().upper()
        if _CVE_RE.match(c) and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _fetch_batch(cves: list, target: str = "epss") -> dict:
    """One HTTP call for a batch of CVEs. Returns {cve: {epss, percentile}}."""
    response = requests.get(
        _EPSS_URL,
        params={"cve": ",".join(cves)},
        headers={"User-Agent": _USER_AGENT},
        timeout=_REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"EPSS returned HTTP {response.status_code}")
    payload = response.json()
    out = {}
    for row in payload.get("data") or []:
        cve = str(row.get("cve") or "").upper()
        if not cve:
            continue
        try:
            out[cve] = {
                "epss": float(row.get("epss")),
                "percentile": float(row.get("percentile")),
            }
        except (TypeError, ValueError):
            continue
    return out


def lookup_epss(cve_ids, target: str = "epss") -> dict:
    """
    Return {cve_id: {"epss": float, "percentile": float}} for the CVEs that
    EPSS knows about.

    A CVE EPSS has never scored simply does not appear in the result — the
    caller treats its absence as "no EPSS data", not zero. Cached per CVE
    for a day; only cache-missing CVEs are actually fetched, batched.

    Never raises.
    """
    cves = _valid_cves(cve_ids)
    if not cves:
        return {}

    result = {}
    missing = []
    for cve in cves:
        cached = enrich_cache.get(_CACHE_NAMESPACE, cve, _CACHE_TTL)
        if cached is not None:
            # A cached miss is stored as {} so we don't re-ask FIRST.org
            # about a CVE it has no score for on every scan.
            if cached:
                result[cve] = cached
        else:
            missing.append(cve)

    if not missing:
        return result

    log_tool_start(target, "epss-lookup")
    print_info(f"[EPSS] querying FIRST.org for {len(missing)} CVE(s)")

    fetched_any = False
    for i in range(0, len(missing), _BATCH):
        batch = missing[i:i + _BATCH]
        outcome = safe_call(_fetch_batch, batch, target=target, label="epss-lookup")
        if not outcome.get("success"):
            log_tool_failure(target, "epss-lookup", outcome.get("error") or "EPSS request failed")
            print_warning("[EPSS] lookup failed for a batch — findings keep CVSS-only risk")
            continue
        fetched_any = True
        scores = outcome.get("data") or {}
        for cve in batch:
            value = scores.get(cve)
            if value:
                result[cve] = value
                enrich_cache.put(_CACHE_NAMESPACE, cve, value)
            else:
                # Cache the miss (empty dict) with its own timestamp.
                enrich_cache.put(_CACHE_NAMESPACE, cve, {})

    if fetched_any:
        log_tool_success(target, "epss-lookup")
    return result
