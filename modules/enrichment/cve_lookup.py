"""
modules/enrichment/cve_lookup.py
NVD CVE correlation for Aegis Scanner (Member C - enrichment layer).

Takes a product + optional version — typically straight out of
modules/scanning/service_detect.py ({port, service, version, product}) or
modules/web/header_check.py (server_banner / powered_by) — and queries the
NVD REST API v2.0 for matching CVEs.

This module does NOT go through run_tool() because it is not a subprocess
call — it is a direct HTTP request via `requests`. To keep the "never
raises" contract the rest of the framework relies on, every request is
wrapped in error_handler.safe_call(), the same approach used by
modules/web/header_check.py and modules/scanning/banner.py.

API key handling
----------------
The key comes from config.NVD_API_KEY and is sent in the `apiKey` request
header (never in the query string, which would put it in logs/proxies).
It is never printed, never logged, and every outbound error string is run
through _sanitise() as a belt-and-braces guard before it reaches the
console, the log file, or the returned dict.
"""

import time

import requests

from modules.utils.config import (
    NVD_API_KEY,
    NVD_BASE_URL,
    NVD_RATE_LIMIT_WINDOW,
    NVD_RATE_LIMIT_REQUESTS,
)
from modules.utils.error_handler import safe_call
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Seconds to wait for connect + response. A module constant rather than
# config.get_timeout() because TOOL_TIMEOUTS is scoped to subprocess tools;
# a single REST call should never take minutes. NVD is occasionally slow
# under load, hence 20s rather than header_check's 10s.
_REQUEST_TIMEOUT = 20.0

# NVD asks every client to identify itself.
_USER_AGENT = "AegisScanner/1.0 (+https://github.com/syedj-hacks/aegis-scanner)"

# Default number of CVEs requested per lookup. NVD allows up to 2000, but a
# service-version correlation only needs the worst handful — pulling 2000
# rows per detected service would be slow and noisy in the report.
_DEFAULT_LIMIT = 10

# Keyword strings longer than this are almost certainly a mangled banner
# rather than a product name; NVD 404s or times out on them.
_MAX_KEYWORD_LEN = 200

# --- Rate limiting -----------------------------------------------------
# NVD documents 50 requests / 30s with a key, 5 / 30s without.
# config derives NVD_RATE_LIMIT_REQUESTS from whether a key is present, so
# the minimum spacing below adapts automatically:
#   with key    -> 30 / 50 = 0.6s between calls
#   without key -> 30 /  5 = 6.0s between calls
# Two layers are enforced:
#   1. _MIN_INTERVAL — a hard floor between consecutive calls, which alone
#      is enough to stay under the documented rate.
#   2. A sliding window of recent call timestamps, which catches the case
#      where retries/backoff let calls bunch up at a window boundary.
_MIN_INTERVAL = float(NVD_RATE_LIMIT_WINDOW) / max(int(NVD_RATE_LIMIT_REQUESTS), 1)
_call_times = []

# Retry policy for the responses that are worth retrying (throttling and
# transient server errors). Delays are exponential: 2s, then 4s.
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 2.0
_RETRYABLE_STATUS = (429, 500, 502, 503, 504)


def _sanitise(text) -> str:
    """
    Strip the API key out of any string before it is displayed, logged, or
    returned. Nothing in this module should ever be able to leak the key,
    even via an unexpected exception message from `requests`.
    """
    out = "" if text is None else str(text)
    if NVD_API_KEY:
        out = out.replace(NVD_API_KEY, "***REDACTED***")
    return out


def _throttle():
    """
    Block until it is safe to issue another NVD request.

    Called before every request, so a caller looping over a dozen detected
    services self-paces instead of getting the key throttled or banned.
    """
    global _call_times

    now = time.time()

    # Layer 1: minimum spacing since the previous call.
    if _call_times:
        gap = now - _call_times[-1]
        if gap < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - gap)
            now = time.time()

    # Layer 2: sliding window — drop timestamps older than the window, and
    # if the window is still full, wait for the oldest call to age out.
    _call_times = [t for t in _call_times if now - t < NVD_RATE_LIMIT_WINDOW]
    if len(_call_times) >= NVD_RATE_LIMIT_REQUESTS:
        sleep_for = NVD_RATE_LIMIT_WINDOW - (now - _call_times[0])
        if sleep_for > 0:
            time.sleep(sleep_for)
        now = time.time()
        _call_times = [t for t in _call_times if now - t < NVD_RATE_LIMIT_WINDOW]

    _call_times.append(time.time())


def _build_keyword(product, version=None) -> str:
    """
    Compose the keywordSearch string. NVD treats multiple words as AND, so
    "vsftpd 2.3.4" matches CVEs mentioning both the product and version.
    """
    parts = [str(product).strip()]
    if version is not None and str(version).strip():
        parts.append(str(version).strip())
    return " ".join(parts)[:_MAX_KEYWORD_LEN]


def _validate(product, version) -> str:
    """
    Reject input that cannot produce a meaningful query. Returns a
    human-readable reason, or "" when the input is usable.

    Guarding here means a garbage product string from a mangled banner
    becomes an empty result with an error field, not a wasted API call.
    """
    if product is None:
        return "no product supplied"
    if not isinstance(product, (str, int, float)):
        return f"invalid product type: {type(product).__name__}"
    if not str(product).strip():
        return "empty product string"
    if version is not None and not isinstance(version, (str, int, float)):
        return f"invalid version type: {type(version).__name__}"
    return ""


def _request_nvd(keyword: str, limit: int) -> dict:
    """
    Perform one NVD request and return {status_code, json, text}.

    May raise (ConnectionError, Timeout, SSLError...) — callers MUST invoke
    this through safe_call() so those exceptions are captured instead of
    propagating.

    The API key travels in the `apiKey` header, never the query string.
    """
    headers = {"User-Agent": _USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    response = requests.get(
        NVD_BASE_URL,
        params={"keywordSearch": keyword, "resultsPerPage": limit},
        headers=headers,
        timeout=_REQUEST_TIMEOUT,
    )

    payload = None
    if response.status_code == 200:
        # NVD occasionally returns an HTML error page from a load balancer
        # with a 200; treat an unparseable body as a malformed response
        # rather than letting the JSON error escape as a crash.
        try:
            payload = response.json()
        except ValueError:
            payload = None

    return {
        "status_code": response.status_code,
        "json": payload,
        "text": response.text[:300] if response.text else "",
    }


def _status_error(status_code, body: str) -> str:
    """Map an HTTP status onto a human-readable, key-free failure reason."""
    if status_code == 401:
        return "NVD rejected the API key (401 unauthorized)"
    if status_code == 403:
        return "NVD forbade the request (403 — blocked/invalid key or rate limit)"
    if status_code == 404:
        # NVD answers an invalid apiKey with 404, not 401 — verified
        # against the live API — so this message covers both causes.
        return "NVD returned 404 (endpoint not found, or the API key is invalid)"
    if status_code == 429:
        return "NVD rate limit exceeded (429)"
    if isinstance(status_code, int) and 500 <= status_code < 600:
        return f"NVD server error ({status_code})"
    return f"unexpected NVD status {status_code}: {_sanitise(body)}"


def _extract_metric(metrics) -> tuple:
    """
    Pull the best available CVSS score out of an NVD `metrics` block.

    NVD returns cvssMetricV31 / V30 / V2 lists (any of which may be
    absent). Preference order is v3.1 -> v3.0 -> v2.0; the version actually
    used is returned so the report can state which scale a score came from.

    Returns (score: float|None, severity: str|None, version: str|None).
    """
    if not isinstance(metrics, dict):
        return None, None, None

    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for entry in metrics.get(key) or []:
            data = (entry or {}).get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            return float(score), (severity or "").upper() or None, label

    # CVSS v2 fallback — note baseSeverity sits on the entry here, not
    # inside cvssData as it does for v3.
    for entry in metrics.get("cvssMetricV2") or []:
        data = (entry or {}).get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        severity = entry.get("baseSeverity") or data.get("baseSeverity")
        return float(score), (severity or "").upper() or None, "2.0"

    return None, None, None


def _extract_description(cve: dict) -> str:
    """First English description, falling back to whatever language exists."""
    descriptions = cve.get("descriptions") or []
    for d in descriptions:
        if (d or {}).get("lang") == "en" and d.get("value"):
            return d["value"].strip()
    for d in descriptions:
        value = (d or {}).get("value")
        if value:
            return value.strip()
    return ""


def _extract_references(cve: dict) -> list:
    """
    Normalise the reference list to [{url, source, tags}].

    Tags are kept because remediation.py uses them to pick out the vendor
    advisory / patch link rather than the first mailing-list post in the list.
    """
    refs = []
    for ref in cve.get("references") or []:
        url = (ref or {}).get("url")
        if not url:
            continue
        refs.append({
            "url": url,
            "source": ref.get("source", ""),
            "tags": list(ref.get("tags") or []),
        })
    return refs


def _parse_cves(payload, product: str = "", version=None) -> list:
    """
    Turn an NVD 2.0 response body into this module's clean CVE dicts.

    The product/version that produced the match are stamped onto every CVE
    so a single CVE dict stands on its own downstream: severity.py and
    remediation.py can name the affected software, and database/db.py's
    findings row (service, version, cve_id, cvss, severity) can be filled
    without carrying the parent result around.

    Sorted worst-first so a caller that only shows the top few gets the
    ones that matter; unscored CVEs sort last.
    """
    cves = []
    for item in (payload or {}).get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue

        score, severity, cvss_version = _extract_metric(cve.get("metrics"))

        cves.append({
            "cve_id": cve_id,
            "product": product,
            "version": version,
            "description": _extract_description(cve),
            "cvss_score": score,
            "cvss_severity": severity,
            "cvss_version": cvss_version,
            "published_date": cve.get("published"),
            "references": _extract_references(cve),
        })

    cves.sort(key=lambda c: (c["cvss_score"] is None, -(c["cvss_score"] or 0.0)))
    return cves


def lookup_cves(product, version=None, target: str = "nvd",
                limit: int = _DEFAULT_LIMIT) -> dict:
    """
    Query the NVD REST API v2.0 for CVEs affecting `product` (+ `version`).

    Parameters
    ----------
    product : str   product name, e.g. "vsftpd" — service_detect's
                    `product` field, or a Server header value
    version : str   optional version string, e.g. "2.3.4"
    target  : str   scan target this lookup belongs to; only used to route
                    log lines into that target's scan_errors.log
    limit   : int   max CVEs to request (NVD resultsPerPage, 1-2000)

    Returns
    -------
    dict:
        product : str
        version : str | None
        cves    : list[dict]  {cve_id, product, version, description,
                               cvss_score, cvss_severity, cvss_version,
                               published_date,
                               references[{url, source, tags}]}
                              sorted highest CVSS first; product/version are
                              echoed onto each CVE so it stands alone
                              downstream
        source  : str         always "nvd"
        error   : str | None  human-readable failure reason, if any

    Never raises. A bad key, a rate limit, a network timeout or a malformed
    product string all come back as cves=[] with error set. A query that
    simply matched nothing returns cves=[] with error=None, so the caller
    can tell "nothing known" apart from "lookup broke".
    """
    log_tool_start(target, "nvd-cve-lookup")

    result = {
        "product": "" if product is None else str(product).strip(),
        "version": None if version is None else (str(version).strip() or None),
        "cves": [],
        "source": "nvd",
        "error": None,
    }

    invalid = _validate(product, version)
    if invalid:
        result["error"] = invalid
        log_tool_failure(target, "nvd-cve-lookup", invalid)
        print_warning(f"[CVE] skipping lookup: {invalid}")
        return result

    try:
        limit = max(1, min(int(limit), 2000))
    except (TypeError, ValueError):
        limit = _DEFAULT_LIMIT

    keyword = _build_keyword(product, version)
    print_info(f"[CVE] Querying NVD for '{keyword}'")

    if not NVD_API_KEY:
        # Not fatal — NVD serves anonymous clients at 5 req/30s, and
        # _MIN_INTERVAL has already adapted to that slower rate.
        print_warning("[CVE] no NVD API key configured; using the slower anonymous rate limit")

    attempt = 0
    while True:
        _throttle()

        # safe_call guarantees this never raises: on any request error it
        # returns {success: False, data: None, error: str} and logs it.
        outcome = safe_call(
            _request_nvd, keyword, limit,
            target=target, label="nvd-cve-lookup",
        )

        if not outcome.get("success"):
            # Network-level failure: DNS, TLS, connection refused, timeout.
            err = _sanitise(outcome.get("error") or "NVD request failed")
            if attempt < _MAX_RETRIES:
                attempt += 1
                delay = _RETRY_BASE_DELAY * attempt
                print_warning(f"[CVE] NVD request failed ({err}); retrying in {delay:.0f}s")
                time.sleep(delay)
                continue
            result["error"] = err
            log_tool_failure(target, "nvd-cve-lookup", f"{keyword} — {err}")
            print_error(f"[CVE] NVD lookup failed for '{keyword}': {err}")
            return result

        data = outcome.get("data") or {}
        status = data.get("status_code")

        if status == 200 and data.get("json") is not None:
            break

        if status == 200:
            err = "NVD returned a malformed (non-JSON) response"
        else:
            err = _status_error(status, data.get("text", ""))

        # Only throttling / transient server errors are worth retrying — a
        # 401 fails identically no matter how many times it is repeated.
        if status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            attempt += 1
            delay = _RETRY_BASE_DELAY * attempt
            print_warning(f"[CVE] {err}; backing off {delay:.0f}s before retry")
            time.sleep(delay)
            continue

        result["error"] = err
        log_tool_failure(target, "nvd-cve-lookup", f"{keyword} — {err}")
        print_error(f"[CVE] NVD lookup failed for '{keyword}': {err}")
        return result

    result["cves"] = _parse_cves(data.get("json"), result["product"], result["version"])
    log_tool_success(target, "nvd-cve-lookup")

    if not result["cves"]:
        print_warning(f"[CVE] no CVEs matched '{keyword}'")
        return result

    for c in result["cves"]:
        log_finding(target, {
            "type": "cve",
            "product": result["product"],
            "version": result["version"],
            "cve_id": c["cve_id"],
            "cvss": c["cvss_score"],
            "severity": c["cvss_severity"],
        })

    print_success(f"[CVE] {len(result['cves'])} CVE(s) matched '{keyword}'")
    for c in result["cves"]:
        score = c["cvss_score"] if c["cvss_score"] is not None else "n/a"
        sev = c["cvss_severity"] or "UNRATED"
        print_info(f"[CVE]   {c['cve_id']} — CVSS {score} ({sev})")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.enrichment.cve_lookup <product> [version]")
        sys.exit(1)

    prod = sys.argv[1]
    ver = sys.argv[2] if len(sys.argv) > 2 else None

    print_info(f"Looking up CVEs for {prod} {ver or ''}".strip())
    out = lookup_cves(prod, ver)
    for entry in out["cves"]:
        print_info(
            f"  {entry['cve_id']} | CVSS {entry['cvss_score']} "
            f"(v{entry['cvss_version']}) | {entry['cvss_severity']}"
        )
    print_info(f"Total: {len(out['cves'])} | Error: {out['error'] or 'none'}")
