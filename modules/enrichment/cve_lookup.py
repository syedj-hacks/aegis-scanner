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

import re
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


# ---------------------------------------------------------------------
# Product disambiguation
# ---------------------------------------------------------------------
# A bare banner token like "Apache" is genuinely ambiguous — NVD's
# keywordSearch is a plain AND-of-words match, and "Apache" alone is a
# substring of descriptions for Apache HTTP Server, Apache Tomcat, Apache
# Struts, Apache Groovy, Apache ActiveMQ and dozens of other unrelated
# Apache Software Foundation projects. A real scan hit this: an
# "Apache/2.4.7" Server header returned CVE-2016-6814 (an Apache Groovy
# RCE) as a top match — wrong product entirely, just the same vendor name.
#
# Each alias maps a banner token (lower-cased) to:
#   keyword       : a more specific NVD keywordSearch phrase to send instead
#                   of the bare token, biasing the free-text match toward
#                   the right product
#   cpe_products  : the CPE 2.3 "product" component(s) (the 5th ':'-field
#                   in cpe:2.3:a:vendor:PRODUCT:version:...) that count as
#                   a genuine match — checked in _cve_matches_product()
#                   below against the CVE's own configurations/CPE data, a
#                   much stronger signal than the free-text keyword search
#                   alone since NVD assigns CPEs deliberately per-product.
_PRODUCT_ALIASES = {
    "apache": {"keyword": "apache http server", "cpe_products": {"http_server"}},
    "nginx": {"keyword": "nginx", "cpe_products": {"nginx"}},
    "iis": {"keyword": "internet information services", "cpe_products": {"internet_information_services", "internet_information_server"}},
    "microsoft-iis": {"keyword": "internet information services", "cpe_products": {"internet_information_services", "internet_information_server"}},
    "tomcat": {"keyword": "apache tomcat", "cpe_products": {"tomcat"}},
    "openssh": {"keyword": "openssh", "cpe_products": {"openssh"}},
    "vsftpd": {"keyword": "vsftpd", "cpe_products": {"vsftpd"}},
    "proftpd": {"keyword": "proftpd", "cpe_products": {"proftpd"}},
    "mysql": {"keyword": "mysql", "cpe_products": {"mysql"}},
    "postgresql": {"keyword": "postgresql", "cpe_products": {"postgresql"}},
    "lighttpd": {"keyword": "lighttpd", "cpe_products": {"lighttpd"}},
}


def _disambiguate_product(product) -> tuple:
    """
    Look up a raw product token against _PRODUCT_ALIASES.

    Returns (keyword_product, cpe_products) where keyword_product is what
    should be sent to NVD's keywordSearch (the alias's more specific phrase,
    or the original token when there's no alias) and cpe_products is the
    set of acceptable CPE product components to verify results against, or
    None when this product has no known alias (in which case results are
    not CPE-filtered — see _cve_matches_product()).
    """
    key = str(product or "").strip().lower()
    alias = _PRODUCT_ALIASES.get(key)
    if not alias:
        return product, None
    return alias["keyword"], alias["cpe_products"]


def _extract_cpe_products(cve: dict) -> set:
    """
    Pull every CPE 2.3 "product" component NVD attached to this CVE's
    vulnerable configurations (cpe:2.3:PART:VENDOR:PRODUCT:VERSION:...).
    Returns a lower-cased set; empty when the CVE carries no CPE data (some
    very new or very old entries don't) — callers must treat "no data" as
    "cannot verify", not "does not match".
    """
    products = set()
    for node in (cve.get("configurations") or []):
        for inner in (node.get("nodes") or []):
            for match in (inner.get("cpeMatch") or []):
                criteria = match.get("criteria") or ""
                fields = criteria.split(":")
                # cpe:2.3:part:vendor:product:version:... -> index 4
                if len(fields) > 4 and fields[4]:
                    products.add(fields[4].lower())
    return products


def _cve_matches_product(cve: dict, cpe_products) -> bool:
    """
    True when this CVE should be kept for a disambiguated product query.

    cpe_products is None for products with no known alias — those are
    never filtered (best-effort keyword search remains the only signal, as
    before). For an aliased product, the CVE is kept if either its CPE data
    intersects the expected product set, or it has no CPE data at all (NVD
    entries without configurations are rare but exist; dropping them would
    trade one accuracy problem for another). It is only dropped when NVD
    *does* attach CPE data and none of it matches — the strongest possible
    signal that the keyword hit was a same-vendor, wrong-product false
    positive like the Apache httpd/Groovy case this was built for.
    """
    if cpe_products is None:
        return True
    cve_products = _extract_cpe_products(cve)
    if not cve_products:
        return True
    return bool(cve_products & cpe_products)


# ---------------------------------------------------------------------
# Version-range filtering
# ---------------------------------------------------------------------
# The product filter above answers "is this a CVE for the right software?"
# but says nothing about "does the DETECTED version actually fall in the
# vulnerable range?". Without that second check, NVD's keywordSearch (a
# plain AND-of-words match) reports a CVE described "before 10.3" against a
# host running exactly 10.3 — the *fixed* release — because the string
# "10.3" appears in the description. This was found live: an OpenSSH 10.3
# host was credited with five "before 10.3" CVEs, and an Apache 2.4.25 host
# with two CVEs fixed in 2.4.25. The CVEs are real; they simply don't apply
# to the version detected.
#
# The rule below drops a CVE ONLY when the detected version is *definitively*
# outside every vulnerable CPE range NVD attached for the accepted product.
# Anything it cannot prove out-of-range — no CPE data, a version wildcard, or
# a detected version too imprecise to compare (e.g. a bare "4" against a
# "before 4.1.22" bound) — is kept, on the same "cannot verify != does not
# match" principle as _cve_matches_product(). It therefore never trades a
# false positive for a false negative on an ambiguous version.

def _version_tuple(v) -> tuple:
    """
    Parse a version string into a comparable tuple of (int, str) components.

    "2.4.25" -> ((2,''),(4,''),(25,'')); "6.6.1p1" -> ((6,''),(6,''),(1,'p1')).
    Splits on the usual separators, and within a component peels a leading
    integer off any alpha suffix so "1f"/"1p1" sort after "1". Returns () for
    anything without a leading numeric token (unparseable -> caller treats as
    "cannot compare").
    """
    token = str(v or "").strip().split()[0] if str(v or "").strip() else ""
    if not token:
        return ()
    parts = []
    for comp in re.split(r"[._\-+~:]", token):
        if not comp:
            continue
        m = re.match(r"^(\d+)([A-Za-z].*)?$", comp)
        if m:
            parts.append((int(m.group(1)), (m.group(2) or "").lower()))
        else:
            parts.append((-1, comp.lower()))
    # Reject a token that produced no numeric-led component at all.
    return tuple(parts) if any(p[0] >= 0 for p in parts) else ()


def _version_cmp(a: tuple, b: tuple):
    """
    Compare two _version_tuple()s. Returns -1/0/1, or **None** when one is a
    proper prefix of the other with equal shared components — i.e. the
    comparison is genuinely ambiguous ("4" vs "4.1.22" could be 4.0 or 4.9).
    Ambiguity is never used as a reason to drop a CVE.
    """
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] < b[i]:
            return -1
        if a[i] > b[i]:
            return 1
    if len(a) == len(b):
        return 0
    return None


def _cpe_covers_version(match: dict, dv: tuple):
    """
    For one vulnerable cpeMatch, is version `dv` inside it?
    True = covered, False = definitively outside, None = cannot determine.
    """
    start_incl = match.get("versionStartIncluding")
    start_excl = match.get("versionStartExcluding")
    end_incl = match.get("versionEndIncluding")
    end_excl = match.get("versionEndExcluding")

    fields = (match.get("criteria") or "").split(":")
    explicit = fields[5] if len(fields) > 5 else "*"

    if not any((start_incl, start_excl, end_incl, end_excl)):
        # No range bounds: the CPE names either a single version or a wildcard.
        if explicit in ("*", "-", ""):
            return True  # applies to all versions of the product
        c = _version_cmp(dv, _version_tuple(explicit))
        if c is None:
            return None
        return c == 0

    for bound, op in ((end_excl, "lt"), (end_incl, "le"),
                      (start_incl, "ge"), (start_excl, "gt")):
        if not bound:
            continue
        bt = _version_tuple(bound)
        if not bt:
            continue
        c = _version_cmp(dv, bt)
        if c is None:
            return None  # too imprecise to place against this bound
        if op == "lt" and c >= 0:   # dv >= versionEndExcluding
            return False
        if op == "le" and c > 0:    # dv >  versionEndIncluding
            return False
        if op == "ge" and c < 0:    # dv <  versionStartIncluding
            return False
        if op == "gt" and c <= 0:   # dv <= versionStartExcluding
            return False
    return True


def _cve_version_applicable(cve: dict, dv: tuple, cpe_products) -> bool:
    """
    Keep this CVE for detected version `dv`? True unless every vulnerable CPE
    NVD attached for the accepted product is *definitively* outside `dv`'s
    range. No product CPE data, or any ambiguous/covering CPE, keeps it.
    """
    saw_product_cpe = False
    for node in (cve.get("configurations") or []):
        for inner in (node.get("nodes") or []):
            for match in (inner.get("cpeMatch") or []):
                if not match.get("vulnerable", False):
                    continue
                fields = (match.get("criteria") or "").split(":")
                prod = fields[4].lower() if len(fields) > 4 else ""
                if cpe_products is not None and prod not in cpe_products:
                    continue
                saw_product_cpe = True
                covers = _cpe_covers_version(match, dv)
                if covers is None or covers is True:
                    return True
    if not saw_product_cpe:
        return True  # no CPE data to judge against -> cannot verify -> keep
    return False


_BANNER_TOKEN_RE = re.compile(r"^([A-Za-z][\w.+-]*)/([\w.+-]+)$")
_VERSION_LIKE_RE = re.compile(r"^\d")


def _parse_banner(banner) -> tuple:
    """
    Split a raw Server/X-Powered-By banner into (product, version).

    Server headers commonly follow "Product/Version" (Apache/2.4.7,
    nginx/1.18.0, Tengine/2.3.3), sometimes with trailing comment tokens
    ("Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1f"). Querying NVD with the whole
    raw string as one keyword blob rarely matches anything, since
    keywordSearch is a plain AND-of-words match and a slash-joined value or
    a parenthetical is not a word any CVE description contains. Only the
    first token is used, split on its own "/"; a second half that doesn't
    look like a version (doesn't start with a digit) is dropped rather than
    sent to NVD as a bogus version filter — some WAFs/CDNs return an
    obfuscated Server value (e.g. "Tengine/Aserver") specifically to defeat
    banner-based fingerprinting, and "Tengine" alone still stands a chance
    of matching real CVEs where "Tengine/Aserver" never will.
    """
    text = str(banner or "").strip()
    if not text:
        return text, None

    first_token = text.split()[0]
    match = _BANNER_TOKEN_RE.match(first_token)
    if not match:
        return text, None

    product, version = match.group(1), match.group(2)
    return (product, version) if _VERSION_LIKE_RE.match(version) else (product, None)


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


def _parse_cves(payload, product: str = "", version=None, cpe_products=None) -> list:
    """
    Turn an NVD 2.0 response body into this module's clean CVE dicts.

    The product/version that produced the match are stamped onto every CVE
    so a single CVE dict stands on its own downstream: severity.py and
    remediation.py can name the affected software, and database/db.py's
    findings row (service, version, cve_id, cvss, severity) can be filled
    without carrying the parent result around.

    cpe_products, when given (a disambiguated product — see
    _disambiguate_product()), drops any CVE whose own CPE configuration
    data names a different product entirely (_cve_matches_product()) — the
    keywordSearch endpoint alone cannot tell "Apache HTTP Server" apart
    from "Apache Groovy" beyond both containing the word "Apache".

    Sorted worst-first so a caller that only shows the top few gets the
    ones that matter; unscored CVEs sort last.
    """
    cves = []
    dropped = 0
    dropped_version = 0
    dv = _version_tuple(version) if version is not None else ()
    for item in (payload or {}).get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue

        if not _cve_matches_product(cve, cpe_products):
            dropped += 1
            continue

        # Version-range gate: drop a CVE only when the detected version is
        # provably outside every vulnerable CPE range (see _cve_version_
        # applicable). Skipped entirely when no version was detected.
        if dv and not _cve_version_applicable(cve, dv, cpe_products):
            dropped_version += 1
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
    if dropped:
        print_warning(
            f"[CVE] filtered {dropped} CVE(s) whose CPE data names a different "
            f"product than '{product}' (same-vendor false-positive guard)"
        )
    if dropped_version:
        print_warning(
            f"[CVE] filtered {dropped_version} CVE(s) whose vulnerable version "
            f"range does not include '{version}' (version-range guard)"
        )
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

    # A bare vendor-ish token ("Apache") is disambiguated to a more specific
    # keyword phrase ("apache http server") when a known alias exists, and
    # its acceptable CPE product set is carried through to _parse_cves() so
    # a same-vendor, wrong-product hit (e.g. Apache Groovy for an Apache
    # httpd banner) gets filtered out rather than reported as a real match.
    keyword_product, cpe_products = _disambiguate_product(product)
    keyword = _build_keyword(keyword_product, version)
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

    result["cves"] = _parse_cves(data.get("json"), result["product"], result["version"], cpe_products)
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


def lookup_cves_from_banner(banner, target: str = "nvd", limit: int = _DEFAULT_LIMIT) -> dict:
    """
    Convenience wrapper for callers holding a raw Server/X-Powered-By header
    value (header_check.py's server_banner/powered_by) rather than an
    already-split product/version pair. Splits the banner via _parse_banner()
    (see its docstring) then delegates to lookup_cves() — same return shape.
    """
    product, version = _parse_banner(banner)
    return lookup_cves(product, version, target=target, limit=limit)


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
