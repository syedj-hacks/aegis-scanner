"""
modules/web/header_check.py
HTTP security-header audit for Aegis Scanner (Member C - web layer).

Fetches the HTTP response headers from a target's web service and reports
which recommended security headers are missing, plus the raw Server /
X-Powered-By values (which modules/enrichment/cve_lookup.py uses for
version-based CVE correlation).

This module does NOT go through run_tool() because it is not a subprocess
call — it is a direct HTTP request via `requests`. To keep the "never
raises" contract the rest of the framework relies on, the request is
wrapped in error_handler.safe_call(), so a refused connection / DNS
failure / TLS error / timeout becomes a structured result instead of an
exception (same approach as modules/scanning/banner.py).
"""

import requests
import urllib3

from modules.utils.error_handler import safe_call, is_user_skip
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_tool_skip, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Test targets are routinely self-signed; a cert warning per request would
# flood the Rich console and tells us nothing we act on.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Seconds to wait for connect + response. Kept as a module constant rather
# than config.get_timeout() because TOOL_TIMEOUTS is scoped to subprocess
# tools; a single HTTP GET should never take minutes.
_REQUEST_TIMEOUT = 10.0

# Sent so servers that vary their response by client don't hand us a
# stripped-down error page with different headers than a real browser gets.
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AegisScanner/1.0"

# Security headers we expect a hardened site to set. Order is the order
# they are reported in.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
]

# Headers that leak software/version info — captured verbatim for
# fingerprinting and downstream CVE lookups.
_FINGERPRINT_HEADERS = ["Server", "X-Powered-By"]


def _build_url(target: str, port: int, use_https: bool) -> str:
    """
    Compose the request URL. If the caller already passed a full URL we
    respect it as-is rather than mangling it into http://http://...
    """
    if target.startswith(("http://", "https://")):
        return target

    scheme = "https" if use_https else "http"
    # Omit the default port for tidier output/log lines.
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _fetch_headers(url: str) -> dict:
    """
    Perform the actual HTTP request and return the response headers as a
    plain dict. May raise (ConnectionError, Timeout, TooManyRedirects,
    SSLError...) — callers MUST invoke this through safe_call() so those
    exceptions are captured instead of propagating.

    A GET is used rather than HEAD because a fair number of servers and
    WAFs handle HEAD differently (or reject it outright), which would give
    a misleading header set.
    """
    response = requests.get(
        url,
        timeout=_REQUEST_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
        verify=False,          # self-signed certs are expected on test targets
        allow_redirects=True,
    )
    return {
        "status_code": response.status_code,
        "final_url": response.url,
        # requests' CaseInsensitiveDict -> plain dict for safe serialisation
        "headers": dict(response.headers),
    }


def _lookup(headers: dict, name: str):
    """Case-insensitive header lookup; returns the value or None."""
    target_key = name.lower()
    for key, value in headers.items():
        if key.lower() == target_key:
            return value
    return None


def check_headers(target: str, port: int = 80, use_https: bool = False) -> dict:
    """
    Fetch `target`'s HTTP response headers and audit them for missing
    security headers.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  request over TLS instead of plaintext

    Returns
    -------
    dict:
        target          : str
        port            : int
        missing_headers : list[str]   security headers NOT set by the server
        present_headers : dict        {header: value} for the security
                                      headers that ARE set
        server_banner   : str | None  raw Server header value, verbatim
        powered_by      : str | None  raw X-Powered-By header value, verbatim
        error           : str | None  human-readable failure reason, if any

    On failure (host unreachable, port closed, TLS error) the dict comes
    back with error set and missing_headers left empty — a dead host must
    never be reported as a badly-configured one.
    """
    log_tool_start(target, "header_check")

    result = {
        "tool": "header_check",
        "target": target,
        "port": port,
        "missing_headers": [],
        "present_headers": {},
        "server_banner": None,
        "powered_by": None,
        "error": None,
        # Required by every profile's failure count: a result carrying an
        # error but not marked skipped is reported as a FAILED tool. This
        # module drives requests via safe_call() rather than run_tool(), so
        # it has to set the flag itself — see the assignment below.
        "skipped": False,
    }

    url = _build_url(target, port, use_https)
    print_info(f"[Headers] Fetching response headers from {url}")

    # safe_call guarantees this never raises: on any request error it
    # returns {success: False, data: None, error: str} and logs it.
    outcome = safe_call(
        _fetch_headers, url,
        target=target, label="header_check",
    )

    if not outcome.get("success"):
        err = outcome.get("error") or "request failed"
        result["error"] = err

        if is_user_skip(err):
            # A deliberate Ctrl+C, not a failure. Without this the profiles
            # counted — and, since the failure-reporting change, printed —
            # the user's own skip as a tool failure.
            result["skipped"] = True
            log_tool_skip(target, "header_check")
            print_warning(f"[Headers] {url} skipped by user")
            return result

        # safe_call already logged via log_tool_failure; this line records
        # the target/port context the generic wrapper doesn't know about.
        log_tool_failure(target, "header_check", f"{url} — {err}")
        print_error(f"[Headers] {url} unreachable: {err}")
        return result

    data = outcome.get("data") or {}
    headers = data.get("headers", {})
    status_code = data.get("status_code")

    # --- Fingerprinting headers, captured verbatim ---
    result["server_banner"] = _lookup(headers, "Server")
    result["powered_by"] = _lookup(headers, "X-Powered-By")

    # --- Security header audit ---
    for name in SECURITY_HEADERS:
        value = _lookup(headers, name)
        if value is None:
            result["missing_headers"].append(name)
        else:
            result["present_headers"][name] = value

    print_success(f"[Headers] {url} responded {status_code}")

    for name, value in result["present_headers"].items():
        print_success(f"[Headers] present: {name}: {value}")

    for name in result["missing_headers"]:
        log_finding(target, {
            "type": "missing_security_header",
            "port": port,
            "header": name,
            "severity": "MEDIUM",
        })
        print_warning(f"[Headers] missing: {name}")

    for name in _FINGERPRINT_HEADERS:
        value = _lookup(headers, name)
        if value:
            log_finding(target, {
                "type": "fingerprint_header",
                "port": port,
                "header": name,
                "value": value,
            })
            print_info(f"[Headers] fingerprint: {name}: {value}")

    log_tool_success(target, "header_check")
    print_info(
        f"[Headers] {target}:{port} — {len(result['missing_headers'])} missing, "
        f"{len(result['present_headers'])} present"
    )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.header_check <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Checking security headers on {tgt}:{prt} (https={https})...")
    out = check_headers(tgt, port=prt, use_https=https)
    print_info(f"Server: {out['server_banner'] or '(none)'}")
    print_info(f"X-Powered-By: {out['powered_by'] or '(none)'}")
    print_info(f"Missing: {out['missing_headers']}")
    print_info(f"Error: {out['error'] or 'none'}")
