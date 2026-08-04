"""
modules/recon/cert_transparency.py
Certificate Transparency subdomain discovery via crt.sh.

Why this sits alongside subdomain.py rather than inside it
----------------------------------------------------------
subdomain.py shells out to subfinder and amass. Both are excellent and both
are optional binaries that a fresh Kali box may or may not have, and amass
in passive mode is slow enough to have its own 600s budget. crt.sh is a
plain HTTPS GET against a public database of every certificate a public CA
has issued, needs no binary and no API key, and returns in seconds.

It also finds a genuinely different set of names. subfinder/amass aggregate
public sources and DNS; CT logs contain every hostname anyone ever put in a
certificate, including internal-sounding names on hosts that were never
meant to be public and that resolve nowhere — staging.internal.example.com,
vpn-old.example.com. Those are frequently the interesting ones, and they are
exactly what a DNS-based enumerator cannot see.

What comes back is unverified
-----------------------------
A name in a CT log proves a certificate was issued for it, not that a host
answers on it today. The recon profile records these as LOW-severity
`recon_subdomain` findings for that reason: a lead to check, not a finding
that something is exposed. Nothing here resolves or connects to anything.
"""

import time

import requests

from modules.utils.error_handler import safe_call, is_user_skip
from modules.utils.logger import get_logger, log_finding
from modules.utils.display import print_info, print_success, print_warning

CRTSH_URL = "https://crt.sh/"

# crt.sh is a single volunteer-run service that is frequently slow and
# periodically down; it is the one dependency of this module and it is
# nobody's SLA. Measured while writing this module: three consecutive
# requests for example.com returned 502 Bad Gateway, which is crt.sh's
# ordinary overload behaviour rather than anything about the query.
#
# So a single attempt is retried a couple of times with a short backoff —
# a 502 here usually is transient — and after that the failure is reported
# as a failure. What this module must never do is return an empty subdomain
# list when the service was unreachable: "crt.sh is down" and "this domain
# has no certificates" would then be indistinguishable, and a recon report
# would quietly under-state a target's attack surface. The recon profile
# runs subfinder/amass alongside this for the same reason.
_TIMEOUT = 30
_ATTEMPTS = 3
_BACKOFF_SECONDS = 3

# crt.sh returns the certificate's name_value field, which holds one or more
# newline-separated names, and for a wildcard cert those names start "*.".
# The leading label is stripped so "*.example.com" becomes "example.com"
# rather than an entry no tool downstream could use.
_WILDCARD_PREFIX = "*."


def _clean_names(entries, domain: str) -> list:
    """
    Flatten crt.sh's JSON into a sorted, deduplicated hostname list.

    Only names that actually sit under `domain` are kept. crt.sh matches on
    the certificate's whole name set, so a certificate covering both
    example.com and an unrelated co-hosted domain would otherwise contribute
    the unrelated one to this target's results — attributing someone else's
    hostname to the scan target.
    """
    suffix = "." + domain.lower().lstrip(".")
    seen = set()

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value") or "").splitlines():
            name = raw.strip().lower().rstrip(".")
            if name.startswith(_WILDCARD_PREFIX):
                name = name[len(_WILDCARD_PREFIX):]
            if not name:
                continue
            # Endswith on a dot-prefixed suffix, not a substring test: a
            # substring test would accept "example.com.attacker.net".
            if name == domain.lower() or name.endswith(suffix):
                seen.add(name)

    return sorted(seen)


def find_subdomains_crtsh(domain: str, target: str = None) -> dict:
    """
    Query crt.sh's certificate transparency database for `domain`.

    Returns
    -------
    dict:
        tool        : "crtsh"
        target      : str
        subdomains  : list[str]  sorted, deduplicated, all under `domain`
        count       : int
        source      : "crt.sh"
        skipped     : bool       True when the user skipped it (Ctrl+C)
        error       : str | None

    Never raises. The result dict carries the same tool/skipped/error keys
    every run_tool()-based wrapper returns, so the profile orchestrators'
    stats loop and persist_tool_run() count this like any other tool — the
    convention that stops a failure here from being invisible.
    """
    target = target or domain
    logger = get_logger(target)

    result = {
        "tool": "crtsh",
        "target": target,
        "subdomains": [],
        "count": 0,
        "source": "crt.sh",
        "skipped": False,
        "error": None,
    }

    if not domain:
        result["error"] = "no domain given — crt.sh needs a domain name"
        return result

    def _fetch():
        last_error = None
        for attempt in range(1, _ATTEMPTS + 1):
            try:
                response = requests.get(
                    CRTSH_URL,
                    params={"q": f"%.{domain}", "output": "json"},
                    timeout=_TIMEOUT,
                    headers={"User-Agent": "AegisScanner/1.0"},
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                last_error = exc
                if attempt < _ATTEMPTS:
                    logger.warning(
                        f"[crt.sh] attempt {attempt}/{_ATTEMPTS} failed ({exc}) "
                        f"— retrying in {_BACKOFF_SECONDS}s"
                    )
                    time.sleep(_BACKOFF_SECONDS)
        raise last_error

    print_info(f"[crt.sh] querying certificate transparency logs for {domain}...")
    call = safe_call(_fetch, target=target, label="crt.sh")

    if not call.get("success"):
        # safe_call() distinguishes a user interrupt from a real failure by
        # the reason string it returns; is_user_skip() is the project's test
        # for that, and honouring it here is what keeps a skipped crt.sh
        # from being counted and reported as a failed one.
        reason = call.get("error") or "crt.sh unreachable"
        result["error"] = reason
        result["skipped"] = is_user_skip(reason)
        if result["skipped"]:
            print_warning("[crt.sh] skipped by user")
        else:
            logger.error(f"[crt.sh] lookup failed for {domain}: {reason}")
            print_warning(f"[crt.sh] lookup failed for {domain}: {reason}")
        return result

    data = call.get("data")
    if not isinstance(data, list):
        # crt.sh answers an overloaded query with an HTML error page and a
        # 200, so a successful request is not a successful lookup. Reported
        # as a failure rather than as zero subdomains: "the service did not
        # answer" and "this domain has no certificates" are different facts
        # and must not render the same way.
        result["error"] = "crt.sh returned an unexpected response (not a JSON list)"
        logger.error(f"[crt.sh] {result['error']} for {domain}")
        print_warning(f"[crt.sh] {result['error']}")
        return result

    result["subdomains"] = _clean_names(data, domain)
    result["count"] = len(result["subdomains"])

    for name in result["subdomains"]:
        log_finding(target, {"type": "recon_subdomain", "value": name, "source": "crt.sh"})

    print_success(
        f"[crt.sh] {result['count']} unique name(s) in certificate transparency "
        f"logs for {domain}"
    )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_warning("Usage: python -m modules.recon.cert_transparency <domain>")
        sys.exit(1)

    out = find_subdomains_crtsh(sys.argv[1])
    for sub in out["subdomains"]:
        print_info(sub)
    print_info(f"{out['count']} name(s); error={out['error']}")
