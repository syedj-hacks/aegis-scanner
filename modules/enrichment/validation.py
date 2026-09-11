"""
modules/enrichment/validation.py
Lightweight active validation — the Confirmed-vs-Potential distinction.

THE PROBLEM PHASE 3 IS SOLVING
------------------------------
Most of what a CVE-matching scanner reports is a version-string inference:
"the Server header says Apache 2.4.25, and Apache 2.4.25 has CVE-2017-7679,
therefore this host has CVE-2017-7679." That inference is often right and
occasionally wrong — the version may be back-patched by the distro, the
banner may be spoofed, the vulnerable module may not be loaded. Reporting
all of it with the same confidence as a vulnerability the scanner actually
EXERCISED (a payload that reflected, an injection that returned data) is
exactly the false-positive noise that makes a report hard to act on.

So every finding carries a confidence:

  Confirmed  the scanner observed the vulnerable behaviour itself — a nuclei
             template matched, sqlmap extracted data, a header was provably
             absent, a bucket listed. Set by the plugin that made the
             observation (see plugins/*.py).

  Potential  the finding rests on a version/banner match and nothing was
             exercised. This is the default for CVE findings.

WHAT "ACTIVE VALIDATION" DOES HERE
----------------------------------
For a version-matched CVE on a live web service, one cheap, safe check can
corroborate (not prove) the version claim: re-read the service's own banner
and confirm it still advertises the version the CVE was matched against. It
does NOT send an exploit — that would be neither safe nor in scope for a
defensive scanner. A corroborated version stays Potential (a banner is
still a banner) but gains a validation note saying the version was
confirmed live, which is materially more than a one-shot header read; a
banner that no longer matches DOWNGRADES the finding's note to flag the
discrepancy, which is the false positive this is meant to catch.

Never raises: a validation probe that fails leaves the finding exactly as
it was (Potential, unvalidated) — validation can only add confidence, never
remove a finding.
"""

from __future__ import annotations

import requests
import urllib3

from modules.enrichment.cve_lookup import _parse_banner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 8.0
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AegisScanner/1.0"

# Findings whose type already means "we observed it happen". These are
# Confirmed by construction and validation leaves them alone.
_OBSERVED_TYPES = {
    "sqlmap_finding", "xss_finding", "nuclei_finding", "zap_finding",
    "missing_security_header", "discovered_path", "recon_bucket",
    "recon_leak", "weak_credentials", "smb_share", "smb_user",
    "sslyze_finding", "nikto_finding", "banner",
}

# Findings that are pure version/banner inference — Potential unless a live
# probe corroborates the version.
_VERSION_MATCHED_TYPES = {"cve", "service_version", "fingerprint_header",
                          "technology_fingerprint"}


def _server_banner(host: str, port: int, use_https: bool) -> str:
    """Re-read the Server header from a web service. '' on any failure."""
    scheme = "https" if use_https else "http"
    default = 443 if use_https else 80
    netloc = host if port == default else f"{host}:{port}"
    try:
        resp = requests.get(f"{scheme}://{netloc}", timeout=_TIMEOUT,
                            headers={"User-Agent": _USER_AGENT},
                            verify=False, allow_redirects=True)
        return resp.headers.get("Server", "") or ""
    except Exception:  # noqa: BLE001 — a failed probe just means "not validated"
        return ""


def classify_confidence(finding) -> str:
    """
    The confidence a finding should carry from its TYPE alone, before any
    active probe. Confirmed for observed behaviours, Potential for
    version/banner inferences, Potential as the conservative default for
    anything unrecognised (over-claiming confidence is the failure mode to
    avoid).
    """
    ftype = _ftype(finding)
    if ftype in _OBSERVED_TYPES:
        return "Confirmed"
    return "Potential"


def _ftype(finding):
    if isinstance(finding, dict):
        return finding.get("finding_type") or finding.get("type") or ""
    return getattr(finding, "finding_type", "") or ""


def _get(finding, key, default=None):
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _set(finding, key, value):
    if isinstance(finding, dict):
        finding[key] = value
    else:
        setattr(finding, key, value)


def actively_validate(finding, host: str, allow_network: bool = True) -> str:
    """
    Try to corroborate a version-matched finding with a live banner re-read.

    Returns a short validation note (also stored on the finding). Only
    version-matched web findings with a known port and version are probed;
    everything else returns "" and is untouched. This is the "confirm a
    banner-matched CVE by checking an actual response characteristic" step —
    cheap, safe, and honest about what it does and does not prove.
    """
    ftype = _ftype(finding)
    if ftype not in _VERSION_MATCHED_TYPES:
        return ""

    version = _get(finding, "version")
    port = _get(finding, "port")
    if not (allow_network and version and port):
        return ""

    # Only web ports have a Server header to re-read.
    use_https = port in (443, 8443)
    if port not in (80, 443, 8080, 8443, 8081, 8082, 8000, 8888):
        return ""

    banner = _server_banner(host, port, use_https)
    if not banner:
        return ""

    _prod, banner_version = _parse_banner(banner)
    note = ""
    if banner_version and str(version) in banner:
        note = f"version {version} corroborated live via Server banner ({banner})"
    elif banner_version:
        note = (f"version discrepancy: matched on {version} but live banner "
                f"reports {banner_version} ({banner}) — treat as unconfirmed")
    if note:
        _set(finding, "validation", note)
    return note
