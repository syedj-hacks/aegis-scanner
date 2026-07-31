"""
modules/web/wpscan_wrap.py
WPScan WordPress vulnerability scanner wrapper for Aegis Scanner (web
layer).

This is the wrapper config.CONDITIONAL_TOOLS has pointed "wpscan" at since
before it existed: gobuster_wrap.run_gobuster() sets
`wordpress_fingerprinted` when it finds a /wp-* marker path, and
modules/profiles/deepscan.py's conditional-tool dispatch calls this module
once that flag is True.

Runs `wpscan` through error_handler.run_tool() requesting JSON output and
parses vulnerabilities out of the core/plugins/themes sections.
"""

import json

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# --no-banner        : skip the ASCII banner (keeps stdout to the JSON)
# --random-user-agent: avoid a static UA getting blocked by a WAF
# --format json       : machine-parseable output on stdout
_WPSCAN_BASE_ARGS = ["--no-banner", "--random-user-agent", "--format", "json"]


def _build_url(target: str, port: int, use_https: bool) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


# Severity floor for wpscan output that is NOT a CVE/vuln match: an
# identified version, an enumerated plugin/theme, or an "interesting finding"
# (xmlrpc/readme/wp-cron exposure, ...). These are real, tool-reported
# evidence — just informational, not a known-vulnerable match — so they are
# graded LOW rather than dropped. Without a WPScan API token the
# `vulnerabilities` arrays are always empty, so before this the wrapper
# reported nothing at all on a WordPress site it had genuinely fingerprinted.
_INFO_SEVERITY = "LOW"

# A WordPress core whose own reported status is one of these is out of date:
# graded MEDIUM (a known-outdated CMS is a real, actionable finding) even
# though no specific CVE match came back without an API token.
_OUTDATED_STATUSES = ("outdated", "insecure")

# The generic "headers" interesting-finding entry carries no detail beyond
# the word "Headers" (header_check/ZAP already report the actual headers),
# so it is dropped rather than reported as evidence-free noise.
_SKIP_INTERESTING_TYPES = ("headers",)


def _vulns_from_section(section: dict) -> list:
    """Extract {title, references} from one section's `vulnerabilities` list."""
    out = []
    for vuln in (section or {}).get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        refs = vuln.get("references") or {}
        urls = []
        for ref_list in refs.values() if isinstance(refs, dict) else []:
            if isinstance(ref_list, list):
                urls.extend(str(u) for u in ref_list)
        out.append({
            "title": vuln.get("title") or "unnamed vulnerability",
            "reference": urls[0] if urls else "",
        })
    return out


def _first_reference_url(refs) -> str:
    """First URL out of an interesting-finding's `references` dict, else ""."""
    if not isinstance(refs, dict):
        return ""
    for ref_list in refs.values():
        if isinstance(ref_list, list) and ref_list:
            return str(ref_list[0])
        if isinstance(ref_list, str) and ref_list:
            return ref_list
    return ""


def _parse_wpscan_json(raw_json: str) -> list:
    """
    Parse wpscan's JSON report into a list of:
        {component: str, title: str, reference: str, severity: str}

    Two classes of output are surfaced, not just the first:

      1. Known-vulnerability matches (the `vulnerabilities` arrays under the
         core version block and every plugin/theme) — graded HIGH. These are
         only ever populated when a WPScan API token is configured.

      2. Real enumeration evidence that carries no CVE match: the identified
         WordPress version, each enumerated plugin/theme (with version), and
         wpscan's own "interesting findings" (xmlrpc enabled, readme.html /
         version disclosure, external wp-cron, exposed robots.txt, ...) —
         graded LOW, or MEDIUM for a core whose reported status is outdated.

    Before (2) was added, a token-less run against a genuine WordPress site
    parsed zero findings and reported "no known vulnerabilities", discarding
    everything wpscan had actually discovered. Any missing/renamed key yields
    fewer findings, never an exception.
    """
    findings = []

    try:
        data = json.loads(raw_json) if raw_json else {}
    except (json.JSONDecodeError, TypeError):
        return findings

    if not isinstance(data, dict):
        return findings

    # --- (1) known-vulnerability matches (HIGH) ---------------------------
    version_block = data.get("version") or {}
    for vuln in _vulns_from_section(version_block):
        findings.append({"component": "WordPress core", "severity": "HIGH", **vuln})

    for section_name in ("plugins", "themes"):
        section = data.get(section_name) or {}
        if not isinstance(section, dict):
            continue
        for name, entry in section.items():
            for vuln in _vulns_from_section(entry if isinstance(entry, dict) else {}):
                findings.append({
                    "component": f"{section_name[:-1]}: {name}",
                    "severity": "HIGH", **vuln,
                })

    # --- (2) enumeration evidence with no CVE match -----------------------
    number = version_block.get("number")
    if number:
        status = str(version_block.get("status") or "").lower()
        if status in _OUTDATED_STATUSES:
            findings.append({
                "component": "WordPress core",
                "title": f"WordPress {number} is {status}",
                "reference": "",
                "severity": "MEDIUM",
            })
        else:
            status_note = f" (status: {status})" if status else ""
            findings.append({
                "component": "WordPress core",
                "title": f"WordPress {number} identified{status_note}",
                "reference": "",
                "severity": _INFO_SEVERITY,
            })

    for finding in data.get("interesting_findings") or []:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("type") or "").lower() in _SKIP_INTERESTING_TYPES:
            continue
        title = str(finding.get("to_s") or finding.get("type") or "").strip()
        if not title:
            continue
        findings.append({
            "component": "WordPress",
            "title": title,
            "reference": _first_reference_url(finding.get("references")),
            "severity": _INFO_SEVERITY,
        })

    # Enumerated theme(s) and plugins that had no vuln match still confirm a
    # real, versioned component was found on the host.
    main_theme = data.get("main_theme") or {}
    theme_slug = main_theme.get("slug")
    if theme_slug and not (main_theme.get("vulnerabilities") or []):
        theme_ver = (main_theme.get("version") or {}).get("number")
        findings.append({
            "component": f"theme: {theme_slug}",
            "title": f"Theme '{theme_slug}'"
                     + (f" v{theme_ver}" if theme_ver else "") + " enumerated",
            "reference": "",
            "severity": _INFO_SEVERITY,
        })

    plugins = data.get("plugins") or {}
    if isinstance(plugins, dict):
        for name, entry in plugins.items():
            if name == "*" or not isinstance(entry, dict):
                continue
            if entry.get("vulnerabilities") or []:
                continue  # already reported as a HIGH vuln above
            plugin_ver = (entry.get("version") or {}).get("number")
            findings.append({
                "component": f"plugin: {name}",
                "title": f"Plugin '{name}'"
                         + (f" v{plugin_ver}" if plugin_ver else "") + " enumerated",
                "reference": "",
                "severity": _INFO_SEVERITY,
            })

    return findings


def run_wpscan(target: str, port: int = 80, use_https: bool = False,
               api_token: str = None) -> dict:
    """
    Scan a fingerprinted WordPress install on `target` with wpscan.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS
    api_token : str   optional WPVulnDB/WPScan API token for vulnerability
                      data lookups (passed as --api-token); wpscan still
                      runs without one, just with a smaller vuln database

    Returns
    -------
    dict:
        target      : str
        port        : int
        findings    : list[dict]  {component, title, reference}
        raw_output  : str         wpscan's stdout
        error       : str | None  human-readable failure reason, if any

    Never raises. A missing wpscan binary, an unreachable target, or a
    non-WordPress site (wpscan still exits successfully and just reports
    nothing) all come back as error set (for the former) or findings empty
    (for the latter).
    """
    result = {
        "tool": "wpscan",
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    url = _build_url(target, port, use_https)
    command = ["wpscan", "--url", url] + _WPSCAN_BASE_ARGS
    if api_token:
        command += ["--api-token", api_token]

    print_info(f"[WPScan] Scanning WordPress install at {url}")

    # run_tool() already logs this call's start/success/failure under the
    # "wpscan" tool name — no need to log it again here.
    tool_result = run_tool(target, "wpscan", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "wpscan failed"
        print_error(f"[WPScan] wpscan failed for {url} — {result['error']}")
        return result

    findings = _parse_wpscan_json(result["raw_output"])
    result["findings"] = findings

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "wpscan_finding",
                "port": port,
                "component": f["component"],
                "title": f["title"],
                "severity": f.get("severity", "MEDIUM"),
            })
            print_success(f"[WPScan] {f['component']} — {f['title']}")
        print_info(f"[WPScan] {url} — {len(findings)} finding(s)")
    else:
        print_warning(f"[WPScan] {url} — scan completed, WordPress not confirmed / nothing enumerated")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.wpscan_wrap <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Running wpscan against {tgt}:{prt} (https={https})...")
    out = run_wpscan(tgt, port=prt, use_https=https)
    for item in out["findings"]:
        print_info(f"  {item['component']}: {item['title']}")
    print_info(f"Error: {out['error'] or 'none'}")
