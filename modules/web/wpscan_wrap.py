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
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
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


def _parse_wpscan_json(raw_json: str) -> list:
    """
    Parse wpscan's JSON report into a list of:
        {component: str, title: str, reference: str}

    Walks the WordPress core version block plus every entry under
    `plugins` and `themes`. Any missing/renamed key yields fewer findings,
    never an exception.
    """
    findings = []

    try:
        data = json.loads(raw_json) if raw_json else {}
    except (json.JSONDecodeError, TypeError):
        return findings

    if not isinstance(data, dict):
        return findings

    version_block = data.get("version") or {}
    for vuln in _vulns_from_section(version_block):
        findings.append({"component": "WordPress core", **vuln})

    for section_name in ("plugins", "themes"):
        section = data.get(section_name) or {}
        if not isinstance(section, dict):
            continue
        for name, entry in section.items():
            for vuln in _vulns_from_section(entry if isinstance(entry, dict) else {}):
                findings.append({"component": f"{section_name[:-1]}: {name}", **vuln})

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
    log_tool_start(target, "wpscan")

    result = {
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
    }

    url = _build_url(target, port, use_https)
    command = ["wpscan", "--url", url] + _WPSCAN_BASE_ARGS
    if api_token:
        command += ["--api-token", api_token]

    print_info(f"[WPScan] Scanning WordPress install at {url}")

    tool_result = run_tool(target, "wpscan", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success") and not result["raw_output"].strip():
        err = tool_result.get("error") or tool_result.get("stderr") or "wpscan failed"
        result["error"] = err
        log_tool_failure(target, "wpscan", err)
        print_error(f"[WPScan] wpscan failed for {url} — {err}")
        return result

    findings = _parse_wpscan_json(result["raw_output"])
    result["findings"] = findings

    log_tool_success(target, "wpscan", tool_result.get("duration"))

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "wpscan_finding",
                "port": port,
                "component": f["component"],
                "title": f["title"],
            })
            print_success(f"[WPScan] {f['component']} — {f['title']}")
        print_info(f"[WPScan] {url} — {len(findings)} vulnerability(ies)")
    else:
        print_warning(f"[WPScan] {url} — scan completed, no known vulnerabilities matched")

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
