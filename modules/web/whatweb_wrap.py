"""
modules/web/whatweb_wrap.py
WhatWeb technology-fingerprinting wrapper for Aegis Scanner (web layer).

Runs `whatweb` against a target's web service through error_handler.run_tool()
and parses its single-line "Plugin[value], Plugin[value], ..." report into a
structured list of {name, value} technology hits.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -a 3    : aggression level 3 — more plugin checks without being as noisy/
#           slow as level 4's link-following recon
# --color=never : no ANSI escapes to pollute captured stdout
# --quiet : suppress the banner line so only the result line is printed
_WHATWEB_BASE_ARGS = ["-a", "3", "--color=never", "--quiet"]

# Matches "PluginName[value1,value2]" or bare "PluginName" tokens inside
# whatweb's comma-separated report line, e.g.:
#   http://example.com [200 OK] Country[UNITED STATES], HTTPServer[nginx],
#   IP[93.184.216.34], Title[Example Domain], WordPress[6.4]
_PLUGIN_RE = re.compile(r"(?P<name>[A-Za-z0-9_\-]+)(?:\[(?P<value>[^\]]*)\])?")

# Leading "<url> [<status>]" prefix that isn't a plugin hit itself.
_PREFIX_RE = re.compile(r"^\S+\s+\[[^\]]*\]\s*")

# Plugin names strongly associated with a CMS/framework, surfaced separately
# so downstream conditional dispatch (e.g. wpscan) has an easy signal beyond
# gobuster's path-based wordpress_fingerprinted flag.
_CMS_PLUGINS = ("WordPress", "Joomla", "Drupal")


def _build_url(target: str, port: int, use_https: bool) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _parse_whatweb_output(stdout: str) -> list:
    """
    Parse whatweb's single-line report into a list of:
        {name: str, value: str}

    whatweb emits exactly one summary line per target (plus, on some
    versions, a redirect note); only the first non-empty line is parsed.
    Malformed/empty input yields [].
    """
    line = ""
    for raw_line in (stdout or "").splitlines():
        candidate = raw_line.strip()
        if candidate:
            line = candidate
            break
    if not line:
        return []

    line = _PREFIX_RE.sub("", line, count=1)

    technologies = []
    seen = set()
    for part in line.split(","):
        part = part.strip()
        if not part:
            continue
        match = _PLUGIN_RE.match(part)
        if not match:
            continue
        name = match.group("name").strip()
        value = (match.group("value") or "").strip()
        key = (name, value)
        if not name or key in seen:
            continue
        seen.add(key)
        technologies.append({"name": name, "value": value})

    return technologies


def run_whatweb(target: str, port: int = 80, use_https: bool = False) -> dict:
    """
    Fingerprint web technologies on `target`'s web service with whatweb.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS

    Returns
    -------
    dict:
        target        : str
        port          : int
        technologies  : list[dict]  {name, value} plugin hits
        cms_detected  : str | None  first CMS name from _CMS_PLUGINS found,
                                    or None
        raw_output    : str         whatweb's stdout
        error         : str | None  human-readable failure reason, if any

    Never raises. A missing whatweb binary or unreachable target come back
    as error set + technologies empty.
    """
    result = {
        "tool": "whatweb",
        "target": target,
        "port": port,
        "technologies": [],
        "cms_detected": None,
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    url = _build_url(target, port, use_https)
    command = ["whatweb"] + _WHATWEB_BASE_ARGS + [url]
    print_info(f"[WhatWeb] Fingerprinting {url}")

    # run_tool() already logs this call's start/success/failure under the
    # "whatweb" tool name — no need to log it again here.
    tool_result = run_tool(target, "whatweb", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success"):
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "whatweb failed"
        print_error(f"[WhatWeb] whatweb failed for {url} — {result['error']}")
        return result

    technologies = _parse_whatweb_output(result["raw_output"])
    result["technologies"] = technologies

    for tech in technologies:
        if tech["name"] in _CMS_PLUGINS:
            result["cms_detected"] = tech["name"]
            break

    if technologies:
        for tech in technologies:
            log_finding(target, {
                "type": "technology_fingerprint",
                "port": port,
                "name": tech["name"],
                "value": tech["value"],
            })
        names = ", ".join(t["name"] for t in technologies)
        print_success(f"[WhatWeb] {url} — {len(technologies)} technolog(y/ies): {names}")
    else:
        print_warning(f"[WhatWeb] {url} — scan completed, nothing fingerprinted")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.whatweb_wrap <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Running whatweb against {tgt}:{prt} (https={https})...")
    out = run_whatweb(tgt, port=prt, use_https=https)
    for item in out["technologies"]:
        print_info(f"  {item['name']}: {item['value'] or '(no value)'}")
    print_info(f"CMS detected: {out['cms_detected'] or 'none'}")
    print_info(f"Error: {out['error'] or 'none'}")
