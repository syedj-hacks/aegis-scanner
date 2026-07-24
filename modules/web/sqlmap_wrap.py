"""
modules/web/sqlmap_wrap.py
sqlmap SQL-injection scanner wrapper for Aegis Scanner (web layer).

config.CONDITIONAL_TOOLS maps "sqlmap" -> "injectable_param_found", a flag
nothing in the codebase used to produce. modules/profiles/deepscan.py now
runs a lightweight param-probe over gobuster/dirb's already-discovered
paths (looking for query strings with common vulnerable parameter names —
see deepscan.py's _detect_injectable_candidates()) to set that flag and
hand this module a candidate URL, rather than sqlmap crawling the site
itself.

Runs `sqlmap` through error_handler.run_tool() in --batch mode (never
prompts) and parses its "Parameter: ... is vulnerable" report blocks.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# --batch          : never prompt for input — required in a subprocess with
#                     no TTY
# --random-agent   : avoid a static UA getting blocked by a WAF
# --level 1 --risk 1: default (safest, fastest) test depth; this is a
#                     confirmation pass on a candidate the param-probe
#                     already flagged, not an exhaustive audit
_SQLMAP_BASE_ARGS = ["--batch", "--random-agent", "--level", "1", "--risk", "1"]

# Matches the start of one of sqlmap's per-parameter result blocks:
#   Parameter: id (GET)
_PARAM_LINE = re.compile(r"^Parameter:\s+(?P<param>\S+)\s+\((?P<method>[A-Z]+)\)")
_TYPE_LINE = re.compile(r"^\s*Type:\s+(?P<type>.+)$")
_TITLE_LINE = re.compile(r"^\s*Title:\s+(?P<title>.+)$")


def _parse_sqlmap_output(stdout: str) -> list:
    """
    Parse sqlmap's stdout into a list of:
        {parameter, method, type, title}

    sqlmap prints one block per vulnerable parameter, each starting with a
    "Parameter: <name> (<METHOD>)" line followed by one or more
    Type/Title/Payload lines; only the first Type/Title pair per parameter
    block is kept (further ones are additional exploitation techniques for
    the same parameter, not new findings). Malformed/empty input yields [].
    """
    findings = []
    current = None

    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip()

        param_match = _PARAM_LINE.match(line)
        if param_match:
            if current:
                findings.append(current)
            current = {
                "parameter": param_match.group("param"),
                "method": param_match.group("method"),
                "type": "",
                "title": "",
            }
            continue

        if current is None:
            continue

        if not current["type"]:
            type_match = _TYPE_LINE.match(line)
            if type_match:
                current["type"] = type_match.group("type").strip()
                continue

        if not current["title"]:
            title_match = _TITLE_LINE.match(line)
            if title_match:
                current["title"] = title_match.group("title").strip()

    if current:
        findings.append(current)

    return findings


def run_sqlmap(target: str, url: str) -> dict:
    """
    Test a specific URL (with a query string) for SQL injection with sqlmap.

    Parameters
    ----------
    target : str  host / IP the URL belongs to (used only for logging/output
                  routing)
    url    : str  full URL including the query string to test, e.g.
                  "http://target/page.php?id=1" — normally supplied by
                  deepscan._detect_injectable_candidates()

    Returns
    -------
    dict:
        target       : str
        url          : str
        injectable   : bool        True when sqlmap confirmed at least one
                                   vulnerable parameter
        findings     : list[dict]  {parameter, method, type, title}
        raw_output   : str         sqlmap's stdout
        error        : str | None  human-readable failure reason, if any

    Never raises. A missing sqlmap binary, an unreachable target, or a
    non-vulnerable URL (sqlmap still exits successfully and just reports
    nothing) all come back as error set (for the former) or
    injectable=False (for the latter).
    """
    log_tool_start(target, "sqlmap")

    result = {
        "target": target,
        "url": url,
        "injectable": False,
        "findings": [],
        "raw_output": "",
        "error": None,
    }

    if not url or "?" not in url:
        msg = "no query-string URL supplied; skipping sqlmap scan"
        result["error"] = msg
        log_tool_failure(target, "sqlmap", msg)
        print_warning(f"[Sqlmap] {target}: {msg}")
        return result

    command = ["sqlmap", "-u", url] + _SQLMAP_BASE_ARGS
    print_info(f"[Sqlmap] Testing {url} for SQL injection")

    tool_result = run_tool(target, "sqlmap", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success") and not result["raw_output"].strip():
        err = tool_result.get("error") or tool_result.get("stderr") or "sqlmap failed"
        result["error"] = err
        log_tool_failure(target, "sqlmap", err)
        print_error(f"[Sqlmap] sqlmap failed for {url} — {err}")
        return result

    findings = _parse_sqlmap_output(result["raw_output"])
    result["findings"] = findings
    result["injectable"] = bool(findings)

    log_tool_success(target, "sqlmap", tool_result.get("duration"))

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "sqlmap_finding",
                "parameter": f["parameter"],
                "method": f["method"],
                "title": f["title"],
            })
            print_success(f"[Sqlmap] {f['parameter']} ({f['method']}) — {f['title']}")
        print_info(f"[Sqlmap] {url} — {len(findings)} injectable parameter(s)")
    else:
        print_warning(f"[Sqlmap] {url} — scan completed, no injection confirmed")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print_error("Usage: python -m modules.web.sqlmap_wrap <target> <url-with-query-string>")
        sys.exit(1)

    tgt = sys.argv[1]
    test_url = sys.argv[2]

    print_info(f"Running sqlmap against {test_url}...")
    out = run_sqlmap(tgt, test_url)
    print_info(f"Injectable: {out['injectable']}")
    for item in out["findings"]:
        print_info(f"  {item['parameter']}: {item['title']}")
    print_info(f"Error: {out['error'] or 'none'}")
