"""
modules/web/dirb_wrap.py
Dirb content-discovery wrapper for Aegis Scanner (web layer).

dirb was already an install.sh dependency (it ships
/usr/share/wordlists/dirb/common.txt, gobuster_wrap.py's default wordlist)
but was never invoked directly. This module runs `dirb` itself through
error_handler.run_tool() as a supplementary, independent content-discovery
pass alongside gobuster — different engine, same target — rather than a
replacement for it. Its findings are kept in a separate `discovered_paths`
list so callers can tell the two sources apart if they want to.
"""

import os
import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Same candidate list gobuster_wrap.py falls back to, in the same order —
# dirb's own default wordlist is the first choice.
_DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# -S : silent mode, only print found items (no banner/progress noise)
# -w : don't stop on WARNING messages (e.g. connection warnings mid-scan)
# -r : non-recursive — a supplementary pass shouldn't multiply the runtime
#      of gobuster's own (recursive-by-default-off) sweep
_DIRB_BASE_ARGS = ["-S", "-w", "-r"]

# Matches dirb's found-item lines, e.g.:
#   + http://example.com/admin (CODE:301|SIZE:0)
#   ==> DIRECTORY: http://example.com/images/
_FOUND_LINE = re.compile(r"^\+\s+(?P<url>\S+)\s+\(CODE:(?P<code>\d+)\|SIZE:(?P<size>\d+)\)")
_DIR_LINE = re.compile(r"^==>\s+DIRECTORY:\s+(?P<url>\S+)")


def _build_url(target: str, port: int, use_https: bool) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _resolve_wordlist(wordlist: str = None) -> tuple:
    if wordlist:
        if os.path.isfile(wordlist):
            return wordlist, ""
        return None, f"wordlist not found: {wordlist}"

    for candidate in _DEFAULT_WORDLISTS:
        if os.path.isfile(candidate):
            return candidate, ""

    return None, (
        "no wordlist available; tried " + ", ".join(_DEFAULT_WORDLISTS)
    )


def _path_from_url(url: str, base_url: str) -> str:
    """Strip the base URL prefix so only the discovered path remains."""
    path = url[len(base_url):] if url.startswith(base_url) else url
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def _parse_dirb_output(stdout: str, base_url: str) -> list:
    """
    Parse dirb's result lines into a list of:
        {path: str, status_code: int}

    Directory hits (which dirb reports without a status code) are recorded
    with status_code 301, matching how gobuster reports a bare directory
    redirect — this keeps severity heuristics (which look at the path, not
    the code) consistent across both sources.
    """
    discovered = []
    seen = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = _FOUND_LINE.match(line)
        if match:
            path = _path_from_url(match.group("url"), base_url)
            try:
                status_code = int(match.group("code"))
            except (TypeError, ValueError):
                continue
        else:
            dir_match = _DIR_LINE.match(line)
            if not dir_match:
                continue
            path = _path_from_url(dir_match.group("url"), base_url)
            status_code = 301

        if path in seen:
            continue
        seen.add(path)
        discovered.append({"path": path, "status_code": status_code})

    discovered.sort(key=lambda d: d["path"])
    return discovered


def run_dirb(target: str, port: int = 80, use_https: bool = False,
             wordlist: str = None) -> dict:
    """
    Brute-force directories/files on `target`'s web service with dirb, as a
    supplementary pass alongside gobuster_wrap.run_gobuster() (not a
    replacement for it).

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS
    wordlist  : str   path to a wordlist; defaults to the first entry of
                      _DEFAULT_WORDLISTS that exists on this system

    Returns
    -------
    dict:
        target            : str
        port              : int
        discovered_paths  : list[dict]  {path, status_code}
        raw_output        : str         dirb's stdout
        error             : str | None  human-readable failure reason

    Never raises. A missing dirb binary, a missing wordlist, or an
    unreachable target all come back as error set + discovered_paths empty.
    """
    log_tool_start(target, "dirb")

    result = {
        "target": target,
        "port": port,
        "discovered_paths": [],
        "raw_output": "",
        "error": None,
    }

    resolved_wordlist, wordlist_error = _resolve_wordlist(wordlist)
    if wordlist_error:
        result["error"] = wordlist_error
        log_tool_failure(target, "dirb", wordlist_error)
        print_error(f"[Dirb] {target}:{port} — {wordlist_error}")
        return result

    url = _build_url(target, port, use_https)
    command = ["dirb", url, resolved_wordlist] + _DIRB_BASE_ARGS

    print_info(f"[Dirb] Enumerating {url} with {resolved_wordlist}")

    tool_result = run_tool(target, "dirb", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success"):
        stderr = (tool_result.get("stderr") or "").strip()
        err = stderr or tool_result.get("error") or "dirb failed"
        result["error"] = err
        log_tool_failure(target, "dirb", err)
        print_error(f"[Dirb] dirb failed for {url} — {err}")
        return result

    discovered = _parse_dirb_output(result["raw_output"], url)
    result["discovered_paths"] = discovered

    log_tool_success(target, "dirb", tool_result.get("duration"))

    if discovered:
        for entry in discovered:
            log_finding(target, {
                "type": "discovered_path",
                "port": port,
                "path": entry["path"],
                "status_code": entry["status_code"],
                "source": "dirb",
            })
            print_success(f"[Dirb] {entry['path']} ({entry['status_code']})")
        print_info(f"[Dirb] {url} — {len(discovered)} path(s) discovered")
    else:
        print_warning(f"[Dirb] {url} — scan completed, no paths discovered")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.dirb_wrap <target> [port] [https] [wordlist]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")
    wl = sys.argv[4] if len(sys.argv) > 4 else None

    print_info(f"Running dirb against {tgt}:{prt} (https={https})...")
    out = run_dirb(tgt, port=prt, use_https=https, wordlist=wl)
    for item in out["discovered_paths"]:
        print_info(f"  {item['status_code']}  {item['path']}")
    print_info(f"Error: {out['error'] or 'none'}")
