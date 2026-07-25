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
from modules.utils.logger import log_tool_failure, log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# dirb/small.txt (959 words), not gobuster_wrap.py's common.txt (4614
# words) — root-caused live against pentest-ground.com (smoke_test2's New
# Issue E): dirb is single-threaded and opens one connection per request,
# and a full common.txt run reliably died with "(!) FATAL: Too many errors
# connecting to host" at the SAME word count (1711/4614) whether or not a
# -z flood-delay was added, which rules out a rate-based limiter and points
# at a target-side cumulative connection-count threshold instead — dirb has
# no flag that reduces its per-request connection count, so the only real
# fix is to not send that many requests in the first place. Verified live:
# small.txt completed cleanly (exit 0, 959/959 downloaded, no FATAL) against
# the same target where common.txt failed every time. gobuster still runs
# the full common.txt list (its 30 concurrent threads finish fast enough
# that this target's threshold was never observed to trip), so coverage
# isn't lost — dirb remains a genuinely supplementary, different-engine
# pass rather than a duplicate of gobuster's sweep.
_DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/small.txt",
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

# dirb writes its own fatal-abort reason ("(!) FATAL: Too many errors
# connecting to host ...") to STDOUT, not stderr — a non-zero exit with no
# stderr text used to fall through to run_tool()'s generic "non-zero exit
# code (N)", losing the actual reason. Matched against raw_output as a
# fallback so the real cause reaches scan_errors.log.
_FATAL_LINE = re.compile(r"^\(!\)\s*(?P<reason>.+)$")

# Same wildcard/soft-404 flood guard as gobuster_wrap.py — a SPA or edge-CDN
# that answers every path with 200 can "discover" nearly the whole wordlist,
# and dirb has no built-in wildcard detection of its own to catch it.
_FLOOD_MIN_COUNT = 200
_FLOOD_RATIO = 0.5


def _looks_like_wildcard_flood(discovered_count: int, wordlist_path: str) -> bool:
    if discovered_count < _FLOOD_MIN_COUNT:
        return False
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            wordlist_size = sum(1 for line in fh if line.strip())
    except OSError:
        return False
    return bool(wordlist_size) and (discovered_count / wordlist_size) >= _FLOOD_RATIO


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


def _extract_fatal_reason(stdout: str) -> str:
    """Pull dirb's own '(!) FATAL: ...' abort line(s) out of its stdout, if
    present — see _FATAL_LINE's comment for why this is needed at all."""
    reasons = [
        m.group("reason").strip()
        for m in (_FATAL_LINE.match(line.strip()) for line in (stdout or "").splitlines())
        if m
    ]
    return " | ".join(reasons)


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
        {path, status_code, size, url}

    Directory hits (which dirb reports without a status code) are recorded
    with status_code 301, matching how gobuster reports a bare directory
    redirect — this keeps severity heuristics (which look at the path, not
    the code) consistent across both sources. Those lines carry no SIZE
    either, so size stays None for them rather than being invented as 0.

    dirb prints SIZE on every "+ <url> (CODE:n|SIZE:n)" hit and _FOUND_LINE
    has always captured it; it was simply dropped when the dict was built.
    url is dirb's own absolute URL, which carries the scheme and port.
    """
    discovered = []
    seen = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = _FOUND_LINE.match(line)
        if match:
            found_url = match.group("url")
            path = _path_from_url(found_url, base_url)
            try:
                status_code = int(match.group("code"))
            except (TypeError, ValueError):
                continue
            try:
                size = int(match.group("size"))
            except (TypeError, ValueError):
                size = None
        else:
            dir_match = _DIR_LINE.match(line)
            if not dir_match:
                continue
            found_url = dir_match.group("url")
            path = _path_from_url(found_url, base_url)
            status_code = 301
            size = None

        if path in seen:
            continue
        seen.add(path)
        discovered.append({
            "path": path,
            "status_code": status_code,
            "size": size,
            "redirect": None,   # dirb never reports a redirect target
            "url": found_url or None,
        })

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
        discovered_paths  : list[dict]  {path, status_code, size, redirect,
                                        url}  size is None on directory
                                        hits, which dirb reports without
                                        one; redirect is always None —
                                        dirb does not report redirect
                                        targets at all
        raw_output        : str         dirb's stdout
        error             : str | None  human-readable failure reason

    Never raises. A missing dirb binary, a missing wordlist, or an
    unreachable target all come back as error set + discovered_paths empty.
    """
    result = {
        "tool": "dirb",
        "target": target,
        "port": port,
        "discovered_paths": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
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

    # run_tool() already logs this call's start/success/failure under the
    # "dirb" tool name — no need to log it again here.
    tool_result = run_tool(target, "dirb", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success"):
        stderr = (tool_result.get("stderr") or "").strip()
        fatal = _extract_fatal_reason(result["raw_output"])
        result["error"] = stderr or fatal or tool_result.get("error") or "dirb failed"
        print_error(f"[Dirb] dirb failed for {url} — {result['error']}")
        return result

    discovered = _parse_dirb_output(result["raw_output"], url)

    if _looks_like_wildcard_flood(len(discovered), resolved_wordlist):
        # A genuinely new fact worth its own log line (distinct from
        # run_tool()'s "succeeded" — the process succeeded, the *data* is
        # being discarded as noise), so this one stays.
        msg = (
            f"{url} answered {len(discovered)} of the wordlist's entries — "
            "that's almost certainly a soft-404/wildcard response, not real "
            "content; discarding these results"
        )
        log_tool_failure(target, "dirb", msg)
        print_warning(f"[Dirb] {msg}")
        return result

    result["discovered_paths"] = discovered

    if discovered:
        for entry in discovered:
            log_finding(target, {
                "type": "discovered_path",
                "port": port,
                "path": entry["path"],
                "status_code": entry["status_code"],
                "size": entry["size"],
                "url": entry["url"],
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
