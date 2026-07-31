"""
modules/web/gobuster_wrap.py
Directory / content brute-force wrapper for Aegis Scanner (Member C - web).

Runs `gobuster dir` against a target's web service through
error_handler.run_tool() and parses the discovered paths and their HTTP
status codes into a structured list.

WordPress signalling
--------------------
config.CONDITIONAL_TOOLS maps "wpscan" -> "wordpress_fingerprinted": a
detection flag that gates whether the orchestrator should later run wpscan.
Nothing in the codebase reads or writes that flag yet (modules/profiles/*
and aegis.py are still empty stubs), so rather than invent a global
flag store this module simply returns `wordpress_fingerprinted` as a
boolean under exactly that key. Whoever writes modules/profiles/webaudit.py
reads it straight off this function's return dict and matches it against
CONDITIONAL_TOOLS without any extra plumbing.
"""

import os
import re

from modules.utils.error_handler import run_tool
from modules.utils.config import get_rate_limits
from modules.utils.logger import log_tool_failure, log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Wordlists tried in order when the caller doesn't supply one. First one
# that actually exists on this box wins — paths differ between Kali
# releases and a hardcoded missing path would fail every scan.
_DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# -q  : suppress banner/noise so only result lines reach stdout
# --np: no progress meter (it would otherwise pollute captured output)
# (-k, to skip TLS validation on self-signed test certs, is appended only
#  when use_https is set)
#
# -t (threads) is deliberately NOT here any more: it is per-profile now, via
# config.get_rate_limits(), and appended in run_gobuster(). Leaving a "-t 30"
# here as well would put -t on the command line twice. Every profile's
# configured value is 30, so the resolved command is identical to before.
_GOBUSTER_BASE_ARGS = ["-q", "--np"]

# Matches gobuster's result lines, e.g.
#   admin                (Status: 301) [Size: 0] [--> /admin/]
#   /index.html          (Status: 200) [Size: 55]
#
# Size and the redirect target are gobuster's own output and were previously
# matched-but-discarded — the pattern stopped at the status code. Both are
# real, tool-reported detail: the size distinguishes a 0-byte stub from a
# real page, and the redirect target says where a 301/302 actually goes
# (verified against live gobuster output — see smoke_test8.txt §3.1). Both
# groups are optional: gobuster omits [--> ...] on non-redirects, and a
# future/older build that omits [Size: ...] must still parse rather than
# silently yielding zero paths.
_RESULT_LINE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"
)

# Single-page apps and sites with a soft 404 answer *every* URL with the
# same page, so gobuster refuses to start and exits 1. Its own error text
# carries the wildcard response's length, which is exactly what's needed to
# filter that page out — so we detect this and retry once.
_WILDCARD_ERROR = "status code that matches the provided options for non existing urls"
_WILDCARD_LENGTH = re.compile(r"\(Length:\s*(?P<length>\d+)\)")

# Paths whose presence is strong evidence of a WordPress install.
_WORDPRESS_MARKERS = (
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/wp-includes",
    "/xmlrpc.php",
)

# Some SPAs / edge-CDN setups answer *every* path with 200 and a body that
# varies just enough (a per-request token, a timestamp) to defeat gobuster's
# own wildcard auto-detection (which only fires when the response is
# byte-for-byte identical). Left unchecked this "discovers" nearly the whole
# wordlist as real content — e.g. 4606 of 4614 common.txt entries on one
# real-world target — flooding the findings table with noise. If a
# suspiciously large fraction of the wordlist "hit", treat the whole run as
# a soft-404 wildcard the tool missed rather than real content.
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
    """Compose the base URL, respecting a full URL if one was passed in."""
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")

    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _resolve_wordlist(wordlist: str = None) -> tuple:
    """
    Decide which wordlist to use.

    Returns (path, error). On success error is ""; on failure path is None
    and error explains what was missing, so the caller can degrade
    gracefully instead of launching a doomed gobuster run.
    """
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


def _wildcard_length(stderr: str) -> str:
    """
    If gobuster bailed out because the target answers every URL with the
    same page, return that page's content length as a string (suitable for
    --exclude-length). Returns "" for any other failure, so the caller only
    retries on this specific, recoverable condition.
    """
    text = stderr or ""
    if _WILDCARD_ERROR not in text.lower():
        return ""
    match = _WILDCARD_LENGTH.search(text)
    return match.group("length") if match else ""


def _normalise_path(path: str) -> str:
    """
    gobuster prints bare entries ("admin") in quiet mode and rooted ones
    ("/admin") in others. Normalise to a leading slash so downstream
    reporting and the WordPress markers compare consistently.
    """
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def _parse_gobuster_output(stdout: str, base_url: str = "") -> list:
    """
    Parse gobuster's result lines into a list of:
        {path, status_code, size, redirect, url}

    size is None when gobuster did not print a [Size: ...] block, and
    redirect is None on anything that is not a redirect — in both cases the
    tool genuinely said nothing, which the report renders as "not determined
    by gobuster" rather than as a zero or a dash.

    url is the absolute URL the path was found at. gobuster is launched
    against a scheme-qualified base URL, so http-vs-https and the port are
    known here for certain; recording the composed URL keeps that knowledge
    instead of discarding it and leaving the report to guess a scheme.

    Non-matching lines (blank lines, stray progress output) are skipped.
    Duplicates are collapsed. Malformed/empty input yields [].
    """
    discovered = []
    seen = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = _RESULT_LINE.match(line)
        if not match:
            continue

        path = _normalise_path(match.group("path"))
        try:
            status_code = int(match.group("status"))
        except (TypeError, ValueError):
            continue

        if path in seen:
            continue
        seen.add(path)

        size = match.group("size")
        redirect = (match.group("redirect") or "").strip()

        discovered.append({
            "path": path,
            "status_code": status_code,
            "size": int(size) if size is not None else None,
            "redirect": redirect or None,
            "url": f"{base_url.rstrip('/')}{path}" if base_url else None,
        })

    discovered.sort(key=lambda d: d["path"])
    return discovered


def _detect_wordpress(discovered: list) -> list:
    """
    Return the WordPress marker paths present in the discovered set.
    Matching is prefix-based and case-insensitive so /wp-admin/ and
    /WP-Admin both count.
    """
    hits = []
    for entry in discovered:
        path = entry.get("path", "").lower().rstrip("/")
        for marker in _WORDPRESS_MARKERS:
            if path == marker or path.startswith(marker + "/"):
                hits.append(entry["path"])
                break
    return hits


def run_gobuster(target: str, port: int = 80, use_https: bool = False,
                 wordlist: str = None, profile: str = None, auth=None) -> dict:
    """
    Brute-force directories/files on `target`'s web service with gobuster.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS (adds gobuster's -k so self-signed
                      certs on test targets don't abort the run)
    wordlist  : str   path to a wordlist; defaults to the first entry of
                      _DEFAULT_WORDLISTS that exists on this system
    profile   : str   scan profile name, used to look up this profile's
                      thread count (config.get_rate_limits). Omitted/unknown
                      resolves to the default 30 — the value that was
                      hardcoded here before, so behaviour is unchanged.
    auth      : AuthConfig | None  credentials for an authenticated scan.
                      None (the default) builds exactly the same command as
                      before; see modules/utils/auth.py.

    Returns
    -------
    dict:
        target                 : str
        port                   : int
        base_url               : str         the scheme-qualified URL gobuster
                                             was actually pointed at
        discovered_paths       : list[dict]  {path, status_code, size,
                                             redirect, url}
                                             path always leading-slashed;
                                             size/redirect are None where
                                             gobuster reported neither
        wordpress_fingerprinted: bool        True when a /wp-* marker was
                                             found — this is the flag
                                             config.CONDITIONAL_TOOLS maps
                                             to wpscan
        raw_output             : str         gobuster's stdout
        error                  : str | None  human-readable failure reason

    Never raises. A missing gobuster binary, a missing wordlist, or an
    unreachable target all come back as error set + discovered_paths empty
    + wordpress_fingerprinted False.

    Targets that answer every URL with the same page (SPAs, soft 404s) make
    gobuster refuse to run; that one case is retried automatically with the
    wildcard page's length excluded, so such targets still return results.
    """
    result = {
        "tool": "gobuster",
        "target": target,
        "port": port,
        "base_url": "",
        "discovered_paths": [],
        "wordpress_fingerprinted": False,
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    resolved_wordlist, wordlist_error = _resolve_wordlist(wordlist)
    if wordlist_error:
        result["error"] = wordlist_error
        log_tool_failure(target, "gobuster", wordlist_error)
        print_error(f"[Gobuster] {target}:{port} — {wordlist_error}")
        return result

    url = _build_url(target, port, use_https)
    result["base_url"] = url
    # -t comes from the profile's rate limit rather than _GOBUSTER_BASE_ARGS
    # so a profile can go gentler on a target that throttles by connection
    # count. get_rate_limits() returns 30 for every profile today, which is
    # the value _GOBUSTER_BASE_ARGS carried, so this changes nothing by
    # default — it only makes the knob reachable.
    threads = get_rate_limits(profile).get("gobuster_threads") or 30
    command = (
        ["gobuster", "dir", "-u", url, "-w", resolved_wordlist]
        + _GOBUSTER_BASE_ARGS + ["-t", str(threads)]
    )
    if use_https:
        command.append("-k")
    if auth is not None:
        command += auth.gobuster_args()

    print_info(f"[Gobuster] Enumerating {url} with {resolved_wordlist} (-t {threads})")

    # run_tool() applies config.get_timeout('gobuster') itself — no timeout
    # argument is passed or accepted here.
    tool_result = run_tool(target, "gobuster", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    # A wildcard-response refusal isn't a real failure — retry once with the
    # offending page length excluded, otherwise SPA targets always yield
    # zero paths.
    if not tool_result.get("success"):
        retry_length = _wildcard_length(tool_result.get("stderr", ""))
        if retry_length:
            print_warning(
                f"[Gobuster] {url} answers every URL with a {retry_length}-byte page; "
                "retrying with that length excluded"
            )
            tool_result = run_tool(
                target, "gobuster",
                command + ["--exclude-length", retry_length],
            )
            result["raw_output"] = tool_result.get("stdout", "") or ""
            result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success"):
        # gobuster writes the real reason (connection refused, bad
        # wordlist) to stderr and exits non-zero, so prefer stderr text
        # over run_tool's generic "non-zero exit code" wording.
        stderr = (tool_result.get("stderr") or "").strip()
        result["error"] = stderr or tool_result.get("error") or "gobuster failed"
        print_error(f"[Gobuster] gobuster failed for {url} — {result['error']}")
        return result

    discovered = _parse_gobuster_output(result["raw_output"], base_url=url)

    if _looks_like_wildcard_flood(len(discovered), resolved_wordlist):
        # New information beyond run_tool()'s own success/failure verdict
        # (the process succeeded; the *data* is being discarded as noise),
        # so this one keeps its own log line.
        msg = (
            f"{url} answered {len(discovered)} of the wordlist's entries — "
            "that's almost certainly a soft-404/wildcard response gobuster's "
            "own detection missed, not real content; discarding these results"
        )
        log_tool_failure(target, "gobuster", msg)
        print_warning(f"[Gobuster] {msg}")
        return result

    result["discovered_paths"] = discovered

    wordpress_hits = _detect_wordpress(discovered)
    result["wordpress_fingerprinted"] = bool(wordpress_hits)

    if discovered:
        for entry in discovered:
            log_finding(target, {
                "type": "discovered_path",
                "port": port,
                "path": entry["path"],
                "status_code": entry["status_code"],
                "size": entry["size"],
                "redirect": entry["redirect"],
                "url": entry["url"],
            })
            print_success(f"[Gobuster] {entry['path']} ({entry['status_code']})")
        print_info(f"[Gobuster] {url} — {len(discovered)} path(s) discovered")
    else:
        print_warning(f"[Gobuster] {url} — scan completed, no paths discovered")

    if result["wordpress_fingerprinted"]:
        log_finding(target, {
            "type": "wordpress_fingerprinted",
            "port": port,
            "evidence": wordpress_hits,
        })
        print_success(
            f"[Gobuster] WordPress fingerprinted via {', '.join(wordpress_hits)} "
            "— wpscan is now applicable (CONDITIONAL_TOOLS)"
        )

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error(
            "Usage: python -m modules.web.gobuster_wrap <target> [port] [https] [wordlist]"
        )
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")
    wl = sys.argv[4] if len(sys.argv) > 4 else None

    print_info(f"Running gobuster against {tgt}:{prt} (https={https})...")
    out = run_gobuster(tgt, port=prt, use_https=https, wordlist=wl)
    for item in out["discovered_paths"]:
        print_info(f"  {item['status_code']}  {item['path']}")
    print_info(f"WordPress fingerprinted: {out['wordpress_fingerprinted']}")
    print_info(f"Error: {out['error'] or 'none'}")
