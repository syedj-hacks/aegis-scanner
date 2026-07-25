"""
modules/web/nikto_wrap.py
Nikto web-server scanner wrapper for Aegis Scanner (Member C - web layer).

Runs nikto against a target's web service through error_handler.run_tool()
and parses its "+ "-prefixed plain-text findings into a structured list of
{description, reference} dicts for modules/enrichment/ and
modules/reporting/ to consume.

Two nikto quirks this wrapper exists to absorb:

1. Nikto exits 0 even when it could not connect to the target at all, so
   run_tool()'s success flag is necessary but NOT sufficient — the output
   is inspected for nikto's own failure markers before findings are
   trusted.
2. A long scan hitting run_tool()'s hard subprocess timeout would be
   killed with all output discarded. To avoid that, nikto is given
   -maxtime slightly under the configured timeout so it terminates itself
   gracefully and we keep whatever it found up to that point.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.config import get_timeout
from modules.utils.logger import log_tool_failure, log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Suppress nikto's interactive prompts so it can never block on stdin
# inside a subprocess with no TTY.
_NIKTO_BASE_ARGS = ["-nointeractive"]

# Seconds shaved off the configured tool timeout so nikto self-terminates
# and flushes its report before run_tool() would hard-kill it.
_MAXTIME_MARGIN = 30

# Lines that start with "+ " but are scan metadata, not findings.
_METADATA_PREFIXES = (
    "Target IP:",
    "Target Hostname:",
    "Target Port:",
    "Target Site:",
    "Platform:",
    "Start Time:",
    "End Time:",
    "Server:",
    "Scan terminated:",
    "SSL Info:",
    "Root page",
    "No CGI Directories",
)

# Trailer lines that carry a leading count instead of a fixed prefix:
#   "+ 1 host(s) tested"
#   "+ 8877 requests: 2 errors and 25 items reported on the remote host"
# The second form is how nikto 2.6 ends a scan that ran to completion;
# a scan cut short by -maxtime ends with "Scan terminated:" instead, so
# both spellings have to be filtered.
_METADATA_PATTERNS = (
    re.compile(r"^\d+\s+host\(s\)\s+tested", re.IGNORECASE),
    re.compile(r"^\d+\s+requests?:", re.IGNORECASE),
    re.compile(r"^ERROR:", re.IGNORECASE),
)

# Nikto's own connection-failure markers. It exits 0 in these cases, so
# they are the only reliable signal that the scan never really ran.
_FAILURE_MARKERS = (
    "unable to connect",
    "no web server found",
    "0 host(s) tested",
)

# Splits "description. See: https://..." into its two halves.
_REFERENCE_SPLIT = re.compile(r"\s+See:\s+", re.IGNORECASE)

# nikto prefixes each finding with its own test id, and (for most tests) the
# URI the finding concerns. Verified against real nikto 2.6.0 output — see
# smoke_test8.txt §3.1:
#     + [013587] /: Suggested security header missing: referrer-policy. See: ...
#     + [750500] /config/: Directory indexing found.
#     + [600050] Apache/2.4.25 appears to be outdated (current is at least ...)
#     + [95] /: Cookie PHPSESSID created without the httponly flag. See: ...
# Both are real, tool-reported detail that was previously left buried in the
# description string. The id width varies (95 vs 013587), and the third
# example shows the path is genuinely absent on some tests — so the path
# group only matches a leading "/", and stays empty rather than
# misattributing "Apache/2.4.25 appears to be outdated" as a URI.
_TEST_ID_PREFIX = re.compile(r"^\[(?P<test_id>\d+)\]\s*")
_PATH_PREFIX = re.compile(r"^(?P<path>/\S*):\s+")

# "+ Server: Apache/2.4.25 (Debian)" is filtered out of the findings list as
# metadata, but it is nikto's own observation of the server banner and the
# only place in this wrapper's output where the product/version appears.
_SERVER_LINE = re.compile(r"^Server:\s*(?P<server>.+?)\s*$")


def _strip_scheme(target: str) -> str:
    """
    nikto is given host and port as separate arguments, so a caller that
    passes a full URL must not end up with the scheme duplicated.
    """
    for scheme in ("http://", "https://"):
        if target.startswith(scheme):
            target = target[len(scheme):]
    return target.rstrip("/").split("/")[0]


def _nikto_maxtime() -> int:
    """
    Derive nikto's own -maxtime from config.TOOL_TIMEOUTS['nikto'] so the
    two never fight: nikto stops first, run_tool()'s timeout stays a
    backstop. Never returns less than 30s.
    """
    return max(30, get_timeout("nikto") - _MAXTIME_MARGIN)


def _is_metadata(text: str) -> bool:
    """True if a '+ ' line is scan bookkeeping rather than a finding."""
    if text.startswith(_METADATA_PREFIXES):
        return True
    return any(pattern.match(text) for pattern in _METADATA_PATTERNS)


def _server_banner(stdout: str) -> str:
    """nikto's reported server banner, or "" if it printed none.

    Some targets return no Server header at all, and nikto then prints
    "Server: No banner retrieved" — which is nikto telling us it did not
    determine one, not a product called "No banner retrieved".
    """
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("+ "):
            continue
        match = _SERVER_LINE.match(line[2:].strip())
        if match:
            banner = match.group("server").strip()
            if banner.lower().startswith("no banner"):
                return ""
            return banner
    return ""


def _split_server_banner(banner: str) -> tuple:
    """"Apache/2.4.25 (Debian)" -> ("Apache", "2.4.25 (Debian)").

    Only splits on the "product/version" form nikto actually emits. A banner
    with no slash is reported as the product with no version, rather than
    being sliced at a guess.
    """
    if not banner:
        return "", ""
    if "/" not in banner:
        return banner, ""
    product, _, version = banner.partition("/")
    return product.strip(), version.strip()


def _parse_nikto_output(stdout: str) -> list:
    """
    Parse nikto's plain-text report into a list of:
        {description, reference, test_id, path}

    test_id and path are nikto's own, pulled off the front of the finding
    line; both are "" when nikto printed neither. `description` deliberately
    keeps the whole original text, id and path included: it is what
    summary.finding_identifier() and the dedup key are built from, and
    rewriting it would silently change the identity of every historical
    nikto finding.

    Nikto marks every reported item with a leading "+ ". Finding lines look
    like:

        + [013587] /: Suggested security header missing: csp. See: https://...
        + [001675] /ftp/: This might be interesting.
        + OSVDB-3268: /admin/: Directory indexing found.   (older versions)

    Metadata lines share the "+ " prefix and are filtered out. The
    "See: <url>" suffix, when present, becomes `reference`; otherwise
    reference is an empty string. Descriptions keep their path prefix
    ("/ftp/: ...") because that context matters in the report.
    """
    findings = []
    seen = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("+ "):
            continue

        text = line[2:].strip()
        if not text or _is_metadata(text):
            continue

        parts = _REFERENCE_SPLIT.split(text, maxsplit=1)
        description = parts[0].strip()
        reference = parts[1].strip() if len(parts) > 1 else ""

        if not description or description in seen:
            continue
        seen.add(description)

        remainder = description
        id_match = _TEST_ID_PREFIX.match(remainder)
        test_id = id_match.group("test_id") if id_match else ""
        if id_match:
            remainder = remainder[id_match.end():]
        path_match = _PATH_PREFIX.match(remainder)
        path = path_match.group("path") if path_match else ""

        findings.append({
            "description": description,
            "reference": reference,
            "test_id": test_id,
            "path": path,
        })

    return findings


def _detect_failure(stdout: str) -> str:
    """
    Nikto returns exit code 0 whether it scanned a host or failed to reach
    it, so its text output is the only place a connection failure shows up.
    Returns a human-readable reason, or "" if the scan looks legitimate.
    """
    lowered = (stdout or "").lower()
    for marker in _FAILURE_MARKERS:
        if marker in lowered:
            return f"nikto could not scan the target ({marker})"
    return ""


def run_nikto(target: str, port: int = 80, use_https: bool = False) -> dict:
    """
    Run nikto against `target`'s web service.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS (adds nikto's -ssl)

    Returns
    -------
    dict:
        target     : str
        port       : int
        base_url   : str         scheme://host:port nikto was pointed at
        server     : str         nikto's reported server banner, "" if none
        product    : str         banner split at "/", "" if no banner
        version    : str         ditto; "" when the banner carried no version
        findings   : list[dict]  {description, reference, test_id, path}
                                 reference is "" when nikto cited no URL;
                                 test_id/path are "" when nikto printed
                                 neither (some tests carry no URI)
        raw_output : str         nikto's full stdout, for the report appendix
        error      : str | None  human-readable failure reason, if any

    Never raises. A missing nikto binary, a timeout, or an unreachable
    target all come back as error set + findings empty.
    """
    result = {
        "tool": "nikto",
        "target": target,
        "port": port,
        "base_url": "",
        "server": "",
        "product": "",
        "version": "",
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    host = _strip_scheme(target)
    if not host:
        msg = "empty target supplied; skipping nikto scan"
        result["error"] = msg
        log_tool_failure(target, "nikto", msg)
        print_warning(f"[Nikto] {target}: {msg}")
        return result

    maxtime = _nikto_maxtime()
    command = (
        ["nikto", "-h", host, "-p", str(port)]
        + _NIKTO_BASE_ARGS
        + ["-maxtime", f"{maxtime}s"]
    )
    if use_https:
        command.append("-ssl")

    scheme = "https" if use_https else "http"
    result["base_url"] = f"{scheme}://{host}:{port}"
    print_info(f"[Nikto] Scanning {scheme}://{host}:{port} (maxtime {maxtime}s)")

    # run_tool() applies config.get_timeout('nikto') itself — no timeout
    # argument is passed or accepted here. It also already logs this call's
    # start/success/failure under the "nikto" tool name.
    tool_result = run_tool(target, "nikto", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success"):
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "nikto failed"
        print_error(f"[Nikto] nikto failed for {target}:{port} — {result['error']}")
        return result

    # Exit code 0 is not proof the scan happened — check nikto's own text.
    # This is new information run_tool() couldn't have logged (it saw a
    # clean exit), so it still gets its own failure line.
    failure_reason = _detect_failure(result["raw_output"])
    if failure_reason:
        result["error"] = failure_reason
        log_tool_failure(target, "nikto", failure_reason)
        print_error(f"[Nikto] {host}:{port} — {failure_reason}")
        return result

    findings = _parse_nikto_output(result["raw_output"])
    result["findings"] = findings

    result["server"] = _server_banner(result["raw_output"])
    result["product"], result["version"] = _split_server_banner(result["server"])
    if result["server"]:
        print_info(f"[Nikto] {host}:{port} — server banner: {result['server']}")

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "nikto_finding",
                "port": port,
                "description": f["description"],
                "reference": f["reference"],
                "test_id": f["test_id"],
                "path": f["path"],
            })
            print_success(f"[Nikto] {f['description']}")
        print_info(f"[Nikto] {host}:{port} — {len(findings)} finding(s)")
    else:
        print_warning(f"[Nikto] {host}:{port} — scan completed with no findings")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.nikto_wrap <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Running nikto against {tgt}:{prt} (https={https})...")
    out = run_nikto(tgt, port=prt, use_https=https)
    for item in out["findings"]:
        print_info(f"  - {item['description']}")
    print_info(f"Findings: {len(out['findings'])}")
    print_info(f"Error: {out['error'] or 'none'}")
