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

Read-only enumeration
---------------------
Runs `sqlmap` through error_handler.run_tool() in --batch mode (never
prompts). On top of the confirmation pass it requests three SAFE, read-only
metadata enumerations — `--banner --current-db --dbs` — so a confirmed
finding carries real extracted evidence (DB engine/version, the current
database name, the list of database names, and the injection technique
type: boolean-blind / error-based / time-based / UNION) instead of a bare
"vulnerable" boolean. It deliberately never requests `--dump`, `--os-shell`,
`--sql-shell`, `--file-read`/`--file-write` or any other data-exfiltration
or write/execution action — enumeration of metadata only.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding, log_tool_failure
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# --batch          : never prompt for input — required in a subprocess with
#                     no TTY
# --random-agent   : avoid a static UA getting blocked by a WAF
# --level 1 --risk 1: default (safest, fastest) test depth; this is a
#                     confirmation pass on a candidate the param-probe
#                     already flagged, not an exhaustive audit
# --banner         : read-only — fetch the DBMS version banner
# --current-db     : read-only — fetch the name of the current database
# --dbs            : read-only — list the database names
# None of these read table/row data or write anything: metadata only.
_SQLMAP_BASE_ARGS = [
    "--batch", "--random-agent", "--level", "1", "--risk", "1",
    "--banner", "--current-db", "--dbs",
]

# Matches the start of one of sqlmap's per-parameter result blocks:
#   Parameter: id (GET)
_PARAM_LINE = re.compile(r"^Parameter:\s+(?P<param>\S+)\s+\((?P<method>[A-Z]+)\)")
_TYPE_LINE = re.compile(r"^\s*Type:\s+(?P<type>.+)$")
_TITLE_LINE = re.compile(r"^\s*Title:\s+(?P<title>.+)$")
_PAYLOAD_LINE = re.compile(r"^\s*Payload:\s+(?P<payload>.+)$")

# Read-only enumeration output lines.
_DBMS_LINE = re.compile(r"^back-end DBMS:\s+(?P<dbms>.+)$")
_BANNER_LINE = re.compile(r"^banner:\s+'?(?P<banner>.+?)'?\s*$")
_CURRENT_DB_LINE = re.compile(r"^current database:\s+'?(?P<db>.+?)'?\s*$")
# Each listed database is printed as "[*] name" under "available databases".
_DB_ENTRY_LINE = re.compile(r"^\[\*\]\s+(?P<db>\S+)\s*$")
_AVAILABLE_DBS_LINE = re.compile(r"^available databases")


def _parse_sqlmap_output(stdout: str) -> tuple:
    """
    Parse sqlmap's stdout into (findings, metadata).

    findings : list of one dict per vulnerable parameter:
        {parameter, method, type, title, payload, techniques}
      - `techniques` is the full list of {type, title, payload} triples
        sqlmap confirmed for that parameter (boolean-blind, error-based,
        time-based, UNION, ...); `type`/`title`/`payload` mirror the first
        one for back-compat with existing callers.

    metadata : dict of the read-only enumeration results shared across the
        whole target:
        {dbms, banner, current_db, databases}

    Malformed/empty input yields ([], {}). A truncated final line (killed or
    timed-out sqlmap) never aborts the parse.
    """
    findings = []
    current = None
    current_technique = None
    metadata = {"dbms": "", "banner": "", "current_db": "", "databases": []}
    in_available_dbs = False

    def _flush_technique():
        if current is not None and current_technique is not None:
            current["techniques"].append(current_technique)

    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip()

        param_match = _PARAM_LINE.match(line)
        if param_match:
            _flush_technique()
            current_technique = None
            if current:
                findings.append(current)
            current = {
                "parameter": param_match.group("param"),
                "method": param_match.group("method"),
                "type": "",
                "title": "",
                "payload": "",
                "techniques": [],
            }
            in_available_dbs = False
            continue

        # --- per-parameter technique blocks -------------------------------
        # Within one "Parameter:" block sqlmap prints several
        # Type/Title/Payload triples separated by BLANK lines, and closes
        # all parameter blocks with a "---" fence; the read-only metadata
        # lines (non-indented) then follow. So a blank line only ends the
        # current technique — it must NOT close the finding — while a "---"
        # fence or the first non-indented line does.
        if current is not None:
            type_match = _TYPE_LINE.match(line)
            if type_match:
                _flush_technique()
                current_technique = {"type": type_match.group("type").strip(),
                                     "title": "", "payload": ""}
                continue
            if current_technique is not None:
                title_match = _TITLE_LINE.match(line)
                if title_match:
                    current_technique["title"] = title_match.group("title").strip()
                    continue
                payload_match = _PAYLOAD_LINE.match(line)
                if payload_match:
                    current_technique["payload"] = payload_match.group("payload").strip()
                    continue
            if line.strip() == "":
                # blank line separates techniques inside the block — end the
                # current technique but keep the parameter block open
                _flush_technique()
                current_technique = None
                continue
            if line.strip() == "---" or not line.startswith((" ", "\t")):
                # "---" fence, or the first non-indented line (metadata,
                # a prompt echo, ...) — the parameter block is over. Close
                # the finding, then fall through so a metadata line on this
                # same row is still parsed below.
                _flush_technique()
                current_technique = None
                findings.append(current)
                current = None
                if line.strip() == "---":
                    continue
            else:
                # some other indented continuation line inside the block
                continue

        # --- global read-only enumeration output --------------------------
        if _AVAILABLE_DBS_LINE.match(line):
            in_available_dbs = True
            continue
        if in_available_dbs:
            db_entry = _DB_ENTRY_LINE.match(line)
            if db_entry:
                metadata["databases"].append(db_entry.group("db"))
                continue
            if line.strip():
                in_available_dbs = False

        dbms_match = _DBMS_LINE.match(line)
        if dbms_match and not metadata["dbms"]:
            metadata["dbms"] = dbms_match.group("dbms").strip()
            continue
        banner_match = _BANNER_LINE.match(line)
        if banner_match and not metadata["banner"]:
            metadata["banner"] = banner_match.group("banner").strip()
            continue
        current_db_match = _CURRENT_DB_LINE.match(line)
        if current_db_match and not metadata["current_db"]:
            metadata["current_db"] = current_db_match.group("db").strip()
            continue

    _flush_technique()
    if current:
        findings.append(current)

    # Mirror the first technique onto the flat keys for back-compat.
    for f in findings:
        if f["techniques"]:
            first = f["techniques"][0]
            f["type"] = first["type"]
            f["title"] = first["title"]
            f["payload"] = first["payload"]

    return findings, metadata


def run_sqlmap(target: str, url: str) -> dict:
    """
    Test a specific URL (with a query string) for SQL injection with sqlmap,
    then read back safe DB metadata for any confirmed injection.

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
        findings     : list[dict]  {parameter, method, type, title, payload,
                                   techniques}
        metadata     : dict        {dbms, banner, current_db, databases} —
                                   the read-only enumeration results
        raw_output   : str         sqlmap's stdout
        error        : str | None  human-readable failure reason, if any
        skipped      : bool

    Never raises. A missing sqlmap binary, an unreachable target, or a
    non-vulnerable URL (sqlmap still exits successfully and just reports
    nothing) all come back as error set (for the former) or
    injectable=False (for the latter).
    """
    result = {
        "tool": "sqlmap",
        "target": target,
        "url": url,
        "injectable": False,
        "findings": [],
        "metadata": {"dbms": "", "banner": "", "current_db": "", "databases": []},
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    if not url or "?" not in url:
        msg = "no query-string URL supplied; skipping sqlmap scan"
        result["error"] = msg
        log_tool_failure(target, "sqlmap", msg)
        print_warning(f"[Sqlmap] {target}: {msg}")
        return result

    command = ["sqlmap", "-u", url] + _SQLMAP_BASE_ARGS
    print_info(f"[Sqlmap] Testing {url} for SQL injection (+ read-only DB enumeration)")

    # run_tool() already logs this call's start/success/failure under the
    # "sqlmap" tool name — no need to log it again here.
    tool_result = run_tool(target, "sqlmap", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "sqlmap failed"
        print_error(f"[Sqlmap] sqlmap failed for {url} — {result['error']}")
        return result

    findings, metadata = _parse_sqlmap_output(result["raw_output"])
    result["findings"] = findings
    result["metadata"] = metadata
    result["injectable"] = bool(findings)

    if findings:
        for f in findings:
            technique_names = ", ".join(t["type"] for t in f["techniques"]) or f["type"]
            log_finding(target, {
                "type": "sqlmap_finding",
                "parameter": f["parameter"],
                "method": f["method"],
                "title": f["title"],
                "techniques": technique_names,
            })
            print_success(f"[Sqlmap] {f['parameter']} ({f['method']}) — {technique_names}")
        if metadata["dbms"] or metadata["current_db"] or metadata["databases"]:
            print_info(
                f"[Sqlmap] enumerated — DBMS: {metadata['dbms'] or 'unknown'}, "
                f"current DB: {metadata['current_db'] or 'unknown'}, "
                f"databases: {', '.join(metadata['databases']) or 'none listed'}"
            )
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
        print_info(f"    payload: {item['payload']}")
    print_info(f"Metadata: {out['metadata']}")
    print_info(f"Error: {out['error'] or 'none'}")
