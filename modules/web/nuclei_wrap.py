"""
modules/web/nuclei_wrap.py
Nuclei template-based vulnerability scanner wrapper for Aegis Scanner (web
layer).

Runs `nuclei` against a target's web service through error_handler.run_tool()
requesting JSON-lines output (-jsonl) for reliable structured parsing, and
turns each matched template into a finding dict.

Severity filtering
-------------------
config.PROFILES[<profile>]['nuclei_severity'] (e.g. quickscan's
["critical", "high"]) is passed straight to nuclei's own -severity flag, so
the tool itself does the filtering rather than this wrapper post-filtering a
larger result set.
"""

import json

from modules.utils.error_handler import run_tool
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -jsonl        : one JSON object per line on stdout — the only reliably
#                 parseable nuclei output format
# -silent       : suppress the banner/progress noise nuclei otherwise writes
#                 to stdout ahead of the JSON lines
# -no-color     : no ANSI escapes
_NUCLEI_BASE_ARGS = ["-jsonl", "-silent", "-no-color"]

_DEFAULT_SEVERITY = ["critical", "high", "medium"]


def _build_url(target: str, port: int, use_https: bool) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _parse_nuclei_jsonl(stdout: str) -> list:
    """
    Parse nuclei's -jsonl output into a list of:
        {template_id, name, severity, description, matched_at, reference}

    Each stdout line is an independent JSON object; a malformed line is
    skipped rather than aborting the whole parse (a truncated final line
    from a killed/timed-out process is the common case).
    """
    findings = []

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue

        info = obj.get("info") or {}
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        findings.append({
            "template_id": obj.get("template-id") or obj.get("templateID") or "",
            "name": info.get("name") or "",
            "severity": info.get("severity") or "",
            "description": info.get("description") or info.get("name") or "",
            "matched_at": obj.get("matched-at") or obj.get("host") or "",
            "reference": references[0] if references else "",
        })

    return findings


def run_nuclei(target: str, port: int = 80, use_https: bool = False,
               severity: list = None) -> dict:
    """
    Scan `target`'s web service with nuclei's community template set.

    Parameters
    ----------
    target    : str        host / IP (a full http(s):// URL is also accepted)
    port      : int        web service port (default 80)
    use_https : bool       scan over TLS
    severity  : list[str]  template severities to include, passed to
                           nuclei's -severity flag (e.g. ["critical","high"]
                           from PROFILES[profile]['nuclei_severity']);
                           defaults to critical/high/medium when omitted

    Returns
    -------
    dict:
        target      : str
        port        : int
        findings    : list[dict]  {template_id, name, severity, description,
                                   matched_at, reference}
        raw_output  : str         nuclei's stdout
        error       : str | None  human-readable failure reason, if any

    Never raises. A missing nuclei binary, no templates installed, or an
    unreachable target all come back as error set + findings empty. Nuclei
    exits non-zero on some transport errors even with valid partial output,
    so any JSON that did make it to stdout is still parsed and returned.
    """
    log_tool_start(target, "nuclei")

    result = {
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
    }

    url = _build_url(target, port, use_https)
    severity_list = severity or _DEFAULT_SEVERITY
    command = (
        ["nuclei", "-u", url, "-severity", ",".join(severity_list)]
        + _NUCLEI_BASE_ARGS
    )

    print_info(f"[Nuclei] Scanning {url} (severity={','.join(severity_list)})")

    tool_result = run_tool(target, "nuclei", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success") and not result["raw_output"].strip():
        # No partial output to salvage — a genuine failure (missing binary,
        # no templates, connection refused before the first match).
        err = tool_result.get("error") or tool_result.get("stderr") or "nuclei failed"
        result["error"] = err
        log_tool_failure(target, "nuclei", err)
        print_error(f"[Nuclei] nuclei failed for {url} — {err}")
        return result

    findings = _parse_nuclei_jsonl(result["raw_output"])
    result["findings"] = findings

    log_tool_success(target, "nuclei", tool_result.get("duration"))

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "nuclei_finding",
                "port": port,
                "template_id": f["template_id"],
                "severity": f["severity"],
                "name": f["name"],
            })
            print_success(f"[Nuclei] [{f['severity']}] {f['name']} ({f['template_id']})")
        print_info(f"[Nuclei] {url} — {len(findings)} finding(s)")
    else:
        print_warning(f"[Nuclei] {url} — scan completed, no matches")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.nuclei_wrap <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Running nuclei against {tgt}:{prt} (https={https})...")
    out = run_nuclei(tgt, port=prt, use_https=https)
    for item in out["findings"]:
        print_info(f"  [{item['severity']}] {item['name']}")
    print_info(f"Error: {out['error'] or 'none'}")
