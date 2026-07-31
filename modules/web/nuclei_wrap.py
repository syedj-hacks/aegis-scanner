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
import re

from modules.utils.error_handler import run_tool
from modules.utils.config import get_rate_limits
from modules.utils.logger import log_finding
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

# A nuclei template whose *id* is itself a CVE identifier — the whole of
# nuclei-templates/**/cves/ is named this way (e.g. CVE-2025-46817.yaml).
# Anchored and case-insensitive; the year is 4 digits, the sequence 4 or
# more (CVE-2014-6271 through CVE-2025-100000+).
_CVE_TEMPLATE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _cve_from_template(template_id: str, classification: dict) -> str:
    """
    Best available CVE id for a template match, or None.

    `info.classification.cve-id` is the documented field and is preferred
    when present. It is frequently ABSENT, though — none of the four Redis
    Lua templates (CVE-2025-46817/46818/46819/49844) carry a classification
    block at all, yet every one of them is named for the CVE it detects.
    Falling back to a CVE-shaped template id recovers that, and recovers it
    from nuclei's own output rather than guessing: the id is the upstream
    template author's own statement of which CVE the template matches.

    Nothing is invented — a template whose id is not CVE-shaped (e.g.
    `exposed-redis`) still yields None.
    """
    cve_ids = (classification or {}).get("cve-id") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    if cve_ids:
        # A template can map to more than one CVE; joined into one string
        # since db.py's cve_id column holds a single TEXT value, same as
        # every other producer.
        return ",".join(cve_ids)

    template_id = (template_id or "").strip()
    if _CVE_TEMPLATE_ID.match(template_id):
        return template_id.upper()
    return None


def _cvss_from_classification(classification: dict):
    """
    `info.classification.cvss-score` as a float, or None.

    Read because nuclei supplies it for a good number of templates
    (exposed-redis carries 7.2) and the reports were rendering "not scored"
    for every nuclei finding regardless. A non-numeric or out-of-range
    value is discarded rather than stored — a bogus score is worse than no
    score, and severity.py already has a heuristic for the None case.
    """
    raw = (classification or {}).get("cvss-score")
    if raw is None:
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _matched_port(obj: dict):
    """
    The port nuclei reports for a match, as an int, or None.

    Prefers nuclei's explicit `port` field and falls back to the trailing
    ":<port>" of `matched-at` / `url` for older nuclei builds that omit it.
    Returns None rather than a guess when neither is usable, which leaves
    the caller's probed port in place — the previous behaviour.
    """
    raw = obj.get("port")
    if raw is None:
        for field in ("matched-at", "url", "host"):
            value = str(obj.get(field) or "")
            # Take the last colon-separated chunk, but only when it is
            # digits: an IPv6 literal or a "http://host/a:b" path must not
            # be mistaken for a port.
            tail = value.rsplit(":", 1)[-1].split("/")[0]
            if tail.isdigit():
                raw = tail
                break

    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


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
        {template_id, name, severity, description, matched_at, reference,
         cve_id}

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

        classification = info.get("classification") or {}
        template_id = obj.get("template-id") or obj.get("templateID") or ""

        findings.append({
            "template_id": template_id,
            "name": info.get("name") or "",
            "severity": info.get("severity") or "",
            "description": info.get("description") or info.get("name") or "",
            "matched_at": obj.get("matched-at") or obj.get("host") or "",
            "reference": references[0] if references else "",
            "cve_id": _cve_from_template(template_id, classification),
            "cvss": _cvss_from_classification(classification),
            # The port nuclei actually matched on, which is NOT always the
            # port it was pointed at: a template can pivot to its own
            # service. The Redis Lua templates hardcode Port "6379", so a
            # scan launched at http://host:80 matches on host:6379 and
            # reports `"port": 6379`. Recording the probed port instead
            # attributes a Redis flaw to the web server.
            "matched_port": _matched_port(obj),
            # nuclei's own protocol classification for the match ("http",
            # "tcp", "javascript", "dns"...). Not a service name, so it is
            # never rendered as one — see _common.nuclei_service().
            "protocol": (obj.get("type") or "").strip().lower(),
            "scheme": (obj.get("scheme") or "").strip().lower(),
        })

    return findings


def run_nuclei(target: str, port: int = 80, use_https: bool = False,
               severity: list = None, profile: str = None, auth=None) -> dict:
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
    result = {
        "tool": "nuclei",
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    url = _build_url(target, port, use_https)
    severity_list = severity or _DEFAULT_SEVERITY
    command = (
        ["nuclei", "-u", url, "-severity", ",".join(severity_list)]
        + _NUCLEI_BASE_ARGS
    )

    # Per-profile request-rate ceiling (-rate-limit, requests/second). None
    # for every profile today, which leaves nuclei on its own default (150/s)
    # exactly as before -- passing nothing and passing 150 are the same run,
    # but only passing nothing is guaranteed to stay the same if nuclei ever
    # changes that default, so the flag is genuinely omitted.
    rate_limit = get_rate_limits(profile).get("nuclei_rate_limit")
    if rate_limit:
        command += ["-rate-limit", str(int(rate_limit))]
    if auth is not None:
        command += auth.nuclei_args()

    pacing = f", rate-limit={int(rate_limit)}/s" if rate_limit else ""
    print_info(f"[Nuclei] Scanning {url} (severity={','.join(severity_list)}{pacing})")

    # run_tool() already logs this call's start/success/failure under the
    # "nuclei" tool name — no need to log it again here.
    tool_result = run_tool(target, "nuclei", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        # No partial output to salvage — a genuine failure (missing binary,
        # no templates, connection refused before the first match).
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "nuclei failed"
        print_error(f"[Nuclei] nuclei failed for {url} — {result['error']}")
        return result

    findings = _parse_nuclei_jsonl(result["raw_output"])
    result["findings"] = findings

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "nuclei_finding",
                # The port nuclei matched on, falling back to the probed
                # port. Logged the same way the profiles persist it, so
                # scan_errors.log and the findings table agree — a log line
                # saying port 80 for a row stored as 6379 is worse than no
                # log line, because it looks like the database is wrong.
                "port": f.get("matched_port") or port,
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
