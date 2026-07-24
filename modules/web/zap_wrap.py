"""
modules/web/zap_wrap.py
OWASP ZAP baseline scan wrapper for Aegis Scanner (web layer).

Runs ZAP's `zap-baseline.py` helper script (a spidered passive scan — no
active/attack payloads, safe to run against a target that hasn't explicitly
opted into active testing) through error_handler.run_tool() and parses its
plain-text alert summary.

Exit-code quirk
----------------
zap-baseline.py uses its exit code as a pass/fail policy signal, not a
"did it run" signal: 0 = no alerts, 1 = WARN-level alerts present, 2 =
FAIL-level alerts present. A non-zero exit is therefore not necessarily a
run_tool() failure — the alert text on stdout is what's checked instead,
the same approach nikto_wrap.py uses for its own "exits 0 either way" quirk
in reverse.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -j : use the Ajax spider in addition to the traditional one
# -I : do not return a non-zero exit code for WARN-level alerts (only
#      FAIL); kept anyway so the plain-text output is still parsed
#      regardless of exit code, but this reduces false "failure" logging
_ZAP_BASE_ARGS = ["-I"]

# Matches zap-baseline.py's summary lines, e.g.:
#   WARN-NEW: X-Frame-Options Header Not Set [10020] x 2
#   FAIL-NEW: SQL Injection [40018] x 1
_ALERT_LINE = re.compile(
    r"^(?P<status>WARN|FAIL)-(?:NEW|INF)?:?\s*(?P<name>.+?)\s+\[(?P<rule_id>\d+)\]"
)

# Coarse status -> severity mapping. ZAP itself carries a finer Risk rating
# in its JSON report, but the baseline script's plain-text output only
# exposes WARN/FAIL/INFO, so that's what's available to grade on here.
_STATUS_SEVERITY = {"FAIL": "HIGH", "WARN": "MEDIUM"}


def _build_url(target: str, port: int, use_https: bool) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    host = target if port == default_port else f"{target}:{port}"
    return f"{scheme}://{host}"


def _parse_zap_output(stdout: str) -> list:
    """
    Parse zap-baseline.py's plain-text alert lines into a list of:
        {rule_id, name, status, severity}

    PASS lines are not findings and are skipped. Malformed/empty input
    yields [].
    """
    findings = []
    seen = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        match = _ALERT_LINE.match(line)
        if not match:
            continue

        rule_id = match.group("rule_id")
        name = match.group("name").strip()
        status = match.group("status")

        key = (rule_id, name)
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "rule_id": rule_id,
            "name": name,
            "status": status,
            "severity": _STATUS_SEVERITY.get(status, "MEDIUM"),
        })

    return findings


def run_zap_baseline(target: str, port: int = 80, use_https: bool = False) -> dict:
    """
    Run a ZAP baseline (passive) scan against `target`'s web service.

    Parameters
    ----------
    target    : str   host / IP (a full http(s):// URL is also accepted)
    port      : int   web service port (default 80)
    use_https : bool  scan over TLS

    Returns
    -------
    dict:
        target      : str
        port        : int
        findings    : list[dict]  {rule_id, name, status, severity}
        raw_output  : str         zap-baseline.py's stdout
        error       : str | None  human-readable failure reason, if any

    Never raises. A missing zap-baseline.py script (it ships separately from
    the `zaproxy` apt package on some Kali releases) or an unreachable
    target come back as error set + findings empty; WARN/FAIL alerts are
    normal output, not failures, and are always parsed when present.
    """
    log_tool_start(target, "zaproxy")

    result = {
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
    }

    url = _build_url(target, port, use_https)
    command = ["zap-baseline.py", "-t", url] + _ZAP_BASE_ARGS

    print_info(f"[ZAP] Running baseline scan against {url}")

    tool_result = run_tool(target, "zaproxy", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success") and not result["raw_output"].strip():
        err = tool_result.get("error") or tool_result.get("stderr") or "zap-baseline.py failed"
        result["error"] = err
        log_tool_failure(target, "zaproxy", err)
        print_error(f"[ZAP] baseline scan failed for {url} — {err}")
        return result

    findings = _parse_zap_output(result["raw_output"])
    result["findings"] = findings

    log_tool_success(target, "zaproxy", tool_result.get("duration"))

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "zap_finding",
                "port": port,
                "rule_id": f["rule_id"],
                "name": f["name"],
                "status": f["status"],
            })
            print_success(f"[ZAP] [{f['status']}] {f['name']} ({f['rule_id']})")
        print_info(f"[ZAP] {url} — {len(findings)} alert(s)")
    else:
        print_warning(f"[ZAP] {url} — scan completed, no alerts")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.zap_wrap <target> [port] [https]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    https = len(sys.argv) > 3 and sys.argv[3].lower() in ("https", "true", "1", "yes")

    print_info(f"Running ZAP baseline against {tgt}:{prt} (https={https})...")
    out = run_zap_baseline(tgt, port=prt, use_https=https)
    for item in out["findings"]:
        print_info(f"  [{item['status']}] {item['name']}")
    print_info(f"Error: {out['error'] or 'none'}")
