"""
modules/profiles/compliance.py
Compliance profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

PROFILES['compliance']['tools'] is ["nmap", "sslyze", "whatweb"] — notably
no "nslookup", unlike every other profile — with nmap_args
(-T4 --script ssl-enum-ciphers,http-headers). Per the instruction to base
this strictly on what config.py actually lists rather than assumptions
about what a "compliance" scan conventionally covers, DNS resolution is
still not run here.

nmap --script results are now captured
-----------------------------------------
port_scanner.py's XML parser now also extracts <script>/<hostscript>
results (see its _parse_nmap_scripts()), so the ssl-enum-ciphers/
http-headers script output this profile's nmap_args request is no longer
discarded — each script result becomes a scored, remediated finding. This
was the highest-priority gap in the whole codebase: compliance's entire
point is those two scripts, and previously only the underlying open-port
list ever reached the findings table.

sslyze is now wired in too
----------------------------
Rather than run sslyze against every open port, it targets specifically the
port(s) nmap's own ssl-enum-ciphers script identified as TLS-speaking — the
same evidence this profile already gathered, reused instead of re-probed.
If ssl-enum-ciphers didn't fire on any port (e.g. it's not open) but 443 is
open anyway, 443 is tried as a fallback.

whatweb still has no wrapper wired into *this* profile (see task scope) and
remains logged as skipped.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.scanning.port_scanner import scan_ports
from modules.web.sslyze_wrap import run_sslyze
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report

PROFILE_NAME = "compliance"

_AVAILABLE_TOOLS = {"nslookup", "nmap", "nikto", "gobuster", "sslyze"}

_SSL_SCRIPT_ID = "ssl-enum-ciphers"
_FALLBACK_TLS_PORT = 443


def _warn_unavailable_tools(target: str, tools, profile_name: str) -> None:
    if not tools or tools == "ALL":
        return
    for tool in tools:
        if tool not in _AVAILABLE_TOOLS:
            msg = (
                f"'{tool}' is listed in PROFILES['{profile_name}'] but has no "
                "wrapper module in this codebase yet — skipping"
            )
            log_tool_failure(target, tool, msg)
            print_warning(f"[{profile_name}] {msg}")


def _score_and_remediate(findings: list) -> list:
    out = []
    for finding in findings:
        scored = score_finding(finding)
        out.append(get_remediation(scored))
    return out


def _findings_from_scripts(scripts: list) -> list:
    findings = []
    for script in scripts:
        findings.append(dict(script, type="nmap_script", description=(
            f"nmap script {script['script_id']}: {script['output'][:300]}"
        )))
    return findings


def _findings_from_sslyze(sslyze_result: dict) -> list:
    port = sslyze_result.get("port")
    findings = []
    for f in sslyze_result.get("findings") or []:
        severity = "HIGH" if "legacy protocol" in f["issue"].lower() else "MEDIUM"
        findings.append({
            "type": "sslyze_finding", "port": port,
            "issue": f["issue"], "severity": severity,
            "description": f"{f['issue']}: {f['detail']}",
        })
    return findings


def _tls_ports(scripts: list, open_ports: list) -> list:
    ports = sorted({s["port"] for s in scripts if s.get("script_id") == _SSL_SCRIPT_ID and s.get("port")})
    if ports:
        return ports
    if any(p.get("port") == _FALLBACK_TLS_PORT for p in open_ports):
        return [_FALLBACK_TLS_PORT]
    return []


def run_compliance(target: str):
    """
    Run the compliance profile against `target`: the nmap scan configured by
    PROFILES['compliance']['nmap_args'] (its --script results now captured
    and scored), an sslyze pass against whatever port(s) ssl-enum-ciphers
    identified as TLS, then a text report.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"COMPLIANCE — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    _warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    findings = []

    with scan_progress_bar(2, f"Compliance: {target}") as advance:
        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        scripts = port_result.get("scripts") or []
        advance("Compliance nmap scan")

        findings.extend(open_ports)
        findings.extend(_score_and_remediate(_findings_from_scripts(scripts)))
        advance("Scoring script findings")

    sslyze_results = []
    tls_ports = _tls_ports(scripts, open_ports)
    if tls_ports:
        with scan_progress_bar(len(tls_ports), f"TLS audit: {target}") as advance:
            for port in tls_ports:
                sslyze_result = run_sslyze(target, port=port)
                tool_results.append(sslyze_result)
                sslyze_results.append(sslyze_result)
                advance(f"Sslyze :{port}")

    for sslyze_result in sslyze_results:
        findings.extend(_score_and_remediate(_findings_from_sslyze(sslyze_result)))

    insert_findings_bulk(scan_id, findings)

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": sum(1 for r in tool_results if r.get("error")),
    }
    log_scan_end(target, stats)

    report_path = generate_txt_report(scan_id)
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s)")
    return scan_id, report_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.compliance <target>")
        sys.exit(1)

    sid, path = run_compliance(sys.argv[1])
    print_success(f"Compliance scan complete — scan_id={sid} report={path}")
