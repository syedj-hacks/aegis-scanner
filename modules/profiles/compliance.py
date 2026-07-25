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

sslyze and whatweb are both wired in now
------------------------------------------
Neither runs against every open port. sslyze targets specifically the
port(s) nmap's own ssl-enum-ciphers script identified as TLS-speaking — the
same evidence this profile already gathered, reused instead of re-probed.
whatweb runs against the same port(s): a compliance baseline benefits from
knowing what server/framework versions are actually serving that TLS
endpoint, not just how its ciphers are configured. If ssl-enum-ciphers
didn't fire on any port (e.g. it's not open) but 443 is open anyway, 443 is
tried as a fallback for both.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end
from modules.scanning.port_scanner import scan_ports
from modules.web.sslyze_wrap import run_sslyze
from modules.web.whatweb_wrap import run_whatweb
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.profiles._common import (
    warn_unavailable_tools, count_and_report_tool_failures, finalise_reports,
)

PROFILE_NAME = "compliance"

_WIRED_TOOLS = {"nmap", "sslyze", "whatweb"}

_SSL_SCRIPT_ID = "ssl-enum-ciphers"
_FALLBACK_TLS_PORT = 443


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


def _findings_from_whatweb(whatweb_result: dict) -> list:
    port = whatweb_result.get("port")
    return [
        {
            "type": "technology_fingerprint", "port": port,
            "name": tech["name"], "value": tech["value"],
            "description": f"Technology fingerprinted: {tech['name']}"
                            + (f" ({tech['value']})" if tech["value"] else ""),
        }
        for tech in whatweb_result.get("technologies") or []
    ]


def _tls_ports(scripts: list, open_ports: list) -> list:
    ports = sorted({s["port"] for s in scripts if s.get("script_id") == _SSL_SCRIPT_ID and s.get("port")})
    if ports:
        return ports
    if any(p.get("port") == _FALLBACK_TLS_PORT for p in open_ports):
        return [_FALLBACK_TLS_PORT]
    return []


def run_compliance(target: str, non_interactive: bool = False):
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
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    findings = []

    with scan_progress_bar(2, f"Compliance: {target}") as advance:
        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        scripts = port_result.get("scripts") or []
        advance("Compliance nmap scan")

        # type="open_port" stamped at the source — see stealth.py for why an
        # untyped row is a liability once a report has to classify it.
        findings.extend(dict(p, type="open_port") for p in open_ports)
        findings.extend(_score_and_remediate(_findings_from_scripts(scripts)))
        advance("Scoring script findings")

    # Persisted immediately after the nmap phase — this profile's core
    # deliverable (open ports + ssl-enum-ciphers/http-headers script
    # findings) is already complete at this point, so an interrupt during
    # the sslyze/whatweb TLS audit below can never cost it.
    insert_findings_bulk(scan_id, findings)

    tls_ports = _tls_ports(scripts, open_ports)
    if tls_ports:
        with scan_progress_bar(len(tls_ports) * 2, f"TLS audit: {target}") as advance:
            for port in tls_ports:
                port_findings = []

                sslyze_result = run_sslyze(target, port=port)
                tool_results.append(sslyze_result)
                port_findings.extend(_score_and_remediate(_findings_from_sslyze(sslyze_result)))
                advance(f"Sslyze :{port}")

                whatweb_result = run_whatweb(target, port=port, use_https=True)
                tool_results.append(whatweb_result)
                port_findings.extend(_score_and_remediate(_findings_from_whatweb(whatweb_result)))
                advance(f"WhatWeb :{port}")

                # Persisted per-port rather than batched across every TLS
                # port — a target with several TLS ports open no longer
                # risks losing earlier ports' findings to a later one's
                # interrupt.
                insert_findings_bulk(scan_id, port_findings)
                findings.extend(port_findings)

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": count_and_report_tool_failures(target, tool_results),
        "tools_skipped": sum(1 for r in tool_results if r.get("skipped")),
    }
    log_scan_end(target, stats)

    # Writes both reports, prunes the capped history and prints the
    # end-of-scan REPORT GENERATED banner — see _common.finalise_reports().
    txt_path, pdf_path = finalise_reports(
        target, PROFILE_NAME, scan_id, non_interactive=non_interactive
    )
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s)")
    return scan_id, txt_path, pdf_path, stats


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.compliance <target>")
        sys.exit(1)

    sid, path, _stats = run_compliance(sys.argv[1])
    print_success(f"Compliance scan complete — scan_id={sid} report={path}")
