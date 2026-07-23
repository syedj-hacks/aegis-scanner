"""
modules/profiles/stealth.py
Stealth profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

PROFILES['stealthscan']['tools'] is just ["nslookup", "nmap"] — no whatweb,
nikto, gobuster or anything else — and its nmap_args
(-T1 -p- --randomize-hosts -Pn) are a single slow, paranoid-timing full-port
sweep. A second nmap -sV pass (as quickscan/deepscan run via
service_detect()) would double the probe traffic against the target, which
directly works against the "lighter tool set" this profile is meant to be,
so it is deliberately not called here. Open ports are persisted with
service names only (whatever nmap's default probe returned), no
version/CVE enrichment — this profile trades depth for a minimal footprint.

Both configured tools have real wrapper modules (modules/recon/dns.py,
modules/scanning/port_scanner.py), so nothing is skipped here today.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report

PROFILE_NAME = "stealthscan"

_AVAILABLE_TOOLS = {"nslookup", "nmap", "nikto", "gobuster"}


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


def run_stealthscan(target: str):
    """
    Run the stealth profile against `target`: DNS resolution and a single
    slow-timing, full-port nmap sweep (PROFILES['stealthscan']['nmap_args']),
    then a text report. No second probing pass is made against the target.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"STEALTHSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    _warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []

    with scan_progress_bar(3, f"Stealthscan: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Stealth port sweep")

        insert_findings_bulk(scan_id, open_ports)
        advance("Persisting findings")

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": sum(1 for r in tool_results if r.get("error")),
    }
    log_scan_end(target, stats)

    report_path = generate_txt_report(scan_id)
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(open_ports)} finding(s)")
    return scan_id, report_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.stealth <target>")
        sys.exit(1)

    sid, path = run_stealthscan(sys.argv[1])
    print_success(f"Stealthscan complete — scan_id={sid} report={path}")
