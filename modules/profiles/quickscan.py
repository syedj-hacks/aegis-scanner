"""
modules/profiles/quickscan.py
Quickscan profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

Thin orchestrator: reads modules.utils.config.PROFILES['quickscan'] for the
tool list / nmap_args and calls the recon -> scanning -> reporting modules
in order. It does not reimplement anything those modules already do.

Flow: resolve_dns() -> scan_ports(profile='quickscan') -> detect_services()
-> persist findings -> generate_txt_report().

Wrapper availability
---------------------
PROFILES['quickscan']['tools'] lists whatweb and nuclei alongside nslookup
and nmap, but no wrapper module for whatweb/nuclei exists anywhere in this
codebase (only modules/recon/dns.py covers nslookup and
modules/scanning/port_scanner.py covers nmap). Rather than invent a stub
call to a tool with no wrapper, this profile logs a clear warning for any
configured tool it cannot actually run and proceeds with what it has.

Severity is intentionally not scored here: quickscan persists the raw
port/service/version columns db.py expects, and a NULL severity is graded
LOW by summary.py at report time — the same graceful default the reporting
layer already documents. Full severity/CVE enrichment is deepscan's job.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.scanning.service_detect import detect_services
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report

PROFILE_NAME = "quickscan"

# Tool names with a real wrapper module in this codebase today. Anything a
# profile's config.PROFILES tool list names beyond this set gets logged as
# skipped rather than faked.
_AVAILABLE_TOOLS = {"nslookup", "nmap", "nikto", "gobuster"}


def _warn_unavailable_tools(target: str, tools, profile_name: str) -> None:
    """Log+warn about any configured tool with no wrapper module. No-op for 'ALL'."""
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


def run_quickscan(target: str):
    """
    Run the quickscan profile against `target`: DNS resolution, a fast
    profile-driven nmap port scan, service/version detection on whatever
    ports came back open, and a plain-text report.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"QUICKSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    _warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    findings = []

    with scan_progress_bar(4, f"Quickscan: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Port scan")

        ports = [p["port"] for p in open_ports]
        if ports:
            service_result = detect_services(target, ports)
            tool_results.append(service_result)
            findings = service_result.get("services") or []
        advance("Service detection")

        insert_findings_bulk(scan_id, findings)
        advance("Persisting findings")

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
        print_error("Usage: python -m modules.profiles.quickscan <target>")
        sys.exit(1)

    sid, path = run_quickscan(sys.argv[1])
    print_success(f"Quickscan complete — scan_id={sid} report={path}")
