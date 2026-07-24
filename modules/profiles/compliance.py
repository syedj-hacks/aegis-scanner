"""
modules/profiles/compliance.py
Compliance profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

PROFILES['compliance']['tools'] is ["nmap", "sslyze", "whatweb"] — notably
no "nslookup", unlike every other profile — with nmap_args
(-T4 --script ssl-enum-ciphers,http-headers). Per the instruction to base
this strictly on what config.py actually lists rather than assumptions
about what a "compliance" scan conventionally covers, DNS resolution is
not run here (it is not in this profile's tool list), and only the nmap
scan actually executes.

Wrapper availability
---------------------
Neither sslyze nor whatweb has a wrapper module anywhere in this codebase,
so both are logged as skipped rather than faked. Note also that
modules/scanning/port_scanner.py's XML parser only extracts
port/protocol/service/state — it does not parse nmap's <script> output —
so the ssl-enum-ciphers/http-headers script results this profile's
nmap_args request are not currently captured into structured findings even
though the script runs; only the underlying open-port data is.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.scanning.port_scanner import scan_ports
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report

PROFILE_NAME = "compliance"

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


def run_compliance(target: str):
    """
    Run the compliance profile against `target`: the nmap scan configured by
    PROFILES['compliance']['nmap_args'], then a text report. sslyze/whatweb
    are configured but have no wrapper module, so they are logged as skipped.

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

    with scan_progress_bar(2, f"Compliance: {target}") as advance:
        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Compliance nmap scan")

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
        print_error("Usage: python -m modules.profiles.compliance <target>")
        sys.exit(1)

    sid, path = run_compliance(sys.argv[1])
    print_success(f"Compliance scan complete — scan_id={sid} report={path}")
