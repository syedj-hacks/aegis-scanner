"""
modules/profiles/stealth.py
Stealth profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

PROFILES['stealthscan']['tools'] is just ["nslookup", "nmap"] — no whatweb,
nikto, gobuster or anything else — and its nmap_args are a single quiet,
polite-timing (-T2) scan of a small, fixed list of the ports that matter
for this project's assessments (see config.py's PROFILES['stealthscan']
comment: a full 65535-port '-p-' sweep at any quiet timing template was
measured live to be architecturally too slow — 60+ hours extrapolated at
-T2 — so this profile scans a curated port list instead of the whole
range). A second nmap -sV pass (as quickscan/deepscan run via
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
    scan_progress_bar, print_phase, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from database.db import insert_scan, insert_findings_bulk
from modules.profiles._common import (
    warn_unavailable_tools, count_and_report_tool_failures, finalise_reports,
)

PROFILE_NAME = "stealthscan"

# Both configured tools (nslookup, nmap) are wired in here — nothing else
# this profile lists needs a wrapper. Migrated onto the shared
# GLOBAL_AVAILABLE_TOOLS set (modules/profiles/_common.py) instead of a
# profile-local, easily-stale _AVAILABLE_TOOLS copy, matching
# quickscan.py/webaudit.py/compliance.py.
_WIRED_TOOLS = {"nslookup", "nmap"}


def run_stealthscan(target: str, non_interactive: bool = False):
    """
    Run the stealth profile against `target`: DNS resolution and a single
    quiet, curated-port-list nmap scan (PROFILES['stealthscan']['nmap_args']),
    then a text report. No second probing pass is made against the target.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"STEALTHSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    open_ports = []

    with scan_progress_bar(3, f"Stealthscan: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Stealth port sweep")

        # Persisted as soon as the (possibly chunked, possibly
        # partially-recovered — see port_scanner.py) sweep returns, rather
        # than held any longer in memory — this is the last step of this
        # profile's flow anyway, but keeping the insert immediately after
        # the data exists (not gated behind anything further) means an
        # interrupt anywhere after this point can never cost these findings.
        #
        # type="open_port" is stamped on here rather than left off: a row
        # inserted with no finding_type has to be classified by SHAPE when a
        # report reads it back, and shape-sniffing on columns every SQLite
        # row carries is exactly what mislabelled a stealthscan open port as
        # a nikto finding (smoke_test8 §4.2). A finding that declares what it
        # is cannot be guessed at wrongly.
        insert_findings_bulk(scan_id, [dict(p, type="open_port") for p in open_ports])
        advance("Persisting findings")

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
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(open_ports)} finding(s)")
    return scan_id, txt_path, pdf_path, stats


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.stealth <target>")
        sys.exit(1)

    sid, path, _stats = run_stealthscan(sys.argv[1])
    print_success(f"Stealthscan complete — scan_id={sid} report={path}")
