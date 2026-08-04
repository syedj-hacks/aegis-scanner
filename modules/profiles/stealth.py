"""
modules/profiles/stealth.py
Stealth profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

PROFILES['stealthscan']['tools'] is a deliberately short list — no nikto,
gobuster, ZAP or anything else that sweeps — and its nmap_args are a single
quiet, polite-timing (-T2) scan of a small, fixed list of the ports that matter
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

whatweb, and only whatweb
-------------------------
A single whatweb fingerprint runs against the first open web port. It is
the one web tool whose cost fits this profile: whatweb issues a handful of
requests to one URL and reads the responses, which against a host that has
already been port-scanned is negligible additional exposure, and it turns
"port 80 is open" into "port 80 is nginx 1.18 running WordPress" — the
difference between an open-port list and a usable one.

nuclei is deliberately NOT run here, and the omission is the point. nuclei
fires thousands of templated HTTP requests per port; running it would make
stealthscan the second-loudest profile in the framework while its nmap
half was still politely pacing itself at -T2 to stay quiet. A profile that
is quiet in one half and loud in the other is not a quiet profile, it is a
profile that misrepresents itself — and anyone who wants nuclei has
quickscan (fast, critical/high) and deepscan (everything) already.
PROFILES['stealthscan']['nuclei_severity'] is left in config.py untouched
so those two profiles' shared config shape is unchanged; this profile just
never reads it.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_info, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.web.whatweb_wrap import run_whatweb
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.dashboard_live import update_live_data
from modules.profiles._common import (
    warn_unavailable_tools, count_and_report_tool_failures, persist_tool_run,
    finalise_reports, is_web_port, is_https_port, findings_from_whatweb,
)

PROFILE_NAME = "stealthscan"

# nslookup, nmap and whatweb are wired in here. nuclei is listed in
# PROFILES['stealthscan']['tools'] on purpose but is NOT in this set, so
# warn_unavailable_tools() reports it as "has a wrapper but is not run by
# this profile (by design)" — an accurate, discoverable note rather than a
# silent absence. See the docstring for why.
_WIRED_TOOLS = {"nslookup", "nmap", "whatweb"}


def _score_and_remediate(findings: list) -> list:
    return [get_remediation(score_finding(f)) for f in findings]


def run_stealthscan(target: str, non_interactive: bool = False, auth=None):
    """
    Run the stealth profile against `target`: DNS resolution and a single
    quiet, curated-port-list nmap scan (PROFILES['stealthscan']['nmap_args']),
    then a text report. No second probing pass is made against the target.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    
    `auth` is accepted and deliberately unused: every profile is dispatched
    through the same call in aegis.py/multi_target.py, so the signature has
    to be uniform. This profile runs no tool that takes a credential, and
    silently accepting one it cannot use is better than a TypeError only
    some profiles raise -- announce_auth() in the profiles that DO use it is
    what tells the user where auth actually applies.
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"STEALTHSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)

    scan_id = insert_scan(target, PROFILE_NAME)
    update_live_data(target, [], current_tool="quiet nmap sweep (-T2)", progress_pct=10)

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
        port_findings = [dict(p, type="open_port") for p in open_ports]
        insert_findings_bulk(scan_id, port_findings)
        update_live_data(target, port_findings, current_tool="nmap", progress_pct=65)
        advance("Persisting findings")

    # One whatweb fingerprint against the first open web port — see the
    # module docstring for why this tool and no other. Kept outside the
    # progress bar above so the open-port findings are already committed
    # before any further request leaves this machine.
    findings = []
    web_ports = [p for p in open_ports if is_web_port(p)]
    if web_ports:
        port_entry = web_ports[0]
        port = port_entry["port"]
        with scan_progress_bar(1, f"Quiet web check: {target}") as advance:
            whatweb_result = run_whatweb(
                target, port=port, use_https=is_https_port(port_entry)
            )
            tool_results.append(whatweb_result)
            findings = _score_and_remediate(findings_from_whatweb(whatweb_result))
            advance(f"WhatWeb :{port}")
        insert_findings_bulk(scan_id, findings)
        update_live_data(target, findings, current_tool="whatweb", progress_pct=92)
    else:
        print_info(
            f"[{PROFILE_NAME}] no web port found among open ports — whatweb skipped"
        )

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": count_and_report_tool_failures(target, tool_results),
        "tools_skipped": sum(1 for r in tool_results if r.get("skipped")),
    }
    persist_tool_run(scan_id, tool_results)
    log_scan_end(target, stats)

    # Writes both reports, prunes the capped history and prints the
    # end-of-scan REPORT GENERATED banner — see _common.finalise_reports().
    txt_path, pdf_path, html_path = finalise_reports(
        target, PROFILE_NAME, scan_id, non_interactive=non_interactive
    )
    print_success(
        f"[{PROFILE_NAME}] scan {scan_id} complete — "
        f"{len(open_ports) + len(findings)} finding(s)"
    )
    return scan_id, txt_path, pdf_path, html_path, stats


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.stealth <target>")
        sys.exit(1)

    sid, path, _pdf, _html, _stats = run_stealthscan(sys.argv[1])
    print_success(f"Stealthscan complete — scan_id={sid} report={path}")
