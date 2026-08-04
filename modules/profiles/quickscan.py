"""
modules/profiles/quickscan.py
Quickscan profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

Thin orchestrator: reads modules.utils.config.PROFILES['quickscan'] for the
tool list / nmap_args and calls the recon -> scanning -> web -> reporting
modules in order. It does not reimplement anything those modules already do.

Flow: resolve_dns() -> scan_ports(profile='quickscan') -> detect_services()
-> whatweb + nuclei on whatever web port came back open -> persist findings
-> generate_txt_report().

Wrapper availability
---------------------
PROFILES['quickscan']['tools'] lists whatweb and nuclei alongside nslookup
and nmap, and both now have real wrapper modules
(modules/web/whatweb_wrap.py, modules/web/nuclei_wrap.py) — they used to be
logged as "no wrapper module exists" and silently skipped even though the
wrappers existed, which is exactly why quickscan and stealthscan used to
come back near-identical: quickscan wasn't actually running anything
webaudit/deepscan didn't already cover. They are wired in here now, scoped
to nuclei's fast critical/high severity filter
(PROFILES['quickscan']['nuclei_severity']) to keep this profile's whole
point — speed — intact.

Severity: whatweb/nuclei findings are scored via severity.py like every
other profile. The raw port/service/version rows from detect_services() are
still persisted unscored (NULL severity, graded LOW by summary.py at report
time) — deepscan's job is the full CVE/severity/remediation enrichment
pass over every service, not this one.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_info, print_success, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.scanning.service_detect import detect_services
from modules.web.whatweb_wrap import run_whatweb
from modules.web.nuclei_wrap import run_nuclei
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report
from modules.reporting.dashboard_live import update_live_data
from modules.profiles._common import (
    warn_unavailable_tools, count_and_report_tool_failures, persist_tool_run,
    finalise_reports,
    nuclei_description, nuclei_port, nuclei_service,
    is_web_port as _is_web_port, is_https_port as _is_https_port,
    findings_from_whatweb as _findings_from_whatweb,
)

PROFILE_NAME = "quickscan"

# Tools this profile actually calls — anything else PROFILES['quickscan']
# lists gets an accurate (not-run-here vs. no-wrapper-exists) note from
# warn_unavailable_tools() instead of silently vanishing.
_WIRED_TOOLS = {"nslookup", "nmap", "whatweb", "nuclei"}

# The web-port predicates and the whatweb mapper now live in _common.py
# (imported above under their previous private names) — quickscan,
# stealthscan and deepscan all need them, and three identical copies of a
# rule that is not per-profile is three places for it to go stale.


def _score_and_remediate(findings: list) -> list:
    return [get_remediation(score_finding(f)) for f in findings]


def _findings_from_nuclei(nuclei_result: dict) -> list:
    probed_port = nuclei_result.get("port")
    findings = []
    for f in nuclei_result.get("findings") or []:
        findings.append({
            "type": "nuclei_finding",
            # nuclei's matched port, not the probed one — see
            # _common.nuclei_port().
            "port": nuclei_port(f, probed_port),
            "service": nuclei_service(f),
            "template_id": f["template_id"], "severity": (f["severity"] or "medium").upper(),
            "reference": f["reference"], "cve_id": f.get("cve_id"),
            # nuclei's own matched-at — the host:port (or URL) it actually
            # matched on, which for a pivoting template is not the URL it
            # was launched against. Parsed by nuclei_wrap since the
            # matched-port fix and dropped at insert until findings gained
            # an endpoint column.
            "endpoint": f.get("matched_at") or None,
            # nuclei's own info.classification.cvss-score when the template
            # carries one; None otherwise, which leaves score_finding()'s
            # heuristic in charge exactly as before.
            "cvss": f.get("cvss"),
            "name": f.get("name") or "",
            "description": nuclei_description(f),
        })
    return findings


def run_quickscan(target: str, non_interactive: bool = False, auth=None):
    """
    Run the quickscan profile against `target`: DNS resolution, a fast
    profile-driven nmap port scan, service/version detection, a quick
    whatweb fingerprint + high-severity nuclei pass on whatever web port
    came back open, and a plain-text report.

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
    print_phase(f"QUICKSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)

    scan_id = insert_scan(target, PROFILE_NAME)
    update_live_data(target, [], current_tool="nmap port scan", progress_pct=10)

    tool_results = []
    findings = []

    with scan_progress_bar(3, f"Quickscan: {target}") as advance:
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
            # type="service_version" stamped at the source: these rows come
            # from nmap -sV and nothing else, so a report should never have
            # to infer that from which columns happen to be populated (see
            # stealth.py's insert and smoke_test8 §4.2).
            findings = [
                dict(svc, type="service_version")
                for svc in (service_result.get("services") or [])
            ]
        advance("Service detection")

    # Persisted here — before whatweb/nuclei even start — rather than held
    # until the very end: these product/version rows (service_detect.py's
    # {port, service, version, product}, product now a real db.py column)
    # are the whole point of this profile's speed/depth tradeoff, and an
    # interrupt during the web check below must not cost them.
    insert_findings_bulk(scan_id, findings)
    update_live_data(target, findings, current_tool="nmap -sV", progress_pct=55)

    web_ports = [p for p in open_ports if _is_web_port(p)]
    if web_ports:
        port_entry = web_ports[0]
        port = port_entry["port"]
        use_https = _is_https_port(port_entry)

        with scan_progress_bar(2, f"Quick web check: {target}") as advance:
            whatweb_result = run_whatweb(target, port=port, use_https=use_https)
            tool_results.append(whatweb_result)
            web_findings = _score_and_remediate(_findings_from_whatweb(whatweb_result))
            advance(f"WhatWeb :{port}")

            severity_list = profile_cfg.get("nuclei_severity")
            nuclei_result = run_nuclei(target, port=port, use_https=use_https, severity=severity_list)
            tool_results.append(nuclei_result)
            web_findings.extend(_score_and_remediate(_findings_from_nuclei(nuclei_result)))
            advance(f"Nuclei :{port}")

        insert_findings_bulk(scan_id, web_findings)
        update_live_data(target, web_findings, current_tool="nuclei", progress_pct=90)
        findings.extend(web_findings)
    else:
        print_info(f"[{PROFILE_NAME}] no web port found among open ports — whatweb/nuclei skipped")

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
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s)")
    return scan_id, txt_path, pdf_path, html_path, stats


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.quickscan <target>")
        sys.exit(1)

    sid, path, _pdf, _html, _stats = run_quickscan(sys.argv[1])
    print_success(f"Quickscan complete — scan_id={sid} report={path}")
