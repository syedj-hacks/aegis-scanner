"""
modules/profiles/deepscan.py
Deepscan profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

The full profile: everything quickscan does (DNS, profile-driven nmap port
scan, service detection) plus subdomain enumeration, OSINT, the full web
module (header audit, nikto, gobuster) on any discovered web port, CVE
lookup + severity + remediation on every finding, a CONDITIONAL_TOOLS
evaluation, and both a text and a PDF report.

Wrapper availability
---------------------
PROFILES['deepscan']['tools'] is "ALL" (the full top-20 toolset), but this
codebase only has wrapper modules for nslookup, nmap, nikto and gobuster —
plus subfinder/amass (modules/recon/subdomain.py) and theHarvester
(modules/recon/osint.py), which no PROFILES entry names but which deepscan's
own description explicitly calls for. Tools named nowhere but in
CONDITIONAL_TOOLS (sqlmap, hydra, wpscan, enum4linux) have no wrapper
either. Nothing here fakes a call to a missing wrapper; every gap is
logged instead.

CONDITIONAL_TOOLS
-----------------
config.CONDITIONAL_TOOLS maps a tool to the flag that would trigger it.
Of the four, only `wordpress_fingerprinted` is ever actually produced by a
module in this codebase (modules/web/gobuster_wrap.py). The other three
flags (injectable_param_found, login_service_found, smb_service_found)
have no producer anywhere, so they are always False here — that is a gap
in the codebase, not something this profile can manufacture evidence for.
"""

from modules.utils.config import get_profile, CONDITIONAL_TOOLS
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error, print_info,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.recon.dns import resolve_dns
from modules.recon.subdomain import enumerate_subdomains
from modules.recon.osint import harvest_osint
from modules.scanning.port_scanner import scan_ports
from modules.scanning.service_detect import detect_services
from modules.web.header_check import check_headers
from modules.web.nikto_wrap import run_nikto
from modules.web.gobuster_wrap import run_gobuster
from modules.enrichment.cve_lookup import lookup_cves
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report
from modules.reporting.report_pdf import generate_pdf_report

PROFILE_NAME = "deepscan"

# Tool names with a real wrapper module in this codebase today.
_AVAILABLE_TOOLS = {
    "nslookup", "nmap", "nikto", "gobuster", "subfinder", "amass", "theharvester",
}

# Ports/service-name hints used to decide which open ports are worth
# running the web module against.
_WEB_PORTS = (80, 443, 8080, 8443)
_WEB_SERVICE_HINTS = ("http", "https", "ssl")
_HTTPS_PORTS = (443, 8443)


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


def _is_web_port(port_entry: dict) -> bool:
    port = port_entry.get("port")
    service = str(port_entry.get("service") or "").lower()
    if port in _WEB_PORTS:
        return True
    return any(hint in service for hint in _WEB_SERVICE_HINTS)


def _is_https_port(port_entry: dict) -> bool:
    port = port_entry.get("port")
    service = str(port_entry.get("service") or "").lower()
    return port in _HTTPS_PORTS or "ssl" in service or "https" in service


def _score_and_remediate(findings: list) -> list:
    out = []
    for finding in findings:
        scored = score_finding(finding)
        out.append(get_remediation(scored))
    return out


def _findings_from_cves(cves: list, port, service_name: str) -> list:
    findings = []
    for cve in cves:
        finding = dict(cve)
        finding["port"] = port
        finding["service"] = finding.get("product") or service_name
        findings.append(finding)
    return _score_and_remediate(findings)


def _enrich_services(target: str, services: list) -> list:
    """CVE-lookup each detected service; fall back to a heuristic grade
    when there is no product to query or NVD matched nothing."""
    findings = []
    for svc in services:
        product = svc.get("product")
        cves = []
        if product:
            cve_result = lookup_cves(product, svc.get("version"), target=target)
            cves = cve_result.get("cves") or []
        if cves:
            findings.extend(_findings_from_cves(cves, svc.get("port"), svc.get("service")))
        else:
            findings.extend(_score_and_remediate([dict(svc)]))
    return findings


def _findings_from_headers(header_result: dict) -> list:
    port = header_result.get("port")
    findings = [
        {"type": "missing_security_header", "port": port, "header": name}
        for name in header_result.get("missing_headers") or []
    ]
    if header_result.get("server_banner"):
        findings.append({
            "type": "fingerprint_header", "port": port,
            "header": "Server", "value": header_result["server_banner"],
        })
    if header_result.get("powered_by"):
        findings.append({
            "type": "fingerprint_header", "port": port,
            "header": "X-Powered-By", "value": header_result["powered_by"],
        })
    return findings


def _findings_from_nikto(nikto_result: dict) -> list:
    port = nikto_result.get("port")
    return [
        {"type": "nikto_finding", "port": port,
         "description": f["description"], "reference": f["reference"]}
        for f in nikto_result.get("findings") or []
    ]


def _findings_from_gobuster(gobuster_result: dict) -> list:
    port = gobuster_result.get("port")
    findings = [
        {"type": "discovered_path", "port": port,
         "path": entry["path"], "status_code": entry["status_code"]}
        for entry in gobuster_result.get("discovered_paths") or []
    ]
    if gobuster_result.get("wordpress_fingerprinted"):
        findings.append({"type": "wordpress_fingerprinted", "port": port})
    return findings


def _check_conditional_tools(target: str, flags: dict) -> None:
    """Evaluate config.CONDITIONAL_TOOLS against whatever flags this run
    actually produced, and run the gated tool only if its wrapper exists."""
    for tool, flag_name in CONDITIONAL_TOOLS.items():
        if not flags.get(flag_name):
            continue
        if tool in _AVAILABLE_TOOLS:
            continue  # would dispatch to the wrapper here if one existed
        msg = (
            f"condition '{flag_name}' was met (tool '{tool}' is applicable) "
            f"but no wrapper module for '{tool}' exists in this codebase yet "
            "— skipping"
        )
        log_tool_failure(target, tool, msg)
        print_warning(f"[{PROFILE_NAME}] {msg}")


def run_deepscan(target: str):
    """
    Run the full deepscan profile against `target`.

    Returns
    -------
    tuple: (scan_id: int, txt_report_path: str | None, pdf_report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"DEEPSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    _warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    findings = []
    gobuster_results = []

    # --- Recon -----------------------------------------------------
    print_phase("RECON")
    with scan_progress_bar(3, f"Recon: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        subdomain_result = enumerate_subdomains(target)
        tool_results.append(subdomain_result)
        advance("Subdomain enumeration")

        osint_result = harvest_osint(target)
        tool_results.append(osint_result)
        advance("OSINT")

    # --- Scanning ----------------------------------------------------
    print_phase("SCANNING")
    with scan_progress_bar(2, f"Scanning: {target}") as advance:
        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Port scan")

        ports = [p["port"] for p in open_ports]
        services = []
        if ports:
            service_result = detect_services(target, ports)
            tool_results.append(service_result)
            services = service_result.get("services") or []
        advance("Service detection")

    # --- Web -----------------------------------------------------------
    print_phase("WEB")
    web_ports = [p for p in open_ports if _is_web_port(p)]
    header_results, nikto_results = [], []
    if web_ports:
        with scan_progress_bar(len(web_ports) * 3, f"Web audit: {target}") as advance:
            for port_entry in web_ports:
                port = port_entry["port"]
                use_https = _is_https_port(port_entry)

                header_result = check_headers(target, port=port, use_https=use_https)
                tool_results.append(header_result)
                header_results.append(header_result)
                advance(f"Headers :{port}")

                nikto_result = run_nikto(target, port=port, use_https=use_https)
                tool_results.append(nikto_result)
                nikto_results.append(nikto_result)
                advance(f"Nikto :{port}")

                gobuster_result = run_gobuster(target, port=port, use_https=use_https)
                tool_results.append(gobuster_result)
                gobuster_results.append(gobuster_result)
                advance(f"Gobuster :{port}")
    else:
        print_info(f"[{PROFILE_NAME}] no web port found among open ports — skipping web module")

    # --- Enrichment ------------------------------------------------
    print_phase("ENRICHMENT")
    findings.extend(_enrich_services(target, services))

    for header_result in header_results:
        raw = _findings_from_headers(header_result)
        findings.extend(_score_and_remediate(raw))
        server_banner = header_result.get("server_banner")
        if server_banner:
            cve_result = lookup_cves(server_banner, target=target)
            findings.extend(_findings_from_cves(
                cve_result.get("cves") or [], header_result.get("port"), server_banner,
            ))

    for nikto_result in nikto_results:
        findings.extend(_score_and_remediate(_findings_from_nikto(nikto_result)))

    for gobuster_result in gobuster_results:
        findings.extend(_score_and_remediate(_findings_from_gobuster(gobuster_result)))

    flags = {
        "wordpress_fingerprinted": any(g.get("wordpress_fingerprinted") for g in gobuster_results),
        # No module in this codebase currently produces these flags.
        "injectable_param_found": False,
        "login_service_found": False,
        "smb_service_found": False,
    }
    _check_conditional_tools(target, flags)

    insert_findings_bulk(scan_id, findings)

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": sum(1 for r in tool_results if r.get("error")),
    }
    log_scan_end(target, stats)

    # --- Reporting -------------------------------------------------
    print_phase("REPORTING")
    txt_path = generate_txt_report(scan_id)
    pdf_path = generate_pdf_report(scan_id)

    print_success(
        f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s), "
        f"txt={txt_path}, pdf={pdf_path}"
    )
    return scan_id, txt_path, pdf_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.deepscan <target>")
        sys.exit(1)

    sid, txt, pdf = run_deepscan(sys.argv[1])
    print_success(f"Deepscan complete — scan_id={sid} txt={txt} pdf={pdf}")
