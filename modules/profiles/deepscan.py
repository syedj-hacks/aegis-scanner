"""
modules/profiles/deepscan.py
Deepscan profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

The full profile: everything quickscan does (DNS, profile-driven nmap port
scan, service detection) plus subdomain enumeration, OSINT, banner grabbing,
the full web module (header audit, nikto, gobuster, dirb, whatweb, nuclei,
ZAP baseline) on any discovered web port, CVE lookup + severity +
remediation on every finding, a real CONDITIONAL_TOOLS dispatch (wpscan,
sqlmap, hydra, enum4linux), and both a text and a PDF report.

Wrapper availability
---------------------
PROFILES['deepscan']['tools'] is "ALL" (the full top-20 toolset). Every tool
named anywhere in this codebase — nslookup, nmap (incl. its -sC script
results), nikto, gobuster, dirb, banner grabbing, subfinder/amass/
theHarvester, whatweb, nuclei, ZAP, and the four CONDITIONAL_TOOLS
(wpscan/sqlmap/hydra/enum4linux) — now has a real wrapper and is called or
dispatched here. sslyze is deliberately not run in this profile — it is
wired into compliance/webaudit only, per the deepscan/webaudit/compliance
tool split.

CONDITIONAL_TOOLS
-----------------
config.CONDITIONAL_TOOLS maps a tool to the flag that triggers it:
    wpscan      -> wordpress_fingerprinted  (set by gobuster_wrap.py)
    sqlmap      -> injectable_param_found   (set by _detect_injectable_candidates()
                                             below — a lightweight param-probe
                                             over gobuster/dirb's discovered
                                             script endpoints)
    hydra       -> login_service_found      (set by _detect_login_services()
                                             below — scans detect_services()
                                             output for ssh/ftp/rdp/telnet)
    enum4linux  -> smb_service_found        (set by _detect_smb_services()
                                             below — scans open_ports for
                                             139/445)
All four now have both a real detection producer and a real wrapper to
dispatch to.
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
from modules.scanning.banner import grab_banners
from modules.scanning.hydra_wrap import run_hydra
from modules.scanning.enum4linux_wrap import run_enum4linux
from modules.web.header_check import check_headers
from modules.web.nikto_wrap import run_nikto
from modules.web.gobuster_wrap import run_gobuster
from modules.web.dirb_wrap import run_dirb
from modules.web.whatweb_wrap import run_whatweb
from modules.web.nuclei_wrap import run_nuclei
from modules.web.zap_wrap import run_zap_baseline
from modules.web.wpscan_wrap import run_wpscan
from modules.web.sqlmap_wrap import run_sqlmap
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
    "dirb", "whatweb", "nuclei", "zaproxy", "banner_grab",
    "wpscan", "sqlmap", "hydra", "enum4linux",
}

# Ports/service-name hints used to decide which open ports are worth
# running the web module against.
_WEB_PORTS = (80, 443, 8080, 8443)
_WEB_SERVICE_HINTS = ("http", "https", "ssl")
_HTTPS_PORTS = (443, 8443)

# --- Lightweight param-probe (injectable_param_found producer) -----------
# Neither gobuster nor dirb discovers query-string parameters — they only
# brute-force paths. This heuristic treats any discovered script endpoint
# (.php/.asp/.aspx/.jsp/.cgi) as a *candidate* and appends a common
# parameter name to build a probe URL; sqlmap_wrap.run_sqlmap() below does
# the actual confirmation. Added here specifically to give
# CONDITIONAL_TOOLS['sqlmap'] ("injectable_param_found") a real producer.
_SCRIPT_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".cgi")
_PROBE_PARAM = "id"

# --- Login-service detection (login_service_found producer) --------------
# Maps an nmap/service-detect service name to the hydra module name that
# targets it. Added to give CONDITIONAL_TOOLS['hydra'] a real producer.
_LOGIN_SERVICE_MAP = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
}

# --- SMB detection (smb_service_found producer) ---------------------------
# Added to give CONDITIONAL_TOOLS['enum4linux'] a real producer.
_SMB_PORTS = (139, 445)


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
            raw = dict(svc, type="service_version")
            label = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
            raw["description"] = (
                f"{svc.get('service') or 'unknown service'}"
                + (f" ({label})" if label else "")
                + f" detected on port {svc.get('port')}"
            )
            findings.extend(_score_and_remediate([raw]))
    return findings


def _findings_from_headers(header_result: dict) -> list:
    port = header_result.get("port")
    findings = [
        {
            "type": "missing_security_header", "port": port, "header": name,
            "description": f"Missing security header: {name}",
        }
        for name in header_result.get("missing_headers") or []
    ]
    if header_result.get("server_banner"):
        findings.append({
            "type": "fingerprint_header", "port": port,
            "header": "Server", "value": header_result["server_banner"],
            "description": f"Server header discloses: {header_result['server_banner']}",
        })
    if header_result.get("powered_by"):
        findings.append({
            "type": "fingerprint_header", "port": port,
            "header": "X-Powered-By", "value": header_result["powered_by"],
            "description": f"X-Powered-By header discloses: {header_result['powered_by']}",
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
        {
            "type": "discovered_path", "port": port,
            "path": entry["path"], "status_code": entry["status_code"],
            "description": f"Discovered path {entry['path']} (HTTP {entry['status_code']})",
        }
        for entry in gobuster_result.get("discovered_paths") or []
    ]
    if gobuster_result.get("wordpress_fingerprinted"):
        findings.append({
            "type": "wordpress_fingerprinted", "port": port,
            "description": "WordPress installation fingerprinted via /wp-* marker path(s)",
        })
    return findings


def _findings_from_dirb(dirb_result: dict) -> list:
    port = dirb_result.get("port")
    return [
        {
            "type": "discovered_path", "port": port,
            "path": entry["path"], "status_code": entry["status_code"],
            "description": f"Discovered path {entry['path']} (HTTP {entry['status_code']}, via dirb)",
        }
        for entry in dirb_result.get("discovered_paths") or []
    ]


def _findings_from_banners(banner_result: dict) -> list:
    return [
        {
            "type": "banner", "port": b["port"], "banner_text": b["banner_text"],
            "description": f"Service banner on port {b['port']}: {b['banner_text']}",
        }
        for b in banner_result.get("banners") or []
        if b.get("banner_text")
    ]


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


def _findings_from_nuclei(nuclei_result: dict) -> list:
    port = nuclei_result.get("port")
    findings = []
    for f in nuclei_result.get("findings") or []:
        findings.append({
            "type": "nuclei_finding", "port": port,
            "template_id": f["template_id"], "severity": (f["severity"] or "medium").upper(),
            "reference": f["reference"],
            "description": f["description"] or f["name"],
        })
    return findings


def _findings_from_zap(zap_result: dict) -> list:
    port = zap_result.get("port")
    return [
        {
            "type": "zap_finding", "port": port,
            "name": f["name"], "severity": f["severity"],
            "description": f"ZAP {f['status']} alert: {f['name']}",
        }
        for f in zap_result.get("findings") or []
    ]


def _findings_from_wpscan(wpscan_result: dict, port) -> list:
    return [
        {
            "type": "wpscan_finding", "port": port,
            "component": f["component"], "reference": f["reference"],
            "severity": "HIGH",
            "description": f"{f['component']}: {f['title']}",
        }
        for f in wpscan_result.get("findings") or []
    ]


def _findings_from_sqlmap(sqlmap_result: dict, port) -> list:
    return [
        {
            "type": "sqlmap_finding", "port": port,
            "parameter": f["parameter"], "severity": "CRITICAL",
            "description": f"Confirmed SQL injection ({f['type']}) in parameter "
                            f"'{f['parameter']}': {f['title']}",
        }
        for f in sqlmap_result.get("findings") or []
    ]


def _findings_from_hydra(hydra_result: dict) -> list:
    return [
        {
            "type": "weak_credentials", "port": c.get("port"), "severity": "CRITICAL",
            "description": f"Weak {c['service']} credentials found: "
                            f"{c['login']}:{c['password']}",
        }
        for c in hydra_result.get("credentials_found") or []
    ]


def _findings_from_enum4linux(enum_result: dict) -> list:
    findings = [
        {
            "type": "smb_share", "severity": "MEDIUM",
            "description": f"SMB share exposed: {s['name']} ({s['type']})"
                            + (f" — {s['comment']}" if s.get("comment") else ""),
        }
        for s in enum_result.get("shares") or []
    ]
    findings += [
        {
            "type": "smb_user", "severity": "MEDIUM",
            "description": f"SMB user enumerated via null session: {u['user']}",
        }
        for u in enum_result.get("users") or []
    ]
    return findings


def _detect_injectable_candidates(gobuster_results: list, dirb_results: list) -> tuple:
    """
    Lightweight param-probe: look for a script-extension path already
    discovered by gobuster/dirb, and build a candidate URL by appending a
    common parameter name. Not a crawl or a confirmed vulnerability —
    sqlmap_wrap.run_sqlmap() does the actual confirmation.

    Returns (found: bool, candidate_url: str | None, port: int | None).
    """
    for result in list(gobuster_results) + list(dirb_results):
        port = result.get("port")
        for entry in result.get("discovered_paths") or []:
            path = entry.get("path", "")
            if entry.get("status_code") not in (200, 301, 302):
                continue
            if path.lower().endswith(_SCRIPT_EXTENSIONS):
                url = f"http://{result.get('target')}:{port}{path}?{_PROBE_PARAM}=1"
                return True, url, port
    return False, None, None


def _detect_login_services(services: list) -> tuple:
    """
    Scan detect_services() output for a login/auth protocol hydra can
    target. Returns (found: bool, hydra_service: str | None, port: int | None).
    """
    for svc in services:
        name = str(svc.get("service") or "").lower()
        hydra_service = _LOGIN_SERVICE_MAP.get(name)
        if hydra_service:
            return True, hydra_service, svc.get("port")
    return False, None, None


def _detect_smb_services(open_ports: list) -> bool:
    """Scan scan_ports() output for SMB/NetBIOS ports (139/445)."""
    return any(p.get("port") in _SMB_PORTS for p in open_ports)


def _check_conditional_tools(target: str, flags: dict, context: dict) -> tuple:
    """
    Evaluate config.CONDITIONAL_TOOLS against whatever flags this run
    actually produced, dispatch to the real wrapper for each tool whose
    condition was met, and return (raw_findings, tool_results) for the
    caller to score/insert.
    """
    new_findings = []
    new_tool_results = []

    for tool, flag_name in CONDITIONAL_TOOLS.items():
        if not flags.get(flag_name):
            continue
        if tool not in _AVAILABLE_TOOLS:
            msg = (
                f"condition '{flag_name}' was met (tool '{tool}' is applicable) "
                f"but no wrapper module for '{tool}' exists in this codebase yet "
                "— skipping"
            )
            log_tool_failure(target, tool, msg)
            print_warning(f"[{PROFILE_NAME}] {msg}")
            continue

        if tool == "wpscan":
            wp_port = context.get("wordpress_port")
            if wp_port is None:
                continue
            wp_result = run_wpscan(target, port=wp_port, use_https=context.get("wordpress_https", False))
            new_tool_results.append(wp_result)
            new_findings.extend(_findings_from_wpscan(wp_result, wp_port))

        elif tool == "sqlmap":
            candidate_url = context.get("injectable_url")
            if not candidate_url:
                continue
            sqlmap_result = run_sqlmap(target, candidate_url)
            new_tool_results.append(sqlmap_result)
            new_findings.extend(_findings_from_sqlmap(sqlmap_result, context.get("injectable_port")))

        elif tool == "hydra":
            login_service = context.get("login_service")
            if not login_service:
                continue
            hydra_result = run_hydra(target, login_service, port=context.get("login_port"))
            new_tool_results.append(hydra_result)
            new_findings.extend(_findings_from_hydra(hydra_result))

        elif tool == "enum4linux":
            enum_result = run_enum4linux(target)
            new_tool_results.append(enum_result)
            new_findings.extend(_findings_from_enum4linux(enum_result))

    return new_findings, new_tool_results


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
    dirb_results = []

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
    with scan_progress_bar(3, f"Scanning: {target}") as advance:
        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        nmap_scripts = port_result.get("scripts") or []
        advance("Port scan")

        ports = [p["port"] for p in open_ports]
        services = []
        if ports:
            service_result = detect_services(target, ports)
            tool_results.append(service_result)
            services = service_result.get("services") or []
        advance("Service detection")

        banner_result = {"banners": []}
        if ports:
            banner_result = grab_banners(target, ports)
            tool_results.append(banner_result)
        advance("Banner grabbing")

    # --- Web -----------------------------------------------------------
    print_phase("WEB")
    web_ports = [p for p in open_ports if _is_web_port(p)]
    header_results, nikto_results, whatweb_results = [], [], []
    nuclei_results, zap_results = [], []
    if web_ports:
        with scan_progress_bar(len(web_ports) * 7, f"Web audit: {target}") as advance:
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

                dirb_result = run_dirb(target, port=port, use_https=use_https)
                tool_results.append(dirb_result)
                dirb_results.append(dirb_result)
                advance(f"Dirb :{port}")

                whatweb_result = run_whatweb(target, port=port, use_https=use_https)
                tool_results.append(whatweb_result)
                whatweb_results.append(whatweb_result)
                advance(f"WhatWeb :{port}")

                severity_list = profile_cfg.get("nuclei_severity")
                nuclei_result = run_nuclei(target, port=port, use_https=use_https, severity=severity_list)
                tool_results.append(nuclei_result)
                nuclei_results.append(nuclei_result)
                advance(f"Nuclei :{port}")

                zap_result = run_zap_baseline(target, port=port, use_https=use_https)
                tool_results.append(zap_result)
                zap_results.append(zap_result)
                advance(f"ZAP :{port}")
    else:
        print_info(f"[{PROFILE_NAME}] no web port found among open ports — skipping web module")

    # --- Enrichment ------------------------------------------------
    print_phase("ENRICHMENT")
    findings.extend(_enrich_services(target, services))
    findings.extend(_score_and_remediate(_findings_from_banners(banner_result)))

    for script in nmap_scripts:
        findings.extend(_score_and_remediate([dict(script, type="nmap_script", description=(
            f"nmap script {script['script_id']}: {script['output'][:300]}"
        ))]))

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

    for dirb_result in dirb_results:
        findings.extend(_score_and_remediate(_findings_from_dirb(dirb_result)))

    for whatweb_result in whatweb_results:
        findings.extend(_score_and_remediate(_findings_from_whatweb(whatweb_result)))

    for nuclei_result in nuclei_results:
        findings.extend(_score_and_remediate(_findings_from_nuclei(nuclei_result)))

    for zap_result in zap_results:
        findings.extend(_score_and_remediate(_findings_from_zap(zap_result)))

    # --- Conditional tools ------------------------------------------
    wordpress_port, wordpress_https = None, False
    for gobuster_result in gobuster_results:
        if gobuster_result.get("wordpress_fingerprinted"):
            wordpress_port = gobuster_result.get("port")
            wordpress_https = _is_https_port({"port": wordpress_port})
            break

    injectable_found, injectable_url, injectable_port = _detect_injectable_candidates(
        gobuster_results, dirb_results,
    )
    login_found, login_service, login_port = _detect_login_services(services)
    smb_found = _detect_smb_services(open_ports)

    flags = {
        "wordpress_fingerprinted": wordpress_port is not None,
        "injectable_param_found": injectable_found,
        "login_service_found": login_found,
        "smb_service_found": smb_found,
    }
    context = {
        "wordpress_port": wordpress_port,
        "wordpress_https": wordpress_https,
        "injectable_url": injectable_url,
        "injectable_port": injectable_port,
        "login_service": login_service,
        "login_port": login_port,
    }
    conditional_findings, conditional_tool_results = _check_conditional_tools(target, flags, context)
    tool_results.extend(conditional_tool_results)
    findings.extend(_score_and_remediate(conditional_findings))

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
