"""
modules/profiles/webaudit.py
Webaudit profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

Web-focused profile: DNS resolution, a port scan restricted to web ports
(PROFILES['webaudit']['nmap_args'] already scopes nmap to 80,443,8080,8443),
the full web module (header audit, nikto, gobuster, dirb, whatweb, sslyze,
banner grabbing) against whatever of those ports came back open, CVE lookup
+ severity + remediation on the web findings, and a text report.

Wrapper availability
---------------------
PROFILES['webaudit']['tools'] also lists zaproxy, which has a wrapper
(modules/web/zap_wrap.py) but is deliberately not run in this profile — it
is wired into deepscan only, per the deepscan/webaudit/compliance tool
split (a full ZAP baseline scan is heavier than webaudit's fast-audit
scope). It is still logged as skipped here rather than silently omitted.
"""

from modules.utils.config import get_profile
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error, print_info,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure
from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.scanning.banner import grab_banners
from modules.web.header_check import check_headers
from modules.web.nikto_wrap import run_nikto
from modules.web.gobuster_wrap import run_gobuster
from modules.web.dirb_wrap import run_dirb
from modules.web.whatweb_wrap import run_whatweb
from modules.web.sslyze_wrap import run_sslyze
from modules.enrichment.cve_lookup import lookup_cves
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.report_txt import generate_txt_report

PROFILE_NAME = "webaudit"

_AVAILABLE_TOOLS = {"nslookup", "nmap", "nikto", "gobuster", "dirb", "whatweb", "sslyze", "banner_grab"}

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


def _findings_from_banners(banner_result: dict) -> list:
    return [
        {
            "type": "banner", "port": b["port"], "banner_text": b["banner_text"],
            "description": f"Service banner on port {b['port']}: {b['banner_text']}",
        }
        for b in banner_result.get("banners") or []
        if b.get("banner_text")
    ]


def run_webaudit(target: str):
    """
    Run the webaudit profile against `target`: DNS resolution, a nmap scan
    restricted to web ports, the full web module against whichever of those
    came back open, CVE/severity/remediation enrichment on the web findings,
    and a text report.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"WEBAUDIT — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    _warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME)

    scan_id = insert_scan(target, PROFILE_NAME)

    tool_results = []
    findings = []

    with scan_progress_bar(2, f"Webaudit: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Web port scan")

    header_results, nikto_results, gobuster_results = [], [], []
    dirb_results, whatweb_results, sslyze_results = [], [], []
    banner_result = {"banners": []}

    if open_ports:
        ports = [p["port"] for p in open_ports]
        banner_result = grab_banners(target, ports)
        tool_results.append(banner_result)

        with scan_progress_bar(len(open_ports) * 5, f"Web module: {target}") as advance:
            for port_entry in open_ports:
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

                if use_https:
                    sslyze_result = run_sslyze(target, port=port)
                    tool_results.append(sslyze_result)
                    sslyze_results.append(sslyze_result)
    else:
        print_info(f"[{PROFILE_NAME}] no web port open on {target} — web module skipped")

    findings.extend(_score_and_remediate(_findings_from_banners(banner_result)))

    for header_result in header_results:
        findings.extend(_score_and_remediate(_findings_from_headers(header_result)))
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
        print_error("Usage: python -m modules.profiles.webaudit <target>")
        sys.exit(1)

    sid, path = run_webaudit(sys.argv[1])
    print_success(f"Webaudit complete — scan_id={sid} report={path}")
