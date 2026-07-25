"""
modules/profiles/deepscan.py
Deepscan profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

The full profile: everything quickscan does (DNS, profile-driven nmap port
scan, service detection) plus subdomain enumeration, OSINT, banner grabbing,
the full web module (header audit, nikto, gobuster, dirb, whatweb, nuclei,
ZAP baseline) on any discovered web port, a dedicated cross-site-scripting
pass (nuclei `-dast -tags xss` via modules/web/xss_wrap.py, fuzzed against
parameterised URLs built from the discovered script endpoints), CVE lookup +
severity + remediation on every finding, a real CONDITIONAL_TOOLS dispatch
(wpscan, sqlmap, hydra, enum4linux — sqlmap now also reads back safe DB
metadata for a confirmed injection), and both a text and a PDF report. The
confirmed SQLi/XSS findings carry the exact payload, parameter/endpoint and
a response snippet, rendered in the report's Injection & Scripting section.

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

import time

from modules.utils.config import get_profile, CONDITIONAL_TOOLS, PROFILE_TIME_BUDGET_SECONDS
from modules.utils.display import (
    scan_progress_bar, print_phase, print_warning, print_success, print_error, print_info,
)
from modules.utils.logger import log_scan_start, log_scan_end, log_tool_failure, get_logger
from modules.profiles._common import (
    warn_unavailable_tools, GLOBAL_AVAILABLE_TOOLS,
    count_and_report_tool_failures, web_param_candidates, finalise_reports,
    nuclei_description, nuclei_port, nuclei_service,
)
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
from modules.web.xss_wrap import run_xss
from modules.enrichment.cve_lookup import lookup_cves, lookup_cves_from_banner
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk

PROFILE_NAME = "deepscan"

# Tool names this profile wires in — kept as an alias of the shared,
# codebase-wide GLOBAL_AVAILABLE_TOOLS (modules/profiles/_common.py) rather
# than its own local copy, which used to drift out of sync with the other
# profiles' sets (Known Issue #8's residual gap).
_AVAILABLE_TOOLS = GLOBAL_AVAILABLE_TOOLS

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


def _findings_from_nuclei(nuclei_result: dict, seen: set = None) -> list:
    """
    Map one nuclei run's matches to findings, skipping any already recorded.

    `seen` is a set of (template_id, port) pairs accumulated ACROSS this
    profile's per-port web loop, and it is required rather than optional in
    practice: this profile runs nuclei once per web port, and a template
    that pivots to its own service matches identically from every one of
    them. The Redis Lua templates connect to 6379 regardless of the URL, so
    a host with 80 and 443 open produced the same Redis finding twice —
    once per probe.

    That only became a true duplicate once the matched port started being
    recorded correctly: with the probed port, the two copies read as "port
    80" and "port 443" and looked like different findings. Observed live on
    scan 127, where "Redis - Default Logins" was inserted twice and the
    report-render dedup pass had to collapse it. Filtering here means the
    duplicate is never written in the first place, so the database row
    count and the report's finding count agree.
    """
    probed_port = nuclei_result.get("port")
    findings = []
    for f in nuclei_result.get("findings") or []:
        matched_port = nuclei_port(f, probed_port)
        if seen is not None:
            key = (f.get("template_id"), matched_port)
            if key in seen:
                print_info(
                    f"[{PROFILE_NAME}] nuclei template {f.get('template_id')} "
                    f"already matched on port {matched_port} from an earlier "
                    f"probe — not recorded twice"
                )
                continue
            seen.add(key)
        findings.append({
            "type": "nuclei_finding",
            "port": matched_port,
            "service": nuclei_service(f),
            "template_id": f["template_id"], "severity": (f["severity"] or "medium").upper(),
            "reference": f["reference"], "cve_id": f.get("cve_id"),
            # See _common.nuclei_description() / nuclei_port(); the two
            # profiles' nuclei mappers are kept identical on purpose.
            "cvss": f.get("cvss"),
            "name": f.get("name") or "",
            "description": nuclei_description(f),
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
    """
    Build SQLi findings carrying the concrete injection evidence the
    report's Injection & Scripting section renders: the exact payload, the
    parameter/endpoint it was sent against, and the read-only metadata
    sqlmap extracted (DB engine/version, current DB, database names) as the
    proof-of-exploitation snippet.
    """
    metadata = sqlmap_result.get("metadata") or {}
    url = sqlmap_result.get("url") or ""

    meta_bits = []
    if metadata.get("dbms"):
        meta_bits.append(f"back-end DBMS: {metadata['dbms']}")
    if metadata.get("banner"):
        meta_bits.append(f"banner: {metadata['banner']}")
    if metadata.get("current_db"):
        meta_bits.append(f"current database: {metadata['current_db']}")
    if metadata.get("databases"):
        meta_bits.append(f"databases: {', '.join(metadata['databases'])}")
    evidence = "; ".join(meta_bits)

    findings = []
    for f in sqlmap_result.get("findings") or []:
        techniques = ", ".join(t["type"] for t in f.get("techniques") or []) or f.get("type") or "unknown technique"
        description = (
            f"Confirmed SQL injection in parameter '{f['parameter']}' ({f['method']}) "
            f"at {url} via {techniques}."
        )
        if evidence:
            description += f" Read-only enumeration extracted — {evidence}."
        findings.append({
            "type": "sqlmap_finding", "port": port,
            "parameter": f["parameter"], "severity": "CRITICAL",
            "payload": f.get("payload") or "",
            "endpoint": url,
            "evidence": evidence,
            "description": description,
        })
    return findings


def _findings_from_xss(xss_result: dict, port) -> list:
    """
    Build reflected-XSS findings carrying the payload nuclei injected, the
    parameter/endpoint it was injected into, and the response snippet
    showing the payload reflected back — the evidence the report's Injection
    & Scripting section renders.
    """
    findings = []
    for f in xss_result.get("findings") or []:
        description = (
            f"Reflected cross-site scripting in parameter '{f['parameter']}' "
            f"({f['method']}) at {f['endpoint']} — the injected payload is "
            f"reflected unescaped in the response body."
        )
        findings.append({
            "type": "xss_finding", "port": port,
            "parameter": f["parameter"],
            "severity": (f["severity"] or "medium").upper(),
            "payload": f["payload"],
            "endpoint": f["endpoint"],
            "evidence": f["evidence"],
            "reference": f.get("reference"),
            "description": description,
        })
    return findings


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
            # Not a failure or a skip — this run's target simply never
            # produced the signal (e.g. no WordPress fingerprint, no SMB
            # port) that would make this tool applicable. Logged explicitly
            # so "why didn't wpscan/sqlmap/hydra/enum4linux run" always has
            # an answer in scan_errors.log instead of the tool just being
            # invisibly absent from the run.
            msg = f"condition '{flag_name}' not met — skipping {tool}"
            get_logger(target).info(f"[{PROFILE_NAME}] {msg}")
            print_info(f"[{PROFILE_NAME}] {msg}")
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


def run_deepscan(target: str, non_interactive: bool = False):
    """
    Run the full deepscan profile against `target`.

    Returns
    -------
    tuple: (scan_id: int, txt_report_path: str | None, pdf_report_path: str | None)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"DEEPSCAN — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _AVAILABLE_TOOLS)

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
        advance("Port scan")

        ports = [p["port"] for p in open_ports]
        services = []
        # -sC (default script) results now come from this targeted pass,
        # not the initial full-range scan above — see config.py's
        # PROFILES['deepscan']['nmap_args'] comment for why.
        nmap_scripts = []
        if ports:
            service_result = detect_services(target, ports)
            tool_results.append(service_result)
            services = service_result.get("services") or []
            nmap_scripts = service_result.get("scripts") or []
        advance("Service detection")

        # banner_grab is only useful on ports NOT already known to be
        # HTTP(S) — those don't send an unsolicited banner (they wait for a
        # request first), so probing them here always times out for no
        # data: -sV/header_check already cover them via a real request.
        non_web_ports = [p["port"] for p in open_ports if not _is_web_port(p)]
        banner_result = {"banners": []}
        if non_web_ports:
            banner_result = grab_banners(target, non_web_ports)
            tool_results.append(banner_result)
        advance("Banner grabbing")

    # Recon + scanning-phase findings are persisted here, before the web
    # module even starts — service/version + CVE enrichment, nmap --script
    # results and banners are already final at this point, so an interrupt
    # anywhere in the (often much longer) web phase below can't cost them.
    findings.extend(_enrich_services(target, services))
    findings.extend(_score_and_remediate(_findings_from_banners(banner_result)))
    for script in nmap_scripts:
        findings.extend(_score_and_remediate([dict(script, type="nmap_script", description=(
            f"nmap script {script['script_id']}: {script['output'][:300]}"
        ))]))
    insert_findings_bulk(scan_id, findings)

    # --- Web -----------------------------------------------------------
    print_phase("WEB")
    web_ports = [p for p in open_ports if _is_web_port(p)]
    budget = PROFILE_TIME_BUDGET_SECONDS.get(PROFILE_NAME)
    web_loop_start = time.time()

    # (template_id, matched_port) pairs already recorded, shared across the
    # per-port loop below. A nuclei template that pivots to its own service
    # matches identically from every web port probed — see
    # _findings_from_nuclei().
    seen_nuclei_matches = set()

    if web_ports:
        with scan_progress_bar(len(web_ports) * 7, f"Web audit: {target}") as advance:
            for port_entry in web_ports:
                if budget is not None and (time.time() - web_loop_start) > budget:
                    remaining = [p["port"] for p in web_ports[web_ports.index(port_entry):]]
                    msg = (
                        f"time budget ({budget}s) exhausted — skipping remaining "
                        f"web port(s) {remaining}, finishing with partial results"
                    )
                    log_tool_failure(target, PROFILE_NAME, msg)
                    print_warning(f"[{PROFILE_NAME}] {msg}")
                    break

                port = port_entry["port"]
                use_https = _is_https_port(port_entry)
                port_findings = []

                header_result = check_headers(target, port=port, use_https=use_https)
                tool_results.append(header_result)
                port_findings.extend(_score_and_remediate(_findings_from_headers(header_result)))
                server_banner = header_result.get("server_banner")
                if server_banner:
                    cve_result = lookup_cves_from_banner(server_banner, target=target)
                    port_findings.extend(_findings_from_cves(
                        cve_result.get("cves") or [], port, server_banner,
                    ))
                advance(f"Headers :{port}")

                nikto_result = run_nikto(target, port=port, use_https=use_https)
                tool_results.append(nikto_result)
                port_findings.extend(_score_and_remediate(_findings_from_nikto(nikto_result)))
                advance(f"Nikto :{port}")

                gobuster_result = run_gobuster(target, port=port, use_https=use_https)
                tool_results.append(gobuster_result)
                gobuster_results.append(gobuster_result)
                port_findings.extend(_score_and_remediate(_findings_from_gobuster(gobuster_result)))
                advance(f"Gobuster :{port}")

                dirb_result = run_dirb(target, port=port, use_https=use_https)
                tool_results.append(dirb_result)
                dirb_results.append(dirb_result)
                port_findings.extend(_score_and_remediate(_findings_from_dirb(dirb_result)))
                advance(f"Dirb :{port}")

                whatweb_result = run_whatweb(target, port=port, use_https=use_https)
                tool_results.append(whatweb_result)
                port_findings.extend(_score_and_remediate(_findings_from_whatweb(whatweb_result)))
                advance(f"WhatWeb :{port}")

                severity_list = profile_cfg.get("nuclei_severity")
                nuclei_result = run_nuclei(target, port=port, use_https=use_https, severity=severity_list)
                tool_results.append(nuclei_result)
                port_findings.extend(_score_and_remediate(
                    _findings_from_nuclei(nuclei_result, seen=seen_nuclei_matches)
                ))
                advance(f"Nuclei :{port}")

                zap_result = run_zap_baseline(target, port=port, use_https=use_https)
                tool_results.append(zap_result)
                port_findings.extend(_score_and_remediate(_findings_from_zap(zap_result)))
                advance(f"ZAP :{port}")

                # Persisted per-port, not batched across the whole web
                # phase — a later port timing out or the budget cutting in
                # never costs an earlier port's findings.
                insert_findings_bulk(scan_id, port_findings)
                findings.extend(port_findings)
    else:
        print_info(f"[{PROFILE_NAME}] no web port found among open ports — skipping web module")

    # --- XSS fuzzing (dedicated) ------------------------------------
    # A first-class cross-site-scripting pass: nuclei in DAST mode scoped to
    # the XSS template tag, fuzzed against parameterised URLs built from the
    # script endpoints gobuster/dirb discovered (web_param_candidates()).
    # This is what makes XSS a real, evidence-bearing finding class rather
    # than something only nikto/nuclei catch incidentally.
    xss_candidates = web_param_candidates(gobuster_results, dirb_results)
    if xss_candidates:
        print_phase("XSS")
        xss_findings = []
        with scan_progress_bar(len(xss_candidates), f"XSS fuzzing: {target}") as advance:
            for candidate_url, candidate_port in xss_candidates:
                xss_result = run_xss(target, candidate_url)
                tool_results.append(xss_result)
                xss_findings.extend(_findings_from_xss(xss_result, candidate_port))
                advance(f"XSS {candidate_url}")
        xss_scored = _score_and_remediate(xss_findings)
        insert_findings_bulk(scan_id, xss_scored)
        findings.extend(xss_scored)
    else:
        print_info(
            f"[{PROFILE_NAME}] no parameterised script endpoint discovered "
            "— XSS fuzzing skipped (nothing to fuzz)"
        )

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
    conditional_scored = _score_and_remediate(conditional_findings)

    # Only this final phase's new findings get inserted here — the
    # scanning-phase and per-port web findings above were already persisted
    # incrementally as soon as they existed, not held until this point.
    insert_findings_bulk(scan_id, conditional_scored)
    findings.extend(conditional_scored)

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": count_and_report_tool_failures(target, tool_results),
        "tools_skipped": sum(1 for r in tool_results if r.get("skipped")),
    }
    log_scan_end(target, stats)

    # --- Reporting -------------------------------------------------
    print_phase("REPORTING")
    # Writes both reports, prunes the capped history and prints the
    # end-of-scan REPORT GENERATED banner — see _common.finalise_reports().
    txt_path, pdf_path = finalise_reports(
        target, PROFILE_NAME, scan_id, non_interactive=non_interactive
    )

    print_success(
        f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s), "
        f"txt={txt_path}, pdf={pdf_path}"
    )
    return scan_id, txt_path, pdf_path, stats


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.profiles.deepscan <target>")
        sys.exit(1)

    sid, txt, pdf, _stats = run_deepscan(sys.argv[1])
    print_success(f"Deepscan complete — scan_id={sid} txt={txt} pdf={pdf}")
