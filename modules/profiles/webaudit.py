"""
modules/profiles/webaudit.py
Webaudit profile orchestrator for Aegis Scanner (Phase 8 - profiles layer).

Web-focused profile: DNS resolution, a port scan restricted to web ports
(PROFILES['webaudit']['nmap_args'] already scopes nmap to 80,443,8080,8443),
the full web module (header audit, nikto, gobuster, dirb, whatweb, sslyze,
banner grabbing) against whatever of those ports came back open, a dedicated
cross-site-scripting pass (nuclei `-dast -tags xss` via
modules/web/xss_wrap.py, fuzzed against parameterised URLs built from the
discovered script endpoints), CVE lookup + severity + remediation on the web
findings, and a text report. Confirmed XSS findings carry the exact payload,
parameter/endpoint and a response snippet, rendered in the report's
Injection & Scripting section.

Wrapper availability
---------------------
PROFILES['webaudit']['tools'] also lists zaproxy, which has a wrapper
(modules/web/zap_wrap.py) but is deliberately not run in this profile — it
is wired into deepscan only, per the deepscan/webaudit/compliance tool
split (a full ZAP baseline scan is heavier than webaudit's fast-audit
scope). It is still logged as skipped here rather than silently omitted.
"""

import time

from modules.utils.config import get_profile, PROFILE_TIME_BUDGET_SECONDS
from modules.utils.display import (
    scan_progress_bar, print_phase, print_success, print_error, print_info, print_warning,
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
from modules.web.xss_wrap import run_xss
from modules.enrichment.cve_lookup import lookup_cves_from_banner
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.dashboard_live import update_live_data
from modules.profiles._common import (
    warn_unavailable_tools, count_and_report_tool_failures, web_param_candidates,
    persist_tool_run, finalise_reports, run_web_tools, web_tool_concurrency,
)
from modules.utils.auth import load_auth, announce as announce_auth

PROFILE_NAME = "webaudit"

# zaproxy has a real wrapper (modules/web/zap_wrap.py) but is deliberately
# not run here — see the module docstring — so it's left out of this set on
# purpose, not because no wrapper exists. warn_unavailable_tools() checks
# GLOBAL_AVAILABLE_TOOLS before deciding which of those two messages to log.
_WIRED_TOOLS = {"nslookup", "nmap", "nikto", "gobuster", "dirb", "whatweb", "sslyze", "banner_grab"}

_HTTPS_PORTS = (443, 8443)
_WEB_PORTS = (80, 443, 8080, 8443)


def _is_https_port(port_entry: dict) -> bool:
    port = port_entry.get("port")
    service = str(port_entry.get("service") or "").lower()
    return port in _HTTPS_PORTS or "ssl" in service or "https" in service


def _is_web_port(port_entry: dict) -> bool:
    port = port_entry.get("port")
    service = str(port_entry.get("service") or "").lower()
    return port in _WEB_PORTS or "http" in service or "ssl" in service


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
    """nikto's own per-finding detail, not just its description text.

    endpoint  — the scheme-qualified URL of the URI nikto flagged. nikto is
                given the scheme as an argument, so http-vs-https is known
                here for certain rather than assumed downstream. Findings
                nikto reported without a URI (e.g. "Apache/2.4.25 appears to
                be outdated") get the base URL, which is still true of them.
    reference — nikto's "See: <url>" citation. Parsed since the wrapper was
                written and dropped at insert until findings gained a
                reference column.
    product/version — nikto's reported Server banner, split on "/". The
                whole scan shares one banner because it is one server.
    """
    port = nikto_result.get("port")
    base_url = (nikto_result.get("base_url") or "").rstrip("/")
    product = nikto_result.get("product") or None
    version = nikto_result.get("version") or None

    findings = []
    for f in nikto_result.get("findings") or []:
        path = f.get("path") or ""
        endpoint = f"{base_url}{path}" if base_url else (path or None)
        findings.append({
            "type": "nikto_finding", "port": port,
            "description": f["description"],
            "reference": f.get("reference") or None,
            "endpoint": endpoint or None,
            "product": product,
            "version": version,
        })
    return findings


def _path_description(entry: dict, source: str = None) -> str:
    """"Discovered path /admin (HTTP 301, 312 bytes) -> /admin/".

    Size and redirect target are gobuster's/dirb's own output. They are
    appended only when the tool actually reported them: a 0-byte page and a
    page whose size the tool never printed are different facts, and writing
    "0 bytes" for the second would state something the scan did not observe.
    """
    bits = [f"HTTP {entry.get('status_code')}"]
    if entry.get("size") is not None:
        bits.append(f"{entry['size']} bytes")
    if source:
        bits.append(f"via {source}")
    text = f"Discovered path {entry.get('path')} ({', '.join(bits)})"
    if entry.get("redirect"):
        text += f" -> {entry['redirect']}"
    return text


def _findings_from_gobuster(gobuster_result: dict) -> list:
    port = gobuster_result.get("port")
    findings = [
        {
            "type": "discovered_path", "port": port,
            "path": entry["path"], "status_code": entry["status_code"],
            "description": _path_description(entry),
            "endpoint": entry.get("url"),
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
            "description": _path_description(entry, source="dirb"),
            "endpoint": entry.get("url"),
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


def run_webaudit(target: str, non_interactive: bool = False, auth=None):
    """
    Run the webaudit profile against `target`: DNS resolution, a nmap scan
    restricted to web ports, the full web module against whichever of those
    came back open, CVE/severity/remediation enrichment on the web findings,
    and a text report.

    Findings are persisted per-port, immediately after that port's tool
    loop finishes, rather than held in memory until every port has been
    audited — an interrupt partway through a multi-port target keeps every
    completed port's findings. A profile-level wall-clock budget
    (config.PROFILE_TIME_BUDGET_SECONDS['webaudit']) also bounds the
    per-port loop as a whole: TOOL_TIMEOUTS bounds one subprocess call, not
    "headers+nikto+gobuster+dirb+whatweb+sslyze, repeated per open web
    port", which has no ceiling of its own otherwise.

    Returns
    -------
    tuple: (scan_id: int, report_path: str | None, stats: dict)
    """
    log_scan_start(target, PROFILE_NAME)
    print_phase(f"WEBAUDIT — {target}")

    profile_cfg = get_profile(PROFILE_NAME)
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)

    # None (the default, and every existing call site) resolves to whatever
    # .env/environment configures — which, with nothing set, is a disabled
    # AuthConfig whose *_args() all return [], so every command is built
    # exactly as before.
    if auth is None:
        auth = load_auth()
    announce_auth(auth, PROFILE_NAME)

    concurrency = web_tool_concurrency(PROFILE_NAME)
    if concurrency > 1:
        print_info(
            f"[{PROFILE_NAME}] running independent per-port web tools "
            f"{concurrency}-way concurrent"
        )

    scan_id = insert_scan(target, PROFILE_NAME)
    update_live_data(target, [], current_tool="nmap port scan", progress_pct=10)

    tool_results = []
    findings = []
    gobuster_results = []
    dirb_results = []

    with scan_progress_bar(2, f"Webaudit: {target}") as advance:
        dns_result = resolve_dns(target)
        tool_results.append(dns_result)
        advance("DNS resolution")

        port_result = scan_ports(target, profile=PROFILE_NAME)
        tool_results.append(port_result)
        open_ports = port_result.get("open_ports") or []
        advance("Web port scan")

    if open_ports:
        # webaudit's own nmap scan is already scoped to web ports only
        # (PROFILES['webaudit']['nmap_args'] = -p 80,443,8080,8443), so
        # every open port here is, by construction, one banner_grab's raw
        # TCP probe wastes ~11s timing out on for nothing (HTTP(S) servers
        # don't send an unsolicited banner — header_check/-sV already
        # cover them). Kept as a filter rather than deleted outright in
        # case that port scope ever changes.
        non_web_ports = [p["port"] for p in open_ports if not _is_web_port(p)]
        if non_web_ports:
            banner_result = grab_banners(target, non_web_ports)
            tool_results.append(banner_result)
            banner_findings = _score_and_remediate(_findings_from_banners(banner_result))
            insert_findings_bulk(scan_id, banner_findings)
            update_live_data(target, banner_findings,
                             current_tool="banner grab", progress_pct=30)
        else:
            print_info(f"[{PROFILE_NAME}] all open ports are web ports — banner_grab skipped (nmap/headers already cover them)")

        budget = PROFILE_TIME_BUDGET_SECONDS.get(PROFILE_NAME)
        loop_start = time.time()
        budget_exhausted = False

        with scan_progress_bar(len(open_ports) * 5, f"Web module: {target}") as advance:
            for port_entry in open_ports:
                if budget is not None and (time.time() - loop_start) > budget:
                    remaining = [p["port"] for p in open_ports[open_ports.index(port_entry):]]
                    msg = (
                        f"time budget ({budget}s) exhausted — skipping remaining "
                        f"port(s) {remaining}, finishing with partial results"
                    )
                    log_tool_failure(target, PROFILE_NAME, msg)
                    print_warning(f"[{PROFILE_NAME}] {msg}")
                    budget_exhausted = True
                    break

                port = port_entry["port"]
                use_https = _is_https_port(port_entry)
                port_findings = []

                # header_check runs first and alone, outside the pool: its
                # Server banner is what the CVE lookup below is keyed on, so
                # this one IS a data dependency, unlike the five that follow.
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

                # nikto / gobuster / dirb / whatweb / sslyze are mutually
                # independent for a given port — none reads another's output —
                # so they go through the shared pool. run_web_tools() returns
                # results in task order regardless of completion order, which
                # is what keeps finding rows stable across runs.
                tasks = [
                    ("nikto", lambda: run_nikto(target, port=port, use_https=use_https,
                                                profile=PROFILE_NAME, auth=auth)),
                    ("gobuster", lambda: run_gobuster(target, port=port, use_https=use_https,
                                                      profile=PROFILE_NAME, auth=auth)),
                    ("dirb", lambda: run_dirb(target, port=port, use_https=use_https,
                                              profile=PROFILE_NAME)),
                    ("whatweb", lambda: run_whatweb(target, port=port, use_https=use_https)),
                ]
                if use_https:
                    tasks.append(("sslyze", lambda: run_sslyze(target, port=port)))

                results = run_web_tools(tasks, profile=PROFILE_NAME)
                by_tool = dict(zip([name for name, _ in tasks], results))

                nikto_result = by_tool["nikto"]
                tool_results.append(nikto_result)
                port_findings.extend(_score_and_remediate(_findings_from_nikto(nikto_result)))
                advance(f"Nikto :{port}")

                gobuster_result = by_tool["gobuster"]
                tool_results.append(gobuster_result)
                gobuster_results.append(gobuster_result)
                port_findings.extend(_score_and_remediate(_findings_from_gobuster(gobuster_result)))
                advance(f"Gobuster :{port}")

                dirb_result = by_tool["dirb"]
                tool_results.append(dirb_result)
                dirb_results.append(dirb_result)
                port_findings.extend(_score_and_remediate(_findings_from_dirb(dirb_result)))
                advance(f"Dirb :{port}")

                whatweb_result = by_tool["whatweb"]
                tool_results.append(whatweb_result)
                port_findings.extend(_score_and_remediate(_findings_from_whatweb(whatweb_result)))
                advance(f"WhatWeb :{port}")

                if use_https:
                    sslyze_result = by_tool["sslyze"]
                    tool_results.append(sslyze_result)
                    port_findings.extend(_score_and_remediate(_findings_from_sslyze(sslyze_result)))

                # Persisted as soon as this port's tools finish — not
                # batched across the whole port loop — so a later port's
                # interrupt/budget cutoff never costs this one's findings.
                insert_findings_bulk(scan_id, port_findings)
                update_live_data(target, port_findings,
                                 current_tool=f"web audit :{port}", progress_pct=75)
                findings.extend(port_findings)

        # --- XSS fuzzing (dedicated) ---------------------------------
        # nuclei DAST scoped to XSS templates, fuzzed against parameterised
        # URLs built from the script endpoints gobuster/dirb discovered.
        # Runs after the per-port loop so it has the full discovery set.
        xss_candidates = web_param_candidates(gobuster_results, dirb_results)
        if xss_candidates:
            print_phase(f"XSS — {target}")
            xss_findings = []
            with scan_progress_bar(len(xss_candidates), f"XSS fuzzing: {target}") as advance:
                for candidate_url, candidate_port in xss_candidates:
                    xss_result = run_xss(target, candidate_url)
                    tool_results.append(xss_result)
                    xss_findings.extend(_findings_from_xss(xss_result, candidate_port))
                    advance(f"XSS {candidate_url}")
            xss_scored = _score_and_remediate(xss_findings)
            insert_findings_bulk(scan_id, xss_scored)
            update_live_data(target, xss_scored, current_tool="nuclei DAST (XSS)",
                             progress_pct=92)
            findings.extend(xss_scored)
        else:
            print_info(
                f"[{PROFILE_NAME}] no parameterised script endpoint discovered "
                "— XSS fuzzing skipped (nothing to fuzz)"
            )
    else:
        print_info(f"[{PROFILE_NAME}] no web port open on {target} — web module skipped")

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
        print_error("Usage: python -m modules.profiles.webaudit <target>")
        sys.exit(1)

    sid, path, _pdf, _html, _stats = run_webaudit(sys.argv[1])
    print_success(f"Webaudit complete — scan_id={sid} report={path}")
