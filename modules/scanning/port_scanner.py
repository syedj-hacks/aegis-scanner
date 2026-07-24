"""
modules/scanning/port_scanner.py
Port scanning module for Aegis Scanner (Member C - scanning layer).

Runs nmap against a target via error_handler.run_tool(), requesting XML
output on stdout (-oX -) for reliable, structured parsing instead of
scraping human-readable text. Parses the XML into a list of open ports
with protocol / service / state.

Profile-aware: when a scan profile name is given, the profile's nmap_args
(from modules.utils.config.PROFILES) drive the invocation; otherwise a
sensible default fast-scan is used.
"""

import xml.etree.ElementTree as ET

from modules.utils.error_handler import run_tool
from modules.utils.config import get_profile
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error, print_tree,
)

# Fallback nmap arguments when no profile is supplied.
# -T4  : faster timing template
# -F   : fast scan (nmap's ~100 most common ports)
# -Pn  : treat host as online / skip host-discovery so a filtered ICMP
#        response doesn't make nmap skip the port scan entirely.
_DEFAULT_NMAP_ARGS = ["-T4", "-F", "-Pn"]


def _parse_nmap_xml(xml_text: str) -> list:
    """
    Parse nmap XML (-oX) output into a list of open-port dicts.

    Returns a list of:
        {port: int, protocol: str, service: str, state: str}

    Only ports whose state is 'open' (or 'open|filtered') are returned,
    since those are what downstream service-detection / CVE-correlation
    stages care about. Malformed / empty XML yields an empty list rather
    than raising.
    """
    open_ports = []

    if not xml_text or not xml_text.strip():
        return open_ports

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return open_ports

    for host in root.findall("host"):
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port_el in ports_node.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state not in ("open", "open|filtered"):
                continue

            service_el = port_el.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"

            try:
                port_num = int(port_el.get("portid", "0"))
            except (TypeError, ValueError):
                port_num = 0

            open_ports.append({
                "port": port_num,
                "protocol": port_el.get("protocol", "tcp"),
                "service": service_name,
                "state": state,
            })

    # Sort by port number for stable, readable output.
    open_ports.sort(key=lambda p: p["port"])
    return open_ports


def _parse_nmap_scripts(xml_text: str) -> list:
    """
    Parse nmap XML (-oX) output for <script>/<hostscript> results — the
    data --script runs (e.g. compliance's ssl-enum-ciphers, http-headers)
    produce but scan_ports() previously discarded.

    Returns a list of:
        {port: int | None, protocol: str | None, script_id: str, output: str}

    port/protocol are None for host-level scripts (<hostscript>, e.g.
    scripts that don't target a specific port); per-port scripts carry the
    port they ran against. Malformed/empty XML yields [] rather than
    raising, same contract as _parse_nmap_xml.
    """
    scripts = []

    if not xml_text or not xml_text.strip():
        return scripts

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return scripts

    for host in root.findall("host"):
        hostscript_node = host.find("hostscript")
        if hostscript_node is not None:
            for script_el in hostscript_node.findall("script"):
                scripts.append({
                    "port": None,
                    "protocol": None,
                    "script_id": script_el.get("id", "unknown"),
                    "output": (script_el.get("output") or "").strip(),
                })

        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port_el in ports_node.findall("port"):
            try:
                port_num = int(port_el.get("portid", "0"))
            except (TypeError, ValueError):
                port_num = 0

            for script_el in port_el.findall("script"):
                scripts.append({
                    "port": port_num,
                    "protocol": port_el.get("protocol", "tcp"),
                    "script_id": script_el.get("id", "unknown"),
                    "output": (script_el.get("output") or "").strip(),
                })

    return scripts


def scan_ports(target: str, profile: str = None) -> dict:
    """
    Scan `target` for open ports using nmap.

    Parameters
    ----------
    target  : str   host / IP to scan
    profile : str   optional scan-profile name (see config.PROFILES). When
                    provided and valid, the profile's nmap_args are used.

    Returns
    -------
    dict:
        target        : str
        open_ports    : list[dict]  {port, protocol, service, state}
        scripts       : list[dict]  {port, protocol, script_id, output} from
                                    any --script results in the XML (e.g.
                                    compliance's ssl-enum-ciphers/
                                    http-headers); [] when no --script ran
        profile_used  : str | None  profile name actually applied, or None
        raw_output    : str         raw nmap XML stdout (for logging/debug)
        error         : str | None  human-readable failure reason, if any
    """
    log_tool_start(target, "nmap")

    result = {
        "target": target,
        "open_ports": [],
        "scripts": [],
        "profile_used": None,
        "raw_output": "",
        "error": None,
    }

    # --- Resolve which nmap args to use (profile-driven or default) ---
    nmap_args = _DEFAULT_NMAP_ARGS
    if profile:
        try:
            profile_cfg = get_profile(profile)
            nmap_args = profile_cfg.get("nmap_args", _DEFAULT_NMAP_ARGS)
            result["profile_used"] = profile
            print_info(f"[Ports] Using profile '{profile}' nmap args: {' '.join(nmap_args)}")
        except ValueError as exc:
            # Unknown profile — log, warn, and fall back to defaults rather
            # than aborting the scan.
            log_tool_failure(target, "nmap", f"unknown profile '{profile}': {exc}")
            print_warning(f"[Ports] Unknown profile '{profile}', using default nmap args")

    # Always request XML on stdout for reliable parsing.
    command = ["nmap"] + list(nmap_args) + ["-oX", "-", target]
    print_info(f"[Ports] Scanning {target} -> nmap {' '.join(nmap_args)}")

    tool_result = run_tool(target, "nmap", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""

    if not tool_result.get("success"):
        err = tool_result.get("error") or tool_result.get("stderr") or "nmap failed"
        result["error"] = err
        log_tool_failure(target, "nmap", err)
        print_error(f"[Ports] nmap failed for {target}: {err}")
        return result

    open_ports = _parse_nmap_xml(result["raw_output"])
    result["open_ports"] = open_ports

    scripts = _parse_nmap_scripts(result["raw_output"])
    result["scripts"] = scripts

    if open_ports:
        log_tool_success(target, "nmap", tool_result.get("duration"))
        for p in open_ports:
            log_finding(target, {
                "type": "open_port",
                "port": p["port"],
                "protocol": p["protocol"],
                "service": p["service"],
            })
        print_success(f"[Ports] {target}: {len(open_ports)} open port(s) found")
        # Reuse the recon tree renderer (expects list of {port, service}).
        print_tree(target, ports=open_ports)
    else:
        # nmap ran fine but nothing was open (host down, all filtered, etc.)
        log_tool_success(target, "nmap", tool_result.get("duration"))
        print_warning(f"[Ports] {target}: nmap completed but found no open ports")

    if scripts:
        for s in scripts:
            log_finding(target, {
                "type": "nmap_script",
                "port": s["port"],
                "script_id": s["script_id"],
                "output": s["output"],
            })
        print_success(f"[Ports] {target}: {len(scripts)} nmap script result(s) captured")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.scanning.port_scanner <target> [profile]")
        sys.exit(1)

    tgt = sys.argv[1]
    prof = sys.argv[2] if len(sys.argv) > 2 else None

    print_info(f"Scanning ports for {tgt}" + (f" (profile: {prof})" if prof else ""))
    out = scan_ports(tgt, profile=prof)
    print_info(f"Open ports: {[p['port'] for p in out['open_ports']]}")
    print_info(f"Profile used: {out['profile_used']}")
    print_info(f"Error: {out['error'] or 'none'}")
