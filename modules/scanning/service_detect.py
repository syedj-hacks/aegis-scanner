"""
modules/scanning/service_detect.py
Service / version detection module for Aegis Scanner (Member C - scanning).

Takes the list of open ports found by port_scanner.scan_ports() and runs
nmap -sV against just those ports via error_handler.run_tool(), then parses
the XML output into per-port service name + product + version strings.

Scanning only the already-known-open ports keeps -sV fast instead of
re-probing the whole port range.
"""

import xml.etree.ElementTree as ET

from modules.utils.error_handler import run_tool
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -sV : probe open ports to determine service/version info
# -Pn : skip host discovery (host already confirmed up by port scan)
_NMAP_SV_ARGS = ["-sV", "-Pn"]


def _normalise_ports(ports) -> list:
    """
    Coerce an incoming ports argument into a clean, deduped, sorted list of
    integer port numbers. Accepts ints or numeric strings; silently drops
    anything non-numeric. This lets callers pass either the raw port list
    from scan_ports (ints) or loosely-typed values without crashing.
    """
    clean = []
    for p in ports or []:
        try:
            clean.append(int(p))
        except (TypeError, ValueError):
            continue
    return sorted(set(clean))


def _parse_sv_xml(xml_text: str) -> list:
    """
    Parse nmap -sV XML output into a list of:
        {port: int, service: str, version: str, product: str}

    Only ports still reported 'open' are included. Missing product/version
    attributes become empty strings. Malformed/empty XML yields [].
    """
    services = []

    if not xml_text or not xml_text.strip():
        return services

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return services

    for host in root.findall("host"):
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port_el in ports_node.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state not in ("open", "open|filtered"):
                continue

            try:
                port_num = int(port_el.get("portid", "0"))
            except (TypeError, ValueError):
                port_num = 0

            service_el = port_el.find("service")
            if service_el is not None:
                service_name = service_el.get("name", "unknown")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
            else:
                service_name, product, version = "unknown", "", ""

            services.append({
                "port": port_num,
                "service": service_name,
                "version": version,
                "product": product,
            })

    services.sort(key=lambda s: s["port"])
    return services


def detect_services(target: str, ports) -> dict:
    """
    Run nmap -sV against `target` on the given `ports`.

    Parameters
    ----------
    target : str          host / IP
    ports  : list[int]    open port numbers (e.g. from scan_ports()['open_ports'])

    Returns
    -------
    dict:
        target   : str
        services : list[dict]  {port, service, version, product}
        error    : str | None
    """
    log_tool_start(target, "nmap-sV")

    result = {
        "target": target,
        "services": [],
        "error": None,
    }

    port_list = _normalise_ports(ports)
    if not port_list:
        # Nothing to probe — not an error, just a no-op. Avoids launching a
        # pointless full -sV scan when port_scanner found nothing open.
        msg = "no open ports supplied; skipping service detection"
        result["error"] = msg
        log_tool_failure(target, "nmap-sV", msg)
        print_warning(f"[Services] {target}: {msg}")
        return result

    port_arg = ",".join(str(p) for p in port_list)
    command = ["nmap"] + _NMAP_SV_ARGS + ["-p", port_arg, "-oX", "-", target]
    print_info(f"[Services] Detecting services on {target} ports {port_arg} (nmap -sV)")

    tool_result = run_tool(target, "nmap-sV", command)

    if not tool_result.get("success"):
        err = tool_result.get("error") or tool_result.get("stderr") or "nmap -sV failed"
        result["error"] = err
        log_tool_failure(target, "nmap-sV", err)
        print_error(f"[Services] nmap -sV failed for {target}: {err}")
        return result

    services = _parse_sv_xml(tool_result.get("stdout", "") or "")
    result["services"] = services

    if services:
        log_tool_success(target, "nmap-sV", tool_result.get("duration"))
        for s in services:
            log_finding(target, {
                "type": "service_version",
                "port": s["port"],
                "service": s["service"],
                "product": s["product"],
                "version": s["version"],
            })
            label = " ".join(x for x in (s["product"], s["version"]) if x) or "unknown version"
            print_success(f"[Services] {target}:{s['port']} -> {s['service']} ({label})")
    else:
        log_tool_success(target, "nmap-sV", tool_result.get("duration"))
        print_warning(f"[Services] {target}: nmap -sV returned no service data")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print_error("Usage: python -m modules.scanning.service_detect <target> <port[,port,...]>")
        sys.exit(1)

    tgt = sys.argv[1]
    ports_in = [p for p in sys.argv[2].split(",") if p.strip()]

    print_info(f"Detecting services on {tgt} ports {ports_in}...")
    out = detect_services(tgt, ports_in)
    for svc in out["services"]:
        print_info(f"  {svc['port']}: {svc['service']} | {svc['product']} {svc['version']}")
    print_info(f"Error: {out['error'] or 'none'}")
