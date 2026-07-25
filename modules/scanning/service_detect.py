"""
modules/scanning/service_detect.py
Service / version detection module for Aegis Scanner (Member C - scanning).

Takes the list of open ports found by port_scanner.scan_ports() and runs
nmap -sV -sC against just those ports via error_handler.run_tool(), then
parses the XML output into per-port service name + product + version
strings, plus any --script (-sC default set) results.

Scanning only the already-known-open ports keeps -sV/-sC fast instead of
re-probing the whole port range. This is also why deepscan's own initial
full-range discovery sweep (PROFILES['deepscan']['nmap_args']) does NOT
carry -sV/-sC itself any more: combining a 65535-port sweep with per-port
version+script probing is nmap's slowest possible shape, and running it
after chunking (see port_scanner.py) meant even a single ~8000-port chunk
routinely blew its time budget and the whole port-discovery phase came back
empty. -sC ended up folded in here rather than added to a separate call so
deepscan doesn't pay for a third full nmap invocation beyond scan_ports()
and this one.
"""

import xml.etree.ElementTree as ET

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_tool_failure, log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -sV : probe open ports to determine service/version info
# -sC : run nmap's default NSE script set against those same ports — safe to
#       combine with -sV here (unlike on the full port range) because this
#       call only ever targets the small set scan_ports() already narrowed
#       down to.
# -Pn : skip host discovery (host already confirmed up by port scan)
_NMAP_SV_ARGS = ["-sV", "-sC", "-Pn"]


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


def _parse_sc_scripts(xml_text: str) -> list:
    """
    Parse the -sC (default NSE script set) results out of the same XML this
    call already produced. Same shape/behaviour as
    port_scanner._parse_nmap_scripts() (not imported directly to keep this
    module's only dependency on port_scanner's *data shape*, not its
    private helpers): {port, protocol, script_id, output}.
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


def detect_services(target: str, ports) -> dict:
    """
    Run nmap -sV -sC against `target` on the given `ports`.

    Parameters
    ----------
    target : str          host / IP
    ports  : list[int]    open port numbers (e.g. from scan_ports()['open_ports'])

    Returns
    -------
    dict:
        target   : str
        services : list[dict]  {port, service, version, product}
        scripts  : list[dict]  {port, protocol, script_id, output} from -sC;
                               [] when nothing fired
        error    : str | None
    """
    result = {
        "tool": "nmap_service_detect",
        "target": target,
        "services": [],
        "scripts": [],
        "error": None,
        "skipped": False,
    }

    port_list = _normalise_ports(ports)
    if not port_list:
        # Nothing to probe — not an error, just a no-op. Avoids launching a
        # pointless full -sV scan when port_scanner found nothing open.
        # run_tool() is never called on this path, so this is the only
        # log line for it — not a duplicate.
        msg = "no open ports supplied; skipping service detection"
        result["error"] = msg
        log_tool_failure(target, "nmap-sV", msg)
        print_warning(f"[Services] {target}: {msg}")
        return result

    port_arg = ",".join(str(p) for p in port_list)
    command = ["nmap"] + _NMAP_SV_ARGS + ["-p", port_arg, "-oX", "-", target]
    print_info(f"[Services] Detecting services on {target} ports {port_arg} (nmap -sV -sC)")

    # run_tool() already logs this call's start/success/failure under the
    # "nmap-sV" tool name — no need to log it again here.
    tool_result = run_tool(target, "nmap-sV", command)
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success"):
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "nmap -sV failed"
        print_error(f"[Services] nmap -sV failed for {target}: {result['error']}")
        return result

    raw_xml = tool_result.get("stdout", "") or ""
    services = _parse_sv_xml(raw_xml)
    result["services"] = services
    result["scripts"] = _parse_sc_scripts(raw_xml)

    if services:
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
