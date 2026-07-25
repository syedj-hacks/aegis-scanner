"""
modules/recon/dns.py
DNS resolution module for Aegis Scanner (Member B - recon layer).

Resolves a target hostname to its IPv4 address(es).
Primary method : `nslookup <target>` via error_handler.run_tool()
Fallback method: socket.gethostbyname() if nslookup is missing, times
                 out, errors, or returns no parsable addresses.
"""

import re
import socket

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_tool_start, log_tool_success, log_tool_failure, log_finding
from modules.utils.display import print_info, print_success, print_warning, print_error, print_panel

_ADDRESS_LINE = re.compile(r"^Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.MULTILINE)


def _parse_nslookup_output(stdout: str) -> list:
    """
    Extract resolved IPv4 addresses from raw nslookup stdout.

    Typical nslookup output:

        Server:         127.0.0.53
        Address:        127.0.0.53#53

        Non-authoritative answer:
        Name:   example.com
        Address: 93.184.216.34

    We only collect 'Address:' lines that appear *after* a 'Name:' line,
    so we don't accidentally return the local DNS resolver's own IP
    (the first Address block, before any Name: line, is the resolver).
    """
    lines = stdout.splitlines()
    addresses = []
    seen_name = False

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("Name:"):
            seen_name = True
            continue
        if seen_name:
            match = _ADDRESS_LINE.match(line)
            if match:
                addresses.append(match.group(1))

    if not addresses:
        # Some nslookup builds format this differently. Fall back to
        # grabbing every Address line except the first (resolver) one.
        all_matches = _ADDRESS_LINE.findall(stdout)
        if len(all_matches) > 1:
            addresses = all_matches[1:]

    return list(dict.fromkeys(addresses))  # dedupe, preserve order


def resolve_dns(target: str) -> dict:
    """
    Resolve `target` to one or more IPv4 addresses.

    Returns
    -------
    dict:
        target       : str   input hostname
        resolved     : bool
        ip_addresses : list[str]
        method       : "nslookup" | "socket" | "failed"
        raw_output   : str   raw nslookup stdout, kept for debugging/logging
        error        : str | None
    """
    log_tool_start(target, "dns_resolve")

    result = {
        "tool": "nslookup",
        "target": target,
        "resolved": False,
        "ip_addresses": [],
        "method": None,
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    tool_result = run_tool(target, "nslookup", ["nslookup", target])
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if tool_result.get("success"):
        ips = _parse_nslookup_output(result["raw_output"])
        if ips:
            result["resolved"] = True
            result["ip_addresses"] = ips
            result["method"] = "nslookup"
            log_tool_success(target, "dns_resolve", tool_result.get("duration"))
            log_finding(target, {"type": "dns_resolution", "method": "nslookup", "ip_addresses": ips})
            print_success(f"[DNS] {target} -> {', '.join(ips)} (nslookup)")
            return result

        log_tool_failure(target, "dns_resolve", "nslookup succeeded but returned no parsable addresses")
        print_warning(f"[DNS] nslookup ran but returned nothing usable for {target}, falling back to socket")
    else:
        err = tool_result.get("error") or tool_result.get("stderr") or "nslookup failed"
        log_tool_failure(target, "dns_resolve", err)
        print_warning(f"[DNS] nslookup failed for {target} ({err}), falling back to socket resolution")

    # --- Fallback: socket.gethostbyname ---
    try:
        ip = socket.gethostbyname(target)
        result["resolved"] = True
        result["ip_addresses"] = [ip]
        result["method"] = "socket"
        log_tool_success(target, "dns_resolve")
        log_finding(target, {"type": "dns_resolution", "method": "socket", "ip_addresses": [ip]})
        print_success(f"[DNS] {target} -> {ip} (socket fallback)")
    except socket.gaierror as exc:
        result["resolved"] = False
        result["method"] = "failed"
        result["error"] = str(exc)
        log_tool_failure(target, "dns_resolve", str(exc))
        print_error(f"[DNS] Could not resolve {target}: {exc}")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.recon.dns <target>")
        sys.exit(1)

    print_info(f"Resolving DNS for {sys.argv[1]}...")
    out = resolve_dns(sys.argv[1])
    print_panel(
        f"Resolved: {out['resolved']}\n"
        f"Method:   {out['method']}\n"
        f"IPs:      {', '.join(out['ip_addresses']) or 'none'}\n"
        f"Error:    {out['error'] or 'none'}",
        title=f"DNS Resolution - {sys.argv[1]}",
    )