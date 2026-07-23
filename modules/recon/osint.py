"""
modules/recon/osint.py
OSINT gathering module for Aegis Scanner (Member B - recon layer).

Runs theHarvester against a target domain via error_handler.run_tool()
and parses its section-based stdout into structured emails/hosts/IPs.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_tool_start, log_tool_success, log_tool_failure, log_finding
from modules.utils.display import print_info, print_success, print_warning, print_error

_SECTION_HEADER = re.compile(r"^\[\*\]\s*(Emails|Hosts|IPs)\s+found:\s*(\d+)", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def _parse_theharvester_output(stdout: str) -> dict:
    """
    Parse theHarvester's labeled-section text output, e.g.:

        [*] Emails found: 2
        --------------------
        alice@target.com
        bob@target.com

        [*] Hosts found: 1
        -------------------
        www.target.com:93.184.216.34

    Walks the output line by line, tracks the active section, and pulls
    out emails / hostnames / IPs accordingly. Also runs a best-effort
    regex sweep over the whole output as a safety net in case a
    theHarvester version changes its section headers.
    """
    emails = set()
    hosts = set()
    ips = set()

    current_section = None
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        header_match = _SECTION_HEADER.match(line)
        if header_match:
            current_section = header_match.group(1).lower()
            continue

        if set(line) <= {"-"}:  # separator lines like "-----"
            continue

        if current_section == "emails":
            emails.update(_EMAIL_PATTERN.findall(line))
        elif current_section == "hosts":
            host_part = line.split(":")[0].strip()
            if host_part:
                hosts.add(host_part)
            ips.update(_IP_PATTERN.findall(line))
        elif current_section == "ips":
            ips.update(_IP_PATTERN.findall(line))

    if not emails:
        emails.update(_EMAIL_PATTERN.findall(stdout))

    return {
        "emails": sorted(emails),
        "hosts": sorted(hosts),
        "ips": sorted(ips),
    }


def harvest_osint(target: str, source: str = "crtsh", limit: int = 500) -> dict:
    """
    Run theHarvester against `target` and return structured OSINT results.

    Parameters
    ----------
    target : str   domain to search for
    source : str   theHarvester data source (default "crtsh" - certificate
                    transparency logs; needs no API key, works out of the box)
    limit  : int   max results requested from the source

    Returns
    -------
    dict:
        target  : str
        emails  : list[str]
        hosts   : list[str]
        ips     : list[str]
        counts  : dict[str, int]
        success : bool
        error   : str | None
    """
    log_tool_start(target, "theHarvester")

    command = ["theHarvester", "-d", target, "-b", source, "-l", str(limit)]
    tool_result = run_tool(target, "theHarvester", command)

    result = {
        "target": target,
        "emails": [],
        "hosts": [],
        "ips": [],
        "counts": {"emails": 0, "hosts": 0, "ips": 0},
        "success": False,
        "error": None,
    }

    if tool_result.get("success"):
        parsed = _parse_theharvester_output(tool_result.get("stdout", "") or "")
        result.update(parsed)
        result["success"] = True
        result["counts"] = {
            "emails": len(parsed["emails"]),
            "hosts": len(parsed["hosts"]),
            "ips": len(parsed["ips"]),
        }
        log_tool_success(target, "theHarvester", tool_result.get("duration"))
        for email in parsed["emails"]:
            log_finding(target, {"type": "osint_email", "value": email})
        for host in parsed["hosts"]:
            log_finding(target, {"type": "osint_host", "value": host})

        print_success(
            f"[OSINT] {target}: {result['counts']['emails']} email(s), "
            f"{result['counts']['hosts']} host(s), {result['counts']['ips']} ip(s)"
        )
    else:
        err = tool_result.get("error") or tool_result.get("stderr") or "theHarvester failed"
        result["error"] = err
        log_tool_failure(target, "theHarvester", err)
        print_warning(f"[OSINT] theHarvester failed for {target}: {err}")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.recon.osint <target> [source]")
        sys.exit(1)

    tgt = sys.argv[1]
    src = sys.argv[2] if len(sys.argv) > 2 else "crtsh"

    print_info(f"Harvesting OSINT for {tgt} (source: {src})...")
    out = harvest_osint(tgt, source=src)
    print_info(f"Emails: {out['emails']}")
    print_info(f"Hosts:  {out['hosts']}")
    print_info(f"IPs:    {out['ips']}")