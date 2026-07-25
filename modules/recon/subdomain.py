"""
modules/recon/subdomain.py
Subdomain enumeration module for Aegis Scanner (Member B - recon layer).

Runs subfinder and amass (passive mode) against a target domain via
error_handler.run_tool(), parses each tool's line-based output, merges
and dedupes the results, and returns a clean sorted list of subdomains.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import print_info, print_success, print_warning, print_error, print_tree

# Loose hostname validator: label.label.label..., each label alnum/hyphen,
# not starting/ending with a hyphen. Used to filter out banner/log noise
# that might slip into stdout instead of an actual discovered hostname.
_HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def _extract_hostnames(stdout: str) -> set:
    """
    Pull well-formed hostnames out of raw tool stdout, one per line.

    Both subfinder (-silent) and amass (enum -passive) print one
    subdomain per line with no extra decoration in their standard output
    modes. We still validate each line against a hostname pattern to
    guard against stray banner/progress lines being picked up.
    """
    found = set()
    for raw_line in stdout.splitlines():
        line = raw_line.strip().lower()
        if not line:
            continue
        if _HOSTNAME_PATTERN.match(line):
            found.add(line)
    return found


def enumerate_subdomains(target: str) -> dict:
    """
    Enumerate subdomains of `target` using subfinder and amass.

    Each tool runs independently through run_tool() so a failure or
    timeout in one does not block the other. Results are merged into a
    single deduped set and returned sorted.

    Returns
    -------
    dict:
        target       : str
        subdomains   : list[str]        sorted, deduped
        count        : int
        tools_used   : list[str]        tools that ran successfully
        tool_results : dict[str, dict]  raw run_tool() result per tool
    """
    all_subdomains = set()
    tools_used = []
    tool_results = {}

    tool_commands = {
        "subfinder": ["subfinder", "-d", target, "-silent"],
        "amass": ["amass", "enum", "-passive", "-d", target],
    }

    for tool_name, command in tool_commands.items():
        print_info(f"[Subdomain] Running {tool_name} against {target}...")
        # run_tool() already logs each call's start/success/failure under
        # its own tool_name — no need to log it again here.
        tool_result = run_tool(target, tool_name, command)
        tool_results[tool_name] = tool_result

        if tool_result.get("success"):
            found = _extract_hostnames(tool_result.get("stdout", "") or "")
            all_subdomains.update(found)
            tools_used.append(tool_name)
            print_success(f"[Subdomain] {tool_name} found {len(found)} subdomain(s)")
        else:
            err = tool_result.get("error") or tool_result.get("stderr") or f"{tool_name} failed"
            print_warning(f"[Subdomain] {tool_name} failed or unavailable: {err}")

    subdomains_sorted = sorted(all_subdomains)

    # This wraps two independent run_tool() calls (subfinder, amass), each
    # with its own "skipped" flag nested in tool_results[name] — surfaced
    # here as one top-level flag too so a profile orchestrator's simple
    # per-result stats loop (which only ever looks at r.get("skipped"), not
    # this dict's nested per-tool breakdown) still counts a skip as a skip
    # rather than silently miscounting it as neither a success nor failure.
    any_skipped = any(tr.get("skipped") for tr in tool_results.values())

    if not tools_used:
        if any_skipped:
            print_warning(f"[Subdomain] enumeration skipped by user for {target}")
        else:
            print_error(f"[Subdomain] All enumeration tools failed for {target}")
    else:
        print_success(f"[Subdomain] {len(subdomains_sorted)} unique subdomain(s) found for {target}")

    for sub in subdomains_sorted:
        log_finding(target, {"type": "subdomain", "value": sub})

    return {
        "tool": "subdomain_enum",
        "target": target,
        "subdomains": subdomains_sorted,
        "count": len(subdomains_sorted),
        "tools_used": tools_used,
        "tool_results": tool_results,
        "skipped": any_skipped,
        "error": None if tools_used else "all enumeration tools failed or were skipped",
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.recon.subdomain <target>")
        sys.exit(1)

    print_info(f"Enumerating subdomains for {sys.argv[1]}...")
    out = enumerate_subdomains(sys.argv[1])
    print_tree(f"Subdomains ({out['count']})", out["subdomains"])