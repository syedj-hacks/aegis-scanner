"""
modules/scanning/hydra_wrap.py
Hydra credential brute-forcer wrapper for Aegis Scanner (scanning layer).

config.CONDITIONAL_TOOLS maps "hydra" -> "login_service_found", a flag
nothing in the codebase used to produce. modules/profiles/deepscan.py now
inspects detect_services()'s output for common login/auth protocols (ssh,
ftp, rdp, telnet — see deepscan.py's _detect_login_services()) to set that
flag and hand this module the specific service/port to target, rather than
hydra scanning every open port itself.

Runs `hydra` through error_handler.run_tool() against a small, known-good
credential list pair (never rockyou.txt-scale — this is a confirmation
pass, not an exhaustive brute force) and parses its "login:...password:..."
success lines.
"""

import os
import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Small, commonly-present-on-Kali candidate lists, checked in order. Kept
# deliberately modest in size (shortlists, not rockyou.txt) so a conditional
# dispatch triggered mid-scan finishes in a reasonable time.
_DEFAULT_USERLISTS = [
    "/usr/share/wordlists/metasploit/unix_users.txt",
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
]
_DEFAULT_PASSLISTS = [
    "/usr/share/wordlists/metasploit/unix_passwords.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-most-common.txt",
]

# -t 4      : 4 parallel connection tasks — polite default, avoids tripping
#             lockouts/rate limits on the target
# -f        : stop after the first valid credential pair is found per host
_HYDRA_BASE_ARGS = ["-t", "4", "-f"]

# Matches hydra's success lines, e.g.:
#   [22][ssh] host: 10.0.0.5   login: admin   password: admin123
# Some services/hydra versions (confirmed live: hydra 9.6 against ssh)
# insert an extra "misc: <text>" field between host and login, e.g.:
#   [2222][ssh] host: 10.0.0.5   misc: (null)   login: admin   password: admin
# — that optional segment used to break this match entirely (every real
# credential silently came back as "no valid credentials found"), so it's
# matched and discarded here rather than assumed absent.
_SUCCESS_LINE = re.compile(
    r"^\[(?P<port>\d+)\]\[(?P<service>\S+)\]\s+host:\s+(?P<host>\S+)\s+"
    r"(?:misc:\s+.*?\s+)?"
    r"login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S*)"
)


def _resolve_list(candidates: list, override: str = None) -> tuple:
    if override:
        if os.path.isfile(override):
            return override, ""
        return None, f"wordlist not found: {override}"
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate, ""
    return None, "no wordlist available; tried " + ", ".join(candidates)


def _parse_hydra_output(stdout: str) -> list:
    """
    Parse hydra's stdout into a list of:
        {port, service, login, password}

    Only successful-credential lines match; hydra's progress/status noise is
    ignored. Malformed/empty input yields [].
    """
    found = []
    for raw_line in (stdout or "").splitlines():
        match = _SUCCESS_LINE.match(raw_line.strip())
        if not match:
            continue
        try:
            port = int(match.group("port"))
        except (TypeError, ValueError):
            port = None
        found.append({
            "port": port,
            "service": match.group("service"),
            "login": match.group("login"),
            "password": match.group("password"),
        })
    return found


def run_hydra(target: str, service: str, port: int = None,
              userlist: str = None, passlist: str = None) -> dict:
    """
    Attempt a small, targeted credential brute-force against one login
    service on `target` with hydra.

    Parameters
    ----------
    target   : str  host / IP
    service  : str  hydra service module name, e.g. "ssh", "ftp", "rdp",
                    "telnet" — normally supplied by
                    deepscan._detect_login_services()
    port     : int  service port; omitted to let hydra use the protocol's
                    default port
    userlist : str  path to a username list; defaults to the first entry of
                    _DEFAULT_USERLISTS that exists on this system
    passlist : str  path to a password list; defaults to the first entry of
                    _DEFAULT_PASSLISTS that exists on this system

    Returns
    -------
    dict:
        target             : str
        service             : str
        port                : int | None
        credentials_found   : list[dict]  {port, service, login, password}
        raw_output          : str         hydra's stdout
        error               : str | None  human-readable failure reason

    Never raises. A missing hydra binary, missing wordlists, or an
    unreachable target all come back as error set + credentials_found empty.
    """
    result = {
        "tool": "hydra",
        "target": target,
        "service": service,
        "port": port,
        "credentials_found": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    resolved_users, user_error = _resolve_list(_DEFAULT_USERLISTS, userlist)
    if user_error:
        result["error"] = user_error
        print_error(f"[Hydra] {target}: {user_error}")
        return result

    resolved_passwords, pass_error = _resolve_list(_DEFAULT_PASSLISTS, passlist)
    if pass_error:
        result["error"] = pass_error
        print_error(f"[Hydra] {target}: {pass_error}")
        return result

    command = (
        ["hydra", "-L", resolved_users, "-P", resolved_passwords]
        + _HYDRA_BASE_ARGS
    )
    if port:
        command += ["-s", str(port)]
    command += [target, service]

    print_info(f"[Hydra] Testing {service} on {target}" + (f":{port}" if port else ""))

    # run_tool() already logs this call's start/success/failure under the
    # "hydra" tool name — no need to log it again here.
    tool_result = run_tool(target, "hydra", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "hydra failed"
        print_error(f"[Hydra] hydra failed for {target}/{service} — {result['error']}")
        return result

    credentials = _parse_hydra_output(result["raw_output"])
    result["credentials_found"] = credentials

    if credentials:
        for cred in credentials:
            log_finding(target, {
                "type": "weak_credentials",
                "port": cred["port"],
                "service": cred["service"],
                "login": cred["login"],
            })
            print_success(
                f"[Hydra] {service} credential found — {cred['login']}:{cred['password']}"
            )
        print_info(f"[Hydra] {target}/{service} — {len(credentials)} credential(s) found")
    else:
        print_warning(f"[Hydra] {target}/{service} — scan completed, no valid credentials found")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print_error("Usage: python -m modules.scanning.hydra_wrap <target> <service> [port]")
        sys.exit(1)

    tgt = sys.argv[1]
    svc = sys.argv[2]
    prt = int(sys.argv[3]) if len(sys.argv) > 3 else None

    print_info(f"Running hydra against {tgt} ({svc})...")
    out = run_hydra(tgt, svc, port=prt)
    for item in out["credentials_found"]:
        print_info(f"  {item['login']}:{item['password']}")
    print_info(f"Error: {out['error'] or 'none'}")
