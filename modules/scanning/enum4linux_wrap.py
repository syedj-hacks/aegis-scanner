"""
modules/scanning/enum4linux_wrap.py
enum4linux SMB/NetBIOS enumeration wrapper for Aegis Scanner (scanning
layer).

config.CONDITIONAL_TOOLS maps "enum4linux" -> "smb_service_found", a flag
nothing in the codebase used to produce. modules/profiles/deepscan.py now
checks detect_services()/scan_ports()'s output for ports 139/445 (see
deepscan.py's _detect_smb_services()) to set that flag before dispatching
here.

Runs `enum4linux` through error_handler.run_tool() and does best-effort
regex parsing of its free-text report — the classic Perl tool's output
format varies across versions and target OSes, so parsing degrades to
"nothing extracted" rather than raising on an unrecognised layout.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -a : do all the simple enumeration (equivalent to -U -S -G -P -O -N -I)
_ENUM4LINUX_BASE_ARGS = ["-a"]

# Matches share-listing rows, e.g.:
#       print$          Disk      Printer Drivers
#       IPC$             IPC       IPC Service
_SHARE_LINE = re.compile(r"^\s*(?P<name>\S+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*)$")

# Matches user-enumeration rows, e.g.:
#   user:[Administrator] rid:[0x1f4]
_USER_LINE = re.compile(r"user:\[(?P<user>[^\]]+)\]\s+rid:\[(?P<rid>0x[0-9a-fA-F]+)\]")

# Matches the OS-info summary line, e.g.:
#   OS=[Windows 6.1] Server=[Windows 6.1 Service Pack 1]
_OS_LINE = re.compile(r"OS=\[(?P<os>[^\]]+)\]")


def _parse_enum4linux_output(stdout: str) -> tuple:
    """
    Best-effort parse of enum4linux's free-text report.

    Returns (shares, users, os_info):
        shares  : list[dict]  {name, type, comment}
        users   : list[dict]  {user, rid}
        os_info : str | None

    Any section enum4linux didn't print (e.g. null sessions disabled)
    simply yields an empty list/None for that section — never an exception.
    """
    shares, users = [], []
    seen_shares, seen_users = set(), set()
    os_info = None

    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip()

        if os_info is None:
            os_match = _OS_LINE.search(line)
            if os_match:
                os_info = os_match.group("os").strip()
                continue

        user_match = _USER_LINE.search(line)
        if user_match:
            key = user_match.group("user")
            if key not in seen_users:
                seen_users.add(key)
                users.append({"user": key, "rid": user_match.group("rid")})
            continue

        share_match = _SHARE_LINE.match(line)
        if share_match:
            name = share_match.group("name").strip()
            if name and name not in ("Sharename", "----") and name not in seen_shares:
                seen_shares.add(name)
                shares.append({
                    "name": name,
                    "type": share_match.group("type"),
                    "comment": share_match.group("comment").strip(),
                })

    return shares, users, os_info


def run_enum4linux(target: str) -> dict:
    """
    Enumerate SMB/NetBIOS shares, users and OS info on `target` with
    enum4linux.

    Parameters
    ----------
    target : str  host / IP with SMB (139/445) open

    Returns
    -------
    dict:
        target      : str
        shares      : list[dict]  {name, type, comment}
        users       : list[dict]  {user, rid}
        os_info     : str | None
        raw_output  : str         enum4linux's stdout
        error       : str | None  human-readable failure reason, if any

    Never raises. A missing enum4linux binary or an unreachable target come
    back as error set + shares/users empty. A live SMB host that simply
    doesn't allow null-session enumeration also comes back with everything
    empty, but without `error` set — that's a valid (if uninformative)
    result, not a failure.
    """
    result = {
        "tool": "enum4linux",
        "target": target,
        "shares": [],
        "users": [],
        "os_info": None,
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    command = ["enum4linux"] + _ENUM4LINUX_BASE_ARGS + [target]
    print_info(f"[Enum4linux] Enumerating SMB/NetBIOS on {target}")

    # run_tool() already logs this call's start/success/failure under the
    # "enum4linux" tool name — no need to log it again here.
    tool_result = run_tool(target, "enum4linux", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "enum4linux failed"
        print_error(f"[Enum4linux] enum4linux failed for {target} — {result['error']}")
        return result

    shares, users, os_info = _parse_enum4linux_output(result["raw_output"])
    result["shares"] = shares
    result["users"] = users
    result["os_info"] = os_info

    for share in shares:
        log_finding(target, {
            "type": "smb_share",
            "name": share["name"],
            "share_type": share["type"],
        })
        print_success(f"[Enum4linux] share: {share['name']} ({share['type']})")

    for user in users:
        log_finding(target, {"type": "smb_user", "user": user["user"], "rid": user["rid"]})
        print_success(f"[Enum4linux] user: {user['user']} (rid {user['rid']})")

    if os_info:
        print_info(f"[Enum4linux] OS: {os_info}")

    if not shares and not users and not os_info:
        print_warning(f"[Enum4linux] {target} — scan completed, nothing extracted (null session likely disabled)")
    else:
        print_info(
            f"[Enum4linux] {target} — {len(shares)} share(s), {len(users)} user(s)"
        )

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.scanning.enum4linux_wrap <target>")
        sys.exit(1)

    tgt = sys.argv[1]

    print_info(f"Running enum4linux against {tgt}...")
    out = run_enum4linux(tgt)
    print_info(f"OS: {out['os_info'] or 'unknown'}")
    for s in out["shares"]:
        print_info(f"  share: {s['name']} ({s['type']})")
    for u in out["users"]:
        print_info(f"  user: {u['user']}")
    print_info(f"Error: {out['error'] or 'none'}")
