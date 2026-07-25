"""
modules/scanning/banner.py
Banner grabbing module for Aegis Scanner (Member C - scanning layer).

A lightweight supplement / fallback to nmap's -sV detection: for each open
port we open a raw TCP socket, read the initial bytes the service emits on
connect (SSH / FTP / SMTP / telnet style banners), and return them.

This module does NOT go through run_tool() because it is not a subprocess
call — it is a direct socket operation. To keep the "never raises" contract
the rest of the framework relies on, every socket attempt is wrapped in
error_handler.safe_call(), so a refused connection / timeout / reset becomes
a structured result instead of an exception.
"""

import socket
import time

from modules.utils.error_handler import safe_call, is_user_skip
from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_tool_skip, log_finding,
)
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# How long (seconds) to wait for a connect and for the initial read. 5s
# rather than a shorter value because this module usually runs after a
# round of nikto/gobuster/nuclei traffic against the same host already
# (deepscan's flow), and a WAF/CDN under that load is measurably slower to
# complete a fresh TCP handshake than it is on a cold connection.
_CONNECT_TIMEOUT = 5.0
# Max bytes to read from the initial banner.
_READ_BYTES = 1024
# One retry after a short pause: a single dropped SYN or a transient
# rate-limit window shouldn't read as "unreachable" when the port is, in
# fact, open (nikto/gobuster/header_check reaching it prove that).
_RETRY_DELAY = 1.5


def _normalise_ports(ports) -> list:
    """Coerce ports into a deduped, sorted list of ints; drop non-numerics."""
    clean = []
    for p in ports or []:
        try:
            clean.append(int(p))
        except (TypeError, ValueError):
            continue
    return sorted(set(clean))


def _grab_single(host: str, port: int, timeout: float) -> str:
    """
    Open a TCP socket to host:port, read the initial banner bytes, return
    them as a cleaned string. May raise (socket.timeout, ConnectionRefused,
    OSError) — callers MUST invoke this through safe_call() so those
    exceptions are captured instead of propagating.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        # Most banner-emitting services (SSH/FTP/SMTP) speak first, so a
        # plain recv is enough. Request-driven services (HTTP) simply time
        # out here and yield an empty banner — that's fine, -sV covers them.
        data = sock.recv(_READ_BYTES)
    return data.decode("utf-8", errors="replace").strip()


def grab_banners(target: str, ports) -> dict:
    """
    Attempt to grab initial TCP banners from `target` on each of `ports`.

    Parameters
    ----------
    target : str        host / IP
    ports  : list[int]  ports to probe (typically the open ports from
                         port_scanner.scan_ports())

    Returns
    -------
    dict:
        target  : str
        banners : list[dict]  {port: int, banner_text: str}
                              one entry per probed port; banner_text is ""
                              when the port sent nothing / was unreachable
        error   : str | None  set only for a top-level problem (e.g. no
                              ports supplied); per-port failures are logged,
                              not surfaced here
    """
    log_tool_start(target, "banner_grab")

    result = {
        "tool": "banner_grab",
        "target": target,
        "banners": [],
        "error": None,
        # Set below if the operator skips out of the per-port loop. Unlike
        # header_check, a skip here was never *miscounted* as a failure —
        # per-port errors are logged rather than raised to result['error']
        # — but it was entirely invisible: not counted as failed, not
        # counted as skipped, nothing on the summary panel at all.
        "skipped": False,
    }

    port_list = _normalise_ports(ports)
    if not port_list:
        msg = "no ports supplied; skipping banner grab"
        result["error"] = msg
        log_tool_failure(target, "banner_grab", msg)
        print_warning(f"[Banner] {target}: {msg}")
        return result

    print_info(f"[Banner] Grabbing banners on {target} ports {port_list}")

    grabbed = 0
    for port in port_list:
        # safe_call guarantees this never raises: on any socket error it
        # returns {success: False, data: None, error: str} and logs it.
        outcome = safe_call(
            _grab_single, target, port, _CONNECT_TIMEOUT,
            target=target, label=f"banner_grab:{port}",
        )

        if not outcome.get("success"):
            # One retry after a short pause — see _RETRY_DELAY above. Not
            # retried through safe_call's KeyboardInterrupt handling twice:
            # a Ctrl+C during the sleep just skips straight to the next port.
            time.sleep(_RETRY_DELAY)
            outcome = safe_call(
                _grab_single, target, port, _CONNECT_TIMEOUT,
                target=target, label=f"banner_grab:{port}",
            )

        banner_text = ""
        if outcome.get("success") and outcome.get("data"):
            banner_text = outcome["data"]
            grabbed += 1
            log_finding(target, {
                "type": "banner",
                "port": port,
                "banner_text": banner_text,
            })
            # Show only the first line to keep the console tidy.
            first_line = banner_text.splitlines()[0] if banner_text.splitlines() else banner_text
            print_success(f"[Banner] {target}:{port} -> {first_line}")
        elif outcome.get("success"):
            # Connected but no data (e.g. HTTP waiting for a request).
            print_warning(f"[Banner] {target}:{port} connected but sent no banner")
        elif is_user_skip(outcome.get("error")):
            # A deliberate Ctrl+C. Stop probing the remaining ports rather
            # than making the operator interrupt once per port, and record
            # the skip so the summary panel accounts for it instead of
            # showing a banner grab that silently did nothing.
            result["skipped"] = True
            result["error"] = outcome.get("error")
            log_tool_skip(target, "banner_grab")
            print_warning(
                f"[Banner] {target}: skipped by user — "
                f"{grabbed}/{len(port_list)} banner(s) grabbed before the skip"
            )
            break
        else:
            # safe_call already logged the failure reason.
            print_warning(f"[Banner] {target}:{port} unreachable: {outcome.get('error')}")

        result["banners"].append({"port": port, "banner_text": banner_text})

    if not result["skipped"]:
        log_tool_success(target, "banner_grab")
    print_info(f"[Banner] {target}: grabbed {grabbed}/{len(port_list)} banner(s)")
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print_error("Usage: python -m modules.scanning.banner <target> <port[,port,...]>")
        sys.exit(1)

    tgt = sys.argv[1]
    ports_in = [p for p in sys.argv[2].split(",") if p.strip()]

    print_info(f"Grabbing banners on {tgt} ports {ports_in}...")
    out = grab_banners(tgt, ports_in)
    for b in out["banners"]:
        preview = (b["banner_text"][:60] + "...") if len(b["banner_text"]) > 60 else b["banner_text"]
        print_info(f"  {b['port']}: {preview or '(no banner)'}")
    print_info(f"Error: {out['error'] or 'none'}")
