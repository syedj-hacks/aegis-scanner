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

import os
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from modules.utils.error_handler import run_tool
from modules.utils.config import get_profile, get_timeout, NMAP_TIMEOUTS

# config.py is gitignored, so a per-user copy predating this key is a real
# possibility — 1 restores the previous fully-sequential sweep.
try:
    from modules.utils.config import MAX_CONCURRENT_NMAP_CHUNKS as _MAX_CONCURRENT_CHUNKS
except ImportError:
    _MAX_CONCURRENT_CHUNKS = 1

# config.py is gitignored (each install carries its own), so an older copy
# predating the regression guard is a real possibility — fall back to the
# built-in default rather than failing to import the whole scanning layer.
try:
    from modules.utils.config import KNOWN_GOOD_TARGETS
except ImportError:
    KNOWN_GOOD_TARGETS = {"scanme.nmap.org": [22, 80]}

from modules.utils.logger import log_tool_failure, log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error, print_tree,
)

# Fallback nmap arguments when no profile is supplied.
# -T4  : faster timing template
# -F   : fast scan (nmap's ~100 most common ports)
# -Pn  : treat host as online / skip host-discovery so a filtered ICMP
#        response doesn't make nmap skip the port scan entirely.
_DEFAULT_NMAP_ARGS = ["-T4", "-F", "-Pn"]

# A full 65535-port '-p-' sweep is only used by deepscan's discovery pass
# now (at -T4) — stealthscan was redesigned to a small fixed port list
# instead of '-p-' at a quiet timing template, which live measurement
# showed was architecturally too slow (see config.NMAP_TIMEOUTS' comment).


def _compute_nmap_timeout(nmap_args) -> float:
    """
    A single TOOL_TIMEOUTS['nmap'] budget cannot fit both a top-100-port -F
    scan and a full 65535-port -p- sweep — the latter legitimately needs
    tens of minutes even against a fast, responsive host. Inspects the
    actual args this call is about to use and returns
    NMAP_TIMEOUTS['full_fast'] for a full-range sweep, falling back to the
    plain per-tool timeout for anything else.
    """
    args = list(nmap_args or [])
    full_range = "-p-" in args or any(
        a.replace(" ", "") == "1-65535" for a in args
    )
    if not full_range:
        return get_timeout("nmap")

    return NMAP_TIMEOUTS["full_fast"]


# How many sequential nmap invocations a "-p-" (full 65535-port) sweep is
# split into. Each chunk is a small, complete, independently-timed-out scan
# — see scan_ports()'s docstring note on why this replaces relying on a
# killed nmap process to flush partial -oX output (it doesn't, verified
# empirically). 32 chunks of ~2048 ports, calibrated against the measured
# ~9.4 ports/sec worst case (see config.NMAP_TIMEOUTS): a smaller chunk
# size than originally used (8 chunks of ~8192) matters because a fixed
# total time budget divided across too few chunks gave each chunk less
# time than a single chunk needed just to finish once — every chunk timed
# out before completing, so 100% of runs came back with zero ports despite
# "succeeding". 32 smaller chunks keeps each one's expected duration well
# inside its share of the total budget even at this measured rate.
_FULL_RANGE_CHUNKS = 32
_TOTAL_PORTS = 65535


def _split_full_range(chunks: int) -> list:
    """Split 1-65535 into `chunks` contiguous (lo, hi) port ranges."""
    size = _TOTAL_PORTS // chunks
    ranges = []
    lo = 1
    for i in range(chunks):
        hi = _TOTAL_PORTS if i == chunks - 1 else lo + size - 1
        ranges.append((lo, hi))
        lo = hi + 1
    return ranges


def _run_nmap_xml(target: str, nmap_args, timeout: float, label: str = "nmap"):
    """
    Run one nmap invocation with -oX pointed at a real temp file, return
    (xml_text, tool_result). The file is used (rather than "-oX -" on
    stdout) purely so a successful run's XML is read the same way
    regardless of pipe-buffering; always cleaned up before returning.
    """
    xml_fd, xml_path = tempfile.mkstemp(prefix="aegis_nmap_", suffix=".xml")
    os.close(xml_fd)
    try:
        command = ["nmap"] + list(nmap_args) + ["-oX", xml_path, target]
        tool_result = run_tool(target, "nmap", command, timeout=timeout)
        try:
            with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
                xml_text = fh.read()
        except OSError:
            xml_text = ""
        return xml_text or (tool_result.get("stdout", "") or ""), tool_result
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


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


# nmap <state reason=...> / <extrareasons reason=...> values that mean "we
# sent a probe and nothing whatsoever came back", as opposed to a real
# answer (reset / conn-refused / syn-ack) that proves the target is
# actually talking to us.
_SILENT_PORT_REASONS = {"no-response"}


def _parse_nmap_reachability(xml_text: str) -> dict:
    """
    Summarise *why* a scan saw no open ports, which the open-port list
    alone cannot distinguish.

    nmap exits 0 ("success") both when a target genuinely has nothing
    listening and when the target answered nothing at all — the latter
    being what a rate-limited, dropped or blackholed scan looks like.
    Verified live: a 2047-port -T4 scan of an unreachable host returns
    exit="success" with a single <extraports state="filtered"
    reason="no-response"> and zero <port> elements, in ~7s. That is
    indistinguishable from a clean "all closed" result unless the reasons
    are inspected, which is exactly how scan 97 reported zero findings on
    a healthy scanme.nmap.org without flagging anything.

    Returns {host_up, responsive, silent}: `responsive` counts ports that
    produced a real answer (reset / conn-refused / syn-ack), `silent`
    counts ports that produced nothing. Malformed/empty XML yields zeroes
    rather than raising, same contract as the other parsers here.
    """
    info = {"host_up": None, "responsive": 0, "silent": 0}

    if not xml_text or not xml_text.strip():
        return info

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return info

    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is not None and status_el.get("state"):
            info["host_up"] = status_el.get("state") == "up"

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        # Individually-reported ports.
        for port_el in ports_node.findall("port"):
            state_el = port_el.find("state")
            reason = state_el.get("reason", "") if state_el is not None else ""
            key = "silent" if reason in _SILENT_PORT_REASONS else "responsive"
            info[key] += 1

        # Ports nmap collapsed into an <extraports> summary — where a
        # fully-dropped scan's evidence actually lives.
        for extra_el in ports_node.findall("extraports"):
            for reason_el in extra_el.findall("extrareasons"):
                try:
                    count = int(reason_el.get("count", "0"))
                except (TypeError, ValueError):
                    count = 0
                key = ("silent" if reason_el.get("reason", "") in _SILENT_PORT_REASONS
                       else "responsive")
                info[key] += count

    return info


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


def _check_known_good_target(target: str, open_ports: list, skipped: bool = False) -> None:
    """
    Regression guard. A scan of a target whose open ports are a known,
    long-established fact must never come back empty and quiet.

    Silent when the user skipped the scan themselves (`skipped`): a
    deliberate skip legitimately yields zero ports and is not a
    regression. Without this the guard cries wolf on every skipped nmap
    run — scans 96 and 99 in this project's own history are exactly that
    case — and a guard that fires on non-events is one people learn to
    ignore, which would defeat its entire purpose.

    Every profile's port scope covers at least one of a known-good
    target's expected ports (deepscan/stealthscan/quickscan all reach
    22 and 80; webaudit and compliance both include 80), so "zero open
    ports on this host" is always wrong, never a scope artefact — which
    makes this safe to flag unconditionally without false positives.
    Deliberately scoped to the zero-port case for that reason: a partial
    result is not necessarily a regression, an empty one is.
    """
    expected = KNOWN_GOOD_TARGETS.get((target or "").strip().lower())
    if not expected or open_ports or skipped:
        return

    msg = (
        f"REGRESSION GUARD: {target} is a known-good target with "
        f"well-established open ports {expected}, but this scan found ZERO "
        f"open ports. This is a scanner or network fault, not a real "
        f"result — do not treat this scan as evidence the host is clean."
    )
    log_tool_failure(target, "nmap", msg)
    print_error(f"[Ports] {msg}")


def _diagnose_no_open_ports(target: str, result: dict, reach: dict) -> None:
    """
    Turn "found nothing" into an explicit, logged, on-screen verdict.

    Previously this path set result['error'] without ever calling
    log_tool_failure(), so the run was counted in the summary panel's
    "Tools failed" tally with no matching line in scan_errors.log and
    nothing on screen — a failure that was real but invisible.
    """
    responsive = reach.get("responsive", 0)
    silent = reach.get("silent", 0)
    probed = responsive + silent

    if probed and responsive == 0:
        msg = (
            f"nmap probed {probed} port(s) and got NO answer from any of them "
            f"— the target returned nothing at all. That is the signature of a "
            f"rate-limited, filtered or dropped scan, NOT a confirmed "
            f"'no open ports' result. These results are unreliable; re-run "
            f"with quieter timing, a smaller port set, or later."
        )
        result["unreachable"] = True
    else:
        msg = (
            f"nmap completed but found no open ports "
            f"({responsive} port(s) answered, {silent} silent)"
        )

    result["error"] = msg
    log_tool_failure(target, "nmap", msg)
    print_error(f"[Ports] {target}: {msg}")


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
    result = {
        "tool": "nmap",
        "target": target,
        "open_ports": [],
        "scripts": [],
        "profile_used": None,
        "raw_output": "",
        "error": None,
        "skipped": False,
        # True when the target answered nothing at all — see
        # _diagnose_no_open_ports(). Distinguishes "nothing is listening"
        # from "we never got a reply", which look identical otherwise.
        "unreachable": False,
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

    timeout = _compute_nmap_timeout(nmap_args)

    # A killed nmap process does NOT reliably flush a partial-but-valid -oX
    # document for a single-host scan — verified empirically before writing
    # this: a -p- sweep against a live, responsive host was sent SIGTERM/
    # SIGINT after 6s, 20s and 90s respectively, and in every case the -oX
    # file still contained nothing past the <scaninfo> header. nmap holds
    # the whole result in memory and only serialises it once the scan
    # actually concludes, so "read whatever the killed process wrote" is
    # not a real recovery strategy for this tool.
    #
    # A full 65535-port sweep ('-p-') is instead split into sequential
    # sub-range chunks, each its own complete nmap invocation with its own
    # -oX file. A chunk that finishes contributes real, valid results
    # immediately; a timeout/skip kills only the chunk in progress and
    # scanning simply stops there — every prior chunk's ports are kept.
    # This is what actually delivers "a kill loses the current unit of work,
    # not the whole scan" given nmap's real behaviour.
    if "-p-" in nmap_args:
        chunk_ranges = _split_full_range(_FULL_RANGE_CHUNKS)
        # Floor of 300s (not the earlier 30s): calibration measured ~9.4
        # ports/sec worst-case against a partially-firewalled target, so a
        # ~2048-port chunk needs ~218s just to finish once — a 30s floor
        # guaranteed every chunk would time out before completing even
        # one, which is exactly what was observed (100% of runs: 0 ports,
        # 0 completed chunks). NMAP_TIMEOUTS['full_fast'] is already sized
        # so timeout/chunks alone clears this floor; it's a backstop for
        # any future change to chunk count or that value.
        per_chunk_timeout = max(timeout / len(chunk_ranges), 300.0)
        other_args = [a for a in nmap_args if a != "-p-"]

        open_ports, scripts = [], []
        reach = {"host_up": None, "responsive": 0, "silent": 0}

        # Chunks run in small concurrent waves rather than strictly one at a
        # time. Each chunk was already a self-contained nmap invocation with
        # its own -oX file and its own timeout, so this is purely a
        # scheduling change — no chunk's result depends on any other's.
        #
        # The stop-on-failure contract is preserved, and is the reason for
        # the wave structure rather than one big pool: the sequential loop
        # stopped at the first failing chunk and kept every chunk before it.
        # With N chunks in flight, "before it" is only well-defined at a wave
        # boundary, so a failure anywhere in a wave lets that whole wave
        # finish (its results are real and already paid for) and then stops.
        # Chunk results are merged in range order, never completion order.
        #
        # per_chunk_timeout is unchanged. It is a per-process wall-clock
        # budget, and running three of them at once does not give any one of
        # them less time — only the total sweep gets shorter.
        concurrency = max(1, min(int(_MAX_CONCURRENT_CHUNKS), len(chunk_ranges)))
        if concurrency > 1:
            print_info(
                f"[Ports] full-range sweep: {len(chunk_ranges)} chunks, "
                f"{concurrency} at a time (per-chunk timeout {per_chunk_timeout:.0f}s)"
            )

        def _run_chunk(indexed):
            i, (lo, hi) = indexed
            chunk_args = other_args + ["-p", f"{lo}-{hi}"]
            xml_text, tool_result = _run_nmap_xml(
                target, chunk_args, per_chunk_timeout,
                label=f"nmap (chunk {i}/{len(chunk_ranges)}: {lo}-{hi})",
            )
            return i, lo, hi, xml_text, tool_result

        indexed_chunks = list(enumerate(chunk_ranges, start=1))
        stopped = False

        for wave_start in range(0, len(indexed_chunks), concurrency):
            wave = indexed_chunks[wave_start:wave_start + concurrency]

            if concurrency == 1:
                wave_results = [_run_chunk(c) for c in wave]
            else:
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    # map() preserves input order, so merging below happens in
                    # port-range order however the chunks actually finished.
                    wave_results = list(pool.map(_run_chunk, wave))

            failure = None
            for i, lo, hi, xml_text, tool_result in wave_results:
                open_ports.extend(_parse_nmap_xml(xml_text))
                scripts.extend(_parse_nmap_scripts(xml_text))

                # Accumulated across every chunk so a sweep that comes back
                # empty can say whether the target was answering at all.
                chunk_reach = _parse_nmap_reachability(xml_text)
                reach["responsive"] += chunk_reach["responsive"]
                reach["silent"] += chunk_reach["silent"]
                if chunk_reach["host_up"] is not None:
                    reach["host_up"] = chunk_reach["host_up"]

                if not tool_result.get("success") and failure is None:
                    failure = (i, lo, hi, tool_result)

            # Reported only after the whole wave has been merged. Building
            # the message at the point of failure would quote the port and
            # chunk counts as they stood mid-wave, understating both — the
            # rest of the wave's results are real and ARE kept, so a message
            # written before them would contradict what the scan returns.
            if failure is not None:
                i, lo, hi, tool_result = failure
                err = tool_result.get("error") or tool_result.get("stderr") or "nmap failed"
                completed = sum(1 for _, _, _, _, tr in wave_results if tr.get("success"))
                completed += wave_start   # every chunk in every prior wave
                result["error"] = (
                    f"chunk {i}/{len(chunk_ranges)} ({lo}-{hi}) {err} — "
                    f"stopping with {len(open_ports)} port(s) recovered from "
                    f"{completed} completed chunk(s)"
                )
                result["skipped"] = tool_result.get("skipped", False)
                log_tool_failure(target, "nmap", result["error"])
                print_warning(f"[Ports] {target}: {result['error']}")
                stopped = True

            if stopped:
                break

        result["open_ports"] = sorted(open_ports, key=lambda p: p["port"])
        result["scripts"] = scripts
        result["raw_output"] = f"{len(chunk_ranges)}-chunk scan; see per-chunk logs"

        if not result["open_ports"] and not result["scripts"] and result["error"] is None:
            _diagnose_no_open_ports(target, result, reach)

        _check_known_good_target(target, result["open_ports"], result.get("skipped", False))

    else:
        command = ["nmap"] + list(nmap_args) + [target]
        print_info(
            f"[Ports] Scanning {target} -> nmap {' '.join(nmap_args)} "
            f"(timeout={timeout:.0f}s)"
        )
        xml_text, tool_result = _run_nmap_xml(target, nmap_args, timeout, label="nmap")
        result["raw_output"] = xml_text
        result["open_ports"] = _parse_nmap_xml(xml_text)
        result["scripts"] = _parse_nmap_scripts(xml_text)

        result["skipped"] = tool_result.get("skipped", False)
        if not tool_result.get("success") and not result["open_ports"] and not result["scripts"]:
            # run_tool() already logged this call's own failure/timeout
            # under the "nmap" tool name.
            result["error"] = tool_result.get("error") or tool_result.get("stderr") or "nmap failed"
            print_error(f"[Ports] nmap failed for {target}: {result['error']}")
            return result

        if not result["open_ports"] and not result["scripts"] and result["error"] is None:
            _diagnose_no_open_ports(target, result, _parse_nmap_reachability(xml_text))

        _check_known_good_target(target, result["open_ports"], result.get("skipped", False))

    open_ports = result["open_ports"]
    scripts = result["scripts"]

    if open_ports:
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
    elif result["error"] is None:
        # nmap ran fine but nothing was open (host down, all filtered, etc.)
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
