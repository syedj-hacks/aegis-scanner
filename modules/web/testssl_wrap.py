"""
modules/web/testssl_wrap.py
testssl.sh TLS audit wrapper for Aegis Scanner (web layer).

Complementary to sslyze_wrap.py, not a replacement for it
----------------------------------------------------------
Both tools audit TLS, and the compliance profile runs both on purpose. They
answer different questions:

  sslyze     what protocols and cipher suites does this endpoint ACCEPT
             (a configuration inventory, parsed from its JSON report)
  testssl.sh is this endpoint VULNERABLE to a named TLS attack —
             Heartbleed, ROBOT, CCS injection, Ticketbleed, insecure
             renegotiation, CRIME, BREACH, LOGJAM, FREAK, DROWN, BEAST,
             Sweet32, POODLE, RC4 — plus certificate-level problems

sslyze does not test for any of the named vulnerabilities above; a
"Heartbleed" finding cannot come out of a cipher-suite inventory, because
the two are not derivable from one another. Running only one leaves a real
gap either way, so compliance runs both and the two sets of findings are
evidence about different properties of the same service.

Finding shape
-------------
Findings are emitted in sslyze_wrap.py's exact {issue, detail} shape and
are mapped into the SAME 'sslyze_finding'-family TLS finding type by the
compliance profile, rather than inventing a parallel schema. A TLS weakness
is the same kind of fact regardless of which tool observed it, and the
reports, severity scoring and compliance mapping should not each need to
learn a second vocabulary for it. The originating tool is recorded in the
detail text, so evidence is still attributable.

Output format
-------------
testssl.sh's --jsonfile-pretty writes a JSON array of finding objects, each
with id/severity/finding keys. Parsed defensively through .get()-chains
with dict/list defaults, exactly like sslyze_wrap.py: a schema this wrapper
does not recognise degrades to "nothing detected" rather than raising.

Binary name
-----------
Packaged as `testssl.sh` on Debian/Kali (apt) but as `testssl` in some
distributions, and as a bare checked-out script when installed via the
git-clone fallback in install.sh. All three are probed, in that order.
"""

import json
import os
import shutil
import tempfile

from modules.utils.error_handler import run_tool
from modules.utils.config import get_timeout
from modules.utils.logger import log_finding, log_tool_failure
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Candidate binary names/locations, most-standard first. The last entry is
# where install.sh's git-clone fallback puts it when apt has no package.
_TESTSSL_CANDIDATES = (
    "testssl.sh",
    "testssl",
    "/usr/bin/testssl.sh",
    "/opt/testssl.sh/testssl.sh",
)

# testssl.sh's own severity vocabulary, worst first. Anything at MEDIUM or
# above is reported as a finding; LOW/INFO/OK/WARN are configuration facts
# rather than weaknesses and would drown the real signal.
_REPORTABLE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")

# How testssl.sh reports that the SCAN ITSELF failed, as opposed to
# reporting something about the target. It emits
#
#   {"id": "scanProblem", "severity": "FATAL",
#    "finding": "Can't connect to '<host>:<port>' ..."}
#
# and exits non-zero, but it STILL WRITES A WELL-FORMED JSON FILE.
#
# That combination is the trap. This wrapper salvages partial output on a
# non-zero exit on purpose — testssl.sh exits non-zero when it FINDS
# vulnerabilities, so treating every non-zero exit as failure would discard
# exactly the runs that found something. But a refused connection also
# leaves a readable JSON file, one containing no results at all, so the
# naive salvage rule turns "we never reached the target" into "scan
# completed, no TLS issue found" — a clean-looking report about a host that
# was never tested.
#
# Reproduced deterministically against a closed port: exit 246, 766 bytes
# of valid JSON, zero parsed findings, wrapper reported success. This is
# the same invisible-failure class as the zero-open-ports result in scan 97
# and the ZAP pscanrules add-on that silently uninstalled itself; the rule
# this codebase settled on is that a failure must be counted AND reported
# by the same code path, never inferred from an absence.
_FATAL_SEVERITY = "FATAL"
_SCAN_PROBLEM_ID = "scanproblem"

# testssl.sh check ids that are vulnerability tests rather than inventory,
# mapped to the human name of the attack. Keys are lowercased because
# testssl.sh is inconsistent about case across its own check ids (`heartbleed`
# and `ticketbleed` are lower, `ROBOT`/`CCS`/`SWEET32`/`BEAST` are upper,
# `fallback_SCSV` and `LOGJAM-common_primes` are mixed) — the lookup
# lowercases before matching so all three conventions resolve.
#
# Taken from an actual --jsonfile-pretty run (testssl.sh 3.2.4), not from
# the documentation: the ids emitted in JSON do not all match the names used
# in the man page or in the script's own function names.
#
# This map only decides how a finding is LABELLED. A reportable severity is
# what decides inclusion, so a check id added in a future testssl.sh version
# is still reported in full — it just gets the generic label rather than a
# pretty one, which is the right way round for a tool whose vocabulary grows.
_VULN_IDS = {
    "heartbleed": "Heartbleed",
    "ccs": "CCS injection",
    "ticketbleed": "Ticketbleed",
    "robot": "ROBOT",
    "secure_renego": "Insecure renegotiation",
    "secure_client_renego": "Insecure client-initiated renegotiation",
    "crime_tls": "CRIME",
    "breach": "BREACH",
    "poodle_ssl": "POODLE (SSL)",
    "fallback_scsv": "Missing TLS_FALLBACK_SCSV",
    "sweet32": "Sweet32",
    "freak": "FREAK",
    "drown": "DROWN",
    "drown_hint": "DROWN (cross-protocol hint)",
    "logjam": "LOGJAM",
    "logjam-common_primes": "LOGJAM (common DH primes)",
    "beast": "BEAST",
    "beast_cbc_tls1": "BEAST (CBC ciphers over TLS 1.0)",
    "lucky13": "Lucky13",
    "rc4": "RC4 ciphers supported",
    "winshock": "Winshock",
}


def _resolve_binary():
    """
    The testssl.sh executable to invoke, or None when none is installed.

    Returned rather than assumed so a missing binary becomes this wrapper's
    own clear error message instead of run_tool()'s generic "binary not
    found on PATH: testssl.sh" — which, given three plausible names, does
    not tell the reader whether the tool is missing or merely named
    differently here.
    """
    for candidate in _TESTSSL_CANDIDATES:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def _scan_problem(raw_json: str):
    """
    testssl.sh's own reason the scan could not run, or None.

    Returned separately from the findings rather than folded into them: a
    scan that never reached the target has not produced a finding of any
    severity, and rendering it as one would put "Can't connect to host" in
    a report's TLS findings section as though it were a property of the
    target's TLS configuration. It is a tool failure, and the caller raises
    it as one.
    """
    entries, _ = _entries(raw_json)
    for entry in entries:
        severity = str(entry.get("severity") or "").strip().upper()
        check_id = str(entry.get("id") or "").strip().lower()
        if severity == _FATAL_SEVERITY or check_id == _SCAN_PROBLEM_ID:
            return " ".join(str(entry.get("finding") or "scan problem").split())
    return None


def _entries(raw_json: str):
    """
    Every finding object in a testssl.sh report, and whether the document
    parsed at all.

    Returns (entries, parsed). `parsed` distinguishes "valid JSON with no
    entries" from "not JSON" — the caller needs to tell an empty report
    apart from an unreadable one.
    """
    try:
        data = json.loads(raw_json) if raw_json else None
    except (json.JSONDecodeError, TypeError):
        return [], False

    if data is None:
        return [], False

    # Two shapes, both handled:
    #
    #   --jsonfile         a flat array of finding objects
    #   --jsonfile-pretty  {..., "scanResult": [ {per-host, with findings
    #                      grouped into named sections} ]}
    #
    # For the pretty shape every LIST-valued key on the host object is
    # walked, rather than a hardcoded list of section names. Verified
    # against testssl.sh 3.2.4, which emits eleven of them (pretest,
    # protocols, grease, ciphers, serverPreferences, fs, serverDefaults,
    # vulnerabilities, cipherTests, browserSimulations, rating) — an earlier
    # draft of this parser named four and silently dropped the findings in
    # the other seven, including every cipherTests result.
    entries = []
    if isinstance(data, list):
        entries = [v for v in data if isinstance(v, dict)]
    elif isinstance(data, dict):
        scan_result = data.get("scanResult") or data.get("findings") or []
        if isinstance(scan_result, list):
            for host_block in scan_result:
                if not isinstance(host_block, dict):
                    continue
                # A scanProblem entry sits directly in scanResult, not
                # inside a per-host section — so the block itself counts.
                if host_block.get("id") or host_block.get("severity"):
                    entries.append(host_block)
                for value in host_block.values():
                    if isinstance(value, list):
                        entries.extend(v for v in value if isinstance(v, dict))
    return entries, True


def _parse_testssl_json(raw_json: str) -> list:
    """
    Parse testssl.sh's --jsonfile-pretty output into a list of:
        {issue: str, detail: str}

    Only CRITICAL/HIGH/MEDIUM entries become findings — see
    _REPORTABLE_SEVERITIES. Malformed or empty JSON yields [] rather than
    raising, same contract as sslyze_wrap._parse_sslyze_json().
    """
    findings = []

    entries, _ = _entries(raw_json)

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        severity = str(entry.get("severity") or "").strip().upper()
        if severity not in _REPORTABLE_SEVERITIES:
            continue

        check_id = str(entry.get("id") or "").strip()
        finding_text = str(entry.get("finding") or "").strip()
        if not finding_text:
            continue

        label = _VULN_IDS.get(check_id.lower())
        if label:
            issue = f"TLS vulnerability: {label}"
        else:
            issue = f"TLS weakness: {check_id or 'unnamed check'}"

        # The originating tool is named in the detail rather than in a
        # separate column: these findings share sslyze's finding type on
        # purpose (see the module docstring), so attribution has to travel
        # in text that survives the database round-trip.
        findings.append({
            "issue": issue,
            "detail": f"{finding_text} [{severity}, via testssl.sh check '{check_id}']",
        })

    return findings


def run_testssl(target: str, port: int = 443) -> dict:
    """
    Audit `target`'s TLS service on `port` with testssl.sh.

    Parameters
    ----------
    target : str   host / IP (a host:port pair is scanned, not a URL)
    port   : int   TLS service port (default 443)

    Returns
    -------
    dict:
        target      : str
        port        : int
        findings    : list[dict]  {issue, detail} — same shape sslyze emits
        raw_output  : str         testssl.sh's JSON report text
        error       : str | None  human-readable failure reason, if any
        skipped     : bool

    Never raises. A missing testssl.sh binary, an unreachable target, or an
    unreadable report file all come back as error set + findings empty.
    """
    result = {
        "tool": "testssl",
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    binary = _resolve_binary()
    if not binary:
        msg = (
            "testssl.sh is not installed (tried "
            + ", ".join(_TESTSSL_CANDIDATES)
            + ") — run install.sh, or apt install testssl.sh"
        )
        result["error"] = msg
        print_error(f"[Testssl] {target}:{port} — {msg}")
        return result

    host_port = f"{target}:{port}"

    fd, json_path = tempfile.mkstemp(prefix="aegis_testssl_", suffix=".json")
    os.close(fd)
    # testssl.sh refuses to overwrite an existing report file, and mkstemp
    # has just created one. Removing it keeps the collision-free name.
    try:
        os.remove(json_path)
    except OSError:
        pass

    try:
        command = [
            binary,
            "--jsonfile-pretty", json_path,
            # -U runs every vulnerability check — the whole reason this tool
            # is here alongside sslyze, which tests none of them.
            "-U",
            # Protocol and cipher-strength inventory, so a run still yields
            # the configuration facts if a vuln check is inconclusive.
            "-p", "-s",
            # Non-interactive, no colour, no update nag: this is the same
            # class of prompt that hung nikto for a full timeout on the
            # CIRT.net check (see nikto_wrap.py) — a tool that stops to ask
            # a question inside run_tool() burns its entire budget and
            # returns nothing.
            "--warnings", "batch",
            "--color", "0",
            "--quiet",
            host_port,
        ]
        print_info(f"[Testssl] Auditing TLS on {host_port} (vulnerability checks enabled)")

        # run_tool() already logs start/success/failure under "testssl".
        tool_result = run_tool(target, "testssl", command,
                               timeout=get_timeout("testssl"))
        result["skipped"] = tool_result.get("skipped", False)

        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                raw_json = fh.read()
        except OSError:
            raw_json = ""

        result["raw_output"] = raw_json

        # testssl.sh exits non-zero when it FINDS vulnerabilities, not only
        # when it fails — so a non-zero exit with a readable report is a
        # successful scan with results, and treating it as a failure would
        # discard exactly the runs that found something.
        if not tool_result.get("success") and not raw_json.strip():
            result["error"] = (
                tool_result.get("error") or tool_result.get("stderr") or "testssl.sh failed"
            )
            print_error(f"[Testssl] testssl.sh failed for {host_port} — {result['error']}")
            return result

        # ...but testssl.sh ALSO writes a well-formed JSON file when it
        # could not reach the target at all, and that file contains a
        # scanProblem/FATAL entry instead of results. Salvaging it as
        # "completed, nothing found" would report a host that was never
        # tested as a host with no TLS problems. Checked before the findings
        # are parsed, because the distinction is not visible in the parsed
        # output — both cases yield zero findings.
        problem = _scan_problem(raw_json)
        if problem:
            result["error"] = f"testssl.sh could not scan {host_port}: {problem}"
            result["skipped"] = tool_result.get("skipped", False)
            log_tool_failure(target, "testssl", result["error"])
            print_error(f"[Testssl] {result['error']}")
            return result

        findings = _parse_testssl_json(raw_json)
        result["findings"] = findings

        if findings:
            for f in findings:
                log_finding(target, {
                    "type": "sslyze_finding",   # shared TLS finding family
                    "port": port,
                    "issue": f["issue"],
                    "detail": f["detail"],
                })
                print_success(f"[Testssl] {f['issue']}")
            print_info(f"[Testssl] {host_port} — {len(findings)} finding(s)")
        else:
            print_warning(
                f"[Testssl] {host_port} — scan completed, no CRITICAL/HIGH/MEDIUM "
                "TLS issue found"
            )

        return result
    finally:
        try:
            os.remove(json_path)
        except OSError:
            pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.testssl_wrap <target> [port]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print_info(f"Running testssl.sh against {tgt}:{prt}...")
    out = run_testssl(tgt, port=prt)
    for item in out["findings"]:
        print_info(f"  {item['issue']}: {item['detail']}")
    print_info(f"Error: {out['error'] or 'none'}")
