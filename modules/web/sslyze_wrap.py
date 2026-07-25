"""
modules/web/sslyze_wrap.py
sslyze TLS/cipher audit wrapper for Aegis Scanner (web layer).

Runs `sslyze` against a target's TLS service through error_handler.run_tool()
and parses its JSON report (sslyze 5.x writes JSON only to a file, not
stdout, hence the temp-file dance below) for legacy protocol support and
weak cipher suites.

Best-effort parsing
--------------------
sslyze's JSON schema has changed across major versions. Every lookup here
goes through .get()-chains with dict/list defaults, so a schema this wrapper
doesn't recognise degrades to "nothing detected" instead of raising — never
a hard failure.
"""

import json
import os
import tempfile

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# Protocol result keys, oldest/weakest first, as sslyze 5.x names them in
# its JSON scan_result block.
_LEGACY_PROTOCOL_KEYS = [
    ("ssl_2_0_cipher_suites", "SSLv2"),
    ("ssl_3_0_cipher_suites", "SSLv3"),
    ("tls_1_0_cipher_suites", "TLSv1.0"),
    ("tls_1_1_cipher_suites", "TLSv1.1"),
]

# Cipher-suite name fragments that indicate a weak/export-grade cipher, even
# on an otherwise-modern protocol version.
_WEAK_CIPHER_MARKERS = ("NULL", "EXPORT", "RC4", "DES", "MD5", "ANON")


def _weak_ciphers(protocol_result: dict) -> list:
    accepted = (
        (protocol_result or {})
        .get("result", {})
        .get("accepted_cipher_suites", [])
    )
    names = []
    for entry in accepted or []:
        suite = (entry or {}).get("cipher_suite", {})
        name = suite.get("name") or suite.get("openssl_name") or ""
        if name and any(marker in name.upper() for marker in _WEAK_CIPHER_MARKERS):
            names.append(name)
    return names


def _parse_sslyze_json(raw_json: str) -> list:
    """
    Parse sslyze's JSON report into a list of:
        {issue: str, detail: str}

    Covers two signal classes: legacy protocol versions still accepted, and
    weak/export ciphers accepted on any protocol version (including modern
    ones). Any missing/renamed key simply yields fewer findings, never an
    exception.
    """
    findings = []

    try:
        data = json.loads(raw_json) if raw_json else {}
    except (json.JSONDecodeError, TypeError):
        return findings

    for server in (data or {}).get("server_scan_results", []) or []:
        scan_result = (server or {}).get("scan_result", {}) or {}

        for key, label in _LEGACY_PROTOCOL_KEYS:
            protocol_result = scan_result.get(key) or {}
            accepted = (protocol_result.get("result") or {}).get("accepted_cipher_suites") or []
            if accepted:
                findings.append({
                    "issue": f"Legacy protocol accepted: {label}",
                    "detail": f"{len(accepted)} cipher suite(s) negotiable over {label}",
                })

        for key in ("tls_1_0_cipher_suites", "tls_1_1_cipher_suites",
                    "tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
            weak = _weak_ciphers(scan_result.get(key))
            if weak:
                findings.append({
                    "issue": "Weak cipher suite(s) accepted",
                    "detail": ", ".join(sorted(set(weak))),
                })

    return findings


def run_sslyze(target: str, port: int = 443) -> dict:
    """
    Audit `target`'s TLS configuration on `port` with sslyze.

    Parameters
    ----------
    target : str   host / IP (bare hostname/IP, not a URL — sslyze scans a
                   host:port pair, not an HTTP endpoint)
    port   : int   TLS service port (default 443)

    Returns
    -------
    dict:
        target      : str
        port        : int
        findings    : list[dict]  {issue, detail}
        raw_output  : str         sslyze's JSON report text (empty if the
                                  report file couldn't be produced/read)
        error       : str | None  human-readable failure reason, if any

    Never raises. A missing sslyze binary, an unreachable target, or a
    report file that couldn't be written/read all come back as error set +
    findings empty.
    """
    result = {
        "tool": "sslyze",
        "target": target,
        "port": port,
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    host_port = f"{target}:{port}"

    fd, json_path = tempfile.mkstemp(prefix="aegis_sslyze_", suffix=".json")
    os.close(fd)

    try:
        command = ["sslyze", f"--json_out={json_path}", host_port]
        print_info(f"[Sslyze] Auditing TLS on {host_port}")

        # run_tool() already logs this call's start/success/failure under
        # the "sslyze" tool name — no need to log it again here.
        tool_result = run_tool(target, "sslyze", command)
        result["skipped"] = tool_result.get("skipped", False)

        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                raw_json = fh.read()
        except OSError:
            raw_json = ""

        result["raw_output"] = raw_json

        if not tool_result.get("success") and not raw_json.strip():
            result["error"] = tool_result.get("error") or tool_result.get("stderr") or "sslyze failed"
            print_error(f"[Sslyze] sslyze failed for {host_port} — {result['error']}")
            return result

        findings = _parse_sslyze_json(raw_json)
        result["findings"] = findings

        if findings:
            for f in findings:
                log_finding(target, {
                    "type": "sslyze_finding",
                    "port": port,
                    "issue": f["issue"],
                    "detail": f["detail"],
                })
                print_success(f"[Sslyze] {f['issue']} — {f['detail']}")
            print_info(f"[Sslyze] {host_port} — {len(findings)} finding(s)")
        else:
            print_warning(f"[Sslyze] {host_port} — scan completed, no weak TLS config found")

        return result
    finally:
        try:
            os.remove(json_path)
        except OSError:
            pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.web.sslyze_wrap <target> [port]")
        sys.exit(1)

    tgt = sys.argv[1]
    prt = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print_info(f"Running sslyze against {tgt}:{prt}...")
    out = run_sslyze(tgt, port=prt)
    for item in out["findings"]:
        print_info(f"  {item['issue']}: {item['detail']}")
    print_info(f"Error: {out['error'] or 'none'}")
