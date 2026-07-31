#!/usr/bin/env python3
"""
tests/t_testssl.py
Checks modules/web/testssl_wrap.py's parsing and — mainly — its failure
reporting.

The bug this file exists to prevent
-----------------------------------
testssl.sh exits non-zero in TWO different situations that must be told
apart:

  - it found vulnerabilities          -> a successful scan WITH results
  - it could not reach the target     -> no scan happened at all

and it writes a well-formed JSON report in both. The wrapper deliberately
salvages output on a non-zero exit (otherwise every run that found
something would be discarded as a failure), which meant the second case was
silently salvaged too: a refused connection parsed to zero findings and was
reported as "scan completed, no CRITICAL/HIGH/MEDIUM TLS issue found".

That was found live — badssl.com began refusing connections partway through
verification, exit 246, 766 bytes of valid JSON, and the compliance scan
reported "Tools failed: 0" about a host it never tested. It is the same
invisible-failure class as scan 97's zero-open-ports result. These
assertions pin the distinction.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.web.testssl_wrap import (  # noqa: E402
    _parse_testssl_json, _scan_problem, _entries, _resolve_binary,
)
from modules.profiles._common import classify_tool_outcome  # noqa: E402

PASS = 0
FAIL = 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


# The exact document testssl.sh 3.2.4 writes when the connection is
# refused — captured from a real run against a closed port (exit 246).
_REFUSED = """{
  "Invocation": "testssl.sh --jsonfile-pretty x.json -U 127.0.0.1:9",
  "version": "3.2.4 ",
  "scanResult" : [
    {
      "id": "scanProblem",
      "severity": "FATAL",
      "finding": "Can't connect to '127.0.0.1:9' Make sure a firewall is not between you and your scanning target!"
    }
  ]
}"""

# A real successful run's shape: findings grouped into per-host sections.
_REAL = """{
  "version": "3.2.4 ",
  "scanResult" : [
    {
      "targetHost": "example.com", "port": "443",
      "pretest": [ {"id":"pre_128cipher","severity":"INFO","finding":"No 128 cipher limit bug"} ],
      "vulnerabilities": [
        {"id":"heartbleed","severity":"OK","finding":"not vulnerable"},
        {"id":"BREACH","severity":"MEDIUM","finding":"potentially VULNERABLE, gzip HTTP compression detected"},
        {"id":"ROBOT","severity":"OK","finding":"not vulnerable"}
      ],
      "cipherTests": [
        {"id":"cipherlist_3DES_IDEA","severity":"MEDIUM","finding":"offered"},
        {"id":"cipherlist_STRONG","severity":"OK","finding":"offered"}
      ],
      "rating": [ {"id":"overall_grade","severity":"INFO","finding":"B"} ]
    }
  ]
}"""


def main():
    print("=== A. a refused scan is a FAILURE, not a clean result ===")
    problem = _scan_problem(_REFUSED)
    check("scanProblem/FATAL is detected", bool(problem), repr(problem))
    check("...and carries testssl's own reason",
          "Can't connect" in (problem or ""))
    check("a refused scan parses to ZERO findings (this is why it was invisible)",
          _parse_testssl_json(_REFUSED) == [])
    # The whole point: zero findings alone cannot distinguish the two, so
    # the caller must consult _scan_problem() and not infer from the count.
    check("a refused scan is NOT reported as a finding of any severity",
          all("connect" not in f["issue"].lower()
              for f in _parse_testssl_json(_REFUSED)))

    result = {"tool": "testssl", "error": f"testssl.sh could not scan x: {problem}",
              "skipped": False}
    check("a refused scan classifies as 'failed'",
          classify_tool_outcome(result) == "failed")

    print("\n=== B. a real scan is not mistaken for a failure ===")
    check("no scan problem reported for a good run", _scan_problem(_REAL) is None)
    findings = _parse_testssl_json(_REAL)
    check(f"only CRITICAL/HIGH/MEDIUM become findings (got {len(findings)}, expect 2)",
          len(findings) == 2, str([f["issue"] for f in findings]))
    issues = " ".join(f["issue"] for f in findings)
    check("the named vulnerability gets its human label", "BREACH" in issues)
    check("OK/INFO entries are excluded",
          "heartbleed" not in issues.lower() and "overall_grade" not in issues)

    print("\n=== C. every section is walked, not a hardcoded subset ===")
    # The first draft walked 4 section names and dropped the rest, losing
    # every cipherTests result. cipherlist_3DES_IDEA lives in cipherTests.
    check("a cipherTests finding is not dropped",
          any("3DES_IDEA" in f["issue"] for f in findings),
          str([f["issue"] for f in findings]))
    entries, parsed = _entries(_REAL)
    check(f"all sections contribute entries (got {len(entries)})",
          len(entries) == 7, str(len(entries)))

    print("\n=== D. degrades rather than raising ===")
    for bad, label in ((None, "None"), ("", "empty"), ("not json", "garbage"),
                       ("{}", "empty object"), ("[]", "empty array")):
        try:
            check(f"{label}: no findings, no problem, no exception",
                  _parse_testssl_json(bad) == [] and _scan_problem(bad) is None)
        except Exception as exc:
            check(f"{label}: no exception", False, f"raised {exc!r}")

    entries, parsed = _entries("not json")
    check("unparseable JSON is reported as not-parsed", parsed is False)

    print("\n=== E. binary discovery ===")
    binary = _resolve_binary()
    check("resolves a binary, or honestly reports none",
          binary is None or os.path.exists(binary),
          f"resolved to {binary!r}")
    if binary is None:
        print("        (note: testssl.sh is not installed on this host — the "
              "wrapper's own 'not installed' path is what runs)")

    print("\n" + "=" * 60)
    print(f"PASS {PASS}   FAIL {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
