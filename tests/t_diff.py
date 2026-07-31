#!/usr/bin/env python3
"""
tests/t_diff.py
Checks modules/reporting/diff.py — the scan-to-scan delta.

What this file is really guarding
---------------------------------
A diff is only useful if it is trusted, and it stops being trusted the
first time it reports churn that did not happen. The failure is asymmetric:
a diff that misses a real change is a gap, but a diff that invents changes
teaches the reader to ignore it, which costs the real changes too.

So most of these assertions are about NOT reporting things:
  - a scan diffed against itself must be entirely unchanged
  - a set-valued fact reported in a different order is the same fact
  - fields that legitimately drift between runs (sizes, timings, severity,
    remediation wording) must not split one finding into fixed+new
while still proving the diff DOES notice a genuinely new or resolved
finding, and that it refuses to call a finding "fixed" when the tool that
would have found it never ran.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reporting import diff as diff_mod  # noqa: E402
from modules.reporting.diff import (  # noqa: E402
    finding_key, _identifier, _normalise_enumeration, diff_scans, render_diff,
)

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


def _f(**kw):
    kw.setdefault("finding_type", "nikto_finding")
    kw.setdefault("port", 80)
    kw.setdefault("severity", "LOW")
    return kw


def _patch(findings_by_scan, tools_by_scan=None):
    """Point diff.py at in-memory scans instead of the real database."""
    diff_mod.get_findings_for_scan = lambda sid: list(findings_by_scan.get(sid, []))
    diff_mod.get_scan_tools_run = lambda sid: list((tools_by_scan or {}).get(sid, []))


def main():
    print("=== A. enumeration order is not a change ===")
    # The exact pair observed live between two real scans of an unchanged
    # target, which the first implementation reported as 1 fixed + 1 new.
    a = "[999990] options: allowed http methods: options, get, head, post ."
    b = "[999990] options: allowed http methods: get, head, post, options ."
    check("reordered HTTP method list normalises to one key",
          _normalise_enumeration(a) == _normalise_enumeration(b))
    check("...and therefore to one finding key",
          finding_key(_f(description=a)) == finding_key(_f(description=b)))

    print("\n=== B. but different findings stay different ===")
    headers = ("content-security-policy", "permissions-policy", "referrer-policy",
               "strict-transport-security", "x-content-type-options")
    keys = {
        finding_key(_f(description=f"[013587] /: Suggested security header missing: {h}."))
        for h in headers
    }
    check(f"5 missing-header findings sharing one nikto test id stay 5 keys "
          f"(got {len(keys)})", len(keys) == 5)
    check("a different port is a different finding",
          finding_key(_f(description="x", port=80)) != finding_key(_f(description="x", port=443)))
    check("a different finding_type is a different finding",
          finding_key(_f(description="x", finding_type="nikto_finding"))
          != finding_key(_f(description="x", finding_type="zap_finding")))

    print("\n=== C. prose containing a comma is never reordered ===")
    for prose in (
        "apache/2.4.7 appears to be outdated, and the current release is at least 2.4.66",
        "[999965] /index: apache mod_negotiation is enabled with multiviews, "
        "which allows attackers to brute force",
    ):
        check(f"untouched: {prose[:52]}...", _normalise_enumeration(prose) == prose)

    print("\n=== D. volatile fields do not split a finding ===")
    pairs = [
        ("byte count", "discovered path /index (http 200, 6974 bytes)",
                       "discovered path /index (http 200, 31 bytes)"),
        ("status code", "discovered path /a (http 200)", "discovered path /a (http 301)"),
        ("timing", "scan took 45 ms", "scan took 900 ms"),
    ]
    for label, x, y in pairs:
        check(f"{label} change is the same finding",
              finding_key(_f(description=x)) == finding_key(_f(description=y)),
              f"{_identifier(_f(description=x))!r} != {_identifier(_f(description=y))!r}")

    print("\n=== E. identity fields beat the description fallback ===")
    check("a CVE is keyed on its id, not its prose",
          finding_key(_f(finding_type="cve", cve_id="CVE-2019-0708", description="one"))
          == finding_key(_f(finding_type="cve", cve_id="CVE-2019-0708", description="two")))
    check("two different CVEs stay distinct",
          finding_key(_f(finding_type="cve", cve_id="CVE-2019-0708"))
          != finding_key(_f(finding_type="cve", cve_id="CVE-2021-4034")))
    check("a discovered path is keyed on the path",
          finding_key(_f(finding_type="discovered_path", path="/admin", description="a"))
          == finding_key(_f(finding_type="discovered_path", path="/admin", description="b")))

    print("\n=== F. new / fixed / unchanged / changed ===")
    ran = {"tool_name": "nikto", "port": 80, "outcome": "ran"}
    _patch(
        {
            1: [_f(description="alpha"), _f(description="beta"), _f(description="gamma")],
            2: [_f(description="beta"), _f(description="gamma", severity="HIGH"),
                _f(description="delta")],
        },
        {1: [ran], 2: [ran]},
    )
    d = diff_scans(1, 2)
    check("new = 1 (delta)", d["counts"]["new"] == 1, str(d["counts"]))
    check("fixed = 1 (alpha)", d["counts"]["fixed"] == 1, str(d["counts"]))
    check("unchanged = 1 (beta)", d["counts"]["unchanged"] == 1, str(d["counts"]))
    check("changed = 1 (gamma LOW->HIGH)", d["counts"]["changed"] == 1, str(d["counts"]))
    check("...and records both severities",
          d["changed"][0].get("severity_from") == "LOW"
          and d["changed"][0].get("severity_to") == "HIGH")
    check("a severity move is NOT counted as fixed+new",
          d["counts"]["fixed"] == 1 and d["counts"]["new"] == 1)

    print("\n=== G. a scan diffed against itself reports no change ===")
    _patch({1: [_f(description=f"finding {i}") for i in range(25)]}, {1: [ran]})
    d = diff_scans(1, 1)
    check("25 findings, all unchanged", d["counts"]["unchanged"] == 25, str(d["counts"]))
    check("nothing new, fixed or changed",
          d["counts"]["new"] == 0 and d["counts"]["fixed"] == 0
          and d["counts"]["changed"] == 0, str(d["counts"]))

    print("\n=== H. absence is only 'fixed' if the tool actually ran ===")
    _patch(
        {1: [_f(description="alpha")], 2: []},
        {1: [ran], 2: [{"tool_name": "nikto", "port": 80, "outcome": "failed"}]},
    )
    d = diff_scans(1, 2)
    check("nikto failed in B -> unverified, not fixed",
          d["counts"]["unverified"] == 1 and d["counts"]["fixed"] == 0, str(d["counts"]))
    check("render_diff spells out that this is not remediation",
          "Do NOT read these as remediated" in render_diff(d))

    _patch({1: [_f(description="alpha")], 2: []}, {1: [ran], 2: [ran]})
    check("nikto ran in B -> genuinely fixed",
          diff_scans(1, 2)["counts"]["fixed"] == 1)

    # A scan predating the scan_tools_run table has no record at all. With
    # no evidence either way the honest default is not to cast doubt.
    _patch({1: [_f(description="alpha")], 2: []}, {1: [], 2: []})
    check("no tools-run record -> falls back to 'fixed', not 'unverified'",
          diff_scans(1, 2)["counts"]["fixed"] == 1)

    print("\n=== I. degrades rather than raising ===")
    _patch({}, {})
    d = diff_scans(1, 2)
    check("two empty scans report not-comparable", d["comparable"] is False)
    check("...and say so rather than implying 'no change'",
          "nothing to compare" in render_diff(d))

    def _boom(_sid):
        raise RuntimeError("database is gone")
    diff_mod.get_findings_for_scan = _boom
    check("a database error yields empty lists, not an exception",
          diff_scans(1, 2)["counts"]["new"] == 0)

    check("finding_key survives a non-dict", finding_key(None) == ("", None, ""))

    print("\n" + "=" * 60)
    print(f"PASS {PASS}   FAIL {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
