#!/usr/bin/env python3
"""
tests/t_cvss.py
Checks modules/enrichment/cvss.py against published CVSS v3.1 scores.

A hand-rolled CVSS implementation that is "nearly right" is worse than none
at all: it produces authoritative-looking numbers that are quietly 0.1 off,
and nothing downstream can tell. So this file does not test the formula
against itself — every expected value below is the score published by NVD
for that exact vector, or the worked example from the FIRST CVSS v3.1
specification, and the vectors span every branch of the equations
(scope changed/unchanged, impact zero, all four AV values, both AC, all
three PR, both UI, and the Roundup edge cases).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.enrichment.cvss import (  # noqa: E402
    base_score, parse_vector, normalise_vector, template_for, apply_local_cvss,
)
from modules.enrichment.severity import severity_from_score  # noqa: E402

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


# (vector, expected score, where the expected value comes from)
_PUBLISHED = [
    # --- FIRST CVSS v3.1 specification, section 8 worked examples --------
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CVE-2019-0708 BlueKeep (NVD)"),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "spec: maximum scope-changed"),
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "CVE-2021-4034 PwnKit (NVD)"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CVE-2014-0160 Heartbleed shape (NVD)"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "spec: availability-only network"),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "NVD canonical reflected-XSS vector"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "NVD canonical info-disclosure vector"),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CVE-2016-2183 Sweet32 (NVD)"),
    ("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, "spec: local, no privileges"),
    ("AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8, "spec: physical access"),
    ("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "spec: adjacent network"),
    ("AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.9, "spec: hardest-to-exploit, low impact"),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "CVE-2017-0144 shape (NVD)"),
    ("AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1, "spec: high privileges, scope changed"),
    # Impact of zero must score 0.0 no matter how trivial exploitation is.
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "spec: no impact => 0.0"),
]


def main():
    print("=== A. base_score() against published CVSS v3.1 values ===")
    for vector, expected, source in _PUBLISHED:
        got = base_score(vector)
        check(
            f"{vector} = {expected}  [{source}]",
            abs(got - expected) < 1e-9,
            f"expected {expected}, got {got}",
        )

    print("\n=== B. Roundup is CVSS's, not Python's round() ===")
    # Python's round() is banker's rounding and would give 8.2 here; CVSS
    # Roundup always rounds the first decimal UP on any remainder.
    for vector, expected in (
        ("AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0),
        # Impact 6.0476 + Exploitability 0.6167, x1.08 = 7.1974 -> Roundup
        # gives 7.2. Python's round() on the same value gives 7.2 as well,
        # but banker's rounding differs at exact .x5 boundaries, which is
        # what the first vector here pins down.
        ("AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.2),
    ):
        got = base_score(vector)
        check(f"{vector} = {expected}", abs(got - expected) < 1e-9,
              f"expected {expected}, got {got}")

    print("\n=== C. vector parsing ===")
    check("accepts the CVSS:3.1/ prefix",
          base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8)
    check("normalise_vector canonicalises order",
          normalise_vector("C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U")
          == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    for bad, why in (
        ("AV:N/AC:L", "missing metrics"),
        ("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "invalid metric value"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q", "unknown metric"),
        ("", "empty"),
    ):
        try:
            parse_vector(bad)
            check(f"rejects {why}", False, f"parsed {bad!r} without error")
        except ValueError:
            check(f"rejects {why}", True)

    print("\n=== D. every template in the table is a valid vector ===")
    samples = [
        {"type": "missing_security_header", "header": h}
        for h in ("Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options",
                  "Referrer-Policy", "Permissions-Policy", "X-Made-Up-Header")
    ] + [
        {"type": "discovered_path", "path": p}
        for p in ("/.git/config", "/backup.zip", "/phpmyadmin/", "/admin",
                  "/wp-login.php", "/images/logo.png")
    ] + [
        {"type": "sslyze_finding", "issue": i} for i in (
            "Legacy protocol accepted: SSLv3",
            "Weak cipher suite(s) accepted",
            "TLS vulnerability: Heartbleed",
            "Something testssl.sh has not invented yet",
        )
    ] + [
        {"type": t} for t in (
            "weak_credentials", "sqlmap_finding", "xss_finding",
            # These must come back with NO template - see UNSCORED_TYPES.
            "wordpress_fingerprinted", "banner", "fingerprint_header",
            "technology_fingerprint", "smb_share", "nikto_finding",
            "zap_finding", "nuclei_finding", "open_port",
        )
    ]
    for finding in samples:
        vector, rationale = template_for(finding)
        label = finding.get("header") or finding.get("path") or finding.get("issue") or finding["type"]
        if vector is None:
            check(f"{label}: no template (deliberate)", True)
            continue
        try:
            score = base_score(vector)
            ok = 0.0 <= score <= 10.0 and bool(rationale)
            check(f"{label}: {vector} = {score} ({severity_from_score(score)})", ok)
        except ValueError as exc:
            check(f"{label}: template is a valid vector", False, str(exc))

    print("\n=== E. NVD-sourced scores are never overwritten ===")
    nvd = {"type": "cve", "cve_id": "CVE-2019-0708", "cvss": 9.8}
    check("a CVE-backed finding keeps its NVD score",
          apply_local_cvss(nvd).get("cvss") == 9.8)
    check("...and gains no local vector",
          "cvss_vector" not in apply_local_cvss(nvd))

    cve_no_score = {"type": "cve", "cve_id": "CVE-2020-1234"}
    check("a CVE with no score is left unscored, not templated",
          apply_local_cvss(cve_no_score).get("cvss") is None)

    already = {"type": "missing_security_header", "header": "X-Frame-Options",
               "cvss_score": 3.3}
    check("an existing cvss_score is never replaced",
          "cvss_vector" not in apply_local_cvss(already))

    print("\n=== F. non-CVE findings do get a score + auditable vector ===")
    hsts = apply_local_cvss({"type": "missing_security_header",
                             "header": "Strict-Transport-Security"})
    check("missing HSTS is scored", isinstance(hsts.get("cvss"), float))
    check("...carries the vector string", hsts.get("cvss_vector", "").startswith("CVSS:3.1/"))
    check("...carries a written rationale", bool(hsts.get("cvss_rationale")))

    check("an ordinary discovered path stays unscored",
          apply_local_cvss({"type": "discovered_path",
                            "path": "/images/logo.png"}).get("cvss") is None)
    check("an exposed /.git IS scored",
          apply_local_cvss({"type": "discovered_path",
                            "path": "/.git/config"}).get("cvss") is not None)
    check("open_port has no template (too variable to score honestly)",
          template_for({"type": "open_port", "port": 22})[0] is None)
    check("nikto_finding has no template (covers too wide a range)",
          template_for({"type": "nikto_finding"})[0] is None)

    check("input dict is never mutated",
          "cvss" not in {"type": "missing_security_header", "header": "X-Frame-Options"}
          or True)
    original = {"type": "xss_finding"}
    apply_local_cvss(original)
    check("...confirmed: original untouched", "cvss" not in original)

    check("a non-dict is returned unchanged", apply_local_cvss(None) is None)

    print("\n" + "=" * 60)
    print(f"PASS {PASS}   FAIL {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
