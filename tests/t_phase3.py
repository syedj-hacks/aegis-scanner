"""Phase 3 verification: no bare dashes, honest labels, real nuclei JSONL."""
import sys, os, tempfile
sys.path.insert(0, "/home/jafar/aegis-scanner")

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")

from modules.web.nuclei_wrap import _parse_nuclei_jsonl, _matched_port
from modules.profiles._common import nuclei_port, nuclei_service, nuclei_description
from modules.reporting.summary import (
    field_display, service_display, cvss_display, finding_identifier,
    FINDING_TYPE_TOOL,
)

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {name}")
    else: fail += 1; print(f"  FAIL  {name}  -> {detail}")

RAW = os.path.join(_FIXTURES, "nuclei_raw.jsonl")

print("=== A. REAL nuclei JSONL: matched port recovered ===")
parsed = _parse_nuclei_jsonl(open(RAW).read())
check("6 findings parsed from real output", len(parsed) == 6, len(parsed))
check("every finding reports matched_port 6379 (NOT the probed 80)",
      all(f["matched_port"] == 6379 for f in parsed),
      [f["matched_port"] for f in parsed])
check("nuclei_port() overrides probed port 80 -> 6379",
      all(nuclei_port(f, 80) == 6379 for f in parsed))
check("nuclei_port() falls back to probed port when nuclei gave none",
      nuclei_port({"matched_port": None}, 8080) == 8080)
check("4 CVE ids recovered from real output",
      sum(1 for f in parsed if f["cve_id"]) == 4,
      [f["cve_id"] for f in parsed])
check("exposed-redis cvss 7.2 read from real classification",
      [f for f in parsed if f["template_id"] == "exposed-redis"][0]["cvss"] == 7.2)
check("cve-id:None in real classification does NOT become a string 'None'",
      [f for f in parsed if f["template_id"] == "exposed-redis"][0]["cve_id"] is None)

print("\n=== B. service: honest, never invented ===")
check("tcp/javascript protocol -> service NOT determined (6379 is not 'redis' by observation)",
      all(nuclei_service(f) is None for f in parsed),
      [nuclei_service(f) for f in parsed])
check("http protocol -> service 'http'", nuclei_service({"protocol": "http"}) == "http")
check("https scheme -> service 'https'", nuclei_service({"scheme": "https", "protocol": "http"}) == "https")
check("dns protocol -> None", nuclei_service({"protocol": "dns"}) is None)

print("\n=== C. _matched_port parsing edge cases ===")
check("explicit port field wins", _matched_port({"port": 6379}) == 6379)
check("string port coerced", _matched_port({"port": "443"}) == 443)
check("parsed from matched-at when port absent",
      _matched_port({"matched-at": "host:6379"}) == 6379)
check("URL with path not mistaken for a port",
      _matched_port({"matched-at": "http://host/a:b"}) is None,
      _matched_port({"matched-at": "http://host/a:b"}))
check("no port info -> None", _matched_port({}) is None)
check("port 0 rejected", _matched_port({"port": 0}) is None)
check("port 99999 rejected", _matched_port({"port": 99999}) is None)
check("garbage -> None", _matched_port({"port": "abc"}) is None)

print("\n=== D. field_display: N/A vs not-determined vs value ===")
cases = [
    ({"finding_type": "missing_security_header"}, "cve_id", "N/A (config finding)"),
    ({"finding_type": "discovered_path"}, "cve_id", "N/A (path discovery)"),
    # CVSS on a missing_security_header is no longer declared inapplicable —
    # item 6 (modules/enrichment/cvss.py) computes a local vector for it, so
    # summary._NOT_APPLICABLE["cvss"] no longer lists it. The CVSS cell is
    # rendered by cvss_display(), not field_display() (which is why
    # report_txt calls cvss_display for that column); cvss_display's own
    # None-path is asserted in section D2 below. field_display on a bare
    # `cvss` key with no value now correctly falls through to
    # "not determined", since it has no _NOT_APPLICABLE reason to give.
    ({"finding_type": "open_port"}, "cvss", "N/A (left unscored — exposure, not an assessed weakness)"),
    ({"finding_type": "nuclei_finding"}, "cve_id", "not determined by nuclei"),
    ({"finding_type": "nuclei_finding"}, "service", "not determined by nuclei"),
    ({"finding_type": "nikto_finding"}, "cve_id", "not determined by nikto"),
    ({"finding_type": "zap_finding"}, "cve_id", "not determined by zaproxy"),
    ({"finding_type": "smb_share"}, "service", "N/A (host-level finding)"),
    ({"finding_type": "sqlmap_finding"}, "cve_id", "N/A (injection class, not a CVE)"),
    ({"finding_type": "cve", "cve_id": "CVE-2021-44228"}, "cve_id", "CVE-2021-44228"),
    ({"finding_type": "cve", "cvss": 9.8}, "cvss", "9.8"),
    ({"finding_type": "wat_is_this"}, "cve_id", "not determined"),
    ({"finding_type": "cve", "service": "  http  "}, "service", "http"),
    ({"finding_type": "cve", "service": "None"}, "service", "not determined by NVD lookup"),
]
for finding, field, expected in cases:
    got = field_display(finding, field)
    check(f"{finding.get('finding_type')}/{field} -> {expected!r}", got == expected, repr(got))

print("\n=== D2. cvss_display: the CVSS column report_txt actually calls ===")
# A locally-scored finding shows the score, the source, and the vector — a
# score with no vector is just a differently-spelled severity bucket.
scored = {"finding_type": "missing_security_header", "cvss": 4.7,
          "severity_source": "cvss",
          "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"}
disp = cvss_display(scored)
check("a scored finding shows score + source + vector",
      disp == "4.7 (source: cvss) [CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N]", repr(disp))
# An unscored-but-scorable type (an ordinary path) is honest that it was
# graded heuristically — NOT "not determined by gobuster", which would
# misattribute the absence to a tool that never scores CVSS.
disp2 = cvss_display({"finding_type": "discovered_path"})
check("an unscored scorable type says 'graded heuristically', not a tool name",
      disp2 == "N/A (graded heuristically — see Severity)", repr(disp2))
# A deliberately-unscored type keeps its specific reason.
disp3 = cvss_display({"finding_type": "open_port"})
check("a deliberately-unscored type keeps its reason",
      disp3.startswith("N/A (left unscored"), repr(disp3))
# Never a bare dash.
check("cvss_display never returns a bare dash",
      cvss_display({"finding_type": "banner"}).strip() not in ("-", "", "None"))

print("\n=== E. NO bare dash anywhere, for EVERY finding_type in the DB ===")
import sqlite3
conn = sqlite3.connect("/home/jafar/aegis-scanner/database/aegis.db")
types = [r[0] for r in conn.execute("SELECT DISTINCT finding_type FROM findings")]
conn.close()
bad = []
for t in types:
    empty = {"finding_type": t}
    for field in ("port", "service", "version", "cve_id", "cvss"):
        v = field_display(empty, field)
        if v.strip() in ("-", "", "None", "unknown"):
            bad.append((t, field, v))
    if service_display(empty).strip() in ("-", "", "None", "unknown"):
        bad.append((t, "service_display", service_display(empty)))
    if cvss_display(empty).strip() in ("-", "", "None", "unknown"):
        bad.append((t, "cvss_display", cvss_display(empty)))
check(f"all {len(types)} real finding_types render no bare/ambiguous cell", not bad, bad)

print("\n=== F. service_display never drops a half-known pair ===")
check("both known", service_display({"finding_type":"cve","service":"http","version":"1.31.3"}) == "http 1.31.3")
check("service only labels the missing version",
      service_display({"finding_type":"cve","service":"nginx"}) == "nginx (version not determined by NVD lookup)",
      service_display({"finding_type":"cve","service":"nginx"}))
check("version only labels the missing service",
      service_display({"finding_type":"nuclei_finding","version":"8.2.1"}) == "not determined by nuclei (version 8.2.1)",
      service_display({"finding_type":"nuclei_finding","version":"8.2.1"}))
check("neither known, N/A type", service_display({"finding_type":"smb_share"}) == "N/A (host-level finding)")

print("\n=== G. finding_identifier shared by txt+pdf; PDF no longer says 'unknown' ===")
redis = {"finding_type":"nuclei_finding","cve_id":None,"service":None,
         "description": nuclei_description({"name":"Redis Lua Parser < 8.2.2 - Use After Free",
                                            "description":"Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below..."})}
ident = finding_identifier(redis)
check("nuclei finding w/o CVE gets a real title (was 'unknown' in PDF)",
      ident != "unknown" and ident.startswith("Redis Lua Parser"), ident)
check("CVE wins when present", finding_identifier({"cve_id":"CVE-1-1","service":"http"}) == "CVE-1-1")
check("service/version next", finding_identifier({"service":"http","version":"1.3"}) == "http 1.3")
check("finding_type as last resort, not 'unknown'",
      finding_identifier({"finding_type":"smb_share"}) == "smb_share")
check("truly empty -> 'unknown'", finding_identifier({}) == "unknown")

print("\n=== H. every DB finding_type has a tool name for the wording ===")
missing = [t for t in types if t and t not in FINDING_TYPE_TOOL]
check("no finding_type lacks a tool mapping", not missing, missing)

print("\n=== I. full render of a REAL scan: zero bare-dash cells ===")
from modules.reporting.report_txt import render_report
from modules.reporting.summary import build_summary
import io, contextlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")
for sid in (117, 115, 109):
    with contextlib.redirect_stdout(io.StringIO()):
        body = render_report(build_summary(sid))
    offenders = [l for l in body.splitlines()
                 if l.strip().endswith(": -") or ": - " in l
                 or l.strip().endswith(": none") or ": not scored" in l]
    check(f"scan {sid} report has no bare '-'/'none'/'not scored' cell",
          not offenders, offenders[:4])

print(f"\n{'='*60}\nPASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
