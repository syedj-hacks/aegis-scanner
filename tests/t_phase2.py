"""Phase 2 verification against REAL data, not fixtures."""
import sys, json
sys.path.insert(0, "/home/jafar/aegis-scanner")

from modules.web.nuclei_wrap import _parse_nuclei_jsonl, _cve_from_template, _cvss_from_classification
from modules.profiles._common import nuclei_description
from modules.reporting.summary import deduplicate_findings

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  PASS  {name}")
    else:
        fail += 1; print(f"  FAIL  {name}  {detail}")

print("=== A. cve_id recovered from CVE-shaped template id ===")
check("CVE-2025-46817 template id -> cve_id",
      _cve_from_template("CVE-2025-46817", {}) == "CVE-2025-46817",
      _cve_from_template("CVE-2025-46817", {}))
check("classification.cve-id still preferred when present",
      _cve_from_template("CVE-2025-46817", {"cve-id": ["CVE-1999-0001"]}) == "CVE-1999-0001")
check("multi-CVE classification joined",
      _cve_from_template("x", {"cve-id": ["CVE-1-1111", "CVE-2-2222"]}) == "CVE-1-1111,CVE-2-2222")
check("non-CVE template id -> None (nothing invented)",
      _cve_from_template("exposed-redis", {}) is None,
      _cve_from_template("exposed-redis", {}))
check("redis-default-logins -> None", _cve_from_template("redis-default-logins", {}) is None)
check("lookalike 'CVE-abc-1234' rejected", _cve_from_template("CVE-abc-1234", {}) is None)
check("empty template id -> None", _cve_from_template("", {}) is None)
check("lowercase cve-2021-44228 normalised",
      _cve_from_template("cve-2021-44228", {}) == "CVE-2021-44228")

print("\n=== B. cvss recovered from classification ===")
check("exposed-redis 7.2 read", _cvss_from_classification({"cvss-score": 7.2}) == 7.2)
check("string score coerced", _cvss_from_classification({"cvss-score": "9.8"}) == 9.8)
check("absent -> None", _cvss_from_classification({}) is None)
check("garbage -> None", _cvss_from_classification({"cvss-score": "n/a"}) is None)
check("out of range 11.0 -> None", _cvss_from_classification({"cvss-score": 11.0}) is None)
check("negative -> None", _cvss_from_classification({"cvss-score": -1}) is None)

print("\n=== C. real nuclei JSONL round-trip (scan 117 template shapes) ===")
# Reconstructed from the actual on-disk templates + real DB descriptions.
REDIS_PREFIX = ("Redis is an open source, in-memory database that persists on disk. "
                "Versions 8.2.1 and below allow an authenticated user to use a "
                "specially crafted Lua script to ")
lines = [
    {"template-id": "CVE-2025-46817", "info": {"name": "Redis < 8.2.1 lua script - Integer Overflow",
        "severity": "critical", "description": REDIS_PREFIX + "cause an integer overflow..."}},
    {"template-id": "CVE-2025-49844", "info": {"name": "Redis Lua Parser < 8.2.2 - Use After Free",
        "severity": "critical", "description": REDIS_PREFIX + "manipulate the garbage collector..."}},
    {"template-id": "CVE-2025-46818", "info": {"name": "Redis Lua Sandbox < 8.2.2 - Cross-User Escape",
        "severity": "high", "description": REDIS_PREFIX + "manipulate different LUA objects..."}},
    {"template-id": "CVE-2025-46819", "info": {"name": "Redis  < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read",
        "severity": "high", "description": REDIS_PREFIX + "read out-of-bound data..."}},
    {"template-id": "redis-default-logins", "info": {"name": "Redis - Default Logins",
        "severity": "high", "description": "Redis service was accessed with easily guessed credentials."}},
    {"template-id": "exposed-redis", "info": {"name": "Redis Server - Unauthenticated Access",
        "severity": "high", "description": "Redis server without any required authentication was discovered.",
        "classification": {"cvss-score": 7.2, "cwe-id": "CWE-306"}}},
]
parsed = _parse_nuclei_jsonl("\n".join(json.dumps(o) for o in lines))
check("all 6 templates parsed", len(parsed) == 6, len(parsed))
cves = [f["cve_id"] for f in parsed]
check("4 CVEs recovered, 2 correctly None",
      cves == ["CVE-2025-46817", "CVE-2025-49844", "CVE-2025-46818", "CVE-2025-46819", None, None], cves)
check("exposed-redis cvss 7.2 recovered", parsed[5]["cvss"] == 7.2, parsed[5]["cvss"])
check("CVE templates have no cvss (none published)", all(f["cvss"] is None for f in parsed[:5]))

print("\n=== D. THE ORIGINAL SYMPTOM: 60-char truncation collision ===")
MAXLEN = 60
raw_trunc = [f["description"][:MAXLEN - 3] for f in parsed]
check("BEFORE fix: 4 Redis CVEs collide at 60 chars (reproduces the bug)",
      len(set(raw_trunc[:4])) == 1, set(raw_trunc[:4]))
fixed = [nuclei_description(f) for f in parsed]
fixed_trunc = [d[:MAXLEN - 3] for d in fixed]
check("AFTER fix: all 6 truncate to DISTINCT strings",
      len(set(fixed_trunc)) == 6, fixed_trunc)
print("     rendered top-findings lines now read:")
for f, d in zip(parsed, fixed_trunc):
    ident = f["cve_id"] or d
    print(f"       [{f['severity']:<8}] {ident}")

print("\n=== E. nuclei_description edge cases ===")
check("name absent -> description unchanged", nuclei_description({"description": "d"}) == "d")
check("description absent -> name", nuclei_description({"name": "n"}) == "n")
check("both absent -> empty", nuclei_description({}) == "")
check("no double-prefix when desc starts with name",
      nuclei_description({"name": "Foo", "description": "Foo is bad"}) == "Foo is bad")
check("normal join", nuclei_description({"name": "Foo", "description": "Bar"}) == "Foo — Bar")

print("\n=== F. dedup does NOT merge legitimately different findings ===")
same_desc = "Redis server without any required authentication was discovered."
cases = [
    ("same CVE, two DIFFERENT ports stays 2", [
        {"finding_type": "cve", "port": 6379, "cve_id": "CVE-2025-46817", "severity": "CRITICAL", "description": "x"},
        {"finding_type": "cve", "port": 6380, "cve_id": "CVE-2025-46817", "severity": "CRITICAL", "description": "x"}], 2),
    ("two DIFFERENT CVEs, identical description stays 2", [
        {"finding_type": "cve", "port": 80, "cve_id": "CVE-2025-46817", "severity": "HIGH", "description": same_desc},
        {"finding_type": "cve", "port": 80, "cve_id": "CVE-2025-46818", "severity": "HIGH", "description": same_desc}], 2),
    ("different finding_type stays 2", [
        {"finding_type": "nuclei_finding", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc},
        {"finding_type": "nikto_finding", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc}], 2),
    ("different severity stays 2", [
        {"finding_type": "x", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc},
        {"finding_type": "x", "port": 80, "cve_id": None, "severity": "LOW", "description": same_desc}], 2),
    ("descriptions differing ONLY past char 60 stay 2 (the critical case)", [
        {"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": REDIS_PREFIX + "cause an integer overflow"},
        {"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": REDIS_PREFIX + "read out-of-bound data"}], 2),
    ("genuinely identical rows collapse to 1", [
        {"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc},
        {"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc}], 1),
    ("triplicate collapses to 1", [
        {"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": same_desc}] * 3, 1),
    ("empty list", [], 0),
    ("None input", None, 0),
]
for name, inp, expected in cases:
    got = deduplicate_findings(inp, target="test-dedup", scan_id=999)
    check(name, len(got) == expected, f"expected {expected} got {len(got)}")

print("\n=== G. real scan 117 rows through dedup (must stay 9) ===")
from database.db import get_findings_for_scan
rows = get_findings_for_scan(117)
out = deduplicate_findings(rows, target="pentest-ground.com", scan_id=117)
check("scan 117: 9 rows in, 9 rows out (no real data lost)",
      len(rows) == 9 and len(out) == 9, f"{len(rows)} -> {len(out)}")

print("\n=== H. input not mutated ===")
orig = [{"finding_type": "n", "port": 80, "cve_id": None, "severity": "HIGH", "description": "a"}]
snapshot = json.dumps(orig, sort_keys=True)
deduplicate_findings(orig, target="test-dedup")
check("input list/dicts unchanged", json.dumps(orig, sort_keys=True) == snapshot)

print(f"\n{'='*60}\nPASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
