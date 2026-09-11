"""
Phase 1 — plugin architecture verification.

  A  Finding: severity normalisation, stable ids, legacy round-trip,
     to_db_dict shape matches what db.py accepts
  B  ScannerPlugin.execute(): outcome classification (ran/skipped/failed),
     isolation (a raising run() becomes a failed result, not a crash),
     availability short-circuit, target/plugin stamping
  C  the loader: discovery, validation, selection, no load errors,
     every legacy detection tool has a plugin
  D  end to end: a fake plugin's findings insert into a real temp database
     through the same insert path the legacy profiles use
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.base import (
    Finding, ScannerPlugin, normalise_severity, severity_rank,
    POTENTIAL,
)
from plugins import loader

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


# --- A: Finding ----------------------------------------------------------
print("\nA  Finding dataclass")

check("severity normalised to bucket", normalise_severity("Informational") == "INFO")
check("unknown severity -> default", normalise_severity("weird", "LOW") == "LOW")
check("None severity -> default", normalise_severity(None) == "MEDIUM")
check("severity rank orders", severity_rank("CRITICAL") > severity_rank("LOW"))

f1 = Finding(title="Missing X-Frame-Options", finding_type="missing_security_header",
             plugin="header_check", port=80)
f2 = Finding(title="Missing X-Frame-Options", finding_type="missing_security_header",
             plugin="header_check", port=80)
check("id is content-stable across instances", f1.id == f2.id, f"{f1.id} != {f2.id}")
f3 = Finding(title="Missing X-Frame-Options", finding_type="missing_security_header",
             plugin="header_check", port=443)
check("id changes with port", f1.id != f3.id)

# id must survive a severity/score change (diff lines findings up on it)
before = f1.id
f1.severity = "HIGH"
f1.cvss_score = 9.0
check("id stable under re-scoring", f1.id == before)

f = Finding(title="t", cve_ids="CVE-2021-9999", references="http://x")
check("bare-string cve_ids wrapped", f.cve_ids == ["CVE-2021-9999"])
check("bare-string references wrapped", f.references == ["http://x"])
check("cve_id property = first", f.cve_id == "CVE-2021-9999")

# legacy round-trip
legacy = {
    "type": "nikto_finding", "port": 8082,
    "description": "Server leaks inodes via ETags. See: http://cve.example/1",
    "reference": "http://cve.example/1", "severity": "MEDIUM",
    "product": "Apache", "version": "2.4.25", "endpoint": "http://h:8082/",
}
lf = Finding.from_legacy(legacy, plugin="nikto", target="h")
check("legacy type -> finding_type", lf.finding_type == "nikto_finding")
check("legacy target stamped", lf.affected_target == "h")
check("legacy title from description first line",
      lf.title.startswith("Server leaks inodes"))
check("legacy reference -> references list", lf.references == ["http://cve.example/1"])

db_dict = lf.to_db_dict()
for key in ("type", "port", "severity", "description", "reference",
            "confidence", "epss_score", "risk_score", "plugin", "finding_uid"):
    check(f"to_db_dict has {key}", key in db_dict)
check("to_db_dict type populated", db_dict["type"] == "nikto_finding")
check("to_db_dict finding_uid = id", db_dict["finding_uid"] == lf.id)


# --- B: ScannerPlugin.execute ------------------------------------------
print("\nB  ScannerPlugin.execute isolation & outcome")


class RanPlugin(ScannerPlugin):
    name = "t_ran"
    description = "ok"
    target_types = ("host",)

    def run(self, target, config):
        return {"error": None}

    def parse_output(self, raw):
        return [Finding(title="found", finding_type="t", plugin=self.name)]


class FailErrorPlugin(ScannerPlugin):
    name = "t_fail_error"
    target_types = ("host",)

    def run(self, target, config):
        return {"error": "connection refused"}

    def parse_output(self, raw):
        return []


class RaisePlugin(ScannerPlugin):
    name = "t_raise"
    target_types = ("host",)

    def run(self, target, config):
        raise RuntimeError("boom")

    def parse_output(self, raw):
        return []


class SkipPlugin(ScannerPlugin):
    name = "t_skip"
    target_types = ("host",)

    def run(self, target, config):
        return {"skipped": True, "error": "skipped by user"}

    def parse_output(self, raw):
        return []


class NeedsToolPlugin(ScannerPlugin):
    name = "t_needstool"
    target_types = ("host",)
    requires = ("definitely_not_a_real_binary_xyz",)

    def run(self, target, config):
        raise AssertionError("must not run — tool is missing")

    def parse_output(self, raw):
        return []


class BadParsePlugin(ScannerPlugin):
    name = "t_badparse"
    target_types = ("host",)

    def run(self, target, config):
        return {"error": None}

    def parse_output(self, raw):
        raise ValueError("parser broke")


r = RanPlugin().execute("host", {})
check("ran outcome", r.outcome == "ran", r.outcome)
check("ran finding stamped with target", r.findings[0].affected_target == "host")
check("ran finding stamped with plugin", r.findings[0].plugin == "t_ran")

r = FailErrorPlugin().execute("host", {})
check("error result -> failed", r.outcome == "failed" and r.failed)
check("error message preserved", r.error == "connection refused")

r = RaisePlugin().execute("host", {})
check("raising run() -> failed (isolated)", r.outcome == "failed")
check("exception type in error", "RuntimeError" in (r.error or ""))

r = SkipPlugin().execute("host", {})
check("skip flag -> skipped", r.outcome == "skipped" and r.skipped)

r = NeedsToolPlugin().execute("host", {})
check("missing tool -> skipped w/reason", r.outcome == "skipped" and "missing" in r.error)

r = BadParsePlugin().execute("host", {})
check("parse failure -> failed", r.outcome == "failed" and "parsing failed" in r.error)

# to_tool_result feeds the legacy failure-count path
tr = FailErrorPlugin().execute("host", {}).to_tool_result()
check("to_tool_result shape", tr["tool"] == "t_fail_error" and tr["error"] and not tr["skipped"])


# --- C: loader ---------------------------------------------------------
print("\nC  loader discovery & selection")

reg = loader.discover(force=True)
check("no load errors", loader.load_errors == [], str(loader.load_errors))
check("discovered many plugins", len(reg) >= 15, str(len(reg)))

# every legacy detection tool has a plugin
expected = {
    "dns", "port_scan", "service_detect", "banner_grab",
    "header_check", "whatweb", "nikto", "gobuster", "dirb", "nuclei",
    "sslyze", "testssl", "zaproxy", "wpscan",
    "enum4linux", "hydra",
    "subdomain_enum", "cloud_enum", "hibp",
}
missing = expected - set(reg)
check("every legacy tool has a plugin", not missing, f"missing {missing}")

# selection
web = loader.select(target_types=["web"])
check("web selection non-empty", len(web) >= 8)
check("web selection excludes host plugins",
      all("web" in p.target_types for p in web))

sel = loader.select(names=["nuclei", "nikto"])
check("name selection", {p.name for p in sel} == {"nuclei", "nikto"})

sel = loader.select(names=["nuclei", "nikto"], exclude=["nikto"])
check("exclude wins over allow-list", {p.name for p in sel} == {"nuclei"})

check("unknown_names reports bogus", loader.unknown_names(["nuclei", "bogus"]) == ["bogus"])

# ordering: discovery plugins run first
order_names = [p.name for p in loader.all_plugins()]
check("port_scan before nuclei in run order",
      order_names.index("port_scan") < order_names.index("nuclei"))


# --- D: end-to-end DB insert ------------------------------------------
print("\nD  plugin finding -> real database insert")

import database.db as dbmod

tmp = tempfile.mkdtemp()
dbpath = os.path.join(tmp, "t.db")
_orig = dbmod.DB_PATH if hasattr(dbmod, "DB_PATH") else None

# db.py resolves its path via a module constant; patch it if present,
# otherwise fall back to monkeypatching get_connection.
import sqlite3
orig_conn = dbmod.get_connection


def fake_conn():
    c = sqlite3.connect(dbpath)
    c.row_factory = sqlite3.Row
    return c


dbmod.get_connection = fake_conn
try:
    dbmod.init_db()
    sid = dbmod.insert_scan("plugintest", "quickscan")
    findings = RanPlugin().execute("plugintest", {}).findings
    dbmod.insert_findings_bulk(sid, [f.to_db_dict() for f in findings])
    rows = dbmod.get_findings_for_scan(sid)
    check("finding inserted via bulk path", len(rows) == 1, str(len(rows)))
    check("plugin column persisted", rows[0]["plugin"] == "t_ran")
    check("finding_uid persisted", rows[0]["finding_uid"] == findings[0].id)
    check("confidence persisted", rows[0]["confidence"] == POTENTIAL)
finally:
    dbmod.get_connection = orig_conn


print("\n" + "=" * 60)
print(f"PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
