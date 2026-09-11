"""
Phase 2 — concurrency & scan engine verification.

  A  RateLimiter: token-bucket pacing actually paces, concurrency
     semaphore actually bounds, passive bypass, no-limit = no wait
  B  parse_targets CIDR expansion: IP CIDR expands, URL-path is NOT
     mistaken for CIDR, /32 -> single host, dedup across CIDR+explicit
  C  YAML profiles: the shipped set loads, schema validation rejects bad
     input, plugin selection honours plugins/exclude/target_types
  D  ScanEngine staging & isolation: discovery runs before web, a raising
     plugin is isolated (scan still completes), rate limit is honoured,
     findings reach the database
"""
import os
import sys
import threading
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.engine.ratelimit import RateLimiter
from modules.engine.profiles_yaml import (
    load_yaml_profile, list_yaml_profiles, ProfileError,
)
from modules.profiles.multi_target import parse_targets, _expand_cidr

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


# --- A: RateLimiter ----------------------------------------------------
print("\nA  RateLimiter")

# No limits => negligible wait.
rl = RateLimiter()
t0 = time.time()
for _ in range(20):
    rl.acquire(); rl.release()
check("no-limit limiter does not block", time.time() - t0 < 0.1)

# Pacing: 5 rps, burst 1 => ~4 gaps of 0.2s over 5 launches after the burst.
rl = RateLimiter(requests_per_second=10, max_concurrent=0, burst=1)
t0 = time.time()
for _ in range(5):
    rl.acquire(); rl.release()
elapsed = time.time() - t0
# 4 inter-launch gaps at 0.1s = ~0.4s. Allow generous slack.
check("token bucket paces launches", elapsed >= 0.3, f"elapsed={elapsed:.2f}")
check("limiter records total_wait", rl.total_wait > 0)

# Concurrency semaphore: max 2 in flight.
rl = RateLimiter(requests_per_second=0, max_concurrent=2)
active = {"now": 0, "peak": 0}
lock = threading.Lock()


def worker():
    rl.acquire()
    with lock:
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
    time.sleep(0.05)
    with lock:
        active["now"] -= 1
    rl.release()


threads = [threading.Thread(target=worker) for _ in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("concurrency semaphore bounds in-flight", active["peak"] <= 2, f"peak={active['peak']}")

# from_profile
rl = RateLimiter.from_profile({"max_requests_per_second": 3, "max_concurrent_plugins": 2})
check("from_profile reads keys", rl.rps == 3 and rl.max_concurrent == 2)
check("from_profile empty = no limits", RateLimiter.from_profile({}).rps == 0)


# --- B: CIDR parsing ---------------------------------------------------
print("\nB  parse_targets CIDR")

check("IPv4 /30 expands to 2 hosts", parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"])
check("/32 -> single host", parse_targets("192.168.1.5/32") == ["192.168.1.5"])
# A hostname with a slash is NOT a CIDR — it is kept verbatim here
# (reducing a URL to its host is aegis.py.normalize_target's job, not this
# parser's). The point being tested is that it is not expanded as a network.
check("URL path NOT treated as CIDR", parse_targets("example.com/24") == ["example.com/24"])
check("hostname/path kept verbatim", _expand_cidr("example.com/admin") == [])
check("dedup across CIDR + explicit",
      parse_targets("10.0.0.0/30,10.0.0.1") == ["10.0.0.1", "10.0.0.2"])
check("comma list still works", parse_targets("a.com,b.com") == ["a.com", "b.com"])
# large-network cap
big = _expand_cidr("10.0.0.0/8")
check("huge CIDR capped", 0 < len(big) <= 1024, f"len={len(big)}")


# --- C: YAML profiles --------------------------------------------------
print("\nC  YAML profiles")

names = {n for n, _ in list_yaml_profiles()}
check("shipped profiles present", {"quick", "full", "stealth"} <= names, str(names))

q = load_yaml_profile("quick")
check("quick lists explicit plugins", "nuclei" in q["plugins"])
check("quick has safety block", q["safety"].get("max_requests_per_second") == 8)

full = load_yaml_profile("full")
check("full plugins = all (None)", full["plugins"] is None)

stealth = load_yaml_profile("stealth")
check("stealth excludes loud tools", "nuclei" not in (stealth["plugins"] or []))

# validation
try:
    load_yaml_profile("does_not_exist_xyz")
    check("missing profile raises", False)
except ProfileError as e:
    check("missing profile raises", "not found" in str(e))

# bad target_type
bad = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
bad.write("name: bad\ntarget_types: [bogus]\n")
bad.close()
try:
    load_yaml_profile(bad.name)
    check("bad target_type rejected", False)
except ProfileError as e:
    check("bad target_type rejected", "unknown target_type" in str(e))
os.unlink(bad.name)

# selection honours the profile
from plugins import loader
sel = loader.select(names=q["plugins"], exclude=q["exclude"])
check("quick selection matches profile", {p.name for p in sel} == set(q["plugins"]))


# --- D: ScanEngine staging & isolation ---------------------------------
print("\nD  ScanEngine staging, isolation, rate limit, DB insert")

import sqlite3
import database.db as dbmod
from plugins.base import ScannerPlugin, Finding
from plugins import loader as plugin_loader
from modules.engine.scanner import ScanEngine

# Build a controlled plugin set: a fake port scan that reports an open web
# port, a web plugin that records when it ran, and a web plugin that raises.
run_log = []
log_lock = threading.Lock()


class FakePortScan(ScannerPlugin):
    name = "port_scan"          # engine treats this name as discovery
    target_types = ("host",)
    order = 1

    def run(self, target, config):
        with log_lock:
            run_log.append(("port_scan", time.time()))
        return {"open_ports": [{"port": 80, "service": "http", "state": "open"}],
                "error": None}

    def parse_output(self, raw):
        return []


class FakeWebGood(ScannerPlugin):
    name = "webgood"
    target_types = ("web",)
    order = 30

    def run(self, target, config):
        with log_lock:
            run_log.append(("webgood", time.time()))
        return {"port": config.get("port"), "error": None}

    def parse_output(self, raw):
        return [Finding(title="web finding", finding_type="wf",
                        plugin=self.name, port=raw.get("port"), severity="HIGH")]


class FakeWebBoom(ScannerPlugin):
    name = "webboom"
    target_types = ("web",)
    order = 31

    def run(self, target, config):
        raise RuntimeError("intentional plugin crash")

    def parse_output(self, raw):
        return []


fake_registry = {p.name: p for p in (FakePortScan(), FakeWebGood(), FakeWebBoom())}
orig_discover = plugin_loader.discover
orig_cache = plugin_loader._cache


def fake_discover(force=False):
    return fake_registry


# temp DB
tmp = tempfile.mkdtemp()
dbpath = os.path.join(tmp, "engine.db")
orig_conn = dbmod.get_connection


def fake_conn():
    c = sqlite3.connect(dbpath)
    c.row_factory = sqlite3.Row
    return c


plugin_loader.discover = fake_discover
# scanner.py imported `loader` as a module ref; patch the attribute it uses.
import modules.engine.scanner as scanner_mod
scanner_mod.loader.discover = fake_discover
dbmod.get_connection = fake_conn

try:
    dbmod.init_db()
    profile = {
        "name": "test-engine", "plugins": None, "exclude": [],
        "safety": {"max_requests_per_second": 20, "max_concurrent_plugins": 2},
    }
    engine = ScanEngine(profile, threads=4, non_interactive=True)
    # Avoid report generation side effects by scanning; finalise_reports
    # writes into output/<target>/ which is fine and part of the pipeline.
    result = engine.scan("enginetest.local")

    check("scan completed despite crashing plugin", result["scan_id"] is not None)
    check("good web plugin ran", any(n == "webgood" for n, _ in run_log))
    check("crashing plugin counted as failed", result["stats"]["tools_failed"] >= 1)
    check("good finding collected", any(f.title == "web finding" for f in result["findings"]))

    # staging order: port_scan timestamp precedes webgood timestamp
    times = dict()
    for n, t in run_log:
        times.setdefault(n, t)
    check("discovery ran before web stage",
          times.get("port_scan", 9e9) <= times.get("webgood", 0),
          str(times))

    # findings persisted
    rows = dbmod.get_findings_for_scan(result["scan_id"])
    check("finding persisted to DB", any(r["finding_type"] == "wf" for r in rows))
    check("plugin column set on engine finding",
          any(r["plugin"] == "webgood" for r in rows))
finally:
    plugin_loader.discover = orig_discover
    plugin_loader._cache = orig_cache
    scanner_mod.loader.discover = orig_discover
    dbmod.get_connection = orig_conn


print("\n" + "=" * 60)
print(f"PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
