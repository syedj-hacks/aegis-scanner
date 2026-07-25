"""Phase 4 verification: real files on disk, all three prompt choices."""
import sys, os, shutil, io, contextlib, tempfile
sys.path.insert(0, "/home/jafar/aegis-scanner")

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")

from modules.reporting.retention import (
    report_filename, list_stored_reports, prune_reports, retain_reports,
    _parse_stored_name, _prompt_choice, _DEFAULT_KEEP,
)

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {name}")
    else: fail += 1; print(f"  FAIL  {name} -> {detail}")

BASE = os.path.join(_TMP, "retention_test")

def fresh(profile="quickscan", target="pentest-ground.com", scan_ids=(101,106,107,111,117)):
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    for sid in scan_ids:
        for ext in ("txt", "pdf"):
            open(os.path.join(BASE, report_filename(profile, target, sid, ext)), "w").write("x")
    return BASE

print("=== A. filename scheme ===")
check("txt name", report_filename("deepscan","scanme.nmap.org",115,"txt")
      == "report_deepscan_scanme.nmap.org_115.txt",
      report_filename("deepscan","scanme.nmap.org",115,"txt"))
check("pdf name", report_filename("deepscan","scanme.nmap.org",115,"pdf")
      == "report_deepscan_scanme.nmap.org_115.pdf")
check("profile is in the filename", "deepscan" in report_filename("deepscan","t",1,"txt"))
check("unsafe chars sanitised",
      report_filename("q","../../etc/passwd",1,"txt") == "report_q_.._.._etc_passwd_1.txt",
      report_filename("q","../../etc/passwd",1,"txt"))

print("\n=== B. parsing back ===")
check("round-trip parse", _parse_stored_name("report_quickscan_pentest-ground.com_117.txt")
      == ("quickscan", 117))
check("target with underscores still parses",
      _parse_stored_name("report_quickscan_my_host_name_42.pdf") == ("quickscan", 42),
      _parse_stored_name("report_quickscan_my_host_name_42.pdf"))
check("legacy report.txt NOT claimed", _parse_stored_name("report.txt") is None)
check("legacy report.pdf NOT claimed", _parse_stored_name("report.pdf") is None)
check("unrelated file ignored", _parse_stored_name("scan_errors.log") is None)

print("\n=== C. listing: txt+pdf collapse to one entry, ordered by scan_id ===")
d = fresh()
reports = list_stored_reports(d, "quickscan", "pentest-ground.com")
check("5 scans listed (not 10 files)", len(reports) == 5, len(reports))
check("ordered oldest scan first",
      [r["scan_id"] for r in reports] == [101,106,107,111,117],
      [r["scan_id"] for r in reports])
check("each entry pairs .txt and .pdf", all(len(r["paths"]) == 2 for r in reports))
check("missing dir -> empty list", list_stored_reports("/nonexistent/xyz","q","t") == [])

print("\n=== D. other profiles are a SEPARATE budget (per-profile+target) ===")
d = fresh()
for sid in (114, 118):
    for ext in ("txt","pdf"):
        open(os.path.join(d, report_filename("webaudit","pentest-ground.com",sid,ext)),"w").write("x")
check("quickscan still sees only its own 5",
      len(list_stored_reports(d,"quickscan","pentest-ground.com")) == 5)
check("webaudit sees only its own 2",
      len(list_stored_reports(d,"webaudit","pentest-ground.com")) == 2)
# prune quickscan; webaudit must be untouched
with contextlib.redirect_stdout(io.StringIO()):
    prune_reports(d,"quickscan","pentest-ground.com",keep=4,non_interactive=True)
check("pruning quickscan did not touch webaudit",
      len(list_stored_reports(d,"webaudit","pentest-ground.com")) == 2)

print("\n=== E. different target in same dir not confused ===")
d = fresh()
for ext in ("txt","pdf"):
    open(os.path.join(d, report_filename("quickscan","other-host.com",999,ext)),"w").write("x")
check("other-host not counted under pentest-ground",
      len(list_stored_reports(d,"quickscan","pentest-ground.com")) == 5)
check("other-host listed under itself",
      len(list_stored_reports(d,"quickscan","other-host.com")) == 1)

print("\n=== F. under cap -> no prune ===")
d = fresh(scan_ids=(101,106,107))
with contextlib.redirect_stdout(io.StringIO()):
    n = prune_reports(d,"quickscan","pentest-ground.com",keep=5,non_interactive=True)
check("3 stored, cap 5 -> 0 deleted", n == 0, n)
check("all 3 still present", len(list_stored_reports(d,"quickscan","pentest-ground.com")) == 3)

print("\n=== G. non-interactive: deletes OLDEST, keeps newest ===")
d = fresh(scan_ids=(101,106,107,111,117,120))   # 6 stored, cap 5
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    n = prune_reports(d,"quickscan","pentest-ground.com",keep=5,non_interactive=True)
left = [r["scan_id"] for r in list_stored_reports(d,"quickscan","pentest-ground.com")]
check("1 report deleted", n == 1, n)
check("oldest (101) gone, newest (120) kept", left == [106,107,111,117,120], left)
check("both files of the victim removed",
      not os.path.exists(os.path.join(d, report_filename("quickscan","pentest-ground.com",101,"txt")))
      and not os.path.exists(os.path.join(d, report_filename("quickscan","pentest-ground.com",101,"pdf"))))
out = buf.getvalue()
check("choice and reason are logged to console", "oldest" in out and "non-interactive" in out.lower(), out[:200])

print("\n=== H. interactive prompt: all three choices ===")
def run_prompt(answers, scan_ids=(101,106,107,111,117,120)):
    """Drive _prompt_choice with scripted answers; returns (victim, output)."""
    d = fresh(scan_ids=scan_ids)
    reports = list_stored_reports(d,"quickscan","pentest-ground.com")
    candidates = reports[:-1]          # newest is never a candidate
    it = iter(answers)
    buf = io.StringIO()
    import builtins
    orig = builtins.input
    builtins.input = lambda *a, **k: next(it)
    try:
        with contextlib.redirect_stdout(buf):
            victim = _prompt_choice(candidates, "quickscan", "pentest-ground.com")
    finally:
        builtins.input = orig
    return victim, buf.getvalue(), candidates, d

v, out, cands, d = run_prompt(["o"])
check("[o] selects the oldest candidate", v["scan_id"] == 101, v["scan_id"])
check("prompt lists candidates with 1-based indices", "[1]" in out and "[5]" in out, out[:300])
check("prompt shows timestamps", "202" in out)

v, out, cands, d = run_prompt(["3"])
check("[3] selects the 3rd listed candidate (107)", v["scan_id"] == 107, v["scan_id"])

v, out, cands, d = run_prompt(["k"])
check("[k] keeps all -> returns None", v is None)

v, out, cands, d = run_prompt(["99", "abc", "0", "-1", "2"])
check("invalid input re-prompts, never crashes; finally honours '2' (106)",
      v["scan_id"] == 106, v["scan_id"])
check("out-of-range message shown", "out of range" in out, out[:400])
check("non-numeric message shown", "not a valid choice" in out)

# EOF / Ctrl+C -> keep all (conservative)
d = fresh()
reports = list_stored_reports(d,"quickscan","pentest-ground.com")
import builtins

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")
orig = builtins.input
def raise_eof(*a, **k): raise EOFError()
builtins.input = raise_eof
try:
    with contextlib.redirect_stdout(io.StringIO()):
        v = _prompt_choice(reports[:-1], "quickscan", "pentest-ground.com")
finally:
    builtins.input = orig
check("EOF/Ctrl+C -> keep all (no deletion without consent)", v is None)

print("\n=== I. end-to-end prune with a scripted 'keep all' ===")
d = fresh(scan_ids=(101,106,107,111,117,120))
builtins.input = lambda *a, **k: "k"
try:
    with contextlib.redirect_stdout(io.StringIO()):
        n = prune_reports(d,"quickscan","pentest-ground.com",keep=5,non_interactive=False)
finally:
    builtins.input = orig
# note: _is_interactive() is False under redirect, so this exercises the
# scripted path; verified separately that the interactive path calls _prompt_choice.
check("prune never raises regardless of path", isinstance(n, int), n)

print("\n=== J. retain_reports() from writer paths ===")
d = fresh(scan_ids=(101,106,107,111,117,120))
paths = [os.path.join(d, report_filename("quickscan","pentest-ground.com",120,e)) for e in ("txt","pdf")]
with contextlib.redirect_stdout(io.StringIO()):
    n = retain_reports("pentest-ground.com","quickscan",paths,keep=5,non_interactive=True)
check("retain_reports prunes the dir the reports landed in", n == 1, n)
check("None paths tolerated", retain_reports("t","q",[None,None]) == 0)
check("empty paths tolerated", retain_reports("t","q",[]) == 0)

print("\n=== K. never raises on hostile input ===")
for args in [("/nonexistent/xyz","q","t"), (d,"","",), (d,"q","t")]:
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            prune_reports(*args, keep=0, non_interactive=True)
        ok += 1; print(f"  PASS  prune_reports{args} survived")
    except Exception as e:
        fail += 1; print(f"  FAIL  prune_reports{args} raised {e}")

shutil.rmtree(BASE, ignore_errors=True)
print(f"\n{'='*60}\nPASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
