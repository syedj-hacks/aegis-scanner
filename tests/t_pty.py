"""
Interactive retention prompt over a REAL pty.

The unit tests in t_phase4.py drive _prompt_choice() directly; under
redirect_stdout, _is_interactive() is False, so the interactive branch of
prune_reports() was never actually exercised. This drives the whole thing
through a real terminal so the isatty() gate, the prompt rendering and all
three choices are proven end to end.
"""
import os, pty, sys, shutil, subprocess, time, tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")

REPO = "/home/jafar/aegis-scanner"
BASE = os.path.join(_TMP, "pty_reports")

CHILD = r'''
import sys, os
sys.path.insert(0, "{repo}")
from modules.reporting.retention import prune_reports, list_stored_reports
d = "{base}"
print("ISATTY stdin=%s stdout=%s" % (sys.stdin.isatty(), sys.stdout.isatty()), flush=True)
n = prune_reports(d, "quickscan", "pentest-ground.com", keep=5, non_interactive=False)
left = [r["scan_id"] for r in list_stored_reports(d, "quickscan", "pentest-ground.com")]
print("DELETED=%d REMAINING=%s" % (n, left), flush=True)
'''


def seed(scan_ids=(101, 106, 107, 111, 117, 120)):
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    for sid in scan_ids:
        for ext in ("txt", "pdf"):
            open(os.path.join(BASE,
                 f"report_quickscan_pentest-ground.com_{sid}.{ext}"), "w").write("x")


def run(answer: bytes, label: str):
    seed()
    code = CHILD.format(repo=REPO, base=BASE)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(REPO)
        os.execv(sys.executable, [sys.executable, "-c", code])
    time.sleep(1.2)
    os.write(fd, answer)
    out = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    os.waitpid(pid, 0)
    text = out.decode(errors="replace")
    print(f"\n{'='*70}\n### {label}   (typed: {answer!r})\n{'='*70}")
    print(text)
    return text


ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {name}")
    else: fail += 1; print(f"  FAIL  {name} -> {detail}")

# --- choice 1: delete oldest -------------------------------------------
t = run(b"o\n", "CHOICE [o] delete oldest")
check("real TTY detected", "stdin=True stdout=True" in t)
check("prompt appeared", "you already have" in t.lower() and "Delete the oldest" in t)
import re as _re

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")
_TMP = os.path.join(tempfile.gettempdir(), "aegis_tests")
_ANSI = _re.compile(r"\x1b\[[0-9;]*m")
plain = _ANSI.sub("", t)          # Rich colourises the index digits
check("indices 1-5 listed", all(f"[{i}]" in plain for i in range(1, 6)),
      [l for l in plain.splitlines() if l.strip().startswith("[")][:6])
check("newest (120) is NOT offered as a candidate", "_120." not in t.split("Delete the oldest")[0])
check("oldest 101 deleted, 5 remain", "DELETED=1 REMAINING=[106, 107, 111, 117, 120]" in t, t[-200:])

# --- choice 2: delete by index -----------------------------------------
t = run(b"3\n", "CHOICE [3] delete by index")
check("index 3 (=107) deleted", "DELETED=1 REMAINING=[101, 106, 111, 117, 120]" in t, t[-200:])

# --- choice 3: keep all ------------------------------------------------
t = run(b"k\n", "CHOICE [k] keep all")
check("nothing deleted, all 6 kept",
      "DELETED=0 REMAINING=[101, 106, 107, 111, 117, 120]" in t, t[-200:])
check("keep-all is stated explicitly", "keeping all" in t.lower())

# --- invalid input re-prompts ------------------------------------------
t = run(b"99\nxyz\n2\n", "INVALID then valid")
check("out-of-range rejected", "out of range" in t)
check("non-numeric rejected", "not a valid choice" in t)
check("recovers and deletes index 2 (=106)",
      "DELETED=1 REMAINING=[101, 107, 111, 117, 120]" in t, t[-200:])

shutil.rmtree(BASE, ignore_errors=True)
print(f"\n{'='*70}\nPTY TESTS:  PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
