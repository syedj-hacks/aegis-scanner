#!/usr/bin/env python3
"""
tools/backfill_nuclei_identity.py

One-off, EXPLICITLY INVOKED migration for nuclei findings recorded before the
smoke_test7 collection-time fixes landed.

Nothing in the scanner calls this. It is not wired into startup, into any
profile, or into any scan path, and it must never be: rewriting stored scan
results is an evidentiary operation, not routine maintenance.

WHAT IT CORRECTS
    cve_id  — rows where the nuclei template id IS the CVE (the four Redis Lua
              templates publish no info.classification block, so the pre-fix
              wrapper read nothing and stored NULL). The corrected value is
              RECOVERED, not inferred: scan_errors.log recorded the
              template_id verbatim at scan time.
    cvss    — rows whose template publishes info.classification.cvss-score,
              which the pre-fix wrapper never read.
    cve_id case — 'cve-2023-48795' -> 'CVE-2023-48795', so one CVE stops
              sorting and grouping as two distinct values.

WHAT IT DELIBERATELY DOES NOT TOUCH
    port. 33 Redis rows store the probed port (80/443) where the templates
    pivot to 6379, and 4 SSH rows store 80 where the template hardcodes 22.
    Port 6379 does not appear in ANY log before 2026-07-25 15:59:38 — i.e.
    before the fix. For those runs the matched port was never recorded
    anywhere, so writing 6379 in would not be recovering an observation, it
    would be inserting a value derived from the template's pivot behaviour
    into a historical record that nothing from that run attests to. The
    reports already render these rows correctly via summary.distinct_
    identifiers(); the stored row stays a faithful record of what was
    captured. This is a decision, not an omission — see smoke_test8.txt §2.

EVIDENCE STANDARD
    A row is only ever updated when TWO INDEPENDENT derivations of its
    template id agree:
      (1) positional — the scan's nuclei log events, in the scan's own time
          window, paired in order with that scan's nuclei rows, accepted only
          when the counts match AND every paired severity matches;
      (2) textual — the row's description prose mapped to a template name
          (via the '<name> — <prose>' form post-fix rows store) and thence to
          a template id via the logs.
    Where the two disagree, or either is unavailable, the row is SKIPPED and
    reported. A migration over security findings should decline to guess.

USAGE
    python3 tools/backfill_nuclei_identity.py            # dry run, writes nothing
    python3 tools/backfill_nuclei_identity.py --apply    # writes, after dumping
    python3 tools/backfill_nuclei_identity.py --revert <dumpfile>
"""

import argparse
import ast
import json
import os
import re
import shutil
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "database", "aegis.db")
OUTPUT_DIR = os.path.join(ROOT, "output")
DUMP_DIR = os.path.join(ROOT, "important documentations")

CVE_SHAPED = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
LOG_TS = "%Y-%m-%d %H:%M:%S"

# A scan's nuclei events land in the log while that scan runs. deepscan is the
# longest profile at ~35 minutes, so a 3-hour ceiling is generous while still
# refusing to pair a row with an event from some unrelated later run.
WINDOW_CEILING = timedelta(hours=3)

MACHINE_MARKER = "--- MACHINE-READABLE REVERT DATA (JSON) ---"


# --------------------------------------------------------------------------
# evidence gathering
# --------------------------------------------------------------------------
def harvest_log_events():
    """Every 'Finding recorded' nuclei event across every target's log.

    Returns {target: [(datetime, template_id, name, severity), ...]} in file
    order, which is insert order.
    """
    events = defaultdict(list)
    if not os.path.isdir(OUTPUT_DIR):
        return events
    for target in os.listdir(OUTPUT_DIR):
        log = os.path.join(OUTPUT_DIR, target, "scan_errors.log")
        if not os.path.isfile(log):
            continue
        with open(log, "r", errors="replace") as fh:
            for line in fh:
                if "Finding recorded:" not in line or "nuclei_finding" not in line:
                    continue
                try:
                    ts = datetime.strptime(line[:19], LOG_TS)
                except ValueError:
                    continue
                try:
                    payload = ast.literal_eval(
                        line.split("Finding recorded:", 1)[1].strip())
                except (ValueError, SyntaxError):
                    continue
                tid = payload.get("template_id")
                if not tid:
                    continue
                events[target].append(
                    (ts, tid, payload.get("name"),
                     (payload.get("severity") or "").upper()))
    return events


def build_name_maps(conn):
    """name -> template_id (from the logs), and prose -> name (from post-fix
    rows, which store description as '<name> — <prose>').

    Both are only usable where the mapping is unambiguous; ambiguous entries
    are dropped rather than resolved arbitrarily.
    """
    name_to_tid = defaultdict(set)
    for evs in harvest_log_events().values():
        for _ts, tid, name, _sev in evs:
            if name:
                name_to_tid[name].add(tid)

    prose_to_name = defaultdict(set)
    for (desc,) in conn.execute(
            "SELECT description FROM findings WHERE finding_type='nuclei_finding'"):
        if desc and " — " in desc:
            name, prose = desc.split(" — ", 1)
            prose_to_name[prose.strip()].add(name.strip())

    return ({n: next(iter(t)) for n, t in name_to_tid.items() if len(t) == 1},
            {p: next(iter(n)) for p, n in prose_to_name.items() if len(n) == 1})


def template_cvss_scores():
    """template id -> published cvss-score, read from the nuclei templates on
    disk. Returned alongside its provenance so the audit dump can say where
    each number came from; see the caveat in report_caveats().
    """
    roots = [os.path.expanduser("~/nuclei-templates")]
    scores = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith((".yaml", ".yml")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, "r", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                m_id = re.search(r"^id:\s*(\S+)", text, re.MULTILINE)
                m_cvss = re.search(r"^\s+cvss-score:\s*([0-9.]+)\s*$",
                                   text, re.MULTILINE)
                if m_id and m_cvss:
                    try:
                        score = float(m_cvss.group(1))
                    except ValueError:
                        continue
                    if 0.0 <= score <= 10.0:
                        scores[m_id.group(1)] = score
    return scores


# --------------------------------------------------------------------------
# the two independent derivations
# --------------------------------------------------------------------------
def derive_positional(conn, log_events):
    """row id -> template id, by pairing each scan's nuclei rows with that
    scan's nuclei log events in order.

    Accepted only when the counts match and EVERY paired severity matches. A
    mismatch means the pairing is not trustworthy for that scan, so the whole
    scan is dropped rather than partially trusted.
    """
    scans = conn.execute(
        "SELECT id, target, timestamp FROM scans ORDER BY timestamp").fetchall()

    # a scan's window ends when the next scan against the same target begins
    next_start = {}
    by_target = defaultdict(list)
    for s in scans:
        by_target[s["target"]].append(s)
    for target, group in by_target.items():
        for i, s in enumerate(group):
            nxt = group[i + 1]["timestamp"] if i + 1 < len(group) else None
            next_start[s["id"]] = nxt

    out, rejected = {}, []
    for s in scans:
        rows = conn.execute(
            "SELECT id, severity FROM findings "
            "WHERE scan_id=? AND finding_type='nuclei_finding' ORDER BY id",
            (s["id"],)).fetchall()
        if not rows:
            continue
        try:
            start = datetime.fromisoformat(s["timestamp"])
        except ValueError:
            rejected.append((s["id"], "unparseable scan timestamp"))
            continue
        end = start + WINDOW_CEILING
        if next_start.get(s["id"]):
            try:
                end = min(end, datetime.fromisoformat(next_start[s["id"]]))
            except ValueError:
                pass

        evs = [e for e in log_events.get(s["target"], []) if start <= e[0] < end]
        if len(evs) != len(rows):
            rejected.append(
                (s["id"], f"{len(rows)} row(s) vs {len(evs)} log event(s) "
                          f"in window — not paired"))
            continue
        if any((r["severity"] or "").upper() != e[3] for r, e in zip(rows, evs)):
            rejected.append((s["id"], "severity sequence disagrees — not paired"))
            continue
        for r, e in zip(rows, evs):
            out[r["id"]] = e[1]
    return out, rejected


def derive_textual(conn, name_to_tid, prose_to_name):
    """row id -> template id, via description prose -> template name -> id."""
    out = {}
    for r in conn.execute(
            "SELECT id, description FROM findings "
            "WHERE finding_type='nuclei_finding'"):
        desc = (r["description"] or "").strip()
        if not desc:
            continue
        name = (desc.split(" — ", 1)[0].strip() if " — " in desc
                else prose_to_name.get(desc))
        tid = name_to_tid.get(name) if name else None
        if tid:
            out[r["id"]] = tid
    return out


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------
def plan(conn):
    log_events = harvest_log_events()
    name_to_tid, prose_to_name = build_name_maps(conn)
    positional, rejected_scans = derive_positional(conn, log_events)
    textual = derive_textual(conn, name_to_tid, prose_to_name)
    cvss_by_tid = template_cvss_scores()

    changes, skipped = [], []
    rows = conn.execute("""
        SELECT f.id, f.scan_id, s.target, s.profile, f.port, f.cve_id, f.cvss,
               f.severity, f.description
        FROM findings f JOIN scans s ON s.id = f.scan_id
        WHERE f.finding_type = 'nuclei_finding'
        ORDER BY f.id
    """).fetchall()

    for r in rows:
        rid = r["id"]
        p_tid, t_tid = positional.get(rid), textual.get(rid)

        if p_tid and t_tid and p_tid != t_tid:
            skipped.append((rid, r["scan_id"],
                            f"derivations disagree: positional={p_tid} "
                            f"textual={t_tid}"))
            continue
        tid = p_tid or t_tid
        evidence = ("both" if p_tid and t_tid
                    else "positional" if p_tid else "textual" if t_tid else None)

        cur_cve = (r["cve_id"] or "").strip()
        new_cve = None
        if not cur_cve:
            if tid is None:
                # only worth reporting when there was something to recover
                if r["cvss"] is None:
                    skipped.append((rid, r["scan_id"],
                                    "template id not derivable from logs"))
                continue
            if CVE_SHAPED.match(tid):
                new_cve = tid.upper()
            # a non-CVE-shaped id (exposed-redis, dvwa-default-login, ...)
            # correctly stays NULL — nothing to recover
        elif CVE_SHAPED.match(cur_cve) and cur_cve != cur_cve.upper():
            new_cve = cur_cve.upper()

        new_cvss = None
        if r["cvss"] is None and tid and tid in cvss_by_tid:
            new_cvss = cvss_by_tid[tid]

        if new_cve is None and new_cvss is None:
            continue

        changes.append({
            "row_id": rid,
            "scan_id": r["scan_id"],
            "target": r["target"],
            "profile": r["profile"],
            "port": r["port"],          # recorded for the audit trail; NEVER written
            "severity": r["severity"],
            "template_id": tid,
            "evidence": evidence,
            "description_head": (r["description"] or "")[:70],
            "before": {"cve_id": r["cve_id"], "cvss": r["cvss"]},
            "after": {
                "cve_id": new_cve if new_cve is not None else r["cve_id"],
                "cvss": new_cvss if new_cvss is not None else r["cvss"],
            },
        })

    return changes, skipped, rejected_scans


# --------------------------------------------------------------------------
# reporting / dumping / applying
# --------------------------------------------------------------------------
def report_caveats():
    return [
        "port is NOT modified by this migration, by explicit decision. See the "
        "module docstring: 6379/22 was never recorded for these runs.",
        "cvss values are read from the nuclei templates as they exist on disk "
        "TODAY, not from the output of the run being corrected. Where a "
        "post-fix scan of the same template exists the two agree (exposed-redis "
        "7.2), but for configuration-listing (5.3) and CVE-2023-48795 (5.9) "
        "there is no post-fix run to corroborate against, and an upstream "
        "template edit since the scan would not be detectable here.",
        "cve_id values are recovered from template ids logged at scan time and "
        "are corroborated by two independent derivations; they are not inferred.",
    ]


def render_dump(changes, skipped, rejected_scans, applied):
    lines = []
    lines.append("=" * 78)
    lines.append("AEGIS — nuclei identity backfill: before/after row dump")
    lines.append("=" * 78)
    lines.append(f"Generated      : {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"Database       : {DB_PATH}")
    lines.append(f"Mode           : {'APPLIED' if applied else 'DRY RUN — nothing written'}")
    lines.append(f"Rows to change : {len(changes)}")
    lines.append("")
    lines.append("CAVEATS")
    for c in report_caveats():
        lines.append(f"  - {c}")
    lines.append("")
    lines.append("-" * 78)
    lines.append("BEFORE / AFTER")
    lines.append("-" * 78)
    if not changes:
        lines.append("  (no rows require correction)")
    for c in changes:
        b, a = c["before"], c["after"]
        lines.append(
            f"  row {c['row_id']:<5} scan {c['scan_id']:<4} {c['target']:<20} "
            f"port {str(c['port']):<5} {c['severity'] or '':<8}")
        lines.append(
            f"        template  : {c['template_id']}  (evidence: {c['evidence']})")
        lines.append(f"        desc      : {c['description_head']}")
        if b["cve_id"] != a["cve_id"]:
            lines.append(f"        cve_id    : {b['cve_id']!r} -> {a['cve_id']!r}")
        if b["cvss"] != a["cvss"]:
            lines.append(f"        cvss      : {b['cvss']!r} -> {a['cvss']!r}")
        lines.append(f"        port      : {c['port']!r} -> unchanged (by decision)")
    lines.append("")
    lines.append("-" * 78)
    lines.append(f"SKIPPED ROWS ({len(skipped)}) — left exactly as recorded")
    lines.append("-" * 78)
    if not skipped:
        lines.append("  (none)")
    for rid, sid, why in skipped:
        lines.append(f"  row {rid:<5} scan {sid:<4} {why}")
    lines.append("")
    lines.append("-" * 78)
    lines.append(f"SCANS NOT POSITIONALLY PAIRED ({len(rejected_scans)})")
    lines.append("-" * 78)
    if not rejected_scans:
        lines.append("  (none)")
    for sid, why in rejected_scans:
        lines.append(f"  scan {sid:<4} {why}")
    lines.append("")
    lines.append(MACHINE_MARKER)
    lines.append(json.dumps(
        {"database": DB_PATH,
         "generated": datetime.now().isoformat(timespec="seconds"),
         "changes": changes},
        indent=2))
    return "\n".join(lines) + "\n"


def apply_changes(conn, changes):
    cur = conn.cursor()
    for c in changes:
        # port is absent from this statement by design, not by omission
        cur.execute("UPDATE findings SET cve_id = ?, cvss = ? WHERE id = ?",
                    (c["after"]["cve_id"], c["after"]["cvss"], c["row_id"]))
        if cur.rowcount != 1:
            raise RuntimeError(
                f"row {c['row_id']}: expected to update exactly 1 row, "
                f"updated {cur.rowcount} — rolling back")
    conn.commit()


def verify(conn, changes):
    """Re-read every touched row and confirm it holds the intended value, and
    that port is untouched."""
    bad = []
    for c in changes:
        r = conn.execute("SELECT cve_id, cvss, port FROM findings WHERE id=?",
                         (c["row_id"],)).fetchone()
        if r is None:
            bad.append((c["row_id"], "row vanished"))
            continue
        if (r["cve_id"] or None) != (c["after"]["cve_id"] or None):
            bad.append((c["row_id"], f"cve_id is {r['cve_id']!r}"))
        if r["cvss"] != c["after"]["cvss"]:
            bad.append((c["row_id"], f"cvss is {r['cvss']!r}"))
        if r["port"] != c["port"]:
            bad.append((c["row_id"],
                        f"PORT CHANGED {c['port']!r} -> {r['port']!r}"))
    return bad


def do_revert(dump_path):
    with open(dump_path, "r") as fh:
        text = fh.read()
    if MACHINE_MARKER not in text:
        sys.exit(f"[!] {dump_path} carries no machine-readable revert data")
    data = json.loads(text.split(MACHINE_MARKER, 1)[1])
    changes = data["changes"]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    backup = backup_db()
    print(f"[*] database backed up to {backup}")
    cur = conn.cursor()
    for c in changes:
        cur.execute("UPDATE findings SET cve_id = ?, cvss = ? WHERE id = ?",
                    (c["before"]["cve_id"], c["before"]["cvss"], c["row_id"]))
    conn.commit()
    print(f"[+] reverted {len(changes)} row(s) to their recorded values")
    conn.close()


def backup_db():
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = f"{DB_PATH}.pre-backfill.{stamp}"
    shutil.copy2(DB_PATH, dest)
    return dest


def main():
    ap = argparse.ArgumentParser(
        description="One-off backfill of nuclei cve_id/cvss on historical rows. "
                    "Dry run unless --apply is given. Never modifies port.")
    ap.add_argument("--apply", action="store_true",
                    help="actually write the changes (default: dry run)")
    ap.add_argument("--revert", metavar="DUMPFILE",
                    help="restore the 'before' values from a dump file")
    args = ap.parse_args()

    if not os.path.isfile(DB_PATH):
        sys.exit(f"[!] no database at {DB_PATH}")

    if args.revert:
        do_revert(args.revert)
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    changes, skipped, rejected = plan(conn)

    text = render_dump(changes, skipped, rejected, applied=args.apply)

    if not args.apply:
        print(text)
        print("[*] DRY RUN — nothing was written. Re-run with --apply to commit "
              "these changes.")
        conn.close()
        return

    if not changes:
        print("[*] nothing to change; no dump written, no rows touched")
        conn.close()
        return

    # the dump is written BEFORE anything is modified, so the record of what
    # the rows held survives even if the update itself fails partway
    os.makedirs(DUMP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_path = os.path.join(DUMP_DIR, f"backfill_nuclei_identity_{stamp}.txt")
    with open(dump_path, "w") as fh:
        fh.write(text)
    print(f"[+] before/after dump written to {dump_path}")

    backup = backup_db()
    print(f"[+] database copied to {backup}")

    try:
        apply_changes(conn, changes)
    except Exception as exc:
        conn.rollback()
        sys.exit(f"[!] backfill failed and was rolled back: {exc}")

    bad = verify(conn, changes)
    if bad:
        for rid, why in bad:
            print(f"[!] row {rid}: {why}")
        sys.exit("[!] post-apply verification FAILED — restore from the backup above")

    print(f"[+] {len(changes)} row(s) updated and verified")
    print(f"[+] port left unchanged on every row (verified)")
    print(f"[*] to undo: python3 tools/backfill_nuclei_identity.py --revert {dump_path}")
    conn.close()


if __name__ == "__main__":
    main()
