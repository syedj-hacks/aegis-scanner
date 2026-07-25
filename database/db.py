"""
database/db.py
SQLite persistence layer for scan history and findings.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join("database", "aegis.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates tables if they don't already exist. Safe to call every run."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            profile TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER,
            service TEXT,
            version TEXT,
            cve_id TEXT,
            cvss REAL,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Migration: the findings table predates description/remediation/
    # finding_type — add them as nullable columns so existing rows (this
    # database file is tracked in git and ships with scan history already
    # in it) stay valid with those fields simply NULL. ALTER TABLE ADD
    # COLUMN is safe to re-run every process start: skipped once the column
    # already exists.
    #
    # parameter/payload/evidence/endpoint were added later still, for the
    # injection & scripting reporting section: SQLi (sqlmap) and XSS
    # (nuclei DAST) findings carry the exact payload sent, the parameter/URL
    # it was sent against, and a truncated response snippet proving
    # exploitation. Every other finding shape leaves these NULL — they are
    # only read by the report's dedicated injection section, which filters
    # on finding_type.
    # reference was added last, for the web wrappers' field-population pass:
    # nikto prints "... See: <url>", ZAP returns a `reference` field on every
    # alert, and wpscan cites an advisory URL. All three were parsed by their
    # wrappers and then silently dropped at insert, because there was no
    # column to put them in. They are citations for a finding rather than
    # evidence of it, so they get their own column instead of being folded
    # into evidence/remediation.
    cur.execute("PRAGMA table_info(findings)")
    existing_columns = {row[1] for row in cur.fetchall()}
    for column in ("description", "remediation", "finding_type", "product",
                   "parameter", "payload", "evidence", "endpoint",
                   "reference"):
        if column not in existing_columns:
            cur.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")

    # Per-scan tools-run record. Separate table (not a JSON column on scans)
    # to match this schema's convention: findings already hang off scans by
    # scan_id rather than being folded into a blob, and a tool that runs
    # per-port emits one row per (tool, port) — a shape a relational table
    # holds naturally and a JSON summary would flatten.
    #
    # outcome is one of 'ran' / 'skipped' / 'failed', classified from the
    # exact same tool_results dict the summary panel counts (see
    # modules/profiles/_common.classify_tool_outcome), so the persisted
    # record cannot drift from "Tools failed/skipped" on screen.
    #
    # This is collected going forward only: scans that predate the table
    # (every row already in the shipped database) simply have no rows here,
    # and modules/reporting/attribution.py falls back to the profile-level
    # check for those. No historical backfill — same principle as the
    # cve_id/port/finding_type passes: the data was never captured, so it is
    # not invented.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_tools_run (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            port INTEGER,
            outcome TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


def insert_scan(target: str, profile: str) -> int:
    """Creates a new scan record, returns its id for use with insert_finding()."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, timestamp, profile) VALUES (?, ?, ?)",
        (target, datetime.now().isoformat(), profile),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def insert_finding(scan_id: int, finding: dict):
    """
    finding: {port, service, version, product, cve_id, cvss, severity,
              description, remediation, type/finding_type,
              parameter, payload, evidence, endpoint}

    description/remediation/finding_type/product/parameter/payload/evidence/
    endpoint are all nullable — callers that still hand over the old
    CVE-shaped dict (none of those keys) insert cleanly with those columns
    left NULL, same as any pre-migration row. parameter/payload/evidence/
    endpoint are only populated by the injection findings (sqlmap SQLi,
    nuclei-DAST XSS) the report's injection section reads.
    """
    finding_type = finding.get("type") or finding.get("finding_type")
    if not finding_type and finding.get("cve_id"):
        finding_type = "cve"

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO findings
           (scan_id, port, service, version, cve_id, cvss, severity,
            description, remediation, finding_type, product,
            parameter, payload, evidence, endpoint, reference)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            finding.get("port"),
            finding.get("service"),
            finding.get("version"),
            finding.get("cve_id"),
            finding.get("cvss"),
            finding.get("severity"),
            finding.get("description"),
            finding.get("remediation"),
            finding_type,
            finding.get("product"),
            finding.get("parameter"),
            finding.get("payload"),
            finding.get("evidence"),
            finding.get("endpoint"),
            finding.get("reference"),
        ),
    )
    conn.commit()
    conn.close()


def insert_findings_bulk(scan_id: int, findings: list):
    for f in findings:
        insert_finding(scan_id, f)


def record_scan_tools(scan_id: int, records: list):
    """
    Persist which tools ran on one scan.

    `records` is a list of {tool_name, port, outcome} dicts, already
    classified by the caller (modules/profiles/_common.persist_tool_run)
    from the same tool_results the summary panel counts. outcome must be one
    of 'ran' / 'skipped' / 'failed'. A tool that ran per-port produces one
    record per port; the attribution check collapses them.
    """
    rows = [
        (scan_id, r["tool_name"], r.get("port"), r["outcome"])
        for r in (records or [])
        if r.get("tool_name") and r.get("outcome")
    ]
    if not rows:
        return
    conn = get_connection()
    cur = conn.cursor()
    cur.executemany(
        "INSERT INTO scan_tools_run (scan_id, tool_name, port, outcome) "
        "VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


def get_scan_tools_run(scan_id: int) -> list:
    """
    The tools-run record for one scan as a list of {tool_name, port, outcome}
    dicts, or [] when the scan has none — which is the case for every scan
    written before this table existed. Defensive against the table itself
    being absent (a database file that predates the migration and has not had
    init_db() run against it yet) so callers can treat "no record" and "no
    table" identically as "fall back to the profile-level check".
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT tool_name, port, outcome FROM scan_tools_run "
            "WHERE scan_id = ?",
            (scan_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    return rows


def get_scan_history(target: str = None) -> list:
    """Returns all past scans, optionally filtered by target."""
    conn = get_connection()
    cur = conn.cursor()
    if target:
        cur.execute("SELECT * FROM scans WHERE target = ? ORDER BY timestamp DESC", (target,))
    else:
        cur.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_findings_for_scan(scan_id: int) -> list:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_latest_scan(target: str) -> dict:
    history = get_scan_history(target)
    return history[0] if history else None