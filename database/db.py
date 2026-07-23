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
    finding: {port, service, version, cve_id, cvss, severity}
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO findings
           (scan_id, port, service, version, cve_id, cvss, severity)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            finding.get("port"),
            finding.get("service"),
            finding.get("version"),
            finding.get("cve_id"),
            finding.get("cvss"),
            finding.get("severity"),
        ),
    )
    conn.commit()
    conn.close()


def insert_findings_bulk(scan_id: int, findings: list):
    for f in findings:
        insert_finding(scan_id, f)


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