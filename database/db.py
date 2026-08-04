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
    # cvss_vector / compliance_refs were added last. cvss_vector carries the
    # CVSS v3.1 vector string behind a locally-computed score (see
    # modules/enrichment/cvss.py) so a report can show WHY a finding scored
    # what it did — a bare number with no vector is just a differently
    # spelled severity bucket. compliance_refs carries the PCI-DSS/ISO
    # 27001/NIST 800-53 control references for a finding, populated by the
    # compliance profile only.
    for column in ("description", "remediation", "finding_type", "product",
                   "parameter", "payload", "evidence", "endpoint",
                   "reference", "cvss_vector", "compliance_refs"):
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

    # --- Recon mapper tables ---------------------------------------------
    # The recon profile's three result shapes. Every one of these ALSO goes
    # into `findings` (as recon_subdomain / recon_bucket / recon_leak) so it
    # reaches the reports, the severity summary and the scan diff with no
    # special-casing anywhere downstream — that is the point of using the
    # existing finding pipeline rather than a parallel one.
    #
    # These tables exist for what `findings` structurally cannot hold: a
    # subdomain's discovery source (crt.sh vs subfinder vs amass — which
    # matters, since a CT-log-only name may not resolve at all), a bucket's
    # cloud provider, and the one-to-many relationship between a breached
    # address and the breaches it appears in. Flattening those into a
    # description string would make them unqueryable, and re-parsing prose
    # to get them back is exactly the kind of shape-sniffing this codebase
    # has been bitten by before.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS recon_subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL,
            source TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS recon_buckets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            bucket_url TEXT NOT NULL,
            provider TEXT,
            access TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS recon_leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            breach_name TEXT,
            breach_date TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


def _insert_recon_rows(table: str, columns: tuple, scan_id: int, rows: list) -> None:
    """
    Shared writer for the three recon_* tables.

    Never raises, for the same reason record_scan_tools() does not: these
    rows are supplementary detail on a scan whose findings are already
    persisted, and losing the provider name for a bucket must not turn a
    completed recon run into a failed one.
    """
    prepared = [
        tuple([scan_id] + [row.get(column) for column in columns])
        for row in (rows or [])
        if isinstance(row, dict)
    ]
    if not prepared:
        return

    placeholders = ", ".join("?" * (len(columns) + 1))
    column_list = ", ".join(("scan_id",) + columns)
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.executemany(
            f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})",
            prepared,
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        # Reported, not swallowed. An earlier version of this passed
        # silently, and the failure it hid was the interesting one: running
        # a profile via `python3 -m modules.profiles.recon` skips aegis.py's
        # init_db(), so `no such table: recon_subdomains` discarded every
        # row of a 15-minute recon run and printed nothing. A write that
        # quietly loses data is the exact failure mode this codebase keeps
        # having to fix — see modules/utils/error_handler.py's skip-flag
        # note. It still does not raise: the scan's findings are already
        # committed and this is supplementary detail.
        print(f"[db] could not write {len(prepared)} row(s) to {table}: {exc}")


def insert_recon_subdomains(scan_id: int, rows: list) -> None:
    """rows: [{subdomain, source}] — source is crt.sh / subfinder / amass."""
    _insert_recon_rows("recon_subdomains", ("subdomain", "source"), scan_id, rows)


def insert_recon_buckets(scan_id: int, rows: list) -> None:
    """rows: [{bucket_url, provider, access}] — access is open/protected/unknown."""
    _insert_recon_rows(
        "recon_buckets", ("bucket_url", "provider", "access"), scan_id, rows
    )


def insert_recon_leaks(scan_id: int, rows: list) -> None:
    """rows: [{email, breach_name, breach_date}] — one row per (email, breach)."""
    _insert_recon_rows(
        "recon_leaks", ("email", "breach_name", "breach_date"), scan_id, rows
    )


def get_recon_data(scan_id: int) -> dict:
    """
    Every recon_* row for one scan, as
    {"subdomains": [...], "buckets": [...], "leaks": [...]}.

    Returns empty lists for a scan that has none — which is every scan from
    a profile other than recon, and every scan written before these tables
    existed. Defensive against the tables being absent entirely so a
    database file that predates the migration reads as "no recon data"
    rather than raising.
    """
    out = {"subdomains": [], "buckets": [], "leaks": []}
    queries = (
        ("subdomains", "SELECT subdomain, source FROM recon_subdomains WHERE scan_id = ?"),
        ("buckets", "SELECT bucket_url, provider, access FROM recon_buckets WHERE scan_id = ?"),
        ("leaks", "SELECT email, breach_name, breach_date FROM recon_leaks WHERE scan_id = ?"),
    )
    try:
        conn = get_connection()
        cur = conn.cursor()
        for key, sql in queries:
            try:
                cur.execute(sql, (scan_id,))
                out[key] = [dict(r) for r in cur.fetchall()]
            except sqlite3.OperationalError:
                out[key] = []
        conn.close()
    except sqlite3.Error:
        pass
    return out


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
            parameter, payload, evidence, endpoint, reference,
            cvss_vector, compliance_refs)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            finding.get("cvss_vector"),
            # Stored as a comma-separated string: the reports render these
            # as text and never query into them, so a join table would add
            # a schema and a JOIN to buy nothing. Only the compliance
            # profile populates it; every other profile leaves it NULL.
            _compliance_refs_text(finding.get("compliance_refs")),
        ),
    )
    conn.commit()
    conn.close()


def _compliance_refs_text(refs):
    """
    Flatten a finding's compliance_refs to the TEXT column's format.

    Accepts the list of reference strings the mapper produces, or an
    already-flattened string (a row read back out and re-inserted). None
    and an empty list both become NULL rather than an empty string, so
    "no mapping" and "mapped to nothing" cannot be told apart by accident
    downstream — they are the same thing.
    """
    if not refs:
        return None
    if isinstance(refs, str):
        return refs or None
    try:
        return ", ".join(str(r) for r in refs if r) or None
    except TypeError:
        return None


# Columns that carry a finding's SUBSTANCE — the thing a reader would
# actually look at. A row with none of them populated says nothing: it is a
# placeholder that survived a mapper, not an observation. 42 such rows are in
# the shipped database already (scans 3 and 11, port 80, every column NULL),
# which is what "empty port-443 ghost rows" refers to.
#
# Note the shape those rows actually have, because it is not the shape you
# would guess: they carry no finding_type at all, not finding_type
# 'port_scan'. Filtering on a type string would therefore have removed
# nothing. The test is "does this row assert anything", which is both what
# makes a row a ghost and what stays true if a future mapper leaks a
# differently-labelled empty row.
_SUBSTANTIVE_FIELDS = (
    "cve_id", "service", "description", "path", "header", "script_id",
    "rule_id", "template_id", "parameter", "issue", "name", "banner_text",
    "version", "product", "evidence", "payload",
)


def _is_ghost(finding: dict) -> bool:
    """
    A finding that asserts nothing: no declared type AND no substantive
    field. Both halves are required, and the first half is what keeps this
    safe.

    A row that declares what it is has said something even when the rest of
    it is thin — an open_port on a port nmap could not name a service for is
    a real observation with no service, no version and no description, and
    dropping it would be exactly the "deduplication that deletes findings"
    failure this filter exists to avoid. The 42 known ghosts declare no type
    at all, so the conjunction removes all of them and risks nothing.
    """
    if not isinstance(finding, dict):
        return True
    declared = str(
        finding.get("type") or finding.get("finding_type") or ""
    ).strip()
    if declared:
        return False
    return not any(
        str(finding.get(field) or "").strip() for field in _SUBSTANTIVE_FIELDS
    )


def _dedup_key(finding: dict):
    """
    The identity of a finding, for collapsing duplicates inside one batch.

    Delegates to modules.reporting.diff.finding_key() rather than defining a
    second identity rule here. That module already had to solve exactly this
    problem — "are these two rows the same finding?" — and solved it
    carefully: (finding_type, port, identifier), where identifier is the CVE
    id, else the most specific stable label the type carries, else a
    description with volatile byte counts and timestamps stripped out.

    Two identity rules for one question is how they drift, and drifting here
    is expensive in a specific direction: a key of (port, finding_type,
    cve_id) — the obvious one — collapses every CVE-less finding on a port
    into a single row, which on a real target means one surviving
    discovered_path out of the 6,580 in this database. Deduplication that
    deletes real findings is worse than the duplicates it removes.

    Imported lazily because diff.py imports from this module; at call time
    both are loaded, so the cycle never forms. If the import fails for any
    reason the caller falls back to inserting everything, which is the safe
    direction: a duplicate row is a cosmetic problem, a dropped finding is
    not.
    """
    from modules.reporting.diff import finding_key
    return finding_key(finding)


def insert_findings_bulk(scan_id: int, findings: list):
    """
    Insert a batch of findings, dropping ghost rows and within-batch
    duplicates first.

    Deduplication is scoped to this call, deliberately, and that scope is the
    honest one: the profiles insert incrementally (deepscan writes one batch
    per open web port, precisely so a later port timing out cannot cost an
    earlier port's results), so a batch is the unit in which a mapper can
    emit the same finding twice. Widening this to the whole scan would mean
    re-reading every row already written on every insert, and would silently
    suppress the legitimate case of one finding genuinely observed on two
    ports.
    """
    try:
        deduped, seen = [], set()
        for f in findings or []:
            if _is_ghost(f):
                continue
            key = _dedup_key(f)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
    except Exception:
        # Never let a filtering problem cost a scan its findings.
        deduped = findings or []

    for f in deduped:
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