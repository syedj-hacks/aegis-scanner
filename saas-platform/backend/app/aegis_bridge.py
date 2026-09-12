"""
The ONLY place this codebase talks to Aegis Scanner. Everything here is a
direct Python import of Aegis's own modules (never subprocess/CLI) per the
integration rules in the project brief.

Aegis's own SQLite (database/aegis.db) stays the source of truth for
scans/findings; ScanJob.aegis_scan_id links a web platform job to the
scan_id Aegis's insert_scan() returned.
"""
import os
import sys
import threading

from .config import AEGIS_REPO_PATH

if AEGIS_REPO_PATH not in sys.path:
    sys.path.insert(0, AEGIS_REPO_PATH)

# Aegis's own modules use CWD-relative paths (database/aegis.db, output/...,
# per-target logs). Anchor the process's cwd to the Aegis repo once, at
# import time, so those relative paths resolve correctly regardless of where
# uvicorn was launched from.
os.chdir(AEGIS_REPO_PATH)

# Aegis's own DB layer, validator and profile orchestrators, imported as a
# library. init_db() is idempotent (safe to call from a second process) and
# is called once at web app startup (see main.py).
from database.db import (  # noqa: E402
    init_db as aegis_init_db,
    get_scan_history as aegis_get_scan_history,
    get_findings_for_scan as aegis_get_findings_for_scan,
    get_latest_scan as aegis_get_latest_scan,
)
from aegis import (  # noqa: E402
    is_valid_target as aegis_is_valid_target,
    normalize_target as aegis_normalize_target,
    PROFILE_DISPATCH,
)
from modules.utils.auth import AuthConfig  # noqa: E402
from modules.reporting.diff import diff_scans as aegis_diff_scans, latest_two_scans  # noqa: E402
from modules.reporting.retention import list_stored_reports  # noqa: E402

# insert_scan/dispatch functions are NOT re-entrant-safe across truly
# concurrent SQLite writers beyond what SQLite's own busy-timeout tolerates
# (see BACKEND_STRUCTURE.md §"database/db.py" — Concurrency). A single
# process-wide lock keeps our own worker threads serialized against each
# other; Aegis's CLI running standalone at the same time is still fine
# thanks to the busy-timeout.
_AEGIS_CALL_LOCK = threading.Lock()

ALL_AEGIS_PROFILES = list(PROFILE_DISPATCH.keys())

PROFILE_DESCRIPTIONS = {
    "quickscan": "Fast top-port nmap sweep + whatweb/nuclei on the first web port. Good first pass.",
    "stealthscan": "Quiet ~20-port scan at polite timing, minimal footprint, single whatweb fingerprint.",
    "webaudit": "Web application focus: headers, nikto, gobuster/dirb, whatweb, sslyze, XSS fuzzing.",
    "deepscan": "Full assessment: discovery sweep, service detection, all web tools, ZAP, plus "
                "conditional wpscan/sqlmap/hydra/enum4linux when their trigger condition is met.",
    "compliance": "TLS/header compliance check mapped to PCI-DSS/ISO 27001/NIST 800-53.",
    "recon": "Passive attack-surface mapping (crt.sh, subdomains, OSINT, cloud buckets, breach check). "
             "Never sends a packet to the target.",
}


def validate_and_normalize_target(raw_target: str) -> str:
    """
    Reuse Aegis's own validator/normalizer rather than re-implementing target
    parsing. Raises ValueError on anything invalid (including CIDR ranges,
    which normalize_target/is_valid_target reject as not a single host).
    """
    host = aegis_normalize_target(raw_target)
    if not aegis_is_valid_target(host):
        raise ValueError(f"'{raw_target}' is not a valid scan target (hostname/IP, no CIDR ranges).")
    return host


def build_auth_config(cookie: str = None, header: str = None) -> AuthConfig:
    return AuthConfig(cookie=cookie, header=header)


def run_profile_sync(profile: str, target: str, auth: AuthConfig = None):
    """
    Blocking call into an Aegis profile orchestrator. Must run off the
    FastAPI event loop thread (see routers/scans.py background job runner).

    Returns (scan_id, txt_path, pdf_path, html_path, stats) — the shape every
    profile now returns per BACKEND_STRUCTURE.md §"modules/profiles/" — Phase 8.
    """
    if profile not in PROFILE_DISPATCH:
        raise ValueError(f"Unknown Aegis profile: {profile}")
    dispatch = PROFILE_DISPATCH[profile]
    with _AEGIS_CALL_LOCK:
        result = dispatch(target, non_interactive=True, auth=auth)
    # Defensive unpack: keep working even if a profile's return arity drifts.
    if len(result) == 5:
        scan_id, txt_path, pdf_path, html_path, stats = result
    elif len(result) == 4:
        scan_id, txt_path, pdf_path, stats = result
        html_path = None
    else:
        scan_id, txt_path, pdf_path = result
        html_path, stats = None, {}
    return scan_id, txt_path, pdf_path, html_path, stats


def get_findings(scan_id: int) -> list:
    return aegis_get_findings_for_scan(scan_id)


def get_scan_history(target: str = None) -> list:
    return aegis_get_scan_history(target)


def diff(scan_id_a: int, scan_id_b: int) -> dict:
    return aegis_diff_scans(scan_id_a, scan_id_b)


def stored_reports_for(target: str, profile: str) -> list:
    """Surface Aegis's own retention list (max 5 per profile+target) as-is."""
    import os

    from .config import AEGIS_OUTPUT_DIR

    directory = os.path.join(AEGIS_OUTPUT_DIR, target)
    try:
        return list_stored_reports(directory, profile, target)
    except Exception:
        return []
