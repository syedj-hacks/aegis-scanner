"""
modules/reporting/report_json.py
Machine-readable JSON scan report (Phase 4).

WHY
---
The TXT/PDF/HTML reports are for people. This one is for other tools: a CI
job that gates a deploy on the risk score, a script that files a ticket per
Critical finding, a dashboard that ingests scan history. It is the format
you pipe Aegis into something else with, which is exactly what the spec
asks for ("JSON output mode for scripting/chaining into other tools").

CONTRACT
--------
A single JSON object, stable-shaped, with a top-level `schema_version` so a
consumer can detect a breaking change rather than guess. It carries:

    schema_version, generated_at
    scan            {id, target, profile, timestamp, criticality}
    risk            {environment_risk{score, band, ...}, criticality}
    summary         {total_findings, by_severity, by_confidence}
    top_risks       the executive top-5, each with its plain-language line
    findings        every finding, full-fidelity — all the enrichment
                    (cve_ids, cvss, cvss_vector, epss, risk_score,
                    confidence, evidence, remediation, references,
                    endpoint/parameter/payload) that the schema-bound
                    database columns hold, plus the ones only the richer
                    outputs can carry.

Every field a consumer might key on is always present (null, not absent),
so `data["risk"]["environment_risk"]["score"]` never KeyErrors on a scan
that happened to find nothing. Never raises: a failure is logged and
returns None, same contract as the other writers.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from modules.utils.config import output_dir
from modules.utils.logger import get_logger
from modules.utils.display import print_success, print_error
from modules.reporting.retention import report_filename
from modules.reporting.risk_report import risk_posture

SCHEMA_VERSION = "1.0"

# The finding fields the JSON report exposes, and the order they appear in.
# Explicit rather than "dump the row" so a new internal column does not
# silently change the public JSON contract.
_FINDING_FIELDS = (
    "finding_uid", "finding_type", "plugin", "title", "description",
    "severity", "confidence",
    "cve_id", "cvss", "cvss_vector", "epss_score", "epss_percentile",
    "risk_score",
    "service", "version", "product", "port",
    "endpoint", "parameter", "payload", "evidence",
    "remediation", "reference", "compliance_refs", "validation",
)


def build_json_report(summary: dict, criticality: str = None) -> dict:
    """The report as a plain dict (what render + tests read)."""
    meta = summary.get("scan_metadata") or {}
    findings = summary.get("findings") or []
    posture = risk_posture(summary, criticality)

    by_confidence = {}
    for f in findings:
        key = f.get("confidence") or "Unknown"
        by_confidence[key] = by_confidence.get(key, 0) + 1

    def _finding(f: dict) -> dict:
        out = {}
        for field in _FINDING_FIELDS:
            value = f.get(field)
            # `title` falls back to the first line of the description so a
            # consumer always has a short label.
            if field == "title" and not value:
                value = (f.get("description") or "").split("\n")[0][:160] or None
            out[field] = value
        return out

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan": {
            "id": meta.get("id"),
            "target": meta.get("target"),
            "profile": meta.get("profile"),
            "timestamp": meta.get("timestamp"),
            "criticality": posture["criticality"],
        },
        "risk": {
            "environment_risk": posture["environment_risk"],
            "criticality": posture["criticality"],
        },
        "summary": {
            "total_findings": summary.get("total_findings", len(findings)),
            "by_severity": summary.get("by_severity") or {},
            "by_confidence": by_confidence,
        },
        "top_risks": posture["top_risks"],
        "findings": [_finding(f) for f in findings],
        "error": summary.get("error"),
    }


def _resolve_output_path(target, output_path, profile, scan_id) -> str:
    if output_path:
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)
        return output_path
    directory = output_dir(target)
    if profile and scan_id is not None:
        return os.path.join(directory, report_filename(profile, target, scan_id, "json"))
    return os.path.join(directory, "report.json")


def generate_json_report(summary: dict, output_path: str = None,
                         criticality: str = None):
    """
    Write the JSON report for a built summary. Returns the path, or None on
    failure (logged). Never raises.
    """
    meta = summary.get("scan_metadata") or {}
    target = meta.get("target") or "unknown"
    profile = meta.get("profile")
    scan_id = meta.get("id")
    logger = get_logger(target)

    try:
        report = build_json_report(summary, criticality)
        path = _resolve_output_path(target, output_path, profile, scan_id)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        logger.info(f"[Report] json report written to {path} "
                    f"({report['summary']['total_findings']} finding(s))")
        print_success(f"[Report] JSON report written to {path}")
        return path
    except Exception as exc:  # noqa: BLE001 — a report writer must not crash a scan
        logger.error(f"[Report] json report failed: {exc}")
        print_error(f"[Report] JSON report could not be written: {exc}")
        return None
