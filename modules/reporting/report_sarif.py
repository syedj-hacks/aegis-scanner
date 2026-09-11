"""
modules/reporting/report_sarif.py
SARIF 2.1.0 output for CI/CD integration (Phase 4).

WHY SARIF
---------
SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) is the
lingua franca CI systems already understand: GitHub code scanning ingests
it natively (Security tab, PR annotations), as do Azure DevOps, GitLab and
most quality dashboards. Emitting SARIF is what lets an Aegis scan become a
gate in a pipeline without any glue code — the spec's "SARIF output option
(for CI/CD integration)".

THE MAPPING (and the honest bits)
---------------------------------
SARIF is code-analysis-shaped: results point at artifacts (files) and
regions (lines). A network vulnerability scan has no source file, so this
maps each finding's LOCATION to a synthetic URI describing WHERE on the
target it was found — the endpoint URL, or target:port — rather than
inventing a file/line that does not exist. That is the standard,
documented way network scanners emit SARIF, and the physicalLocation uses
the finding's real endpoint so a reader can act on it.

  - Each distinct finding TYPE becomes a `rule` (reportingDescriptor) once,
    in tool.driver.rules, carrying its description and help/remediation.
  - Each finding becomes a `result` referencing its rule, with:
      level        error/warning/note, mapped from severity
      message      the finding's description
      properties   the enrichment SARIF has no native slot for — cvss,
                   epss, risk_score, confidence, cve ids — so a
                   SARIF-aware consumer can still read them
      rank         the combined risk score (SARIF's own 0-100 priority
                   field), so a dashboard can sort by it
      partialFingerprints  the finding's stable uid, so re-scans dedupe

Never raises: failure is logged and returns None.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from modules.utils.config import output_dir
from modules.utils.logger import get_logger
from modules.utils.display import print_success, print_error
from modules.reporting.retention import report_filename
from modules.enrichment.risk import combined_risk_score

_SARIF_VERSION = "2.1.0"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_TOOL_NAME = "Aegis Scanner"
_INFO_URI = "https://github.com/syedj-hacks/aegis-scanner"

# SARIF's result.level is a three-value enum. CVSS severity maps onto it;
# there is no "critical" level in SARIF, so critical and high both become
# `error` (the highest) and the true severity is preserved in properties.
_LEVEL = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning", "LOW": "note", "INFO": "note",
}


def _rule_id(finding: dict) -> str:
    """The SARIF rule a finding belongs to — its finding type."""
    return (finding.get("finding_type") or finding.get("type") or "finding")


def _location(finding: dict, target: str) -> dict:
    """
    A physicalLocation for a finding. Uses the real endpoint when present,
    else a synthetic target:port URI — never a fabricated file/line.
    """
    endpoint = finding.get("endpoint")
    if endpoint:
        uri = endpoint
    else:
        port = finding.get("port")
        uri = f"{target}:{port}" if port else target
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
        }
    }


def build_sarif_report(summary: dict) -> dict:
    """The SARIF log as a dict."""
    meta = summary.get("scan_metadata") or {}
    target = meta.get("target") or "unknown"
    findings = summary.get("findings") or []

    # One rule per finding type, first occurrence wins for the description.
    rules = {}
    rule_index = {}
    results = []

    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rule_index[rid] = len(rules)
            rules[rid] = {
                "id": rid,
                "name": rid.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": rid.replace("_", " ")},
                "fullDescription": {
                    "text": f"Findings of type '{rid}' reported by Aegis Scanner."
                },
                "defaultConfiguration": {"level": _LEVEL.get(
                    str(f.get("severity", "")).upper(), "warning")},
                "helpUri": _INFO_URI,
            }

        severity = str(f.get("severity", "")).upper()
        cvss = f.get("cvss") if f.get("cvss") is not None else f.get("cvss_score")
        risk = f.get("risk_score")
        if risk is None:
            risk = combined_risk_score(cvss, f.get("epss_score"))

        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _LEVEL.get(severity, "warning"),
            "message": {"text": (f.get("description") or f.get("title") or rid).strip()},
            "locations": [_location(f, target)],
            "properties": {
                "severity": severity or None,
                "confidence": f.get("confidence"),
                "cve_ids": [c for c in [f.get("cve_id")] if c],
                "cvss": cvss,
                "cvss_vector": f.get("cvss_vector"),
                "epss_score": f.get("epss_score"),
                "risk_score": risk,
                "plugin": f.get("plugin"),
                "remediation": f.get("remediation"),
                "evidence": f.get("evidence"),
            },
        }
        # SARIF rank: 0-100 priority. Scale the 0-10 risk onto it so a CI
        # dashboard can sort/threshold by exploitability, not just severity.
        if risk is not None:
            result["rank"] = round(min(100.0, float(risk) * 10.0), 1)
        uid = f.get("finding_uid")
        if uid:
            result["partialFingerprints"] = {"aegisFindingUid": uid}
        results.append(result)

    return {
        "$schema": _SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "informationUri": _INFO_URI,
                    "version": "1.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": summary.get("error") is None,
                "endTimeUtc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "properties": {
                    "target": target,
                    "profile": meta.get("profile"),
                    "scan_id": meta.get("id"),
                },
            }],
        }],
    }


def _resolve_output_path(target, output_path, profile, scan_id) -> str:
    if output_path:
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)
        return output_path
    directory = output_dir(target)
    if profile and scan_id is not None:
        return os.path.join(directory, report_filename(profile, target, scan_id, "sarif"))
    return os.path.join(directory, "report.sarif")


def generate_sarif_report(summary: dict, output_path: str = None):
    """Write the SARIF report. Returns the path or None (logged). Never raises."""
    meta = summary.get("scan_metadata") or {}
    target = meta.get("target") or "unknown"
    profile = meta.get("profile")
    scan_id = meta.get("id")
    logger = get_logger(target)

    try:
        report = build_sarif_report(summary)
        path = _resolve_output_path(target, output_path, profile, scan_id)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        n = len(report["runs"][0]["results"])
        logger.info(f"[Report] sarif report written to {path} ({n} result(s))")
        print_success(f"[Report] SARIF report written to {path}")
        return path
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Report] sarif report failed: {exc}")
        print_error(f"[Report] SARIF report could not be written: {exc}")
        return None
