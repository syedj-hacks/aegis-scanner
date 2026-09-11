"""
plugins/base.py
The plugin contract for Aegis Scanner.

WHY THIS EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO
------------------------------------------------------
Before this package, every detection module exposed its own hand-shaped
function (`check_headers(target, port, use_https)`, `run_nuclei(target,
port, use_https, severity)`, `grab_banners(target, ports)`, ...) returning
its own hand-shaped dict, and each profile orchestrator carried its own
`_findings_from_<tool>()` mapper to turn that dict into the flat finding
dicts database/db.py stores. That worked, and it is live-verified against
real targets — but it means adding a check means editing a profile, and
there is no single answer to "what checks does this scanner have".

This module defines that single answer: ScannerPlugin. Every detection
module in modules/ has a plugin in this package that declares its
metadata, invokes it, and normalises its output to Finding objects.

What this package is NOT is a rewrite. The plugins call the existing,
live-verified module functions and reuse the existing mapper functions
(see plugins/_mappers.py) rather than reimplementing either. The detection
logic has one home — modules/ — and this package is the interface to it.
That is a deliberate choice: a parallel reimplementation would be a second
place for detection behaviour to drift, and the existing modules are the
ones with the live evidence behind them.

The legacy profile orchestrators (modules/profiles/*.py) are untouched and
still work exactly as before. The plugin engine (modules/engine/) is a
second, additive way to drive the same detection code.
"""

from __future__ import annotations

import abc
import dataclasses
import hashlib
import time
from typing import Iterable


# --- Severity ------------------------------------------------------------
# The same five labels the rest of the codebase already uses (see
# modules/enrichment/severity.py and the reports). Not an enum, because
# every consumer downstream — db.py's severity column, summary.py's
# counting, the PDF's grouping — reads and writes these as plain uppercase
# strings, and an enum here would mean converting at every boundary.
SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Where a plugin's output can be pointed. A plugin declares which of these
# it handles; the engine only runs it against a matching target/context.
#
#   host     — needs only a hostname/IP (port scan, DNS, banner grab)
#   web      — needs an open HTTP(S) port (headers, nikto, nuclei, ZAP)
#   service  — needs a specific non-web service on a known port
#              (SMB enumeration, SSH credential checks)
#   passive  — contacts third parties ONLY, never the target itself
#              (certificate transparency, OSINT, breach lookup)
TARGET_TYPES = ("host", "web", "service", "passive")


# --- Confidence ----------------------------------------------------------
# The false-positive distinction Phase 3 turns on. CONFIRMED means the
# scanner observed the vulnerable behaviour (a payload reflected, an
# injection that returned data, an exposed share that listed). POTENTIAL
# means the finding rests on a version string or a banner and nothing was
# actually exercised — which is most of what a CVE-matching scanner
# produces, and the thing a reader must be able to tell apart.
CONFIRMED = "Confirmed"
POTENTIAL = "Potential"


def normalise_severity(value, default: str = "MEDIUM") -> str:
    """
    Coerce anything a tool might hand back into one of SEVERITY_ORDER.

    Tools spell severity every way there is: nuclei says "info"/"medium",
    ZAP says "High"/"Informational", NVD says "CRITICAL". Anything
    unrecognised falls back to `default` rather than being invented into a
    new bucket that the report's grouping would then silently drop.
    """
    if value is None:
        return default
    text = str(value).strip().upper()
    if not text:
        return default
    # ZAP's "Informational", nuclei's "unknown".
    if text.startswith("INFO"):
        return "INFO"
    if text in SEVERITY_ORDER:
        return text
    return default


def severity_rank(value) -> int:
    """Sortable rank; higher is worse. Unknown severities sort lowest."""
    try:
        return SEVERITY_ORDER.index(normalise_severity(value, "INFO"))
    except ValueError:
        return 0


@dataclasses.dataclass
class Finding:
    """
    The single finding shape every plugin emits.

    The nine fields named in the plugin spec come first. Everything after
    them exists because database/db.py's findings table already has a
    column for it and dropping it here would lose data the existing
    reports render — this dataclass has to be able to round-trip a finding
    through the database without being lossier than the dicts it replaces.

    Field notes
    -----------
    id            Stable within a scan, derived from the finding's own
                  content (see `assign_id`) rather than a counter, so the
                  same finding in two scans of the same host gets the same
                  id and a diff can line them up.
    cvss_score    The base score. May be None: most findings are not CVEs
                  and inventing a number for them would be worse than
                  admitting there isn't one.
    cve_ids       A list. A single finding can carry several (a nuclei
                  template matching a CVE cluster, say), and the legacy
                  single `cve_id` column takes the first.
    evidence      What was actually observed. Free text, and the thing a
                  reader checks the finding against.
    references    URLs. The legacy schema has one `reference` column, so
                  the first survives a database round-trip and the rest
                  live only in the JSON/SARIF outputs, which have room.
    confidence    CONFIRMED vs POTENTIAL — see the constants above.
    epss_score    FIRST.org exploit-probability, 0.0-1.0. None until the
                  enrichment pass runs (and after it, for anything with no
                  CVE — EPSS is only defined for published CVEs).
    risk_score    Combined CVSS+EPSS score, 0-10. See
                  modules/enrichment/risk.py.
    """

    # --- the spec's fields ---
    title: str
    severity: str = "MEDIUM"
    id: str = ""
    cvss_score: float | None = None
    cve_ids: list = dataclasses.field(default_factory=list)
    affected_target: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list = dataclasses.field(default_factory=list)

    # --- provenance ---
    plugin: str = ""
    finding_type: str = ""

    # --- what the existing findings table holds ---
    port: int | None = None
    service: str | None = None
    version: str | None = None
    product: str | None = None
    parameter: str | None = None
    payload: str | None = None
    endpoint: str | None = None
    cvss_vector: str | None = None
    compliance_refs: list = dataclasses.field(default_factory=list)
    description: str = ""

    # --- Phase 3 enrichment ---
    confidence: str = POTENTIAL
    epss_score: float | None = None
    epss_percentile: float | None = None
    risk_score: float | None = None
    validation: str = ""

    def __post_init__(self):
        self.severity = normalise_severity(self.severity)
        # A caller that passed a bare string where a list belongs gets it
        # wrapped rather than iterated character by character, which is the
        # kind of bug that produces a finding with 24 "references".
        if isinstance(self.cve_ids, str):
            self.cve_ids = [self.cve_ids] if self.cve_ids else []
        if isinstance(self.references, str):
            self.references = [self.references] if self.references else []
        if isinstance(self.compliance_refs, str):
            self.compliance_refs = [self.compliance_refs] if self.compliance_refs else []
        if not self.description:
            self.description = self.title
        if not self.id:
            self.assign_id()

    def assign_id(self) -> str:
        """
        Content-derived stable id: aegis-<plugin>-<10 hex>.

        Derived from the fields that identify WHICH finding this is
        (plugin, type, port, endpoint/parameter, title) and deliberately
        NOT from the ones that describe its current state (severity,
        scores, evidence). A finding whose CVSS is re-scored by a later
        enrichment pass, or whose severity is raised, must keep its id —
        otherwise the scan diff reports one finding disappearing and
        another appearing where the truth is that one finding changed.
        """
        material = "|".join(str(x or "") for x in (
            self.plugin, self.finding_type, self.port,
            self.endpoint, self.parameter, self.title,
            ",".join(sorted(self.cve_ids)),
        ))
        digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:10]
        slug = (self.plugin or self.finding_type or "finding").replace("_", "-")
        self.id = f"aegis-{slug}-{digest}"
        return self.id

    @property
    def cve_id(self):
        """The first CVE, for the single-column legacy database schema."""
        return self.cve_ids[0] if self.cve_ids else None

    @property
    def reference(self):
        """The first reference, for the single-column legacy schema."""
        return self.references[0] if self.references else None

    def to_db_dict(self) -> dict:
        """
        The flat dict database/db.py's insert_finding()/insert_findings_bulk()
        already accept — byte-compatible with what the legacy profiles pass,
        so a plugin-engine scan and a legacy-profile scan produce rows of
        exactly the same shape and everything downstream (reports, diff,
        attribution, summary) reads them identically.

        Fields with no column (epss, risk score, confidence, the 2nd+ CVE
        and reference) are folded into `description` ONLY where they change
        what the finding means — the confidence label — and otherwise left
        to the JSON/SARIF outputs, which are not schema-bound. Inventing
        columns is a migration this does not need: db.py's ALTER TABLE
        migration list is the place for that, and Phase 3 adds them there.
        """
        return {
            "type": self.finding_type or "plugin_finding",
            "port": self.port,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "cve_id": self.cve_id,
            "cvss": self.cvss_score,
            "severity": self.severity,
            "description": self.description or self.title,
            "remediation": self.remediation or None,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence or None,
            "endpoint": self.endpoint,
            "reference": self.reference,
            "cvss_vector": self.cvss_vector,
            "compliance_refs": list(self.compliance_refs) or None,
            # Phase 3 columns (added by db.py's migration list).
            "confidence": self.confidence,
            "epss_score": self.epss_score,
            "risk_score": self.risk_score,
            "plugin": self.plugin or None,
            "finding_uid": self.id,
        }

    def to_dict(self) -> dict:
        """Full, lossless dict — what the JSON report writes."""
        return dataclasses.asdict(self)

    @classmethod
    def from_legacy(cls, legacy: dict, plugin: str = "", target: str = "") -> "Finding":
        """
        Build a Finding from one of the flat dicts the existing
        `_findings_from_<tool>()` mappers produce.

        This is the bridge that lets the plugins reuse those mappers
        verbatim instead of reimplementing twenty result formats. Every
        key the mappers actually set is read here; a key they don't set
        stays at its default, which is why the mapper output can be passed
        straight through without per-tool special-casing.
        """
        legacy = legacy or {}
        finding_type = legacy.get("type") or legacy.get("finding_type") or ""
        description = (legacy.get("description") or "").strip()

        # The mappers put the human-readable sentence in `description`.
        # A title is the first sentence/line of it — short enough for a
        # SARIF rule name and a PDF table row, with the full text kept in
        # `description`. Findings whose mapper set no description (the raw
        # service_version rows) get one built from what they do have.
        title = description
        if not title:
            bits = [finding_type.replace("_", " ").strip() or "finding"]
            if legacy.get("service"):
                bits.append(str(legacy["service"]))
            if legacy.get("port"):
                bits.append(f"port {legacy['port']}")
            title = " — ".join(bits)
        title = title.strip().split("\n")[0]
        if len(title) > 160:
            title = title[:157].rstrip() + "..."

        cve = legacy.get("cve_id")
        ref = legacy.get("reference")
        refs = legacy.get("references")
        if refs:
            reference_list = [r.get("url") if isinstance(r, dict) else str(r) for r in refs]
            reference_list = [r for r in reference_list if r]
        else:
            reference_list = [ref] if ref else []

        return cls(
            title=title,
            description=description,
            severity=normalise_severity(legacy.get("severity"), "MEDIUM"),
            cvss_score=legacy.get("cvss"),
            cve_ids=[cve] if cve else [],
            affected_target=target or legacy.get("target") or "",
            evidence=legacy.get("evidence") or "",
            remediation=legacy.get("remediation") or "",
            references=reference_list,
            plugin=plugin,
            finding_type=finding_type,
            port=legacy.get("port"),
            service=legacy.get("service"),
            version=legacy.get("version"),
            product=legacy.get("product"),
            parameter=legacy.get("parameter"),
            payload=legacy.get("payload"),
            endpoint=legacy.get("endpoint"),
            cvss_vector=legacy.get("cvss_vector"),
            compliance_refs=legacy.get("compliance_refs") or [],
            confidence=legacy.get("confidence") or POTENTIAL,
        )


@dataclasses.dataclass
class PluginResult:
    """
    One plugin's complete outcome for one target/context.

    `outcome` is the same three-valued vocabulary the existing codebase
    already uses everywhere (modules/profiles/_common.classify_tool_outcome,
    the scan_tools_run table, the end-of-scan summary panel): 'ran',
    'skipped', 'failed'. Reusing it — rather than inventing a fourth word
    for the same idea — is what lets a plugin-engine scan be recorded in,
    and reported from, the existing scan_tools_run table with no
    special-casing.

    The one rule this codebase has been bitten by repeatedly (see the
    skip-flag convention in modules/profiles/_common.py): a tool that
    failed must be COUNTED as failed by the same code path that reports
    it. `outcome` is computed once, here, from the raw result — there is
    no second opinion anywhere.
    """

    plugin: str
    outcome: str = "ran"
    findings: list = dataclasses.field(default_factory=list)
    raw: dict = dataclasses.field(default_factory=dict)
    error: str | None = None
    duration: float = 0.0
    port: int | None = None
    target: str = ""

    @property
    def failed(self) -> bool:
        return self.outcome == "failed"

    @property
    def skipped(self) -> bool:
        return self.outcome == "skipped"

    def to_tool_result(self) -> dict:
        """
        The legacy tool-result dict shape that
        _common.count_and_report_tool_failures() / classify_tool_outcome()
        / persist_tool_run() consume, so plugin runs land in
        scan_tools_run exactly as wrapper runs do.
        """
        return {
            "tool": self.plugin,
            "port": self.port,
            "error": self.error,
            "skipped": self.skipped,
        }


class ScannerPlugin(abc.ABC):
    """
    Base class for every Aegis check.

    Subclass contract
    -----------------
        name               unique, lowercase, filesystem-safe. This is the
                           string a YAML profile lists and the string
                           recorded in scan_tools_run.
        description        one line, shown by --list-plugins.
        target_types       tuple from TARGET_TYPES.
        severity_baseline  the severity a finding from this plugin gets
                           when the tool itself does not say. Not a cap and
                           not an override: a tool that reports its own
                           severity always wins.
        run(target, config)        -> raw result dict (never raises)
        parse_output(raw)          -> list[Finding]

    Optional:
        requires           external binaries this plugin shells out to.
                           available() checks them so a missing tool is
                           reported as skipped-with-a-reason rather than
                           failing mid-scan.
        applicable(config) -> bool, for plugins that only make sense in
                           some contexts (a WordPress plugin on a host with
                           no WordPress, say).

    `run()` must not raise. Every existing module already honours that
    (run_tool()/safe_call() convert exceptions into {error: ...} results),
    and execute() below enforces it for anything that slips through, so
    one broken plugin cannot take a scan down — the per-target/per-plugin
    isolation Phase 2 promises depends on this being true at this level,
    not just at the engine's.
    """

    name: str = ""
    description: str = ""
    target_types: tuple = ("host",)
    severity_baseline: str = "MEDIUM"
    requires: tuple = ()
    # Ordering hint for the engine. Lower runs earlier. Plugins that
    # produce the context other plugins consume (the port scan, service
    # detection) sit at 0-10; everything else defaults to 50.
    order: int = 50
    # True for plugins that send nothing to the target. The stealth/recon
    # profiles and the safety throttle both read this.
    passive: bool = False

    @abc.abstractmethod
    def run(self, target: str, config: dict) -> dict:
        """Invoke the underlying check. Must never raise."""

    @abc.abstractmethod
    def parse_output(self, raw: dict) -> list:
        """Normalise a raw result into Finding objects."""

    # --- shared machinery, not usually overridden --------------------

    def applicable(self, config: dict) -> bool:
        """Whether this plugin should run in the given context."""
        return True

    def available(self) -> tuple:
        """
        (bool, reason). False when a required external binary is absent.

        Checked BEFORE run() so a missing tool is recorded as 'skipped'
        with a reason a reader can act on, rather than as a failure that
        looks like the target's fault.
        """
        import shutil
        missing = [b for b in self.requires if not shutil.which(b)]
        if missing:
            return False, f"missing required tool(s): {', '.join(missing)}"
        return True, ""

    def execute(self, target: str, config: dict = None) -> PluginResult:
        """
        run() + parse_output() with timing, availability and isolation.

        This is what the engine calls. It is the ONLY place a plugin's
        outcome is classified, so "counted as failed" and "reported as
        failed" cannot disagree — the bug class this codebase has hit
        three separate times (see the skip-flag convention).
        """
        config = dict(config or {})
        started = time.time()
        port = config.get("port")

        ok, reason = self.available()
        if not ok:
            return PluginResult(
                plugin=self.name, outcome="skipped", error=reason,
                duration=0.0, port=port, target=target,
            )

        if not self.applicable(config):
            return PluginResult(
                plugin=self.name, outcome="skipped",
                error="not applicable to this target/context",
                duration=0.0, port=port, target=target,
            )

        try:
            raw = self.run(target, config) or {}
        except KeyboardInterrupt:
            # A deliberate operator skip is not a failure. The existing
            # wrappers already translate this into a skipped result; this
            # catches it for anything that lets it through.
            return PluginResult(
                plugin=self.name, outcome="skipped", error="skipped by user",
                duration=time.time() - started, port=port, target=target,
            )
        except Exception as exc:  # noqa: BLE001 — isolation is the point
            return PluginResult(
                plugin=self.name, outcome="failed",
                error=f"{type(exc).__name__}: {exc}",
                duration=time.time() - started, port=port, target=target,
            )

        # The wrappers' own convention: a result carrying `error` but not
        # `skipped` is a failure; `skipped` is the operator's choice.
        error = raw.get("error")
        if raw.get("skipped"):
            outcome = "skipped"
        elif error:
            outcome = "failed"
        else:
            outcome = "ran"

        try:
            findings = self.parse_output(raw) or []
        except Exception as exc:  # noqa: BLE001
            # The tool ran; only the mapping broke. Say so precisely —
            # reporting this as "the tool failed" would send someone
            # debugging the target instead of the parser.
            return PluginResult(
                plugin=self.name, outcome="failed",
                raw=raw,
                error=f"output parsing failed: {type(exc).__name__}: {exc}",
                duration=time.time() - started, port=port, target=target,
            )

        for finding in findings:
            if not finding.affected_target:
                finding.affected_target = target
            if not finding.plugin:
                finding.plugin = self.name
            if finding.port is None and port is not None:
                finding.port = port

        return PluginResult(
            plugin=self.name, outcome=outcome, findings=findings, raw=raw,
            error=error, duration=time.time() - started,
            port=raw.get("port", port), target=target,
        )

    def __repr__(self):
        return f"<{type(self).__name__} name={self.name!r} types={self.target_types}>"


def findings_from_legacy(legacy_list: Iterable, plugin: str = "", target: str = "") -> list:
    """Map a list of legacy mapper dicts to Findings. Tolerates None."""
    return [Finding.from_legacy(item, plugin=plugin, target=target)
            for item in (legacy_list or [])]
