"""
plugins/discovery.py
Host-level discovery plugins: DNS, port scan, service/version detection,
banner grab.

These four are the ones that PRODUCE the context every other plugin
consumes — the open-port list, the per-port service and version. Their
`order` values put them at the front of the run and, unlike everything
else, the engine runs them sequentially rather than in parallel: there is
nothing for a web plugin to run against until the port scan has said what
is open (see modules/engine/scanner.py).
"""

from plugins.base import ScannerPlugin, Finding, findings_from_legacy, CONFIRMED, POTENTIAL
from plugins._mappers import (
    findings_from_banners, findings_from_cves, score_and_remediate,
)

from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.scanning.service_detect import detect_services
from modules.scanning.banner import grab_banners
from modules.enrichment.cve_lookup import lookup_cves


class DnsPlugin(ScannerPlugin):
    name = "dns"
    description = "Resolve the target's A/AAAA/MX/NS/TXT records (nslookup)."
    target_types = ("host",)
    severity_baseline = "INFO"
    order = 0

    def run(self, target, config):
        return resolve_dns(target)

    def parse_output(self, raw):
        # DNS resolution is context, not a finding. Emitting "the host has
        # an A record" as a finding would pad every report with a row
        # nobody acts on; the resolved addresses are carried in `raw` and
        # the engine puts them in the scan context instead.
        return []


class PortScanPlugin(ScannerPlugin):
    name = "port_scan"
    description = "nmap port sweep, scoped by the active profile's nmap_args."
    target_types = ("host",)
    severity_baseline = "INFO"
    order = 1

    requires = ("nmap",)

    def run(self, target, config):
        return scan_ports(target, profile=config.get("nmap_profile") or config.get("profile"))

    def parse_output(self, raw):
        # Same reasoning as DNS: an open port is inventory. It becomes a
        # finding only once service detection attaches a product/version to
        # it (ServiceDetectPlugin below), which is the row the CVE
        # enrichment then works from.
        return []


class ServiceDetectPlugin(ScannerPlugin):
    name = "service_detect"
    description = "nmap -sV service detection + NVD CVE correlation on open ports."
    target_types = ("host",)
    severity_baseline = "INFO"
    order = 2

    requires = ("nmap",)

    def applicable(self, config):
        return bool(config.get("open_ports"))

    def run(self, target, config):
        # Service/version detection, then an NVD CVE lookup per detected
        # product — the same two-step the legacy deepscan does
        # (_enrich_services), so the engine surfaces version-based CVEs, not
        # just the service inventory. The NVD lookups are cached (Phase 3),
        # so a host running the same software on several ports pays for one
        # query, and a re-scan pays for none.
        raw = detect_services(target, [p["port"] for p in (config.get("open_ports") or [])])
        services = raw.get("services") or []
        cve_matches = []
        for svc in services:
            product = svc.get("product")
            if not product:
                continue
            cve_result = lookup_cves(product, svc.get("version"), target=target)
            for cve in cve_result.get("cves") or []:
                cve_matches.append((svc, cve))
        raw["_cve_matches"] = cve_matches
        return raw

    def parse_output(self, raw):
        findings = []

        # 1) The service/version inventory rows. type="service_version" is
        # stamped at the source so a report never infers a row's kind from
        # which columns are populated.
        service_rows = [dict(svc, type="service_version")
                        for svc in (raw.get("services") or [])]
        for finding in findings_from_legacy(service_rows, plugin=self.name):
            # A version nmap -sV read off the wire IS an observation.
            finding.confidence = CONFIRMED
            finding.severity = "INFO"
            if not finding.evidence and finding.version:
                finding.evidence = (
                    f"nmap -sV reported {finding.product or finding.service or 'service'} "
                    f"{finding.version} on port {finding.port}")
            findings.append(finding)

        # 2) CVE findings from the NVD correlation. Version-matched, so they
        # are Potential (the false-positive distinction Phase 3 turns on):
        # the version was observed, but exploitability was not exercised.
        seen = set()
        for svc, cve in raw.get("_cve_matches") or []:
            legacy = findings_from_cves([cve], svc.get("port"),
                                        svc.get("service"), seen=seen)
            for finding in findings_from_legacy(score_and_remediate(legacy),
                                                plugin=self.name):
                finding.confidence = POTENTIAL
                finding.version = finding.version or svc.get("version")
                findings.append(finding)
        return findings


class BannerPlugin(ScannerPlugin):
    name = "banner_grab"
    description = "Read service banners directly from open TCP ports."
    target_types = ("host",)
    severity_baseline = "INFO"
    order = 3

    def applicable(self, config):
        return bool(config.get("open_ports"))

    def run(self, target, config):
        ports = [p["port"] for p in (config.get("open_ports") or [])]
        return grab_banners(target, ports)

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_banners(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings
