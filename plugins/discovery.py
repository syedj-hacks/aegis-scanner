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

from plugins.base import ScannerPlugin, Finding, findings_from_legacy, CONFIRMED
from plugins._mappers import findings_from_banners, score_and_remediate

from modules.recon.dns import resolve_dns
from modules.scanning.port_scanner import scan_ports
from modules.scanning.service_detect import detect_services
from modules.scanning.banner import grab_banners


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
    description = "nmap -sV -sC service and version detection on open ports."
    target_types = ("host",)
    severity_baseline = "INFO"
    order = 2

    requires = ("nmap",)

    def applicable(self, config):
        return bool(config.get("open_ports"))

    def run(self, target, config):
        ports = [p["port"] for p in (config.get("open_ports") or [])]
        return detect_services(target, ports)

    def parse_output(self, raw):
        # type="service_version" is stamped at the source here for the same
        # reason quickscan/stealth stamp it: a report must never have to
        # infer a row's kind from which columns happen to be populated.
        legacy = [dict(svc, type="service_version")
                  for svc in (raw.get("services") or [])]
        findings = findings_from_legacy(legacy, plugin=self.name)
        for finding in findings:
            # A version nmap -sV actually read off the wire IS an
            # observation, not a guess — distinct from a CVE inferred from
            # that version, which stays Potential.
            finding.confidence = CONFIRMED
            finding.severity = "INFO"
            if not finding.evidence and finding.version:
                finding.evidence = (
                    f"nmap -sV reported {finding.product or finding.service or 'service'} "
                    f"{finding.version} on port {finding.port}"
                )
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
