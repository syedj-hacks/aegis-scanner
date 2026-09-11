"""
Aegis Scanner plugin package.

Public surface: the ScannerPlugin contract and the Finding/PluginResult
dataclasses from plugins.base, and the loader's discover()/select() from
plugins.loader. Everything else (the concrete plugin modules, the mapper
bridge) is discovered, not imported by name.
"""
from plugins.base import (
    ScannerPlugin, Finding, PluginResult,
    CONFIRMED, POTENTIAL, SEVERITY_ORDER, TARGET_TYPES,
    normalise_severity, severity_rank, findings_from_legacy,
)
from plugins.loader import (
    discover, get, all_plugins, select, describe, unknown_names, load_errors,
)

__all__ = [
    "ScannerPlugin", "Finding", "PluginResult",
    "CONFIRMED", "POTENTIAL", "SEVERITY_ORDER", "TARGET_TYPES",
    "normalise_severity", "severity_rank", "findings_from_legacy",
    "discover", "get", "all_plugins", "select", "describe",
    "unknown_names", "load_errors",
]
