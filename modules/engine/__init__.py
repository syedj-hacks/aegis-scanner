"""
modules/engine/
The plugin-driven scan engine (Phase 2).

An additive second way to drive Aegis's detection code, alongside the
legacy modules/profiles/ orchestrators. Where a profile orchestrator hard-
wires a fixed sequence of tool calls, the engine takes a declarative YAML
profile (which plugins, how throttled, what safety limits) and runs the
selected plugins/base.ScannerPlugin instances concurrently, with a per-
target request-rate cap and full per-plugin result isolation.

The legacy profiles are untouched and remain the default; the engine is
opt-in via aegis.py --engine.
"""
from modules.engine.ratelimit import RateLimiter
from modules.engine.profiles_yaml import load_yaml_profile, list_yaml_profiles
from modules.engine.scanner import ScanEngine, run_engine_scan

__all__ = [
    "RateLimiter", "load_yaml_profile", "list_yaml_profiles",
    "ScanEngine", "run_engine_scan",
]
