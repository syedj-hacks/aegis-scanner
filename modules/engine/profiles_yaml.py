"""
modules/engine/profiles_yaml.py
YAML scan-profile loader for the plugin engine.

A YAML profile is a declarative alternative to a hand-wired
modules/profiles/*.py orchestrator: it names which plugins run, how they
are paced/throttled, and the safety limits — with no Python to edit. The
shipped set lives in profiles_yaml/ at the repo root (quick/full/stealth).

Schema
------
    name:        str            display name
    description: str            one line
    plugins:     [str]|"all"    plugin names to run (loader names). "all"
                                or omitted = every discovered plugin.
    exclude:     [str]          names to drop, applied after `plugins`
    target_types:[str]          restrict to these contexts (host/web/
                                service/passive)
    nmap_profile:str            which config.PROFILES entry supplies
                                nmap_args to the port scan (so the engine
                                reuses the tuned, live-verified nmap flags
                                rather than inventing its own)
    nuclei_severity: [str]      nuclei severity filter
    safety:
      max_requests_per_second: float   engine launch-rate cap per target
      max_concurrent_plugins:  int     concurrent plugins per target
    rate_limits:                       passed through to the wrappers'
      nuclei_rate_limit: int           existing per-tool flags (the same
      gobuster_threads:  int           keys config.get_rate_limits uses)
      ...

Every field is optional. A profile that lists only `plugins` runs those at
full speed — the safety block is opt-in, exactly as config.PROFILE_RATE_LIMITS
defaults reproduce today's behaviour.

Resolution: an explicit path is used as-is; a bare name is looked up as
<name>.yaml in profiles_yaml/. PyYAML is a hard dependency of the engine
(requirements.txt), but its absence is reported as a clear error rather
than an ImportError traceback, because the legacy profiles do not need it
and a user may reach the engine before installing it.
"""

from __future__ import annotations

import os

_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "profiles_yaml",
)


class ProfileError(Exception):
    """A YAML profile could not be loaded or is malformed."""


def _require_yaml():
    try:
        import yaml  # noqa: F401
        return yaml
    except ImportError as exc:  # pragma: no cover
        raise ProfileError(
            "PyYAML is required for --engine YAML profiles. "
            "Install it with: pip install pyyaml"
        ) from exc


def _resolve_path(name_or_path: str) -> str:
    if os.path.sep in name_or_path or name_or_path.endswith((".yaml", ".yml")):
        return name_or_path
    return os.path.join(_PROFILE_DIR, f"{name_or_path}.yaml")


def list_yaml_profiles() -> list:
    """(name, description) for every profile in the shipped directory."""
    yaml = _require_yaml()
    out = []
    if not os.path.isdir(_PROFILE_DIR):
        return out
    for fn in sorted(os.listdir(_PROFILE_DIR)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(_PROFILE_DIR, fn)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            out.append((os.path.splitext(fn)[0],
                        str(data.get("description") or "").strip()))
        except Exception as exc:  # noqa: BLE001 — a bad file must not hide the good ones
            out.append((os.path.splitext(fn)[0], f"(unreadable: {exc})"))
    return out


def load_yaml_profile(name_or_path: str) -> dict:
    """
    Load and validate a YAML profile into a normalised dict.

    Raises ProfileError with a human message on a missing file, malformed
    YAML, or a schema violation (an unknown target_type, a non-list
    `plugins`) — the engine surfaces that to the user rather than scanning
    with a silently-empty plugin set, which would look like "found nothing"
    when the truth is "ran nothing".
    """
    yaml = _require_yaml()
    path = _resolve_path(name_or_path)

    if not os.path.isfile(path):
        available = ", ".join(n for n, _ in list_yaml_profiles()) or "(none)"
        raise ProfileError(
            f"scan profile '{name_or_path}' not found at {path}. "
            f"Available: {available}"
        )

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ProfileError(f"profile '{name_or_path}' is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ProfileError(f"profile '{name_or_path}' must be a YAML mapping")

    plugins = data.get("plugins")
    if plugins in (None, "all", "ALL"):
        plugins = None
    elif not isinstance(plugins, list):
        raise ProfileError(
            f"profile '{name_or_path}': `plugins` must be a list or 'all'"
        )

    exclude = data.get("exclude") or []
    if not isinstance(exclude, list):
        raise ProfileError(f"profile '{name_or_path}': `exclude` must be a list")

    target_types = data.get("target_types") or []
    if target_types and not isinstance(target_types, list):
        raise ProfileError(f"profile '{name_or_path}': `target_types` must be a list")

    from plugins.base import TARGET_TYPES
    bad = [t for t in target_types if t not in TARGET_TYPES]
    if bad:
        raise ProfileError(
            f"profile '{name_or_path}': unknown target_type(s) {bad} "
            f"(valid: {', '.join(TARGET_TYPES)})"
        )

    safety = data.get("safety") or {}
    if not isinstance(safety, dict):
        raise ProfileError(f"profile '{name_or_path}': `safety` must be a mapping")

    return {
        "name": data.get("name") or os.path.splitext(os.path.basename(path))[0],
        "description": str(data.get("description") or "").strip(),
        "plugins": plugins,
        "exclude": exclude,
        "target_types": target_types,
        "nmap_profile": data.get("nmap_profile"),
        "nuclei_severity": data.get("nuclei_severity"),
        "gobuster_wordlist": data.get("gobuster_wordlist"),
        "safety": safety,
        "rate_limits": data.get("rate_limits") or {},
        "source_path": path,
    }
