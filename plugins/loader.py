"""
plugins/loader.py
Auto-discovery for ScannerPlugin subclasses.

Walks this package's directory, imports every module that isn't private
(`_`-prefixed) or infrastructure (base/loader), and collects every
concrete ScannerPlugin subclass it finds. Dropping a new .py file into
plugins/ is the entire installation procedure — nothing registers, and no
core file lists the plugins.

Failure policy
--------------
A plugin module that fails to import does NOT take the loader down: it is
recorded in `load_errors` and the rest still load. That is the same
principle as the per-plugin isolation in base.execute() — one broken check
must not cost you the scan. But it is recorded and surfaced, not
swallowed: an unimportable plugin is invisible otherwise, and this
codebase has been bitten specifically by tools that failed silently while
still producing output (see the skip-flag convention in
modules/profiles/_common.py).
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import threading

from plugins.base import ScannerPlugin, TARGET_TYPES

# Module basenames in this package that are not plugins.
_INFRASTRUCTURE = {"base", "loader", "signature"}

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

_cache = None
_cache_lock = threading.Lock()

# Populated by discover(); [(module_name, error_string), ...]
load_errors: list = []


def _is_plugin_class(obj) -> bool:
    return (
        inspect.isclass(obj)
        and issubclass(obj, ScannerPlugin)
        and obj is not ScannerPlugin
        and not inspect.isabstract(obj)
    )


def _validate(plugin) -> str:
    """
    Return an error string if this plugin's metadata is unusable, else "".

    Checked at load time rather than at run time on purpose: a plugin with
    no `name` would be recorded in scan_tools_run as an empty string and a
    profile could never select it, which is a confusing failure to debug
    three hours into a scan.
    """
    if not getattr(plugin, "name", ""):
        return "plugin declares no name"
    bad_types = [t for t in (plugin.target_types or ()) if t not in TARGET_TYPES]
    if bad_types:
        return (f"unknown target_type(s) {bad_types} "
                f"(valid: {', '.join(TARGET_TYPES)})")
    if not plugin.target_types:
        return "plugin declares no target_types"
    return ""


def discover(force: bool = False) -> dict:
    """
    Import every plugin module and return {name: plugin_instance}.

    Cached after the first call — discovery imports twenty-odd modules,
    several of which pull in requests/scapy, and a scan asks for the
    registry repeatedly. `force=True` re-scans (used by the tests, and by
    anything that writes a signature file at run time).
    """
    global _cache
    if _cache is not None and not force:
        return _cache

    with _cache_lock:
        if _cache is not None and not force:
            return _cache

        registry: dict = {}
        errors: list = []

        for entry in sorted(pkgutil.iter_modules([PLUGIN_DIR]), key=lambda m: m.name):
            modname = entry.name
            if modname.startswith("_") or modname in _INFRASTRUCTURE:
                continue

            try:
                module = importlib.import_module(f"plugins.{modname}")
            except Exception as exc:  # noqa: BLE001 — one bad plugin, not all
                errors.append((modname, f"{type(exc).__name__}: {exc}"))
                continue

            for _, obj in inspect.getmembers(module, _is_plugin_class):
                # Only classes DEFINED in this module, so a plugin that
                # imports another plugin's class for subclassing does not
                # register the parent a second time under its own module.
                if obj.__module__ != module.__name__:
                    continue
                try:
                    instance = obj()
                except Exception as exc:  # noqa: BLE001
                    errors.append((f"{modname}.{obj.__name__}",
                                   f"instantiation failed: {type(exc).__name__}: {exc}"))
                    continue

                problem = _validate(instance)
                if problem:
                    errors.append((f"{modname}.{obj.__name__}", problem))
                    continue

                if instance.name in registry:
                    errors.append((
                        f"{modname}.{obj.__name__}",
                        f"duplicate plugin name {instance.name!r} — "
                        f"already provided by "
                        f"{type(registry[instance.name]).__module__}",
                    ))
                    continue

                registry[instance.name] = instance

        # Signature-backed plugins (Phase 3): declarative YAML/JSON checks
        # from signatures/, each becoming a SignaturePlugin. Loaded through
        # the same failure policy — a malformed signature is recorded, not
        # fatal — and namespaced "sig:<id>" so a signature can never collide
        # with a Python plugin's name.
        try:
            from plugins.signature import load_signatures
            sig_plugins, sig_errors = load_signatures()
            for instance in sig_plugins:
                if instance.name in registry:
                    errors.append((instance.name, "duplicate signature/plugin name"))
                    continue
                registry[instance.name] = instance
            errors.extend(sig_errors)
        except Exception as exc:  # noqa: BLE001 — signatures are additive
            errors.append(("signatures", f"signature loading failed: {exc}"))

        load_errors[:] = errors
        _cache = registry
        return _cache


def get(name: str):
    """One plugin by name, or None."""
    return discover().get(name)


def all_plugins() -> list:
    """Every plugin, in run order then name."""
    return sorted(discover().values(), key=lambda p: (p.order, p.name))


def select(names=None, target_types=None, exclude=None) -> list:
    """
    The plugins matching a selection, in run order.

    names         explicit allow-list (a YAML profile's `plugins:`). None
                  means "everything".
    target_types  restrict to plugins handling any of these contexts.
    exclude       names to drop (a profile's `exclude:`), applied last so
                  it always wins over an allow-list.

    Unknown names in `names` are IGNORED here rather than raising: the
    engine validates a profile's plugin list separately and reports the
    unknown names as a group, which is a far more useful error than
    exploding on the first one.
    """
    registry = discover()
    exclude = set(exclude or ())

    if names is None:
        chosen = list(registry.values())
    else:
        chosen = [registry[n] for n in names if n in registry]

    if target_types:
        wanted = set(target_types)
        chosen = [p for p in chosen if wanted & set(p.target_types)]

    chosen = [p for p in chosen if p.name not in exclude]
    return sorted(chosen, key=lambda p: (p.order, p.name))


def unknown_names(names) -> list:
    """The entries of `names` that match no loaded plugin."""
    registry = discover()
    return [n for n in (names or ()) if n not in registry]


def describe() -> list:
    """
    [(name, target_types, severity_baseline, description, available)] for
    every plugin — what `--list-plugins` prints.
    """
    rows = []
    for plugin in all_plugins():
        ok, reason = plugin.available()
        rows.append((
            plugin.name,
            "/".join(plugin.target_types),
            plugin.severity_baseline,
            plugin.description,
            "yes" if ok else reason,
        ))
    return rows
