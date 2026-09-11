"""
modules/enrichment/enrich_cache.py
A small, dependency-free, thread-safe on-disk cache for enrichment API
responses (NVD, EPSS).

WHY A CACHE IS NOT OPTIONAL HERE
--------------------------------
The Phase 3 enrichment hits two rate-limited public APIs (NVD: 5 req/30s
anonymous, 50 with a key; FIRST.org EPSS: courteous-use). A deepscan of a
host with a dozen services asks about the same handful of CVEs repeatedly,
and re-scanning the same host tomorrow asks again. Without a cache the
scanner is both slow and a bad API citizen, and on NVD's anonymous limit it
would spend most of a scan asleep in the throttle. The spec calls this out
explicitly: "cache responses locally to avoid rate limits".

DESIGN
------
- One JSON file per cache namespace under database/enrich_cache/, keyed by a
  hash of the query. JSON, not a binary store, so a cache entry is
  inspectable and the cache has no schema to migrate.
- Per-entry TTL. CVSS data for a published CVE is effectively immutable, so
  NVD entries live a long time; EPSS scores are re-published daily, so EPSS
  entries expire in a day. A stale entry is ignored, not deleted, so a
  concurrent reader never trips over a half-written file.
- Thread-safe: --targets and the engine both enrich from several threads.
  A process-wide lock guards the read-modify-write of each namespace file.
  This is coarse but correct; enrichment is network-bound, so lock
  contention is irrelevant next to the request latency it saves.
- Never raises. A cache that cannot be read or written degrades to "no
  cache" — the enrichment still works, just without the speed-up. A caching
  layer that could crash a scan would be worse than no cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

_CACHE_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "database", "enrich_cache",
)

# One lock per namespace file. A dict of locks, itself guarded, so two
# namespaces never serialise against each other.
_locks_guard = threading.Lock()
_locks: dict = {}

# In-process memo of loaded namespace dicts, so repeated gets within one run
# don't re-read the file every time. Invalidated by _write.
_memory: dict = {}


def _lock_for(namespace: str) -> threading.Lock:
    with _locks_guard:
        lock = _locks.get(namespace)
        if lock is None:
            lock = threading.Lock()
            _locks[namespace] = lock
        return lock


def _path(namespace: str) -> str:
    return os.path.join(_CACHE_ROOT, f"{namespace}.json")


def _key(query: str) -> str:
    return hashlib.sha256(str(query).encode("utf-8", "replace")).hexdigest()[:20]


def _load(namespace: str) -> dict:
    if namespace in _memory:
        return _memory[namespace]
    path = _path(namespace)
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
    except (OSError, ValueError):
        data = {}
    _memory[namespace] = data
    return data


def get(namespace: str, query: str, ttl: float) -> dict:
    """
    Return the cached value for `query`, or None if absent/expired.

    `ttl` is seconds; an entry older than ttl is treated as a miss. Reading
    is done under the namespace lock so a value being rewritten is never
    seen half-updated.
    """
    with _lock_for(namespace):
        data = _load(namespace)
        entry = data.get(_key(query))
        if not entry:
            return None
        if ttl and (time.time() - entry.get("ts", 0)) > ttl:
            return None
        return entry.get("value")


def put(namespace: str, query: str, value) -> None:
    """
    Store `value` for `query`. Best-effort: a write failure is swallowed so
    a read-only or full disk cannot break a scan.
    """
    with _lock_for(namespace):
        data = _load(namespace)
        data[_key(query)] = {"ts": time.time(), "query": str(query), "value": value}
        try:
            os.makedirs(_CACHE_ROOT, exist_ok=True)
            tmp = _path(namespace) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            # Atomic replace so a concurrent reader sees either the old file
            # or the new one, never a truncated write.
            os.replace(tmp, _path(namespace))
            _memory[namespace] = data
        except OSError:
            pass


def clear(namespace: str = None) -> None:
    """Drop a namespace (or all). Used by the tests and a --refresh flag."""
    with _locks_guard:
        if namespace is None:
            _memory.clear()
            try:
                for fn in os.listdir(_CACHE_ROOT):
                    if fn.endswith(".json"):
                        os.remove(os.path.join(_CACHE_ROOT, fn))
            except OSError:
                pass
        else:
            _memory.pop(namespace, None)
            try:
                os.remove(_path(namespace))
            except OSError:
                pass
