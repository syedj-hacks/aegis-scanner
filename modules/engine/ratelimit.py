"""
modules/engine/ratelimit.py
Per-target request-rate throttle — the Nessus-style safety limit.

WHAT THIS PROTECTS AGAINST
--------------------------
Running independent plugins concurrently (Phase 2's whole point) multiplies
the outbound request rate against one target. A fragile or production-
adjacent host can be knocked over by that, which is exactly the outcome a
professional scanner must not cause on a target it was pointed at. This is
the governor: a token bucket that every plugin acquires from before it
runs, capping the aggregate rate at which the engine starts work against
one target and how much of it runs at once.

WHAT IT HONESTLY IS AND IS NOT
------------------------------
The unit it meters is a plugin launch, not an individual HTTP request — the
plugins shell out to nikto/nuclei/gobuster, whose own request rate is set
by the per-tool flags in config.PROFILE_RATE_LIMITS (nuclei -rate-limit,
gobuster -t, ...). So this is a coarse governor on scan aggressiveness that
composes with those fine-grained flags; it is not, and does not claim to
be, a precise per-HTTP-request limiter. That is the honest description, and
it is the layer that actually prevents "twelve plugins hammer one host at
once" — the failure concurrency introduces.

Two independent limits, both per target:
  requests_per_second  minimum spacing between plugin launches (token
                       bucket). 0/None disables spacing.
  max_concurrent       how many plugins may run against ONE target at once
                       (semaphore). Composes with the engine's own worker
                       pool, which bounds concurrency across ALL targets.

A limiter is created per target, so one slow/throttled host never starves
another. Thread-safe: the engine acquires from several worker threads.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Token-bucket pacing + a concurrency semaphore, both per target."""

    def __init__(self, requests_per_second: float = 0.0,
                 max_concurrent: int = 0, burst: int = None):
        self.rps = float(requests_per_second or 0.0)
        self.max_concurrent = int(max_concurrent or 0)

        # Token bucket. `burst` is how many launches may go out back-to-back
        # before pacing kicks in; defaults to one second's worth (min 1) so
        # a short scan is not needlessly slowed while a long one is capped.
        if burst is None:
            burst = max(1, int(round(self.rps))) if self.rps > 0 else 1
        self._capacity = float(max(burst, 1))
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

        self._sem = threading.Semaphore(self.max_concurrent) if self.max_concurrent > 0 else None

        # Observability: how long, in total, plugins spent parked on this
        # limiter. The engine reports it so a throttle's cost is visible
        # rather than mysterious "why was this slow".
        self.total_wait = 0.0
        self.acquisitions = 0

    def _take_token(self):
        """Block until a token is available; refill at `rps` tokens/sec."""
        if self.rps <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self.rps)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # How long until the next whole token.
                deficit = 1.0 - self._tokens
                sleep_for = deficit / self.rps
            time.sleep(min(sleep_for, 1.0))

    def acquire(self):
        """
        Block until this plugin may launch. Returns a wait duration (s).

        Order matters: take the concurrency slot FIRST, then pace. Pacing
        before the semaphore would let N threads all consume tokens and then
        pile up on the semaphore, defeating the point of metering launches.
        """
        started = time.monotonic()
        if self._sem is not None:
            self._sem.acquire()
        self._take_token()
        waited = time.monotonic() - started
        with self._lock:
            self.total_wait += waited
            self.acquisitions += 1
        return waited

    def release(self):
        """Return the concurrency slot. Always paired with acquire()."""
        if self._sem is not None:
            self._sem.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False

    @classmethod
    def from_profile(cls, safety: dict) -> "RateLimiter":
        """
        Build a limiter from a YAML profile's `safety:` block.

        Absent keys mean "no limit", which reproduces pre-throttle
        behaviour exactly — the engine runs a profile with no safety block
        at full speed, same as the legacy orchestrators do.
        """
        safety = safety or {}
        return cls(
            requests_per_second=safety.get("max_requests_per_second", 0),
            max_concurrent=safety.get("max_concurrent_plugins", 0),
        )
