#!/usr/bin/env python3
"""
tests/t_target.py
Checks aegis.normalize_target() / is_valid_target() — the front door.

What this file is really guarding
---------------------------------
Normalising the target is the one place where being helpful can silently
scan the wrong thing. Stripping a scheme is safe; guessing at a range is
not. So the assertions split three ways:

  1. URL-shaped input reduces to exactly the host underneath it
     (this is the fix: a pasted "Https://www.target" used to be rejected)
  2. input the scanner has never supported — CIDR ranges, malformed
     authorities, junk — stays untouched so is_valid_target() still
     rejects it with the usual error. Normalising must never turn bad
     input into good.
  3. bare hosts and bare IPs, especially IPv6, come out byte-for-byte
     unchanged. IPv6 is the sharp edge here: it is full of colons, so a
     naive authority parse reads "2001:db8::1" as host "2001" plus a port
     and scans an entirely different machine without saying so.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis import normalize_target, is_valid_target  # noqa: E402

PASS = 0
FAIL = 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


def eq(label, raw, expected):
    got = normalize_target(raw)
    check(label, got == expected, f"{raw!r} -> {got!r}, expected {expected!r}")


def accepted(label, raw, expected):
    """Normalises to `expected` AND survives validation — the whole path."""
    got = normalize_target(raw)
    check(label, got == expected and is_valid_target(got),
          f"{raw!r} -> {got!r} (valid={is_valid_target(got)}), expected {expected!r}")


def rejected(label, raw):
    got = normalize_target(raw)
    check(label, not is_valid_target(got), f"{raw!r} -> {got!r} was accepted")


def main():
    print("=== A. pasted URLs reduce to their host ===")
    accepted("scheme is stripped", "https://www.example.com", "www.example.com")
    accepted("...case-insensitively", "Https://www.example.com", "www.example.com")
    accepted("...including HTTP://", "HTTP://example.com", "example.com")
    accepted("trailing slash goes", "https://example.com/", "example.com")
    accepted("path goes", "http://example.com/login", "example.com")
    accepted("query and fragment go",
             "http://example.com/login?next=/x#top", "example.com")
    accepted("explicit port goes", "https://example.com:8443/a", "example.com")
    accepted("credentials go", "http://user:pw@10.0.0.5:8080/admin", "10.0.0.5")
    accepted("a non-web scheme is still just a host", "ftp://example.com/pub",
             "example.com")
    accepted("surrounding quotes go", '"https://example.com"', "example.com")
    accepted("surrounding whitespace goes", "  https://example.com  ",
             "example.com")

    print("\n=== B. bare input is left alone ===")
    accepted("a plain hostname is untouched", "example.com", "example.com")
    accepted("a single label is untouched", "localhost", "localhost")
    accepted("an IPv4 address is untouched", "10.0.0.5", "10.0.0.5")
    accepted("host:port loses only the port", "example.com:8443", "example.com")
    accepted("a trailing root dot goes", "example.com.", "example.com")

    print("\n=== C. IPv6 survives intact ===")
    accepted("a bare IPv6 literal is NOT split at its colons",
             "2001:db8::1", "2001:db8::1")
    accepted("loopback likewise", "::1", "::1")
    accepted("bare brackets are unwrapped", "[2001:db8::1]", "2001:db8::1")
    accepted("bracketed host:port", "[::1]:8080", "::1")
    accepted("a full IPv6 URL", "https://[2001:db8::1]:8443/x", "2001:db8::1")

    print("\n=== D. bad input stays bad ===")
    rejected("an IPv4 CIDR range is not silently collapsed", "10.0.0.0/24")
    rejected("...nor an IPv6 one", "2001:db8::/32")
    rejected("...nor one with a host part", "2001:db8::1/64")
    eq("a CIDR is handed back verbatim for the error message",
       "10.0.0.0/24", "10.0.0.0/24")
    rejected("an unclosed IPv6 bracket", "https://[::1")
    rejected("a double dot", "invalid..hostname")
    rejected("a scheme with no host", "https://")
    rejected("empty input", "")
    rejected("whitespace only", "   ")
    rejected("None", None)
    eq("None normalises to empty rather than raising", None, "")

    print("\n=== E. normalisation is idempotent ===")
    for raw in ("https://www.example.com/a?b#c", "2001:db8::1", "example.com:80",
                "10.0.0.0/24", "invalid..hostname"):
        once = normalize_target(raw)
        check(f"{raw!r} is stable under a second pass",
              normalize_target(once) == once,
              f"{once!r} -> {normalize_target(once)!r}")

    print("\n" + "=" * 60)
    print(f"PASS {PASS}   FAIL {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
