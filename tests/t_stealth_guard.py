#!/usr/bin/env python3
"""
tests/t_stealth_guard.py
Regression guard for the stealthscan profile.

Why this file exists
--------------------
stealthscan was deliberately redesigned (smoke_test2 Issue #5) from a full
65535-port '-p-' sweep onto a small fixed port list at -T2 timing. That was
not a tuning decision that can be revisited by turning a knob: a quiet-timing
full-range sweep was live-measured at ~0.29 ports/sec, which extrapolates to
60+ hours for one scan. It is an architectural dead end, and the fix was to
stop sweeping all 65535 ports at all.

Every later performance change to this codebase — chunk parallelism, thread
pools, per-profile rate limits — is a change that could plausibly be applied
to stealthscan "for consistency" by someone who did not read that history.
This file makes that a test failure rather than a 60-hour scan.

The guard asserts the four properties that define the redesign:
  1. the port list is a fixed, explicit, small '-p' list (not '-p-')
  2. the timing template is -T2, not -T3/-T4
  3. the profile stays sequential — no concurrency knob applies to it
  4. it wires in no sweeping tool — whatweb is the single deliberate
     exception, and nuclei is deliberately excluded (see section E)

Run standalone (python3 tests/t_stealth_guard.py) or via the phase gate.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.utils.config import PROFILES  # noqa: E402

PASS = 0
FAIL = 0

# The exact port list stealthscan was redesigned onto, measured live at 96.0s
# against scanme.nmap.org and 22.5s against pentest-ground.com. Duplicated
# here on purpose: a test that reads the value it is checking from the same
# place the code does cannot detect a change to it.
_EXPECTED_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
]
_EXPECTED_PORT_COUNT = 20


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


def _port_list(nmap_args) -> list:
    """The integer port list from a profile's '-p <list>' argument pair."""
    args = list(nmap_args or [])
    if "-p" not in args:
        return []
    raw = args[args.index("-p") + 1]
    ports = []
    for piece in raw.split(","):
        piece = piece.strip()
        if piece.isdigit():
            ports.append(int(piece))
    return ports


def main() -> int:
    print("=== stealthscan regression guard ===\n")

    cfg = PROFILES.get("stealthscan") or {}
    nmap_args = list(cfg.get("nmap_args") or [])

    print("--- A. port list is fixed and small (never a full-range sweep) ---")
    check(
        "stealthscan does NOT use a full-range '-p-' sweep",
        "-p-" not in nmap_args,
        "a quiet-timing full 65535-port sweep was measured at ~0.29 ports/sec "
        "(60+ hours extrapolated). This profile must never sweep all ports.",
    )
    check(
        "stealthscan does NOT use an explicit 1-65535 range either",
        not any(str(a).replace(" ", "") == "1-65535" for a in nmap_args),
    )
    check("stealthscan passes an explicit '-p' port list", "-p" in nmap_args)

    ports = _port_list(nmap_args)
    check(
        f"stealthscan's port list is exactly {_EXPECTED_PORT_COUNT} ports "
        f"(found {len(ports)})",
        len(ports) == _EXPECTED_PORT_COUNT,
        f"expected {_EXPECTED_PORT_COUNT}, got {len(ports)}: {ports}",
    )
    check(
        "stealthscan's port list is unchanged, port for port",
        ports == _EXPECTED_PORTS,
        f"expected {_EXPECTED_PORTS}\n          got      {ports}",
    )

    print("\n--- B. timing template is -T2 ('Polite'), not faster ---")
    check("stealthscan uses -T2", "-T2" in nmap_args)
    for faster in ("-T3", "-T4", "-T5"):
        check(
            f"stealthscan does NOT use {faster}",
            faster not in nmap_args,
            f"{faster} would defeat this profile's entire minimal-footprint intent",
        )
    check(
        "stealthscan does NOT use -T1 (serialises with a 15s inter-probe wait)",
        "-T1" not in nmap_args,
    )

    print("\n--- C. stays quiet: -Pn and host randomisation retained ---")
    check("stealthscan retains -Pn", "-Pn" in nmap_args)
    check("stealthscan retains --randomize-hosts", "--randomize-hosts" in nmap_args)

    print("\n--- D. stays sequential: no concurrency knob reaches it ---")
    # The parallelism added for webaudit/deepscan is opt-in per profile. If a
    # future change ever adds stealthscan to either map, this fails loudly.
    try:
        from modules.utils.config import PARALLEL_WEB_TOOL_PROFILES
    except ImportError:
        PARALLEL_WEB_TOOL_PROFILES = set()
    check(
        "stealthscan is not in PARALLEL_WEB_TOOL_PROFILES",
        "stealthscan" not in set(PARALLEL_WEB_TOOL_PROFILES or ()),
        "stealthscan must stay sequential — concurrent probing is the opposite "
        "of a minimal-footprint scan",
    )

    # The chunked-sweep parallelism only ever applies to a '-p-' scan, which
    # A. already proved stealthscan does not perform. Asserted explicitly so
    # the coupling is stated, not merely implied.
    check(
        "the chunk-parallel sweep path cannot apply to stealthscan (no '-p-')",
        "-p-" not in nmap_args,
    )
    print("\n--- E. runs no sweeping tool (whatweb is the one exception) ---")
    # This check used to assert tools == ["nslookup", "nmap"] exactly. That
    # was the right guard against the wrong thing: what makes a profile loud
    # is which tools it RUNS, not which its config lists, and the two are
    # deliberately different here — nuclei is listed so
    # warn_unavailable_tools() can print an explicit "not run by this
    # profile, by design" note instead of the tool being invisibly absent.
    #
    # whatweb was added deliberately (a handful of requests against one
    # already-scanned port, in exchange for knowing what is listening).
    # nuclei was deliberately NOT: it fires thousands of templated requests
    # per port and would make this the second-loudest profile in the
    # framework while its nmap half was still pacing at -T2.
    #
    # So the guard now checks the property that actually protects the
    # profile — the wired set contains nothing that sweeps — which is
    # strictly stronger than the old equality, and would still catch someone
    # adding nuclei "for consistency".
    from modules.profiles.stealth import _WIRED_TOOLS  # noqa: E402

    _SWEEPING_TOOLS = {
        "nuclei", "nikto", "gobuster", "dirb", "feroxbuster", "dirsearch",
        "zaproxy", "sqlmap", "hydra", "wpscan", "enum4linux", "amass",
        "masscan", "testssl",
    }
    sweeping = sorted(_WIRED_TOOLS & _SWEEPING_TOOLS)
    check(
        "stealthscan wires in NO sweeping/brute-forcing tool",
        not sweeping,
        f"these would destroy the profile's minimal-footprint intent: {sweeping}",
    )
    check(
        "stealthscan does not run nuclei (listed by design, never wired)",
        "nuclei" not in _WIRED_TOOLS,
        "nuclei issues thousands of requests per port — running it here would "
        "make the quietest profile the second-loudest one",
    )
    check(
        "whatweb is the only web tool stealthscan wires in",
        _WIRED_TOOLS == {"nslookup", "nmap", "whatweb"},
        f"got {sorted(_WIRED_TOOLS)}",
    )
    check(
        "every tool stealthscan wires in is also declared in its config list",
        _WIRED_TOOLS <= set(cfg.get("tools") or []),
        f"wired {sorted(_WIRED_TOOLS)} vs configured {cfg.get('tools')}",
    )

    print("\n" + "=" * 60)
    print(f"PASS {PASS}   FAIL {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
