"""
modules/recon/cloud_enum_wrap.py
Public cloud storage discovery via cloud_enum.

cloud_enum takes a keyword (a company or product name) and brute-forces
plausible bucket/container/blob names across AWS S3, Azure and Google Cloud,
reporting which ones exist and which of those are publicly readable. It is
the one tool in this framework that takes a company NAME rather than a host,
which is why the recon profile can accept "Acme Corp" as a target at all.

What "found" means, and why the two are not the same
----------------------------------------------------
cloud_enum reports two quite different things and it would be easy — and
wrong — to render them identically:

  - a bucket that EXISTS but is protected. Interesting for an inventory,
    not a vulnerability. Someone owns it; that is all this proves.
  - a bucket that is OPEN / publicly listable. That is the finding. It
    means anyone on the internet can enumerate its contents.

_parse_cloud_enum() below classifies each hit into one of those, and only
the open ones become MEDIUM-severity `recon_bucket` findings. Everything
else is recorded as inventory. Reporting a protected bucket as an exposure
would inflate every recon report against any company that uses cloud
storage, which is all of them.

A keyword match is not proof of ownership
-----------------------------------------
cloud_enum guesses names. "acme-backups" existing does not prove it belongs
to Acme — the namespace is global and first-come. Findings from here say a
bucket matching the keyword is open, and the report says exactly that; the
remediation text asks the reader to confirm ownership before acting.
"""

import re

from modules.utils.error_handler import run_tool
from modules.utils.logger import get_logger, log_finding
from modules.utils.display import print_info, print_success, print_warning

TOOL_NAME = "cloud_enum"

# cloud_enum prefixes its result lines with a marker and names the provider
# in the URL. These are the substrings that identify a line as a hit at all.
_PROVIDER_PATTERNS = (
    ("aws",   re.compile(r"s3\.amazonaws\.com|\.s3[.-]", re.IGNORECASE)),
    ("azure", re.compile(r"blob\.core\.windows\.net|\.azurewebsites\.net"
                         r"|cloudapp\.azure\.com", re.IGNORECASE)),
    ("gcp",   re.compile(r"storage\.googleapis\.com|appspot\.com", re.IGNORECASE)),
)

# The distinction that matters — see the module docstring. cloud_enum says
# "OPEN" on a publicly listable container and "Protected"/"AUTH" on one that
# exists but refuses anonymous access.
_OPEN_MARKERS = re.compile(r"\bOPEN\b|public|listable|anonymous", re.IGNORECASE)
_PROTECTED_MARKERS = re.compile(r"protected|\bAUTH\b|forbidden|403", re.IGNORECASE)

_URL_PATTERN = re.compile(r"https?://\S+")


def _provider_for(line: str):
    for name, pattern in _PROVIDER_PATTERNS:
        if pattern.search(line):
            return name
    return None


def _parse_cloud_enum(stdout: str) -> tuple:
    """
    Split cloud_enum's stdout into (open_buckets, protected_buckets).

    Each entry is {url, provider, access, line}. Lines that name no known
    provider URL are ignored: cloud_enum prints progress and banner text to
    the same stream, and a substring test for "s3" or "storage" alone (the
    obvious implementation) matches its own status messages — which would
    turn "[*] Checking for S3 buckets" into a reported finding on every
    single run, against every target, forever.
    """
    open_buckets, protected_buckets = [], []

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        provider = _provider_for(line)
        if not provider:
            continue

        url_match = _URL_PATTERN.search(line)
        if not url_match:
            continue

        entry = {
            "url": url_match.group(0).rstrip(".,)"),
            "provider": provider,
            "line": line,
        }

        if _PROTECTED_MARKERS.search(line):
            entry["access"] = "protected"
            protected_buckets.append(entry)
        elif _OPEN_MARKERS.search(line):
            entry["access"] = "open"
            open_buckets.append(entry)
        else:
            # A hit with no access verdict on the line. Recorded as
            # inventory rather than guessed either way — an unlabelled hit
            # is not evidence of exposure.
            entry["access"] = "unknown"
            protected_buckets.append(entry)

    return open_buckets, protected_buckets


def find_cloud_buckets(keyword: str, target: str = None) -> dict:
    """
    Run cloud_enum against `keyword` and return classified bucket results.

    Returns
    -------
    dict:
        tool       : "cloud_enum"
        target     : str
        keyword    : str
        buckets    : list[dict]  the OPEN ones — these become findings
        inventory  : list[dict]  exists-but-protected, plus unlabelled hits
        count      : int         len(buckets)
        skipped    : bool
        error      : str | None

    Never raises. run_tool() reports a missing binary as
    "binary not found on PATH: cloud_enum", which is the honest result on a
    box where it was never installed — install.sh installs it, but this
    framework has to keep working on one where that step was skipped.
    """
    target = target or keyword
    logger = get_logger(target)

    result = {
        "tool": TOOL_NAME,
        "target": target,
        "keyword": keyword,
        "buckets": [],
        "inventory": [],
        "count": 0,
        "skipped": False,
        "error": None,
    }

    if not keyword:
        result["error"] = "no keyword given — cloud_enum needs a name to guess from"
        return result

    print_info(f"[cloud_enum] searching public cloud storage for '{keyword}'...")

    # -qs / --quickscan: skip the slow mutated-name permutations and check
    # the base keyword set only. The full sweep issues tens of thousands of
    # DNS/HTTP lookups and routinely runs past any sane timeout; the quick
    # pass is what fits inside a recon profile.
    tool_result = run_tool(
        target, TOOL_NAME,
        ["cloud_enum", "-k", keyword, "--quickscan", "--disable-azure"],
    )

    result["skipped"] = bool(tool_result.get("skipped"))

    if not tool_result.get("success"):
        result["error"] = (
            tool_result.get("error")
            or tool_result.get("stderr")
            or "cloud_enum failed"
        )
        if result["skipped"]:
            print_warning("[cloud_enum] skipped by user")
        else:
            logger.error(f"[cloud_enum] failed for '{keyword}': {result['error']}")
            print_warning(f"[cloud_enum] failed for '{keyword}': {result['error']}")
        return result

    open_buckets, inventory = _parse_cloud_enum(tool_result.get("stdout", "") or "")
    result["buckets"] = open_buckets
    result["inventory"] = inventory
    result["count"] = len(open_buckets)

    for bucket in open_buckets:
        log_finding(target, {
            "type": "recon_bucket",
            "value": bucket["url"],
            "provider": bucket["provider"],
        })

    if open_buckets:
        print_success(
            f"[cloud_enum] {len(open_buckets)} PUBLICLY OPEN bucket(s) matching "
            f"'{keyword}' ({len(inventory)} more exist but are protected)"
        )
    else:
        print_info(
            f"[cloud_enum] no open buckets matching '{keyword}' "
            f"({len(inventory)} protected/unlabelled hit(s))"
        )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_warning("Usage: python -m modules.recon.cloud_enum_wrap <keyword>")
        sys.exit(1)

    out = find_cloud_buckets(sys.argv[1])
    for b in out["buckets"]:
        print_info(f"OPEN  {b['provider']:6} {b['url']}")
    for b in out["inventory"]:
        print_info(f"{b['access']:9} {b['provider']:6} {b['url']}")
    print_info(f"{out['count']} open; error={out['error']}")
