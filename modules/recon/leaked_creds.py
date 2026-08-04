"""
modules/recon/leaked_creds.py
Breach exposure for harvested email addresses, via Have I Been Pwned.

The API key is not optional, and pretending otherwise is the bug
-----------------------------------------------------------------
HIBP's breachedaccount endpoint has required a paid API key since 2019.
There is no public/anonymous mode: a request without a valid `hibp-api-key`
header returns 401, and a request with a placeholder value returns 401 too.

That matters more than it looks, because of how a naive implementation
fails. The obvious code treats HTTP 200 as "breached" and everything else
as "not breached" — under which a 401 from a missing key makes every single
address come back clean, and the scan reports "0 accounts breached" for a
company whose credentials are all over the internet. A false all-clear on a
security tool is worse than no check at all: it is the one output a reader
will act on by doing nothing.

So this module treats "no key configured" as an explicit unavailable state
with its own field (`available`), never as a result. Only a genuine 404
from an authenticated request counts as "this address is clean". Anything
else — 401, 403, 429, a timeout — is an error, and the recon report says
the check could not be performed rather than that nothing was found.

Set AEGIS_HIBP_API_KEY in the gitignored .env (same mechanism as
AEGIS_NVD_API_KEY) to enable it. Keys are ~$4/month from
https://haveibeenpwned.com/API/Key .

Rate limit
----------
HIBP rate-limits per key, and the floor for the cheapest tier is one
request every 1.5 seconds; exceeding it returns 429 with a Retry-After.
_REQUEST_INTERVAL paces the loop just above that floor, and a 429 is
honoured rather than retried blindly.
"""

import os
import time

import requests

from modules.utils.error_handler import safe_call, is_user_skip
from modules.utils.logger import get_logger, log_finding
from modules.utils.display import print_info, print_success, print_warning

TOOL_NAME = "hibp"

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

# Same resolution order as config.NVD_API_KEY: an explicit AEGIS_-prefixed
# variable first, then the bare name, then nothing. Deliberately NO default
# key — unlike the NVD key, an HIBP key is a paid personal credential and
# baking one into a shared repo would be billing someone else's account for
# every clone.
def _api_key():
    return (
        os.environ.get("AEGIS_HIBP_API_KEY")
        or os.environ.get("HIBP_API_KEY")
        or ""
    ).strip()


_TIMEOUT = 15
_REQUEST_INTERVAL = 1.7        # just above HIBP's 1.5s floor
_MAX_ACCOUNTS = 20             # bounded so a big harvest can't run for an hour


def _check_one(email: str, key: str) -> dict:
    """
    One authenticated HIBP lookup.

    Returns {"breached": bool, "breaches": list[str]} on a definitive
    answer, or raises. Raising rather than returning a sentinel is
    deliberate: safe_call() in the caller converts an exception into a
    recorded error, whereas a sentinel would have to be distinguished from
    a real "not breached" by every reader of this function.
    """
    response = requests.get(
        HIBP_URL.format(account=requests.utils.quote(email, safe="")),
        headers={
            "User-Agent": "AegisScanner/1.0",
            "hibp-api-key": key,
        },
        params={"truncateResponse": "false"},
        timeout=_TIMEOUT,
    )

    if response.status_code == 200:
        breaches = response.json()
        return {
            "breached": True,
            "breaches": [b.get("Name", "unknown") for b in breaches if isinstance(b, dict)],
            "detail": [
                {
                    "name": b.get("Name"),
                    "date": b.get("BreachDate"),
                    "classes": b.get("DataClasses") or [],
                }
                for b in breaches if isinstance(b, dict)
            ],
        }

    # 404 is HIBP's "this account appears in no breach" — the ONLY response
    # that legitimately means clean, and only because the request was
    # authenticated enough to be answered at all.
    if response.status_code == 404:
        return {"breached": False, "breaches": [], "detail": []}

    if response.status_code == 401:
        raise RuntimeError(
            "HIBP rejected the API key (401) — check AEGIS_HIBP_API_KEY is a "
            "valid, active key"
        )
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After", "?")
        raise RuntimeError(f"HIBP rate limit hit (429), retry-after={retry_after}s")

    raise RuntimeError(f"HIBP returned HTTP {response.status_code}")


def check_leaked_creds(emails: list, target: str = None) -> dict:
    """
    Check harvested email addresses against HIBP's breach database.

    Parameters
    ----------
    emails : list[str]  addresses, typically from osint.harvest_osint()
    target : str        scan target, for logging

    Returns
    -------
    dict:
        tool             : "hibp"
        target           : str
        available        : bool       False when no API key is configured —
                                      the check did not run, and its zero
                                      counts mean nothing
        checked          : int        addresses that got a definitive answer
        breached_count   : int
        breached_accounts: list[dict] {email, breached, breaches, detail}
        clean_count      : int
        skipped          : bool
        error            : str | None

    Never raises.
    """
    target = target or "unknown"
    logger = get_logger(target)

    result = {
        "tool": TOOL_NAME,
        "target": target,
        "available": False,
        "checked": 0,
        "breached_count": 0,
        "breached_accounts": [],
        "clean_count": 0,
        "skipped": False,
        "error": None,
    }

    emails = [e for e in (emails or []) if e and "@" in str(e)]
    if not emails:
        result["error"] = "no email addresses to check"
        print_info("[HIBP] no harvested email addresses — breach check not run")
        return result

    key = _api_key()
    if not key:
        # The single most important branch in this module. Reported as
        # unavailable with a zero count that the caller is told to ignore,
        # NOT as "nothing found" — see the module docstring.
        result["error"] = (
            "no HIBP API key configured — set AEGIS_HIBP_API_KEY in .env to "
            "enable breach checking (https://haveibeenpwned.com/API/Key). "
            "This check did NOT run; it did not come back clean."
        )
        logger.warning(f"[HIBP] {result['error']}")
        print_warning(
            f"[HIBP] breach check skipped for {len(emails)} address(es): no API "
            "key configured. This is NOT an all-clear — set AEGIS_HIBP_API_KEY "
            "in .env to actually check."
        )
        return result

    result["available"] = True

    if len(emails) > _MAX_ACCOUNTS:
        print_info(
            f"[HIBP] {len(emails)} addresses harvested; checking the first "
            f"{_MAX_ACCOUNTS} (rate limit is {_REQUEST_INTERVAL}s per request)"
        )
        emails = emails[:_MAX_ACCOUNTS]

    errors = []
    for index, email in enumerate(emails):
        if index:
            time.sleep(_REQUEST_INTERVAL)

        call = safe_call(_check_one, email, key, target=target, label=f"HIBP:{email}")

        if not call.get("success"):
            reason = call.get("error") or "HIBP lookup failed"
            if is_user_skip(reason):
                result["skipped"] = True
                print_warning("[HIBP] breach check skipped by user")
                break
            errors.append(f"{email}: {reason}")
            # An auth failure or a rate limit will hit every remaining
            # address identically — stop rather than burn the rest of the
            # list producing the same error twenty times.
            if "401" in reason or "429" in reason:
                break
            continue

        data = call.get("data") or {}
        result["checked"] += 1
        if data.get("breached"):
            entry = {"email": email, **data}
            result["breached_accounts"].append(entry)
            log_finding(target, {
                "type": "recon_leak",
                "value": email,
                "breaches": ", ".join(data.get("breaches") or []),
            })
        else:
            result["clean_count"] += 1

    result["breached_count"] = len(result["breached_accounts"])

    if errors:
        result["error"] = "; ".join(errors[:3])
        logger.error(f"[HIBP] {len(errors)} lookup error(s): {result['error']}")
        print_warning(f"[HIBP] {len(errors)} address(es) could not be checked: {result['error']}")

    if result["breached_count"]:
        print_success(
            f"[HIBP] {result['breached_count']} of {result['checked']} checked "
            "address(es) appear in known breaches"
        )
    elif result["checked"]:
        print_info(f"[HIBP] none of the {result['checked']} checked address(es) appear in known breaches")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_warning("Usage: python -m modules.recon.leaked_creds <email> [email...]")
        sys.exit(1)

    out = check_leaked_creds(sys.argv[1:])
    print_info(f"available={out['available']} checked={out['checked']} "
               f"breached={out['breached_count']} error={out['error']}")
    for account in out["breached_accounts"]:
        print_info(f"{account['email']}: {', '.join(account['breaches'])}")
