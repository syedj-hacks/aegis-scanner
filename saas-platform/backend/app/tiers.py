"""
Server-side subscription tier rules. This is the single source of truth for
what a tier can do — the frontend only *reflects* this (lock icons, disabled
buttons); every scan-triggering endpoint re-checks against this module before
calling into Aegis. Never trust a frontend-disabled button alone.
"""
from .models import Tier

# Profiles unlocked at each tier. Every profile is always listed/described to
# every account (see routers/scans.py list_profiles) — this only gates
# *execution*.
TIER_PROFILES = {
    Tier.free: {"quickscan", "compliance"},
    Tier.pro: {"quickscan", "compliance", "webaudit", "stealthscan"},
    Tier.enterprise: {
        "quickscan", "compliance", "webaudit", "stealthscan", "deepscan", "recon",
    },
}

# Aegis profile name -> internal name used by TIER_PROFILES/UI ("stealthscan"
# in the brief maps to Aegis's actual dispatch key "stealthscan" already, so
# this is an identity map kept for clarity/future-proofing).
AEGIS_PROFILE_NAMES = {
    "quickscan": "quickscan",
    "stealthscan": "stealthscan",
    "webaudit": "webaudit",
    "deepscan": "deepscan",
    "compliance": "compliance",
    "recon": "recon",
}

# Monthly list price in cents, shown on invoices in the billing ledger.
PRICE_CENTS = {
    Tier.free: 0,
    Tier.pro: 1999,
    Tier.enterprise: 4999,
}

# Ordering used to tell an upgrade (needs admin approval) from a downgrade
# (applied immediately, since it only removes capabilities).
TIER_RANK = {
    Tier.free: 0,
    Tier.pro: 1,
    Tier.enterprise: 2,
}

# None => unlimited
SCANS_PER_MONTH = {
    Tier.free: 10,
    Tier.pro: None,
    Tier.enterprise: None,
}

MAX_PARALLEL_SCANS = {
    Tier.free: 1,
    Tier.pro: 1,
    Tier.enterprise: 2,
}

REPORT_FORMATS = {
    Tier.free: {"html"},
    Tier.pro: {"html", "pdf"},
    Tier.enterprise: {"html", "pdf", "json"},
}

DIFF_ALLOWED = {
    Tier.free: False,
    Tier.pro: True,
    Tier.enterprise: True,
}

# None => unlimited diffs/month
DIFF_LIMIT_PER_MONTH = {
    Tier.free: 0,
    Tier.pro: 2,
    Tier.enterprise: None,
}

LIVE_VIEW_ALLOWED = {
    Tier.free: False,
    Tier.pro: True,
    Tier.enterprise: True,
}

CUSTOM_CONFIG_ALLOWED = {
    Tier.free: "none",       # no auth/config customization
    Tier.pro: "auth_only",   # auth header/cookie only
    Tier.enterprise: "full", # full profile config
}

# The intrusive/conditional Aegis tools (wpscan, sqlmap, hydra, enum4linux)
# only ever fire from inside deepscan, and deepscan itself is Enterprise-only
# (see TIER_PROFILES). This flag is the SECOND, explicit gate required by the
# brief: even an Enterprise user must tick the authorization checkbox per
# scan before deepscan is allowed to run at all.
CONDITIONAL_TOOLS_REQUIRE_AUTHORIZATION = {"deepscan"}


def profiles_for_tier(tier: Tier) -> set:
    return TIER_PROFILES.get(tier, set())


def scan_limit_for_tier(tier: Tier):
    return SCANS_PER_MONTH.get(tier)


def can_run_profile(tier: Tier, profile: str) -> bool:
    return profile in profiles_for_tier(tier)


def report_formats_for_tier(tier: Tier) -> set:
    return REPORT_FORMATS.get(tier, {"html"})


def diff_allowed_for_tier(tier: Tier) -> bool:
    return DIFF_ALLOWED.get(tier, False)


def max_parallel_for_tier(tier: Tier) -> int:
    return MAX_PARALLEL_SCANS.get(tier, 1)
