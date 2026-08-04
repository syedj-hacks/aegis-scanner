"""
modules/profiles/recon.py
Recon Mapper profile — attack-surface discovery, before any scanning.

What makes this profile different from the other five
------------------------------------------------------
Every other profile answers "what is wrong with this host". This one
answers "what does this organisation actually expose", and that is a
different question with a different input: it accepts a company NAME as
well as a domain.

    python3 aegis.py example.com --recon      domain mode
    python3 aegis.py --recon                  then type: Acme Corp

The distinction is not cosmetic. With a domain there is something to
resolve, certificate transparency logs to query and subdomains to
enumerate. With a bare company name there is not — no DNS, no CT logs, no
subdomain enumeration — and the only tools that still apply are the ones
that take a keyword: cloud_enum's bucket search and theHarvester's
name-based OSINT. _plan() below decides which steps are applicable and the
profile runs only those, rather than running everything and reporting a
string of failures for the steps that were never applicable in the first
place.

Nothing here touches the target
--------------------------------
Every step is passive: public certificate logs, public DNS aggregators,
public cloud storage namespaces, a breach database. Not one of them sends
a packet to the target's own infrastructure. That is what makes this
profile safe to run against a name you do not yet have authorisation to
scan — and it is why it is a separate profile rather than a phase of
deepscan, which is emphatically not passive.

Findings go into the normal pipeline
-------------------------------------
Subdomains, buckets and breached addresses are inserted into `findings` as
recon_subdomain / recon_bucket / recon_leak, scored by severity.py and
given remediation text like anything else, so they reach the TXT/PDF/HTML
reports, the severity summary and the scan diff with no special-casing.
The recon_* tables hold the extra structure `findings` has no columns for
(a subdomain's source, a bucket's provider, an address's breach list).
"""

from modules.utils.display import (
    scan_progress_bar, print_phase, print_info, print_success,
    print_warning, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end
from modules.recon.dns import resolve_dns
from modules.recon.cert_transparency import find_subdomains_crtsh
from modules.recon.subdomain import enumerate_subdomains
from modules.recon.osint import harvest_osint
from modules.recon.cloud_enum_wrap import find_cloud_buckets
from modules.recon.leaked_creds import check_leaked_creds
from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation
from database.db import (
    insert_scan, insert_findings_bulk,
    insert_recon_subdomains, insert_recon_buckets, insert_recon_leaks,
)
from modules.reporting.dashboard_live import update_live_data
from modules.profiles._common import (
    count_and_report_tool_failures, persist_tool_run, finalise_reports,
)

PROFILE_NAME = "recon"


def _score_and_remediate(findings: list) -> list:
    return [get_remediation(score_finding(f)) for f in findings]


def _keyword_from(domain: str) -> str:
    """
    The company-ish keyword inside a domain: "shop.acme-corp.co.uk" -> "acme-corp".

    Used to feed cloud_enum, which wants a name rather than a hostname.
    Takes the label before the public suffix rather than the first label,
    because the first label of a subdomain is "shop"/"www"/"mail" far more
    often than it is the company name. The suffix list here is deliberately
    tiny and only covers the common two-part suffixes — a full public
    suffix list is a dependency this does not justify, and being wrong here
    costs one imperfect keyword, not a wrong result.
    """
    labels = [part for part in str(domain or "").lower().split(".") if part]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]

    _TWO_PART_SUFFIXES = {"co", "com", "org", "net", "gov", "edu", "ac"}
    # "acme.co.uk" -> labels[-3] is the name; "acme.com" -> labels[-2] is.
    if len(labels) >= 3 and labels[-2] in _TWO_PART_SUFFIXES:
        return labels[-3]
    return labels[-2]


def _plan(target: str, is_company: bool) -> dict:
    """
    Decide what this run can actually do, given what the user typed.

    Returns {domain, keyword, steps} where `steps` is the ordered list of
    applicable step labels. A company-name run genuinely has no domain, so
    the DNS/CT/subdomain steps are not merely expected to fail — they are
    not applicable, and the difference is what the progress bar and the
    report should reflect.
    """
    if is_company:
        domain, keyword = None, str(target or "").strip()
    else:
        domain = str(target or "").strip().lower()
        keyword = _keyword_from(domain)

    steps = []
    if domain:
        steps += ["DNS resolution", "Certificate transparency", "Subdomain enumeration"]
    steps += ["OSINT harvest", "Cloud storage discovery", "Breach check"]
    return {"domain": domain, "keyword": keyword, "steps": steps}


# How many discovered subdomains become individual `findings` rows.
#
# Measured, not guessed: a passive run against example.com returned 23,330
# unique names, and persisting one finding each produced a 23,330-row report
# that no one can read and that buries the two or three findings — an open
# bucket, a breached address — that actually need acting on. A report whose
# signal is at position 12,000 has no signal.
#
# Every name is still kept in full, in the recon_subdomains table, which is
# the right home for a long structured list and is queryable. The cap
# applies only to the report-facing findings rows, and when it bites, a
# single summary finding says so explicitly — so the report states that it
# is showing a subset rather than quietly appearing complete.
_MAX_SUBDOMAIN_FINDINGS = 100


def _findings_from_subdomains(subdomains_by_source: dict) -> list:
    """
    One recon_subdomain finding per unique name, crediting every source that
    found it, capped at _MAX_SUBDOMAIN_FINDINGS.

    Deduplicated across sources on purpose: crt.sh, subfinder and amass
    overlap heavily, and emitting one finding per (name, tool) would report
    the same hostname three times and treble the recon section of the
    report for no added information. The sources are merged into the
    finding's own text instead, which is strictly more useful — a name that
    only crt.sh knows about is a different kind of lead from one all three
    agree on.
    """
    by_name = {}
    for source, names in (subdomains_by_source or {}).items():
        for name in names or []:
            by_name.setdefault(name, set()).add(source)

    # Names confirmed by more sources first, then alphabetically. When the
    # cap bites, the names that survive into the report should be the ones
    # several independent sources agree exist, not whichever happen to sort
    # first — "0.0.1.example.com" is not a better lead than "vpn.example.com"
    # merely because a zero sorts early.
    ordered = sorted(by_name, key=lambda n: (-len(by_name[n]), n))

    findings = []
    for name in ordered[:_MAX_SUBDOMAIN_FINDINGS]:
        sources = sorted(by_name[name])
        findings.append({
            "type": "recon_subdomain",
            "name": name,
            "service": "dns",
            "source": ", ".join(sources),
            "description": f"Subdomain discovered: {name} (via {', '.join(sources)})",
        })

    remaining = len(ordered) - len(findings)
    if remaining > 0:
        findings.append({
            "type": "recon_subdomain",
            "name": f"+{remaining} more subdomains",
            "service": "dns",
            "source": ", ".join(sorted(subdomains_by_source)),
            "description": (
                f"{len(ordered)} subdomains were discovered in total; the "
                f"{_MAX_SUBDOMAIN_FINDINGS} most-corroborated are listed "
                f"individually above and the remaining {remaining} are "
                "recorded in full in the scan's recon_subdomains table and "
                "the HTML report's recon section."
            ),
        })
    return findings


def _findings_from_buckets(bucket_result: dict) -> list:
    """
    One recon_bucket finding per PUBLICLY OPEN bucket.

    Protected buckets are recorded in the recon_buckets table as inventory
    but are deliberately not findings — see cloud_enum_wrap's docstring. A
    bucket existing is not an exposure.
    """
    findings = []
    for bucket in bucket_result.get("buckets") or []:
        findings.append({
            "type": "recon_bucket",
            "name": bucket["url"],
            "service": bucket.get("provider"),
            "endpoint": bucket["url"],
            "description": (
                f"Publicly readable {bucket.get('provider', 'cloud').upper()} "
                f"storage matching the target keyword: {bucket['url']}. "
                "Confirm ownership before acting — the cloud storage namespace "
                "is global and a keyword match is not proof of ownership."
            ),
        })
    return findings


def _findings_from_leaks(leak_result: dict) -> list:
    """One recon_leak finding per breached address."""
    findings = []
    for account in leak_result.get("breached_accounts") or []:
        breaches = account.get("breaches") or []
        findings.append({
            "type": "recon_leak",
            "name": account["email"],
            "service": "email",
            "description": (
                f"{account['email']} appears in {len(breaches)} known breach(es): "
                + ", ".join(breaches[:8])
                + ("..." if len(breaches) > 8 else "")
            ),
        })
    return findings


def run_recon(target: str, non_interactive: bool = False, auth=None,
              is_company: bool = None):
    """
    Run the recon mapper against a domain or a company name.

    Parameters
    ----------
    target      : str   a domain (example.com) or a company name (Acme Corp)
    is_company  : bool  None (the default) auto-detects by asking
                        aegis.is_valid_target() whether `target` is a
                        syntactically valid hostname. Passed explicitly by
                        the interactive menu, which already knows.

    Returns
    -------
    tuple: (scan_id, txt_path, pdf_path, html_path, stats)

    `auth` is accepted and unused — every profile is dispatched through the
    same call, so the signature has to be uniform. Nothing this profile runs
    authenticates to the target; nothing it runs contacts the target at all.
    """
    if is_company is None:
        # Imported here rather than at module scope: aegis.py imports this
        # module's run_recon at startup, so a module-level import back into
        # aegis would be circular.
        from aegis import is_valid_target
        is_company = not is_valid_target(target)

    plan = _plan(target, is_company)
    domain, keyword = plan["domain"], plan["keyword"]

    log_scan_start(target, PROFILE_NAME)
    print_phase(f"RECON MAPPER — {target}")

    if is_company:
        print_info(
            f"[{PROFILE_NAME}] '{target}' is not a hostname — running in company-name "
            "mode: cloud storage and OSINT only (no DNS, certificate transparency "
            "or subdomain enumeration, which all need a domain)."
        )
    else:
        print_info(f"[{PROFILE_NAME}] domain mode: {domain} (keyword '{keyword}')")

    print_info(
        f"[{PROFILE_NAME}] every step is passive — public certificate logs, DNS "
        "aggregators, cloud namespaces and a breach database. No packet is sent "
        "to the target's own infrastructure."
    )

    scan_id = insert_scan(target, PROFILE_NAME)
    update_live_data(target, [], current_tool="certificate transparency + subdomains", progress_pct=10)

    tool_results = []
    findings = []
    subdomains_by_source = {}
    emails = []
    bucket_result, leak_result = {}, {}

    with scan_progress_bar(len(plan["steps"]), f"Recon: {target}") as advance:
        if domain:
            dns_result = resolve_dns(domain)
            tool_results.append(dns_result)
            advance("DNS resolution")

            crtsh_result = find_subdomains_crtsh(domain, target=target)
            tool_results.append(crtsh_result)
            if crtsh_result.get("subdomains"):
                subdomains_by_source["crt.sh"] = crtsh_result["subdomains"]
            advance("Certificate transparency")

            subdomain_result = enumerate_subdomains(domain)
            tool_results.append(subdomain_result)
            # enumerate_subdomains merges subfinder and amass into one list
            # and reports which tools succeeded, so the merged list is
            # credited to the tools that actually produced it rather than to
            # a tool that failed.
            if subdomain_result.get("subdomains"):
                credited = "/".join(subdomain_result.get("tools_used") or ["subfinder/amass"])
                subdomains_by_source[credited] = subdomain_result["subdomains"]
            advance("Subdomain enumeration")

        # theHarvester takes either — a domain when there is one, the raw
        # company name otherwise.
        osint_result = harvest_osint(domain or target)
        tool_results.append(osint_result)
        emails = osint_result.get("emails") or []
        if osint_result.get("hosts"):
            # theHarvester's hosts are subdomains by another name, and in
            # company-name mode they are the ONLY subdomain source there is.
            relevant = (
                [h for h in osint_result["hosts"] if domain and domain in h]
                if domain else list(osint_result["hosts"])
            )
            if relevant:
                subdomains_by_source["theHarvester"] = relevant
        advance("OSINT harvest")

        bucket_result = find_cloud_buckets(keyword or target, target=target)
        tool_results.append(bucket_result)
        advance("Cloud storage discovery")

        leak_result = check_leaked_creds(emails, target=target)
        tool_results.append(leak_result)
        advance("Breach check")

    # --- Build and persist findings -------------------------------------
    findings.extend(_score_and_remediate(_findings_from_subdomains(subdomains_by_source)))
    findings.extend(_score_and_remediate(_findings_from_buckets(bucket_result)))
    findings.extend(_score_and_remediate(_findings_from_leaks(leak_result)))

    insert_findings_bulk(scan_id, findings)
    update_live_data(target, findings, current_tool="recon mapper", progress_pct=95)

    # The structured detail `findings` has no columns for.
    insert_recon_subdomains(scan_id, [
        {"subdomain": name, "source": source}
        for source, names in subdomains_by_source.items()
        for name in names
    ])
    insert_recon_buckets(scan_id, [
        {"bucket_url": b["url"], "provider": b.get("provider"), "access": b.get("access")}
        for b in (bucket_result.get("buckets") or []) + (bucket_result.get("inventory") or [])
    ])
    insert_recon_leaks(scan_id, [
        {"email": account["email"], "breach_name": breach.get("name"),
         "breach_date": breach.get("date")}
        for account in (leak_result.get("breached_accounts") or [])
        for breach in (account.get("detail") or [{"name": n} for n in account.get("breaches") or []])
    ])

    stats = {
        "tools_run": len(tool_results),
        "tools_failed": count_and_report_tool_failures(target, tool_results),
        "tools_skipped": sum(1 for r in tool_results if r.get("skipped")),
    }
    persist_tool_run(scan_id, tool_results)
    log_scan_end(target, stats)

    _print_recon_summary(subdomains_by_source, emails, bucket_result, leak_result)

    txt_path, pdf_path, html_path = finalise_reports(
        target, PROFILE_NAME, scan_id, non_interactive=non_interactive
    )
    print_success(f"[{PROFILE_NAME}] scan {scan_id} complete — {len(findings)} finding(s)")
    return scan_id, txt_path, pdf_path, html_path, stats


def _print_recon_summary(subdomains_by_source, emails, bucket_result, leak_result):
    """
    The attack-surface picture, on screen, before the report is written.

    The breach line is the one that needs care: when no HIBP key is
    configured the check did not run, and printing "0 breached" next to the
    other counts would read as an all-clear it has not earned.
    """
    unique_subdomains = {name for names in subdomains_by_source.values() for name in names}

    print_info(f"[{PROFILE_NAME}] attack surface:")
    print_info(f"    subdomains : {len(unique_subdomains)} unique "
               f"(sources: {', '.join(sorted(subdomains_by_source)) or 'none'})")
    print_info(f"    emails     : {len(emails)} harvested")
    print_info(f"    buckets    : {bucket_result.get('count', 0)} publicly open, "
               f"{len(bucket_result.get('inventory') or [])} protected/unlabelled")

    if not leak_result.get("available"):
        print_warning(
            "    breaches   : NOT CHECKED — no HIBP API key configured "
            "(set AEGIS_HIBP_API_KEY in .env). This is not an all-clear."
        )
    else:
        print_info(
            f"    breaches   : {leak_result.get('breached_count', 0)} of "
            f"{leak_result.get('checked', 0)} checked address(es) appear in "
            "known breaches"
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print_error("Usage: python -m modules.profiles.recon <domain|company name>")
        sys.exit(1)

    # aegis.py calls this before dispatching; running the profile directly
    # as a module does not, and without it the recon_* tables do not exist
    # and every row written to them is lost. Idempotent, so calling it here
    # costs nothing on the normal path.
    from database.db import init_db
    init_db()

    sid, txt, _pdf, _html, _st = run_recon(" ".join(sys.argv[1:]))
    print_success(f"Recon complete — scan_id={sid} report={txt}")
