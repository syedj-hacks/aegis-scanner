"""
modules/reporting/retention.py
Capped, indexed report history for Aegis Scanner (reporting layer).

Both report writers used to write a single fixed filename per target —
output/<target>/report.txt and report.pdf — so every scan silently
overwrote the previous scan's report. That has already destroyed evidence
once: scan 112's showcase report for scanme.nmap.org was gone by the time
anyone went looking for it, overwritten by scan 116 an hour later. Nothing
warned, and nothing recorded that a file had been replaced.

Unlimited accumulation is not the answer either — a target scanned nightly
would fill the output directory with reports nobody reads. This module
implements the middle option: reports are named per scan so they never
collide, and the history is capped.

    report_<profile>_<target>_<scan_id>.txt
    report_<profile>_<target>_<scan_id>.pdf

The profile is in the filename deliberately, so a directory listing says
what each report *is* without opening it.

Retention is per profile+target
-------------------------------
Each profile keeps its own budget of _DEFAULT_KEEP reports for a given
target. A burst of quickscans therefore cannot evict the one deepscan
report of that host — which a flat per-target cap would do, and which is
precisely the kind of evidence loss this module exists to prevent.

Deletion is never silent and never automatic in an interactive session
-----------------------------------------------------------------------
When a new report would exceed the cap, an interactive run is asked what to
do (drop the oldest, drop a specific one, or keep everything). Scripted
runs cannot answer a prompt, so they drop the oldest and log that they did
— hanging a CI run on stdin is worse than the pruning itself.

Pruning always runs *after* the new report has been written, and a failure
here never affects report generation: the report already exists on disk by
the time any of this is reached.
"""

import os
import re
import sys
from datetime import datetime

from modules.utils.display import print_info, print_warning, print_error
from modules.utils.logger import get_logger

# How many reports to keep per profile+target pair.
_DEFAULT_KEEP = 5

# Extensions a stored report can have. Both files for one scan are treated
# as a single unit — a .txt without its .pdf is half a report, so they are
# listed, counted and deleted together.
_REPORT_EXTENSIONS = ("txt", "pdf")

_FALLBACK_TARGET = "reporting"

# Characters that are unsafe in a filename on any platform this runs on.
# Targets are validated as hostnames/IPs before a scan starts, so this is
# belt-and-braces against an odd target reaching the filesystem layer.
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def _sanitise(value: str, fallback: str) -> str:
    """Reduce a target/profile to filename-safe characters."""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", str(value or "").strip())
    return cleaned or fallback


def report_filename(profile: str, target: str, scan_id, extension: str) -> str:
    """
    'report_quickscan_pentest-ground.com_117.txt' — the stored name for one
    scan's report.

    Every component is present so the file is self-describing: which
    profile produced it, against what, and which scan it corresponds to in
    the database.
    """
    return (
        f"report_{_sanitise(profile, 'unknown')}"
        f"_{_sanitise(target, 'unknown')}"
        f"_{_sanitise(scan_id, '0')}.{extension.lstrip('.')}"
    )


# Matches the names report_filename() produces, capturing the profile and
# the scan id. The profile group is non-greedy and the scan id is anchored
# to the end so a target containing underscores still parses.
# txt/pdf were the original pair; json and sarif (Phase 4 machine outputs)
# are also per-scan-named and so must be swept up with their scan, or they
# would accumulate one-per-scan forever. html is deliberately absent: it is
# written to a single fixed report.html that each scan overwrites, so it has
# nothing to prune. Grouping is by scan_id, so all of a scan's files are
# kept or removed as one unit.
_STORED_REPORT = re.compile(
    r"^report_(?P<profile>.+?)_(?P<target>.+)_(?P<scan_id>\d+)\.(?P<ext>txt|pdf|json|sarif)$"
)


def _parse_stored_name(filename: str):
    """
    Pull (profile, scan_id) out of a stored report filename, or None.

    Returns None for anything that is not one of our per-scan reports —
    including the legacy fixed-name report.txt/report.pdf, which are
    deliberately left alone rather than swept up by the pruner. They belong
    to no identifiable scan, so this module cannot reason about their age
    relative to the indexed ones and will not delete what it cannot
    account for.
    """
    match = _STORED_REPORT.match(filename)
    if not match:
        return None
    try:
        scan_id = int(match.group("scan_id"))
    except (TypeError, ValueError):
        return None
    return match.group("profile"), scan_id


def list_stored_reports(directory: str, profile: str, target: str) -> list:
    """
    Every stored report for one profile+target, oldest scan first.

    Returns a list of dicts:
        {scan_id, paths: [...], mtime: float, timestamp: str}

    The .txt and .pdf for one scan are collapsed into a single entry, so
    "5 reports" means five scans, not five files. Ordering is by scan_id,
    which is monotonic in the database and therefore a more reliable age
    than a filesystem mtime a re-render could have refreshed.
    """
    wanted_profile = _sanitise(profile, "unknown")
    wanted_target = _sanitise(target, "unknown")

    try:
        entries = os.listdir(directory)
    except OSError:
        # No directory yet (first scan of this target) — nothing stored.
        return []

    by_scan = {}
    for filename in entries:
        parsed = _parse_stored_name(filename)
        if not parsed:
            continue
        found_profile, scan_id = parsed
        if found_profile != wanted_profile:
            continue
        # Guard against two targets sharing a directory.
        if not filename.startswith(f"report_{wanted_profile}_{wanted_target}_"):
            continue

        path = os.path.join(directory, filename)
        record = by_scan.setdefault(scan_id, {"scan_id": scan_id, "paths": [], "mtime": 0.0})
        record["paths"].append(path)
        try:
            record["mtime"] = max(record["mtime"], os.path.getmtime(path))
        except OSError:
            pass

    reports = sorted(by_scan.values(), key=lambda r: r["scan_id"])
    for record in reports:
        record["paths"].sort()
        record["timestamp"] = (
            datetime.fromtimestamp(record["mtime"]).strftime("%Y-%m-%d %H:%M")
            if record["mtime"] else "unknown"
        )
    return reports


def _format_choices(reports: list) -> str:
    """The numbered list shown in the prompt, newest last."""
    lines = []
    for index, record in enumerate(reports, start=1):
        names = ", ".join(os.path.basename(p) for p in record["paths"])
        lines.append(f"    [{index}] {names}  ({record['timestamp']})")
    return "\n".join(lines)


def _delete_report(record: dict, target: str) -> bool:
    """
    Delete both files of one stored report. Returns True if anything went.

    A failure to unlink is reported and survived: the new report is already
    written, and an undeleted old one is untidy rather than harmful.
    """
    logger = get_logger(target)
    removed = []
    for path in record["paths"]:
        try:
            os.remove(path)
            removed.append(path)
        except OSError as exc:
            logger.error(f"[Retention] could not delete {path}: {exc}")
            print_error(f"[Retention] could not delete {os.path.basename(path)}: {exc}")

    if removed:
        names = ", ".join(os.path.basename(p) for p in removed)
        logger.info(f"[Retention] deleted report(s) for scan {record['scan_id']}: {names}")
        print_info(f"[Retention] deleted {names}")
    return bool(removed)


def _is_interactive() -> bool:
    """
    True when there is a real terminal on both stdin and stdout.

    Both are checked because a run with its output piped to a file still
    has a usable stdin but no sensible place to draw a prompt, and a run
    under a scheduler has neither.
    """
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def _prompt_choice(reports: list, profile: str, target: str):
    """
    Ask what to prune. Returns the record to delete, or None to keep all.

    Re-prompts on anything unrecognised rather than crashing or quietly
    picking a default — silently deleting the wrong report because someone
    fat-fingered an index is the exact failure this module exists to
    prevent. Ctrl+C / EOF is read as "keep everything", the conservative
    reading: an interrupted operator has not consented to a deletion.
    """
    print_warning(
        f"[Retention] you already have {len(reports)} saved report(s) for "
        f"{profile}/{target}:"
    )
    print_info("\n" + _format_choices(reports))

    while True:
        try:
            answer = input(
                "  Delete the oldest [o], delete a specific one by number, "
                "or keep all and save the new report anyway [k]? "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print_warning("\n[Retention] no answer given — keeping all reports.")
            return None

        if answer in ("o", "oldest"):
            return reports[0]
        if answer in ("k", "keep", "n", "no"):
            return None
        if answer.isdigit():
            index = int(answer)
            if 1 <= index <= len(reports):
                return reports[index - 1]
            print_error(
                f"  '{answer}' is out of range — enter a number between 1 and {len(reports)}."
            )
            continue

        print_error(
            f"  '{answer}' is not a valid choice — enter 'o' for oldest, "
            f"a number 1-{len(reports)}, or 'k' to keep all."
        )


def prune_reports(directory: str, profile: str, target: str,
                  keep: int = _DEFAULT_KEEP,
                  non_interactive: bool = False) -> int:
    """
    Enforce the per-profile+target cap after a new report has been written.

    Parameters
    ----------
    directory       : str   the target's output directory
    profile, target : str   which report family to prune
    keep            : int   how many reports to retain
    non_interactive : bool  force the scripted behaviour (drop the oldest)
                            even from a terminal — the --non-interactive flag

    Returns the number of stored reports deleted.

    Never raises. This runs after the report the user asked for is safely
    on disk, so every failure here is logged and swallowed: a scan must not
    be reported as failed because housekeeping did not work out.
    """
    logger = get_logger(target or _FALLBACK_TARGET)

    try:
        limit = max(1, int(keep))
    except (TypeError, ValueError):
        limit = _DEFAULT_KEEP

    try:
        reports = list_stored_reports(directory, profile, target)
    except Exception as exc:
        logger.error(f"[Retention] could not list stored reports: {exc}")
        print_warning(f"[Retention] could not check report history: {exc}")
        return 0

    if len(reports) <= limit:
        logger.info(
            f"[Retention] {profile}/{target}: {len(reports)} stored report(s), "
            f"cap {limit} — nothing to prune"
        )
        return 0

    scripted = non_interactive or not _is_interactive()
    deleted = 0

    # Loop rather than deleting one and stopping. In normal operation a run
    # adds exactly one report, so one deletion holds the cap — but a
    # directory can start over-cap (reports restored from elsewhere, or
    # re-rendered by hand, neither of which prunes), and in that case a
    # single deletion per scan would take several scans to converge on a
    # limit the user has already set.
    try:
        while len(reports) > limit:
            # The newest report is the one just written; never a candidate.
            candidates = reports[:-1]
            if not candidates:
                break

            if scripted:
                reason = (
                    "--non-interactive requested" if non_interactive
                    else "no terminal attached (scripted run)"
                )
                victim = candidates[0]
                print_warning(
                    f"[Retention] {len(reports)} stored report(s) for {profile}/{target} "
                    f"exceeds the cap of {limit} — deleting the oldest "
                    f"(scan {victim['scan_id']}) because {reason}."
                )
                logger.info(
                    f"[Retention] {profile}/{target}: auto-deleted oldest report "
                    f"(scan {victim['scan_id']}) — {reason}, cap {limit}"
                )
            else:
                victim = _prompt_choice(candidates, profile, target)
                if victim is None:
                    # "Keep all" ends the pruning entirely — asking again
                    # after the user has just declined would be badgering.
                    print_info(
                        f"[Retention] keeping all {len(reports)} report(s) for "
                        f"{profile}/{target} at your request."
                    )
                    logger.info(
                        f"[Retention] {profile}/{target}: user chose to keep all "
                        f"{len(reports)} report(s) — cap {limit} deliberately exceeded"
                    )
                    return deleted
                logger.info(
                    f"[Retention] {profile}/{target}: user chose to delete the report "
                    f"for scan {victim['scan_id']}"
                )

            if not _delete_report(victim, target or _FALLBACK_TARGET):
                # Could not unlink it — stop rather than spin on the same
                # undeletable report forever.
                break
            deleted += 1
            reports = [r for r in reports if r["scan_id"] != victim["scan_id"]]

        return deleted
    except Exception as exc:
        logger.error(f"[Retention] pruning failed for {profile}/{target}: {exc}")
        print_warning(f"[Retention] report pruning failed: {exc}")
        return deleted


def retain_reports(target: str, profile: str, paths, scan_id=None,
                   keep: int = _DEFAULT_KEEP, non_interactive: bool = False) -> int:
    """
    Convenience entry point for a profile that has just written reports.

    Takes the paths the writers returned (either may be None if that writer
    failed) and prunes the directory they landed in. A profile calls this
    once, after generation, and ignores the return value unless it wants to
    report the count.
    """
    directories = {os.path.dirname(os.path.abspath(p)) for p in (paths or []) if p}
    if not directories:
        return 0

    pruned = 0
    for directory in sorted(directories):
        pruned += prune_reports(
            directory, profile, target, keep=keep, non_interactive=non_interactive
        )
    return pruned
