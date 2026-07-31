#!/usr/bin/env bash
#
# scripts/scheduled_scan.sh
# Scan a target, then report only what CHANGED since the last scan of it.
#
# Why a shell script and cron, and not a scheduler daemon
# --------------------------------------------------------
# A daemon would need its own process supervision, its own restart-on-boot
# story, its own log rotation and its own failure alerting — all of which
# cron already has, has had for decades, and which every sysadmin reading
# this already knows how to operate. `--non-interactive` was added for
# exactly this use, and the diff tool is a plain CLI call. Writing a
# scheduler on top of that would add a component to keep alive without
# answering a question cron leaves open.
#
# What this does
# --------------
#   1. runs one scan of $TARGET with the chosen profile
#   2. finds the previous scan of the same target
#   3. diffs the two and prints ONLY the delta
#   4. exits non-zero when something new was found, so cron mails you
#
# Step 4 is the point. A cron job that emails a full report every night is
# a cron job whose mail nobody reads by week three. This one is silent when
# nothing changed and speaks up when it did — which is the only way the
# alert keeps meaning something.
#
# Usage
#   scripts/scheduled_scan.sh <target> [profile]
#
# Crontab examples
#   # every night at 02:30, quick check, mail only on a change
#   30 2 * * * cd /home/jafar/aegis-scanner && scripts/scheduled_scan.sh example.com quickscan
#
#   # weekly deep scan, Sunday 03:00, log everything and still mail on change
#   0 3 * * 0 cd /home/jafar/aegis-scanner && scripts/scheduled_scan.sh example.com deepscan >> /var/log/aegis-weekly.log 2>&1
#
# cron runs with a minimal PATH and no virtualenv. Either use an absolute
# interpreter path in PYTHON below, or set PATH= at the top of your crontab.
# The scan itself will otherwise fail with "binary not found on PATH" for
# every tool, which looks like a scanner bug and is not one.

set -uo pipefail
# NOTE: deliberately NOT `set -e`. A non-zero exit from the scan step is
# meaningful here (a tool failed, or a target was unreachable) and must
# still be followed by the diff and the summary, not abort the script
# halfway and leave the operator with no output at all.

TARGET="${1:-}"
PROFILE="${2:-quickscan}"

if [[ -z "$TARGET" ]]; then
    echo "usage: $0 <target> [profile]" >&2
    echo "       profile: quickscan (default) | stealthscan | webaudit | deepscan | compliance" >&2
    exit 64
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1

# Prefer the project venv when present — it is the interpreter that is
# guaranteed to have zapv2/weasyprint/rich installed.
if [[ -x "$REPO_DIR/venv/bin/python3" ]]; then
    PYTHON="$REPO_DIR/venv/bin/python3"
else
    PYTHON="$(command -v python3)"
fi

echo "=== aegis scheduled scan: $TARGET ($PROFILE) at $(date -Is) ==="

# --non-interactive is what makes this safe unattended: the stored-report
# cap is enforced by deleting the oldest instead of stopping to ask, so the
# job cannot hang forever waiting on a prompt nobody is there to answer.
"$PYTHON" aegis.py "$TARGET" --profile "$PROFILE" --non-interactive
SCAN_STATUS=$?

if [[ $SCAN_STATUS -ne 0 ]]; then
    echo "[!] the scan itself exited $SCAN_STATUS — the diff below may compare against a partial scan" >&2
fi

# Resolve the (previous, latest) pair for this target. Done in Python
# rather than by parsing sqlite output in shell, because diff.py already
# owns that query and two implementations of "which scan came before this
# one" would eventually disagree.
read -r PREV_ID LATEST_ID < <(
    "$PYTHON" - "$TARGET" <<'PY'
import sys
from modules.reporting.diff import latest_two_scans
prev, latest = latest_two_scans(sys.argv[1])
print(prev or "", latest or "")
PY
)

if [[ -z "${PREV_ID:-}" || -z "${LATEST_ID:-}" ]]; then
    echo
    echo "This is the first recorded scan of $TARGET — there is nothing to compare it to yet."
    echo "The next run of this job will report the delta against scan ${LATEST_ID:-?}."
    exit 0
fi

echo
echo "=== changes since scan $PREV_ID ==="
DIFF_OUTPUT="$("$PYTHON" aegis.py --diff "$PREV_ID" "$LATEST_ID")"
echo "$DIFF_OUTPUT"

# Exit non-zero when the delta is non-empty, so cron's default
# mail-on-output-and-failure behaviour turns this into an alert. Counted
# from the rendered summary rather than re-running the diff, so the number
# that triggers the alert is the same number the operator reads.
NEW_COUNT=$(sed -n 's/^  NEW  *\([0-9][0-9]*\).*/\1/p'     <<<"$DIFF_OUTPUT" | head -1)
CHANGED_COUNT=$(sed -n 's/^  CHANGED  *\([0-9][0-9]*\).*/\1/p' <<<"$DIFF_OUTPUT" | head -1)
NEW_COUNT="${NEW_COUNT:-0}"
CHANGED_COUNT="${CHANGED_COUNT:-0}"

echo
if (( NEW_COUNT > 0 || CHANGED_COUNT > 0 )); then
    echo "[!] $NEW_COUNT new and $CHANGED_COUNT changed finding(s) on $TARGET — review the report above."
    exit 1
fi

echo "[+] No new or changed findings on $TARGET since scan $PREV_ID."
exit 0
