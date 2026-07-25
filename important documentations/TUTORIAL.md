# Aegis Scanner — Tutorial

A walkthrough for running your first scan and understanding what comes out the other end.
For the full command list see [COMMANDS.txt](COMMANDS.txt); for internals see
[BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md).

> **Legal note:** only scan targets you own or have explicit written authorization to test.
> `scanme.nmap.org` is Nmap's official public test target and is safe to use while learning.

---

## Step 1 — Install

```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
chmod +x install.sh
./install.sh
```

`install.sh` will:
1. Ask for your sudo password (it apt-installs `nmap`, `nikto`, `gobuster`, `subfinder`,
   `amass`, `theharvester`, `dirb`, `whatweb`, `nuclei`, `zaproxy`, `sslyze`, `wpscan`,
   `sqlmap`, `hydra`, `enum4linux`, and WeasyPrint's native PDF libraries).
2. Create a Python virtual environment at `venv/`.
3. Install everything in `requirements.txt` into that venv.
4. Run `setup.py`, which checks your Python version, verifies the Python packages actually
   import, creates `output/` and `database/`, copies `modules/utils/config.example.py` to
   `modules/utils/config.py` automatically (no manual step needed), and offers an optional
   personal NVD API key prompt.

**About the NVD API key prompt:** this is now fully optional. `config.example.py` ships a
shared, working default NVD API key, so CVE lookups work immediately even if you skip the
prompt or run install non-interactively. The prompt just lets you set your *own* key instead
of using the shared project quota — if you want one, get a free key at
https://nvd.nist.gov/developers/request-an-api-key and paste it when prompted (the input is
hidden, like a password field). You can always add it later — see Step 6.

> **ZAP note:** `deepscan`'s ZAP step drives ZAP's own daemon directly over its REST API (via
> the `python-owasp-zap-v2.4` client already in `requirements.txt`), not a bundled
> `zap-baseline.py` script — apt's `zaproxy` package doesn't ship one anyway. All you need
> beyond the Python dependency is a JRE and `zap.sh` (both covered by `install.sh`'s apt step);
> if either is missing, ZAP is reported as unavailable rather than the scan failing. A stock ZAP
> install's passive-scanner add-on (`pscanrules`, the real ~60-rule vulnerability-detection set)
> isn't registered as installed until something triggers ZAP's own local bootstrap — without it,
> ZAP scans complete cleanly but silently return 0 findings forever. `install.sh` now does this
> bootstrap automatically, once, on a fresh `~/.ZAP` profile during install, so this shouldn't
> come up in normal use. **If it ever does** (ZAP findings mysteriously go to zero after
> previously working): do **not** try to fix it with `zap.sh -addonupdate` or
> `-addoninstall <id>` — that specific sequence is the leading suspect for how this add-on gets
> silently uninstalled in the first place (a broken marketplace-catalog lookup can cause the
> updater to remove the old version and fail to reinstall the replacement, with no error). The
> real fix is to back up and delete `~/.ZAP` and either re-run `install.sh` or re-run its ZAP
> bootstrap block by hand — see [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) §5.

## Step 2 — Activate the environment

Every new terminal session, before running Aegis:

```bash
source venv/bin/activate
```

You'll know it worked because your shell prompt gets a `(venv)` prefix.

## Step 3 — Run your first scan

```bash
python3 aegis.py scanme.nmap.org --profile quickscan
```

What you'll see, in order:
1. An ASCII banner (`AEGIS SCANNER v1.0.0`).
2. A "Scan Configuration" panel confirming the target and profile — it also reminds you of the
   skip keybind and Ctrl+C behavior (see below).
3. A progress bar stepping through DNS resolution → port scan → service detection → a quick
   whatweb + high-severity nuclei check on whatever web port came back open.
4. A "SCAN COMPLETE" panel with the scan ID, elapsed time, and the report file path.
5. A colour-coded findings summary table (severity counts) and a tool run/failed/skipped line.
6. Last of all, a `REPORT GENERATED` block: what was found, what kind of findings they were
   ("2 CVEs, 7 ZAP alerts, 13 discovered paths"), and the full path to both the `.txt` and the
   `.pdf`. In most terminals those paths are clickable.

**Prefer to be prompted instead of typing flags?** Just run `python3 aegis.py` with no
arguments — you'll be asked for a target (re-prompted if it's invalid) and shown a numbered
menu to pick a profile from. This only kicks in when the target is omitted entirely;
`python3 aegis.py <target>` still works exactly as shown above.

**Stuck on a slow tool?** Press `s` while a scan is running to skip just the tool currently
running and move on to the next one (nmap and DNS resolution can't be skipped — they're load-
bearing for everything downstream, and the key is acknowledged but ignored for those). A single
Ctrl+C does the same thing; press it twice within about two seconds to abort the whole scan
instead. This only works when Aegis is run in a real interactive terminal — piped/non-
interactive runs simply never see a keypress.

## Step 4 — Read the report

Every scan writes **two** files, named after the scan so nothing is ever overwritten:

```bash
ls output/scanme.nmap.org/
# report_quickscan_scanme.nmap.org_151.txt
# report_quickscan_scanme.nmap.org_151.pdf

cat      output/scanme.nmap.org/report_quickscan_scanme.nmap.org_151.txt
xdg-open output/scanme.nmap.org/report_quickscan_scanme.nmap.org_151.pdf
```

(The exact filename is printed in the `REPORT GENERATED` block at the end of the run — you don't
have to guess the scan id.)

The report reads in this order:
1. **Header** — target, profile, timestamp, scan id.
2. **Scope note**, on profiles that need one — `webaudit` says up front that it audits the web
   layer and runs nuclei only for XSS, so you know what this report does *not* cover.
3. **Severity summary** — counts per tier. In the PDF this is also a donut chart on the cover.
4. **Top findings** — the worst ones first.
5. **Injection & Scripting Vulnerabilities** — only when there are any. Confirmed SQL injection
   (sqlmap) and reflected XSS (nuclei DAST) get their own section showing the exact payload sent,
   the parameter/URL it was sent against, and a snippet of the response proving it worked.
6. **Detail** — every finding: port, service, CVE if any, severity, and remediation.

**A blank field always says why it's blank.** A field that can't apply to that kind of finding
says so ("TLS configuration finding" under CVE), and one that should have been filled in names the
tool that didn't fill it ("not determined by nuclei"). An empty cell on its own would mean both
things at once, which is why you won't see one.

**How many reports are kept:** 5 per profile per target. Past that, an interactive run asks you
which to drop; a scripted run drops the oldest and logs it. The cap is per *profile* deliberately,
so a pile of quickscans can't evict the one deepscan report of that host.

## Step 5 — Try the other profiles

Each profile trades speed for depth differently. Try them against the same target and compare
the reports:

```bash
python3 aegis.py scanme.nmap.org --profile quickscan      # DNS + fast port scan + service detect + a quick whatweb/nuclei check on the first web port
python3 aegis.py scanme.nmap.org --profile stealthscan    # quiet -T2 scan of a curated ~20-port list, minimal footprint
python3 aegis.py scanme.nmap.org --profile webaudit       # headers + Nikto + gobuster + dirb + whatweb (+sslyze on HTTPS) + an XSS fuzzing pass, bounded to 30 min
python3 aegis.py scanme.nmap.org --profile deepscan       # everything (incl. nuclei, the XSS pass, ZAP baseline, and conditional sqlmap/hydra/wpscan/enum4linux)
python3 aegis.py scanme.nmap.org --profile compliance     # nmap TLS/header scripts + sslyze + whatweb, scored instead of discarded
```

All five write both a `.txt` and a `.pdf` — that isn't a deepscan-only thing any more.

**About the XSS pass** (`webaudit` and `deepscan`): after gobuster/dirb find paths, Aegis builds
URLs with a query string from the script endpoints among them (`/search.php?q=1` and similar) and
fuzzes those with nuclei in DAST mode. It needs a parameter to mutate — a site with no discovered
script endpoints simply won't have anything to fuzz, and that's why you may see the XSS step do
nothing on a static target. Confirmed hits show up in the report's Injection & Scripting section
with the payload and the reflected response.

`deepscan` in particular runs noticeably more tools than the others (nuclei and the ZAP
baseline scan both take real time against a live target), so expect it to run longer than a
`quickscan` or `webaudit` pass — its web-audit loop and `webaudit`'s own loop are each capped by
a wall-clock budget (30 min for webaudit, 1 hour for deepscan's web loop specifically; deepscan's
separate full-port discovery sweep has its own, much larger budget) so a target with many open
web ports can't run forever — whatever was found before the budget ran out is still in the
report. Conditional tools (`sqlmap`, `hydra`, `wpscan`, `enum4linux`) only fire when `deepscan`
detects their trigger condition — an injectable-looking path, a login-service port, a WordPress
fingerprint, or an open SMB port — so a target with none of those won't show them running at
all; that's expected, not a bug (`scan_errors.log` now logs exactly which condition wasn't met
for each one).

Use `-v` on any of them to see exactly which tools and nmap flags the profile resolved to
before it starts:

```bash
python3 aegis.py scanme.nmap.org --profile deepscan -v
```

Running from a script, a cron job, or anywhere without a terminal? Add `--non-interactive` so the
report-retention step never waits on a prompt (it drops the oldest report and logs that it did).
It's implied automatically when output isn't a terminal, so you rarely need to pass it by hand:

```bash
python3 aegis.py scanme.nmap.org --profile quickscan --non-interactive
```

> **Running through the venv:** use `venv/bin/python` (or activate the venv first) consistently.
> A venv missing one dependency is invisible until a scan reports "tools failed: 1" — that exact
> situation happened here with the ZAP client. `python3 setup.py` verifies every required package
> imports, so run it if a tool starts dropping out for no obvious reason.

## Step 6 — Add or change your NVD API key later

If you skipped the key during install, or want to change it:

```bash
echo "AEGIS_NVD_API_KEY=your-key-here" >> .env
```

(or edit `.env` directly — it's a plain `KEY=value` file, one per line, gitignored so it never
gets committed). Re-run any scan and CVE lookups will pick it up automatically — nothing else
needs restarting.

## Step 7 — Look at scan history

Every scan is recorded, even ones you didn't keep the terminal output for:

```bash
python3 -c "from database.db import get_scan_history; import json; print(json.dumps(get_scan_history(), indent=2))"
```

Or scope it to one target:

```bash
python3 -c "from database.db import get_scan_history; import json; print(json.dumps(get_scan_history('scanme.nmap.org'), indent=2))"
```

Since scan 147, the database also records **which tools actually ran on each scan**, per port,
with whether each one ran, was skipped, or failed:

```bash
python3 -c "from database.db import get_scan_tools_run; print(get_scan_tools_run(150))"
```

That's the honest answer to "did this scan really run nuclei?" — much better than inferring it
from the profile. Scans older than that feature have no record and return `[]`; they were not
backfilled with data that was never captured.

## Step 8 — Debugging a scan that seems to have skipped something

Aegis never crashes on a missing tool or unreachable host — it logs a warning and keeps going.
If a profile's output looks thinner than expected, check that target's error log:

```bash
cat output/<target>/scan_errors.log
```

Common entries you'll see there and what they mean:
- `'<tool>' has a wrapper module but is not run by the '<profile>' profile (by design ...)` —
  an informational note, not a problem: the tool has real code somewhere in `modules/web/` but
  this specific profile deliberately doesn't call it (e.g. `webaudit` never runs `zaproxy`,
  `deepscan` never runs `sslyze`) — see [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) §5 for the
  current, full list of which profile/tool pairings are wired vs. deliberately skipped.
- `'<tool>' is listed in PROFILES[...] but has no wrapper module in this codebase yet` — a real
  gap: no wrapper exists for that tool anywhere. This should be rare; every tool named in any
  `PROFILES` entry has a wrapper today.
- `Tool skipped by user: <tool>` — you pressed the skip key (`s`) or Ctrl+C once while that tool
  was running; not a failure, and it's reflected in the final summary's "Tools skipped" count,
  not "Tools failed".
- `condition '<flag>' not met — skipping <tool>` — one of `deepscan`'s conditional tools
  (sqlmap/hydra/wpscan/enum4linux) didn't fire because its trigger wasn't detected on this
  target (no injectable-looking path, no login-service port open, no WordPress fingerprint, no
  SMB port open) — expected, not a failure.
- A tool timeout or "command not found" — either the target didn't respond in time, or that
  apt package failed to install. Re-run `./install.sh` or `sudo apt install <tool>` directly.
  For `nuclei`, `install.sh` also falls back to `go install` if apt's package is missing/stale on
  your mirror; for ZAP, check that both a JRE and `zap.sh` are present (`install.sh` warns about
  either being missing).
- `time budget (Ns) exhausted — skipping remaining port(s) [...]` — `webaudit`/`deepscan`'s
  per-port web loop hit its wall-clock budget (30 min / 1 hour) before finishing every open web
  port; whatever ports were already audited are still in the report, this just stops it from
  running unbounded on a target with many open web ports.

Two more things worth knowing while debugging:

- **Zero open ports on a host you know is up is usually the target, not Aegis.** Rate limiting is
  by far the most common cause. `config.KNOWN_GOOD_TARGETS` lists hosts whose open ports are an
  established fact, and the port scanner flags loudly when one of them comes back empty — check
  for that flag and try a second target before assuming a scanner bug.
- **Check your own work with the built-in audit.** It re-renders every scan in the database and
  checks for crashes, ambiguous cells, duplicate lines, and findings credited to a tool that never
  ran. It exits non-zero if anything fails:

  ```bash
  python3 tests/db_sweep.py          # every scan
  python3 tests/db_sweep.py 150      # just one
  ```

## Step 9 — Next steps

- Read [WRITEUP.md](WRITEUP.md) for the "why" behind the architecture.
- Read [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) if you're going to modify or extend a
  module — it maps every file to what calls it and what it returns.
- Keep [COMMANDS.txt](COMMANDS.txt) open in a second terminal tab as a cheat sheet.
