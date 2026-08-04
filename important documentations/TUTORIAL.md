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
> real fix is to get a guaranteed-fresh profile.
>
> **The recommended way to do that is now the container** (added 2026-07-31):
>
> ```bash
> docker compose restart zap      # or: docker-compose restart zap
> ```
>
> `docker/zap/` builds ZAP with the add-on bootstrap already done and with **no
> volume mounted over `~/.ZAP`** — the profile lives in the container's own
> writable layer, so a restart discards whatever the last run did to it and
> comes back with the exact profile the image was built with. Verified: a fresh
> container reports **61 passive scan rules loaded and enabled**. That turns a
> debugging session into a one-liner.
>
> To use it: `docker compose up -d zap`, then put `ZAP_HOST=127.0.0.1` and
> `ZAP_PORT=8090` in `.env`. With `ZAP_HOST` unset, nothing changes — the
> scanner spawns a local `zap.sh` exactly as before.
>
> One gotcha worth knowing before you hit it: **ZAP runs in the container's
> network namespace, not yours.** A target you can `curl` from the host may be
> unroutable from inside the container. `zap_wrap.py` detects that (it checks
> ZAP's own site tree, not the spider's attempted-URL list) and reports it as a
> tool **failure** rather than "0 alerts", but the fix is in
> `docker-compose.yml` — see the REACHING YOUR TARGETS comment there.
>
> Without the container, the manual fix is still: back up and delete `~/.ZAP`,
> then re-run `install.sh` or its ZAP bootstrap block by hand — see
> [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) §5.

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
bearing for everything downstream, and the key is acknowledged but ignored for those). This
only works when Aegis is run in a real interactive terminal — piped/non-interactive runs
simply never see a keypress.

**Use `s`, not Ctrl+C, to skip.** Ctrl+C *usually* skips the running tool too, but only while
a tool is actually running: it is `run_tool()`/`safe_call()` that intercept the interrupt.
Press it in one of the gaps between tools — during CVE enrichment, a database write, or report
generation — and there is nothing there to catch it, so it ends the whole scan. (Measured, not
theorised: Ctrl+C during a subprocess returns a normal skipped result and the scan continues;
Ctrl+C between tools exits.) Two presses within about two seconds always end the scan
deliberately. The `s` key has no such gap — it is only ever read while a tool is running, so it
means exactly one thing at every moment of a scan.

While several targets are running (`--targets`), the skip key is disabled entirely — see
Step 9.

## Step 4 — Read the report

Every scan writes **three** files — the TXT and PDF are named after the scan so nothing is ever
overwritten, and `report.html` always holds the latest scan of that target:

```bash
ls output/scanme.nmap.org/
# report_quickscan_scanme.nmap.org_151.txt
# report_quickscan_scanme.nmap.org_151.pdf
# report.html

cat      output/scanme.nmap.org/report_quickscan_scanme.nmap.org_151.txt
xdg-open output/scanme.nmap.org/report_quickscan_scanme.nmap.org_151.pdf
xdg-open output/scanme.nmap.org/report.html
```

**The HTML one is the one to open when you are actually triaging.** Its findings table sorts by
any column and filters by severity, type, or free text, which the TXT and PDF cannot do. It is a
single self-contained file with no external resources — no fonts, no scripts, no images loaded
from anywhere — so it renders identically offline, on an air-gapped review box, or as an email
attachment.

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

**After every scan you also get a one-line delta** against the previous scan of the same target,
without asking for it:

```
Attack surface delta: 2 new, 2 fixed since scan #221 (0 unchanged)
Full comparison: python3 aegis.py --diff 221 222
```

On a target's first scan there is nothing to compare, so the line is simply not printed.

## Step 5 — Try the other profiles

Each profile trades speed for depth differently. Try them against the same target and compare
the reports:

```bash
python3 aegis.py scanme.nmap.org --profile quickscan      # DNS + fast port scan + service detect + a quick whatweb/nuclei check on the first web port
python3 aegis.py scanme.nmap.org --profile stealthscan    # quiet -T2 scan of a curated ~20-port list, minimal footprint
python3 aegis.py scanme.nmap.org --profile webaudit       # headers + Nikto + gobuster + dirb + whatweb (+sslyze on HTTPS) + an XSS fuzzing pass, bounded to 30 min
python3 aegis.py scanme.nmap.org --profile deepscan       # everything (incl. nuclei, the XSS pass, ZAP baseline, and conditional sqlmap/hydra/wpscan/enum4linux)
python3 aegis.py scanme.nmap.org --profile compliance     # nmap TLS/header scripts + sslyze + whatweb, scored instead of discarded
python3 aegis.py example.com      --profile recon         # passive: subdomains, cloud buckets, breached emails — sends nothing to the target
```

All six write a `.txt`, a `.pdf` **and** a self-contained `report.html` — that isn't a
deepscan-only thing any more.

**`stealthscan` runs one `whatweb` fingerprint and deliberately no `nuclei`.** whatweb costs a
handful of requests and turns "port 80 is open" into "port 80 is nginx running WordPress". nuclei
would fire thousands of requests per port and make the quietest profile the second-loudest, so it
is listed in the profile's config (you will see a "not run by this profile, by design" note) but
never actually run. If you want nuclei, use quickscan or deepscan.

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

---

## Step 5a — The guided menu

Run Aegis with no arguments at all and it asks what you want to do first:

```bash
python3 aegis.py
```

```
1. Vulnerability scan   pick a profile and scan a host
2. Recon mapper         map what a domain or company name exposes (passive)
3. Scan diff            compare two finished scans
```

**Any argument at all skips this menu**, so everything you have already learned keeps working
exactly as before — `python3 aegis.py scanme.nmap.org` still goes straight to a quickscan.

---

## Step 5b — Map an attack surface without touching the target (recon)

Every other profile scans a host. The recon mapper answers a different question — *what does this
organisation actually expose?* — and it answers it entirely from public sources: certificate
transparency logs, DNS aggregators, public cloud storage namespaces, and a breach database. **It
sends nothing to the target**, which is what makes it safe to run against a name you do not yet
have written authorisation to scan.

```bash
python3 aegis.py example.com --recon        # domain mode
python3 aegis.py --recon "Acme Corp"        # company-name mode
```

It is the only mode that accepts a **company name**. With a bare name there is no domain, so
there is nothing to resolve, no certificate logs to query and no subdomains to enumerate — those
three steps are reported as *not applicable* rather than run and failed. You get the cloud-bucket
search and the OSINT harvest.

What you get back:

| Finding | Severity | What it means |
|---|---|---|
| `recon_leak` | HIGH | This email address appears in a public breach corpus. Given password reuse, act on this one today. |
| `recon_bucket` | MEDIUM | A publicly readable cloud bucket matching the keyword. **Confirm you own it first** — the cloud namespace is global, so a name match is not proof of ownership. |
| `recon_subdomain` | LOW | A hostname exists. It may not resolve and may be entirely intended. A lead to scan, not a weakness. |

Two things to know before you trust the output:

- **The breach check needs an API key.** Have I Been Pwned has required a paid key since 2019.
  Without `AEGIS_HIBP_API_KEY` in your `.env`, the check reports **NOT CHECKED** — and that is
  deliberately *not* the same as "no breaches found". Never read a missing key as an all-clear.
- **Subdomain counts get large.** A passive sweep of `example.com` returned 23,330 names. The
  report lists the 100 best-corroborated plus a summary line with the true total; the complete
  list is kept in the database (`recon_subdomains`) and in the HTML report's recon section.

---

## Step 5c — Watch a scan happen (live dashboard)

```bash
python3 aegis.py scanme.nmap.org --live
```

Opens a browser page that fills in while the scan runs: which tool is going, a progress bar, and
findings appearing newest-first. You are asked about it anyway on an interactive run; `--no-live`
never asks.

It is served from `127.0.0.1` on a random port — not opened as a `file://` page, because browsers
refuse to let a local file fetch data and the dashboard would sit at "waiting for data" for ever.
Nothing is exposed to your network. **It stops when the command exits**, so an interactive run
pauses at the end and waits for you to press Enter before closing it.

Every scan also writes `output/<target>/report.html` whether or not you use `--live`: one
self-contained file with a sortable, filterable findings table and no external resources at all,
so it works offline and is safe to email.

---

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
  > Fixed 2026-07-31: this was only true of the `s` key. `run_tool()`'s Ctrl+C path set the
  > error string but never the `skipped` flag, so a deliberate Ctrl+C skip was classified as a
  > tool **failure** — printed as `[Failed] nikto: skipped by user (Ctrl+C)` and counted in
  > "Tools failed". If you are reading an older scan's summary, that is what an inflated
  > failure count next to a normal-looking scan means.
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

## Step 9 — Scan several hosts at once

```bash
python3 aegis.py --targets a.example.com,b.example.com --profile quickscan
python3 aegis.py --targets targets.txt --profile webaudit        # one host per line, # comments ok
python3 aegis.py --targets targets.txt --max-concurrent-targets 3
```

Each target gets its own `output/<target>/` directory and its own
`scan_errors.log` — nothing is shared, and one unreachable host does not affect
the others.

Two things deliberately change while several targets are running: the live Rich
progress bar is replaced by one plain line per event (a single live-updating bar
cannot represent three interleaved scans), and the `s` skip key is disabled
(it has no single referent when six tools across three targets are running).
Ctrl+C still stops the run.

The default is 2 at a time and that is intentionally conservative — each target
is *also* running its web tools concurrently, so the real request rate is
roughly `targets x tools`. If you need to be gentler on a set of hosts, use the
per-profile throttles in `config.PROFILE_RATE_LIMITS` (gobuster threads, dirb
delay, nikto pause, nuclei rate limit) rather than only lowering this number.

## Step 10 — Scan behind a login (authenticated scans)

Opt-in. With nothing configured, every command is built exactly as before.

```bash
# preferred: put it in .env, so the credential is not in your shell history
echo 'AEGIS_AUTH_COOKIE=PHPSESSID=abc123; security=low' >> .env
python3 aegis.py 127.0.0.1 --profile webaudit

# or per-run
python3 aegis.py 127.0.0.1 --profile webaudit --auth-cookie 'PHPSESSID=abc123'
python3 aegis.py api.example.com --profile webaudit --auth-header 'Authorization: Bearer <token>'
```

Basic auth uses `AEGIS_AUTH_BASIC_USER` + `AEGIS_AUTH_BASIC_PASS` — **both**, or
neither; half a pair is refused with a warning rather than sent as `user:None`.

The credential reaches nikto (basic auth only), gobuster, nuclei, sqlmap and ZAP.
**whatweb and dirb do not support custom auth cleanly and run unauthenticated** —
the scan says so out loud rather than letting their findings quietly describe the
anonymous view of a target you believe you scanned as a logged-in user.

The credential value is never written to `scan_errors.log`, a report, or the
database. Only the *method* is recorded ("session cookie", "basic auth").

To check it actually worked, compare a path's status code with and without: an
endpoint that redirects (302) to a login page anonymously should return 200 when
the session is being sent.

## Step 11 — Track what changed between scans, on a schedule

Diff any two finished scans:

```bash
python3 aegis.py --diff 137 168             # summary of new / fixed / escalated / unchanged
python3 aegis.py --diff 137 168 --diff-verbose   # also list the unchanged ones
```

Or run `python3 aegis.py` with no arguments and pick mode 3, which lists your last ten scans and
lets you choose two by number — handy when you don't remember the ids.

Read `UNVERIFIED` carefully: those findings are absent from the later scan, but
the tool that would have found them did not run in it. They are **not**
remediated — that distinction is the difference between a diff you can act on
and one you cannot. A real pair from this project's own database reports
**"0 fixed, 71 unverified"**; a naive diff would have told you 71 things got fixed.

`ESCALATED` and `DOWNGRADED` are findings still present whose severity moved, shown as
`LOW → HIGH`. A severity change is reported only when both scans actually scored the finding —
an unscored finding compared against a scored one means one scan didn't grade it, not that your
risk moved.

If you diff two scans of **different targets**, Aegis says so in a banner before the table. That
is not a delta, it is two unrelated scans subtracted from each other, and the counts will look
alarming for no reason.

For scheduling, use cron rather than a daemon — `--non-interactive` exists for
exactly this, and cron already solves restarts, logging and mail:

```bash
crontab -e
```

```cron
# nightly quick check; mails you ONLY when something new or changed appears
30 2 * * * cd /home/jafar/aegis-scanner && scripts/scheduled_scan.sh example.com quickscan

# weekly deep scan
0 3 * * 0 cd /home/jafar/aegis-scanner && scripts/scheduled_scan.sh example.com deepscan
```

`scripts/scheduled_scan.sh` runs the scan, diffs it against the previous scan of
the same target, prints only the delta, and **exits non-zero when something is
new or changed** — which is what makes cron mail you. It stays quiet otherwise,
because a job that mails a full report every night is a job nobody reads by week
three.

> cron runs with a minimal `PATH` and no virtualenv. Either set `PATH=` at the
> top of your crontab or let the script use `venv/bin/python3` (it prefers that
> automatically when present). Otherwise every tool fails with "binary not found
> on PATH", which looks like a scanner bug and is not one.

## Step 12 — Next steps

- Read [WRITEUP.md](WRITEUP.md) for the "why" behind the architecture.
- Read [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) if you're going to modify or extend a
  module — it maps every file to what calls it and what it returns.
- Keep [COMMANDS.txt](COMMANDS.txt) open in a second terminal tab as a cheat sheet.
