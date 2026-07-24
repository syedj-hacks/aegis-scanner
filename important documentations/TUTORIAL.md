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

> **ZAP note:** the apt `zaproxy` package installs the full ZAP application; if
> `zap-baseline.py` isn't on your `PATH` after install, it ships inside the ZAP install
> directory and you may need to add it or symlink it manually.

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
2. A "Scan Configuration" panel confirming the target and profile.
3. A progress bar stepping through DNS resolution → port scan → service detection →
   persisting findings.
4. A "SCAN COMPLETE" panel with the scan ID, elapsed time, and the report file path.
5. A colour-coded findings summary table (severity counts).

**Prefer to be prompted instead of typing flags?** Just run `python3 aegis.py` with no
arguments — you'll be asked for a target (re-prompted if it's invalid) and shown a numbered
menu to pick a profile from. This only kicks in when the target is omitted entirely;
`python3 aegis.py <target>` still works exactly as shown above.

## Step 4 — Read the report

```bash
cat output/scanme.nmap.org/report.txt
```

The report has three sections: a header (target/profile/timestamp), a severity-count summary,
and a detail block listing every finding (port, service, CVE if any, severity, remediation
text where available).

## Step 5 — Try the other profiles

Each profile trades speed for depth differently. Try them against the same target and compare
the reports:

```bash
python3 aegis.py scanme.nmap.org --profile stealthscan   # slow, full port sweep, minimal footprint
python3 aegis.py scanme.nmap.org --profile webaudit       # headers + Nikto + gobuster + dirb + whatweb (+sslyze on HTTPS) on web ports
python3 aegis.py scanme.nmap.org --profile deepscan       # everything (incl. nuclei, ZAP baseline, and conditional sqlmap/hydra/wpscan/enum4linux), produces report.txt + report.pdf
python3 aegis.py scanme.nmap.org --profile compliance     # nmap TLS/header scripts + sslyze, now scored instead of discarded
```

`deepscan` in particular now runs noticeably more tools than before (nuclei and the ZAP
baseline scan both take real time against a live target), so expect it to run longer than a
`quickscan` or `webaudit` pass. Conditional tools (`sqlmap`, `hydra`, `wpscan`,
`enum4linux`) only fire when `deepscan` detects their trigger condition — an injectable-looking
path, a login-service port, a WordPress fingerprint, or an open SMB port — so a target with
none of those won't show them running at all; that's expected, not a bug.

Use `-v` on any of them to see exactly which tools and nmap flags the profile resolved to
before it starts:

```bash
python3 aegis.py scanme.nmap.org --profile deepscan -v
```

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

## Step 8 — Debugging a scan that seems to have skipped something

Aegis never crashes on a missing tool or unreachable host — it logs a warning and keeps going.
If a profile's output looks thinner than expected, check that target's error log:

```bash
cat output/<target>/scan_errors.log
```

Common entries you'll see there and what they mean:
- `'<tool>' is listed in PROFILES[...] but has no wrapper module ... — skipping` — either the
  tool genuinely has no wrapper, or (more likely now) it has one but *this specific profile*
  wasn't wired to call it. `quickscan`/`stealthscan` still log this for `whatweb`/`nuclei`
  even though wrapper modules exist under `modules/web/` — see
  [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) §5 for the full, current list of which
  profile/tool pairings are wired vs. still deliberately skipped.
- A tool timeout or "command not found" — either the target didn't respond in time, or that
  apt package failed to install. Re-run `./install.sh` or `sudo apt install <tool>` directly.
  This is more likely now for the newer tools (`sqlmap`, `hydra`, `wpscan`, `enum4linux`,
  `nuclei`, `sslyze`, `whatweb`, ZAP) if `install.sh` was run before this update — re-run it to
  pick up the newly-added apt packages.
- `deepscan` conditional tools (sqlmap/hydra/wpscan/enum4linux) not appearing in the log at
  all — this means their trigger condition wasn't detected on this target (no injectable-
  looking path, no login-service port open, no WordPress fingerprint, no SMB port open), not
  that something failed.

## Step 9 — Next steps

- Read [WRITEUP.md](WRITEUP.md) for the "why" behind the architecture.
- Read [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) if you're going to modify or extend a
  module — it maps every file to what calls it and what it returns.
- Keep [COMMANDS.txt](COMMANDS.txt) open in a second terminal tab as a cheat sheet.
