# Aegis Scanner
Kali Linux vulnerability assessment framework — 

## Setup
```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
chmod +x install.sh
./install.sh
source venv/bin/activate
```

## Usage
```bash
python3 aegis.py <target> [--profile PROFILE] [-v]
```

| Profile | Description |
|---|---|
| `quickscan` (default) | Fast overview — DNS, top-port nmap scan, service detection, quick whatweb + high-severity nuclei check. |
| `stealthscan` | Quiet -T2 scan of common ports — minimal footprint, no service probing. |
| `webaudit` | Web-focused audit — headers, Nikto, gobuster/dirb, whatweb, sslyze + CVE enrichment on web ports. |
| `deepscan` | Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports. |
| `compliance` | TLS cipher + HTTP header nmap scripts, sslyze and whatweb on TLS ports for a compliance-oriented baseline. |

Example:
```bash
python3 aegis.py 192.168.56.101 --profile deepscan
```

Run from the repo root (paths for `output/`, `database/aegis.db`, and `.env`
are all resolved relative to it). Each scan is recorded in
`database/aegis.db`; reports are written to `output/<target>/`.

`aegis.py --help` lists all flags, and `aegis.py --version` prints the
current version.

## Documentation
All project documentation lives in [`important documentations/`](important%20documentations/):

| File | What it covers |
|---|---|
| `TUTORIAL.md` | Start here — install, first scan, reading a report. |
| `COMMANDS.txt` | Every command, flag, and maintenance/one-off tool invocation. |
| `OVERVIEW_CONTEXT.md` | Repo map, module-by-module API surface, data flow. |
| `BACKEND_STRUCTURE.md` | Internals: every wrapper's contract, the shared conventions, known gaps. |
| `WRITEUP.md` | Design decisions and honesty notes — why things work the way they do. |
| `aegis_scanner_status_and_capabilities.txt` | Plain-language status: what is verified live, what isn't, demo guidance. |

`smoke_test/` holds the per-pass live verification write-ups, and
`test-targets/` is a local, isolated docker lab of intentionally vulnerable
services used to exercise the conditional tools (wpscan/sqlmap/hydra/enum4linux).
